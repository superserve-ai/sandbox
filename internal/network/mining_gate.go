package network

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/uuid"
	"github.com/mdlayher/netlink"
	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/abuse"
	"github.com/superserve-ai/sandbox/internal/blocklist"
	"golang.org/x/sys/unix"
)

const miningGateTable = "sandbox-mining-gate"
const miningQueueNumber = 24731

// Linux nfnetlink_queue UAPI (linux/netfilter/nfnetlink_queue.h).
const (
	nfqPacket      = 0
	nfqVerdict     = 1
	nfqConfig      = 2
	nfqaPacketHdr  = 1
	nfqaMark       = 3
	nfqaPayload    = 10
	nfqaVerdictHdr = 2
)

type MiningPacketGate struct {
	mu                                   sync.Mutex
	nft                                  *nftables.Conn
	queue                                *netlink.Conn
	table                                *nftables.Table
	contained, destinations, assignments *nftables.Set
	tokens                               map[uint32]abuse.SandboxPolicy
	next                                 uint32
	log                                  zerolog.Logger
}

// RemoveMiningGate reconciles a previous process's bypass-only queue rules.
func RemoveMiningGate() error {
	conn, err := nftables.New()
	if err != nil {
		return err
	}
	tables, err := conn.ListTables()
	if err != nil {
		return err
	}
	for _, t := range tables {
		if t.Name == miningGateTable && t.Family == nftables.TableFamilyINet {
			conn.DelTable(t)
			return conn.Flush()
		}
	}
	return nil
}

// NewMiningPacketGate reserves an exclusive NFQUEUE before installing rules.
// Kernel queue bypass plus queue-full fail-open avoid turning a dead daemon or
// an overloaded observer into a fleet-wide outage.
func NewMiningPacketGate(log zerolog.Logger) (*MiningPacketGate, error) {
	q, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, err
	}
	g := &MiningPacketGate{queue: q, tokens: make(map[uint32]abuse.SandboxPolicy), log: log}
	fail := func(err error) (*MiningPacketGate, error) { q.Close(); return nil, err }
	// BIND queue, COPY_PACKET with only an IPv4 header, bounded queue, FAIL_OPEN.
	attrs := []netlink.Attribute{{Type: 1, Data: []byte{1, 0, 0, unix.AF_INET}}, {Type: 2, Data: []byte{0, 0, 0, 64, 2}}, {Type: 3, Data: be32(1024)}, {Type: 4, Data: be32(1)}, {Type: 5, Data: be32(1)}}
	msg, err := queueMessage(nfqConfig, attrs, true)
	if err != nil {
		return fail(err)
	}
	if _, err = q.Execute(msg); err != nil {
		return fail(fmt.Errorf("reserve mining packet queue: %w", err))
	}
	if err = RemoveMiningGate(); err != nil {
		return fail(err)
	}
	n, err := nftables.New()
	if err != nil {
		return fail(err)
	}
	g.nft = n
	g.table = n.AddTable(&nftables.Table{Name: miningGateTable, Family: nftables.TableFamilyINet})
	g.contained = &nftables.Set{Table: g.table, Name: "contained_sources", KeyType: nftables.TypeIPAddr}
	g.destinations = &nftables.Set{Table: g.table, Name: "mining_destinations", KeyType: nftables.TypeIPAddr, Interval: true}
	g.assignments = &nftables.Set{Table: g.table, Name: "assignment_tokens", KeyType: nftables.TypeIPAddr, DataType: nftables.TypeMark, IsMap: true}
	for _, s := range []*nftables.Set{g.contained, g.destinations, g.assignments} {
		if err = n.AddSet(s, nil); err != nil {
			return fail(err)
		}
	}
	// Bootstrap the full deterministic slot binding before activating either
	// network observer. Guests can choose source IPs, but cannot choose the
	// host-side interface on which their packets arrive.
	validSources := &nftables.Set{Table: g.table, Name: "valid_slot_sources", KeyType: nftables.MustConcatSetType(nftables.TypeIFName, nftables.TypeIPAddr), Concatenation: true}
	if err = n.AddSet(validSources, nil); err != nil {
		return fail(err)
	}
	if err = n.Flush(); err != nil {
		return fail(err)
	}
	for start := 1; start <= MaxSlots; start += 512 {
		elements := make([]nftables.SetElement, 0, 512)
		for index := start; index < min(start+512, MaxSlots+1); index++ {
			key := make([]byte, 20)
			copy(key, vethNameForSlot(index))
			ip := netip.MustParseAddr(hostIPForSlot(index)).As4()
			copy(key[16:], ip[:])
			elements = append(elements, nftables.SetElement{Key: key})
		}
		if err = n.SetAddElements(validSources, elements); err != nil {
			return fail(err)
		}
		if err = n.Flush(); err != nil {
			return fail(err)
		}
	}
	accept := nftables.ChainPolicyAccept
	chain := n.AddChain(&nftables.Chain{Name: "egress", Table: g.table, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityRef(-310), Policy: &accept})
	base := func() []expr.Any {
		return flatten(nfprotoIPv4(), []expr.Any{&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1}, &expr.Cmp{Register: 1, Op: expr.CmpOpEq, Data: []byte("veth-")}}, ipv4SrcInPrefix(vmIPRange))
	}
	n.AddRule(&nftables.Rule{Table: g.table, Chain: chain, Exprs: flatten(nfprotoIPv4(), []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Register: 1, Op: expr.CmpOpEq, Data: []byte("veth-")},
		&expr.Payload{DestRegister: 2, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
		&expr.Lookup{SourceRegister: 1, SetName: validSources.Name, SetID: validSources.ID, Invert: true},
	}, verdictDrop())})
	// Assignment tokens are installed in the background. A packet carries the
	// token assigned when it entered the queue; delayed packets cannot accuse a
	// later occupant of the same IP. Marks are cleared in the verdict.
	enqueue := func() []expr.Any {
		return []expr.Any{&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4}, &expr.Lookup{SourceRegister: 1, DestRegister: 1, IsDestRegSet: true, SetName: g.assignments.Name, SetID: g.assignments.ID}, &expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1}, &expr.Queue{Num: miningQueueNumber, Flag: expr.QueueFlagBypass}}
	}
	n.AddRule(&nftables.Rule{Table: g.table, Chain: chain, Exprs: flatten(base(), []expr.Any{&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4}, &expr.Lookup{SourceRegister: 1, SetName: g.contained.Name, SetID: g.contained.ID}}, enqueue())})
	n.AddRule(&nftables.Rule{Table: g.table, Chain: chain, Exprs: flatten(base(), ipv4DstLookup(g.destinations), enqueue())})
	if err = n.Flush(); err != nil {
		return fail(err)
	}
	return g, nil
}
func be32(n uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, n); return b }
func queueMessage(kind uint16, attrs []netlink.Attribute, ack bool) (netlink.Message, error) {
	raw, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return netlink.Message{}, err
	}
	flags := netlink.Request
	if ack {
		flags |= netlink.Acknowledge
	}
	return netlink.Message{Header: netlink.Header{Type: netlink.HeaderType(unix.NFNL_SUBSYS_QUEUE<<8 | kind), Flags: flags}, Data: append([]byte{unix.AF_INET, 0, byte(miningQueueNumber >> 8), byte(miningQueueNumber & 255)}, raw...)}, nil
}
func (g *MiningPacketGate) SetContained(ip string, on bool) error {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		return fmt.Errorf("invalid containment address")
	}
	key := addr.As4()
	g.mu.Lock()
	defer g.mu.Unlock()
	if on {
		err = g.nft.SetAddElements(g.contained, []nftables.SetElement{{Key: key[:]}})
	} else {
		err = g.nft.SetDeleteElements(g.contained, []nftables.SetElement{{Key: key[:]}})
	}
	if err != nil {
		return err
	}
	err = g.nft.Flush()
	if !on && errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}
func (g *MiningPacketGate) UpdateCIDRs(cidrs []string) error {
	elems, err := cidrsToElements(cidrs)
	if err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.nft.FlushSet(g.destinations)
	if err = g.nft.SetAddElements(g.destinations, elems); err != nil {
		return err
	}
	return g.nft.Flush()
}

// SyncAssignments is background-only. Tokens remain stable while a concrete
// assignment is unchanged and never get reused during this daemon lifetime.
func (g *MiningPacketGate) SyncAssignments(source *HostMiningSource) error {
	current := source.cur.Load()
	if current == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	old := make(map[string]uint32, len(g.tokens))
	for token, p := range g.tokens {
		old[p.Assignment] = token
	}
	next := make(map[uint32]abuse.SandboxPolicy)
	published := make(miningAssignments)
	bindings := make(map[uuid.UUID]*EgressRules)
	elems := make([]nftables.SetElement, 0, len(*current))
	for id, p := range *current {
		local, registration := source.proxy.miningRegistration(p.HostIP)
		if local != id.String() || registration == nil || registration != source.curBindings[id] || p.Assignment == "" {
			continue
		}
		ip, err := netip.ParseAddr(p.HostIP)
		if err != nil || !ip.Is4() {
			continue
		}
		token := old[p.Assignment]
		if token == 0 {
			g.next++
			if g.next == 0 {
				return fmt.Errorf("mining assignment token capacity exhausted")
			}
			token = g.next
		}
		key := ip.As4()
		next[token] = p
		published[id] = p
		bindings[id] = registration
		// nft mark map values use native endian; NFQUEUE transmits marks big endian.
		data := make([]byte, 4)
		binary.NativeEndian.PutUint32(data, token)
		elems = append(elems, nftables.SetElement{Key: key[:], Val: data})
	}
	g.nft.FlushSet(g.assignments)
	if err := g.nft.SetAddElements(g.assignments, elems); err != nil {
		return err
	}
	if err := g.nft.Flush(); err != nil {
		return err
	}
	g.tokens = next
	source.ready.Store(&miningReady{policies: published, bindings: bindings})
	return nil
}
func (g *MiningPacketGate) Run(ctx context.Context, policy *blocklist.Blocklist, c *MiningContainment) error {
	workerCtx, cancel := context.WithCancel(ctx)
	pending := make(chan abuse.MiningIncident, 64)
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		c.runPersistence(workerCtx, pending)
	}()
	defer func() {
		// Unregister first so queue-bypass takes effect even if an in-flight
		// spool write delays worker shutdown. Close still removes nft rules.
		_ = g.queue.Close()
		cancel()
		<-workerDone
	}()
	var lastOverflow time.Time
	for ctx.Err() == nil {
		_ = g.queue.SetReadDeadline(time.Now().Add(time.Second))
		messages, err := g.queue.Receive()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			if errors.Is(err, unix.ENOBUFS) {
				if time.Since(lastOverflow) >= 30*time.Second {
					g.log.Warn().Msg("mining packet queue overflow; some detection failed open")
					lastOverflow = time.Now()
				}
				continue
			}
			return err
		}
		for _, message := range messages {
			if uint16(message.Header.Type) != unix.NFNL_SUBSYS_QUEUE<<8|nfqPacket {
				continue
			}
			id, token, src, dst, valid := decodeMiningPacket(message.Data)
			verdict := uint32(1)
			if valid {
				g.mu.Lock()
				assignment, known := g.tokens[token]
				g.mu.Unlock()
				if known && assignment.HostIP == src.String() {
					p, ok := c.source.MiningPolicy(assignment.SandboxID, assignment.HostIP)
					if ok && sameMiningAssignment(p, assignment) {
						if c.Blocked(p.SandboxID, p.HostIP) {
							verdict = 0
						} else if evidence, hit := policy.MiningMatch("", dst); hit {
							c.observeQueued(p.SandboxID, p.HostIP, evidence, assignment.Assignment, pending)
							verdict = 0
						}
					}
				}
			}
			if id == 0 {
				continue
			}
			msg, err := queueMessage(nfqVerdict, []netlink.Attribute{{Type: nfqaVerdictHdr, Data: append(be32(verdict), be32(id)...)}, {Type: nfqaMark, Data: be32(0)}}, false)
			if err != nil {
				return err
			}
			if _, err = g.queue.Send(msg); err != nil {
				return err
			}
		}
	}
	return nil
}
func decodeMiningPacket(data []byte) (id, mark uint32, src, dst net.IP, valid bool) {
	if len(data) < 4 {
		return
	}
	attrs, err := netlink.UnmarshalAttributes(data[4:])
	if err != nil {
		return
	}
	for _, a := range attrs {
		switch a.Type {
		case nfqaPacketHdr:
			if len(a.Data) >= 4 {
				id = binary.BigEndian.Uint32(a.Data[:4])
			}
		case nfqaMark:
			if len(a.Data) == 4 {
				mark = binary.BigEndian.Uint32(a.Data)
			}
		case nfqaPayload:
			if len(a.Data) >= 20 && a.Data[0]>>4 == 4 {
				src = net.IP(append([]byte(nil), a.Data[12:16]...))
				dst = net.IP(append([]byte(nil), a.Data[16:20]...))
				valid = true
			}
		}
	}
	return
}
func (g *MiningPacketGate) Close() error { _ = g.queue.Close(); return RemoveMiningGate() }
