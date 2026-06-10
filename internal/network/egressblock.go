package network

// egressblock.go enforces the blocklist's IP/CIDR entries at the host level.
//
// The egress proxy only sees traffic on the proxied web ports (80/443 are the
// only ports REDIRECTed to it), so a Blocked() IP check there does not cover
// a sandbox dialing a blocklisted address on some other port. This installs a
// host nftables table whose FORWARD chain drops any forwarded packet destined
// for a blocklisted IPv4 prefix, on every port and protocol. The set is
// refreshed from the blocklist on each fetch.
//
// The table is independent of the iptables FORWARD rules in hostfw.go: it only
// ever DROPs, so a misordering relative to those rules can at worst fail to
// block (the status quo) — it can never accept traffic the host would
// otherwise drop, nor break egress.

import (
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/rs/zerolog"
	"golang.org/x/sys/unix"
)

const hostEgressBlockTable = "sandbox-egress-block"

// HostEgressBlock manages the host nftables table that drops traffic to
// blocklisted IPv4 prefixes. Safe for use from a single refresh goroutine.
type HostEgressBlock struct {
	conn  *nftables.Conn
	table *nftables.Table
	set   *nftables.Set
	log   zerolog.Logger
}

// NewHostEgressBlock creates (or recreates) the host drop table in the current
// (root) network namespace. Any pre-existing table of the same name is removed
// first so a vmd restart never stacks duplicate rules.
func NewHostEgressBlock(log zerolog.Logger) (*HostEgressBlock, error) {
	// Best-effort clean slate: delete a stale table from a prior lifetime.
	if c, err := nftables.New(); err == nil {
		c.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: hostEgressBlockTable})
		_ = c.Flush() // ignore: table may not exist
	}

	conn, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return nil, fmt.Errorf("new nftables conn: %w", err)
	}

	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   hostEgressBlockTable,
	})

	set := &nftables.Set{
		Table:    table,
		Name:     "blocked_v4",
		KeyType:  nftables.TypeIPAddr,
		Interval: true,
	}
	if err := conn.AddSet(set, nil); err != nil {
		conn.CloseLasting()
		return nil, fmt.Errorf("add blocked_v4 set: %w", err)
	}

	policy := nftables.ChainPolicyAccept
	chain := conn.AddChain(&nftables.Chain{
		Name:     "forward_block",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityRef(-10),
		Policy:   &policy,
	})

	// ip daddr @blocked_v4 drop — guarded by nfproto ipv4 since this is an
	// inet table (IPv6 sandbox egress is already dropped upstream).
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: flatten(
			nfprotoIPv4(),
			ipv4DstLookup(set),
			verdictDrop(),
		),
	})

	if err := conn.Flush(); err != nil {
		conn.CloseLasting()
		return nil, fmt.Errorf("install host egress block table: %w", err)
	}

	return &HostEgressBlock{
		conn:  conn,
		table: table,
		set:   set,
		log:   log.With().Str("component", "host-egress-block").Logger(),
	}, nil
}

// UpdateCIDRs replaces the drop set with the given IPv4 prefixes. Non-IPv4
// entries are skipped (cidrsToElements handles that). Intended as the
// Blocklist CIDR sink.
func (h *HostEgressBlock) UpdateCIDRs(cidrs []string) {
	elems, err := cidrsToElements(cidrs)
	if err != nil {
		h.log.Warn().Err(err).Msg("failed to parse blocklist CIDRs; keeping previous host drop set")
		return
	}
	h.conn.FlushSet(h.set)
	if len(elems) > 0 {
		if err := h.conn.SetAddElements(h.set, elems); err != nil {
			h.log.Warn().Err(err).Msg("failed to stage host drop set update")
			return
		}
	}
	if err := h.conn.Flush(); err != nil {
		h.log.Warn().Err(err).Msg("failed to apply host drop set update")
		return
	}
	h.log.Info().Int("cidrs", len(elems)/2).Msg("host egress block set updated")
}

// Close releases the netlink handle. The kernel table persists.
func (h *HostEgressBlock) Close() error {
	if h.conn == nil {
		return nil
	}
	err := h.conn.CloseLasting()
	h.conn = nil
	return err
}

// nfprotoIPv4 matches packets whose network-layer protocol is IPv4.
func nfprotoIPv4() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Register: 1, Op: expr.CmpOpEq, Data: []byte{unix.NFPROTO_IPV4}},
	}
}
