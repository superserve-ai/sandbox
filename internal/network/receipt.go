package network

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// The pool receipt is not cached state — it is a short-lived capability
// issued by the immediately preceding, fully quiesced vmd process. A clean
// shutdown snapshots the slots the pool knows are good (settled members of
// the fresh and recycled channels) and vouches for them; the next boot may
// then skip the paranoid per-slot rebuild for vouched slots and run cheap
// validation instead. Every gate fails closed: no receipt, a malformed
// receipt, a crash (which never writes one), a host reboot, an intervening
// process, or a slot-policy change all land on the existing full adoption
// path.
//
// Succession is proven, not assumed: a start generation is bumped by a
// systemd drop-in before every vmd start — including starts of older
// binaries that know nothing of receipts, since drop-ins survive rollback
// deploys — and a receipt written by generation N is honored only by
// generation N+1. Same-boot-ID plus consecutive-generation together mean
// "no other process touched these slots since the writer quiesced".

// slotPolicyVersion names the per-namespace slot contract: the nftables
// table/chain/set layout, tap addressing and MTU, the index-derived IP and
// MAC formulas. Bump it whenever any of those change so receipts written
// under the old contract are rejected and adoption rebuilds every slot —
// the rebuild is also the mechanism that installs new policy onto old
// slots. Deploys that do not touch the slot contract keep the fast path.
const slotPolicyVersion = 1

var (
	receiptPath    = "/run/vmd/netpool-receipt.json"
	generationPath = "/run/vmd/generation"
	bootIDPath     = "/proc/sys/kernel/random/boot_id"
)

type poolReceipt struct {
	BootID      string `json:"boot_id"`
	Generation  uint64 `json:"generation"`
	Fingerprint string `json:"fingerprint"`
	Fresh       []int  `json:"fresh"`
	Recycled    []int  `json:"recycled"`
}

// slotPolicyFingerprint digests every input that determines what a correct
// slot looks like from inside its namespace. Deliberately NOT the binary
// version — that would invalidate the receipt on every deploy, and deploys
// are the case the receipt exists for. Runtime-reloadable policy (user rule
// sets, blocklist CIDR reloads) is excluded: pool slots carry no user rules,
// and per-VM sets are replaced at claim time regardless.
func slotPolicyFingerprint() string {
	h := sha256.New()
	fmt.Fprintf(h, "v%d|%s|%s|%s|%s|%s|%s|%d|%s|", slotPolicyVersion,
		VMInternalIP, VMGatewayIP, TAPName, tapCIDR, tapMAC, ifaceMTU,
		MaxSlots, tableName)
	for _, c := range DeniedCIDRs {
		io.WriteString(h, c)
		io.WriteString(h, ",")
	}
	return hex.EncodeToString(h.Sum(nil))
}

func readBootID() (string, error) {
	b, err := os.ReadFile(bootIDPath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// readGeneration reports the start generation the systemd drop-in stamped
// for this process, or ok=false when the mechanism isn't installed — in
// which case receipts are neither written nor honored.
func readGeneration() (uint64, bool) {
	b, err := os.ReadFile(generationPath)
	if err != nil {
		return 0, false
	}
	gen, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, false
	}
	return gen, true
}

// writePoolReceipt commits the receipt durably: temp + fsync + rename +
// directory fsync, so a crash mid-write leaves either no receipt or a
// complete one — never a torn file (a torn file would be rejected as
// malformed anyway; this keeps the failure mode boring).
func writePoolReceipt(r *poolReceipt) error {
	data, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshal receipt: %w", err)
	}
	dir := filepath.Dir(receiptPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("receipt dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".netpool-receipt-*")
	if err != nil {
		return fmt.Errorf("receipt temp: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("receipt write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("receipt sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("receipt close: %w", err)
	}
	if err := os.Rename(tmpName, receiptPath); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("receipt rename: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// consumePoolReceipt reads and validates the receipt, DELETING IT BEFORE
// acting on its contents — the one-shot invariant: a receipt on disk means
// nobody has acted on it, so a crash mid-adoption can only destroy trust,
// never mint it. Returns the receipt or nil plus a reason for the log line.
func consumePoolReceipt() (*poolReceipt, string) {
	data, err := os.ReadFile(receiptPath)
	if os.IsNotExist(err) {
		return nil, "absent"
	}
	if err != nil {
		return nil, "unreadable: " + err.Error()
	}
	// One-shot: remove before parsing or validating. If the remove fails the
	// invariant can't be guaranteed, so the receipt must not be trusted.
	if err := os.Remove(receiptPath); err != nil {
		return nil, "irrevocable: " + err.Error()
	}
	var r poolReceipt
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, "malformed: " + err.Error()
	}
	bootID, err := readBootID()
	if err != nil || bootID != r.BootID {
		return nil, "boot id mismatch"
	}
	gen, ok := readGeneration()
	if !ok {
		return nil, "generation unavailable"
	}
	if r.Generation+1 != gen {
		return nil, fmt.Sprintf("not the immediate successor (receipt gen %d, ours %d)", r.Generation, gen)
	}
	if r.Fingerprint != slotPolicyFingerprint() {
		return nil, "slot policy changed"
	}
	return &r, "accepted"
}

// nsExecGoFunc is a seam over nsExecGo so tests can drive the vouched-slot
// validation without real kernel namespaces.
var nsExecGoFunc = nsExecGo

// fastAdoptVouched runs the cheap validation a vouched slot must still pass
// before rejoining inventory: namespace present, host veth present, zero
// occupants (from the caller's single batched /proc scan), and — inside the
// namespace — the tap device present and a firewall handle attachable to
// the previous process's ruleset. No teardown, no reinstall, no routes: the
// kernel objects were settled inventory of the immediately preceding
// process and the fingerprint proves the policy that built them is current.
// Any failure returns nil and the slot is demoted to the full path.
func (p *Pool) fastAdoptVouched(idx int, nsSet, vethSet map[string]bool, occupied map[string]bool) *preallocSlot {
	nsName := nsNameForSlot(idx)
	vethName := vethNameForSlot(idx)
	if !nsSet[nsName] || !vethSet[vethName] || occupied[nsName] {
		return nil
	}
	var fw *Firewall
	err := nsExecGoFunc(nsName, func() error {
		if _, err := net.InterfaceByName(TAPName); err != nil {
			return fmt.Errorf("tap missing: %w", err)
		}
		var aerr error
		fw, aerr = AttachFirewall(FirewallConfig{
			TAPInterface: TAPName,
			VethPeer:     "eth0",
			VMIP:         VMInternalIP,
			HostIP:       hostIPForSlot(idx),
			GatewayIP:    VMGatewayIP,
		})
		return aerr
	})
	if err != nil {
		p.log.Debug().Err(err).Int("slot", idx).Msg("pool: vouched slot failed fast validation — demoting to full adoption")
		return nil
	}
	return &preallocSlot{
		idx: idx,
		info: &VMNetInfo{
			Namespace:  nsName,
			TAPDevice:  TAPName,
			VMIP:       VMInternalIP,
			GatewayIP:  VMGatewayIP,
			HostIP:     hostIPForSlot(idx),
			MACAddress: macForSlot(idx),
			Firewall:   fw,
		},
		vethName: vethName,
		adopted:  true,
	}
}
