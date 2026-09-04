package network

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"syscall"

	"github.com/google/nftables"
	"github.com/rs/zerolog"
)

// listRuleHandles returns the kernel's handle for every rule of an ip-family
// chain, in chain order. A handle is nf_tables identity: a rule deleted and
// re-added with identical content comes back with a new one, which is what
// lets a raced rewrite be told apart from an untouched chain. A table or
// chain the kernel does not have lists as empty.
var listRuleHandles = func(table, chain string) ([]uint64, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, err
	}
	rules, err := c.GetRules(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: table}, &nftables.Chain{Name: chain})
	if errors.Is(err, syscall.ENOENT) {
		return []uint64{}, nil
	}
	if err != nil {
		return nil, err
	}
	hs := make([]uint64, len(rules))
	for i, r := range rules {
		hs[i] = r.Handle
	}
	return hs, nil
}

// snapshotSharedChains dumps the ruleset and pairs every shared-chain rule
// with its handle. Handles are read before and after the dump and must
// agree, so the two describe one ruleset. Where the backend has no handles
// (iptables-legacy) or they cannot be paired with the dump, the snapshot
// carries none and later compares fall back to rule content — which cannot
// see a rule replaced by an identical one.
func snapshotSharedChains(ctx context.Context, spec hostFWSpec, log zerolog.Logger) (*parsedDump, error) {
	for attempt := 0; ; attempt++ {
		before, herr := sharedChainHandles(spec)
		out, err := dumpIPTables(ctx)
		if err != nil {
			return nil, err
		}
		d, err := parseIPTablesSave(out)
		if err != nil {
			return nil, err
		}
		if herr != nil {
			go func() {
				log.Warn().Err(herr).Msg("host firewall rule handles unavailable — raced rewrites are detected by rule content only")
			}()
			return d, nil
		}
		after, err := sharedChainHandles(spec)
		if err != nil {
			return nil, err
		}
		if !maps.EqualFunc(before, after, slices.Equal) {
			if attempt == 3 {
				return nil, errors.New("ruleset kept changing while being read")
			}
			continue
		}
		for key, hs := range after {
			if len(hs) != len(d.rules[key]) {
				go func() {
					log.Warn().Str("chain", key).Int("rules", len(d.rules[key])).Int("handles", len(hs)).
						Msg("host firewall rule handles do not pair with the dump — raced rewrites in this chain are detected by rule content only")
				}()
				delete(after, key)
			}
		}
		d.handles = after
		return d, nil
	}
}

func sharedChainHandles(spec hostFWSpec) (map[string][]uint64, error) {
	hs := map[string][]uint64{}
	for key := range spec.sharedOrdered {
		table, chain, _ := strings.Cut(key, "/")
		h, err := listRuleHandles(table, chain)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		hs[key] = h
	}
	return hs, nil
}

// chainRewritten reports whether a chain's foreign rules are not exactly the
// snapshot's survivors in order, or a rule vmd did not insert carries a
// handle the snapshot never saw: a raced insert, or a rule deleted and
// re-added with identical content, which no content compare can see. False
// where either dump carries no handles.
func chainRewritten(snapshot, d *parsedDump, key string, spec hostFWSpec) bool {
	sh, ch := snapshot.handles[key], d.handles[key]
	if sh == nil || ch == nil {
		return false
	}
	want := spec.sharedOrdered[key]
	known := map[uint64]bool{}
	var survivors []uint64
	for i, g := range snapshot.rules[key] {
		known[sh[i]] = true
		if foreignRule(spec, key, g, want) {
			survivors = append(survivors, sh[i])
		}
	}
	var seen []uint64
	for i, g := range d.rules[key] {
		if known[ch[i]] {
			seen = append(seen, ch[i])
		} else if !ownRule(g, want) {
			return true
		}
	}
	return !slices.Equal(seen, survivors)
}
