package network

import (
	"context"
	"fmt"

	"github.com/superserve-ai/sandbox/internal/shellquote"
)

// slotNetOps abstracts the kernel operations that build, adopt, recycle, and
// tear down a slot's namespace, veth pair, tap, and routes. One backend runs
// iproute2 commands; the other issues the equivalent netlink calls directly.
// The slot lifecycle — ordering, ownership, and failure cleanup — lives in
// Manager and is shared by both, so the backends cannot diverge on semantics.
//
// Delete operations are idempotent: removing a namespace, link, or route that
// is already gone returns nil, matching the best-effort shell teardown paths.
type slotNetOps interface {
	// AddNamespace creates the named network namespace.
	AddNamespace(ctx context.Context, ns string) error
	// DelNamespace removes the named network namespace.
	DelNamespace(ctx context.Context, ns string) error
	// BuildSlotVeth creates the veth pair inside ns and configures the vpeer
	// end (up, MTU, address). The veth end stays inside ns, so a failure here
	// is fully cleaned up by deleting the namespace.
	BuildSlotVeth(ctx context.Context, ns, veth, vpeer, vpeerCIDR string) error
	// MoveVethToHost moves the veth end from ns to the host namespace. After
	// it succeeds the link outlives the namespace and must be deleted
	// separately on cleanup.
	MoveVethToHost(ctx context.Context, ns, veth string) error
	// ConfigureHostVeth brings the host-side veth up and sets MTU and address.
	ConfigureHostVeth(ctx context.Context, veth, vethCIDR string) error
	// RebuildTap deletes any existing tap inside ns and creates a fresh
	// persistent one with the package's fixed name, MTU, and address.
	RebuildTap(ctx context.Context, ns string) error
	// EnableLoopback brings lo up inside ns.
	EnableLoopback(ctx context.Context, ns string) error
	// AddDefaultRoute installs the default route inside ns.
	AddDefaultRoute(ctx context.Context, ns, gateway string) error
	// ReplaceDefaultRoute installs or replaces the default route inside ns.
	ReplaceDefaultRoute(ctx context.Context, ns, gateway string) error
	// AddHostRoute installs a host route to cidr via gateway on dev.
	AddHostRoute(ctx context.Context, cidr, gateway, dev string) error
	// ReplaceHostRoute installs or replaces a host route to cidr via gateway on dev.
	ReplaceHostRoute(ctx context.Context, cidr, gateway, dev string) error
	// DelHostRoute removes a host route.
	DelHostRoute(ctx context.Context, cidr, gateway, dev string) error
	// DelHostLink deletes a host link by name.
	DelHostLink(ctx context.Context, name string) error
}

// shellSlotOps is the iproute2 backend: every operation forks the ip binary,
// and namespace-scoped operations run under `ip netns exec`, which clones the
// host mount table into a throwaway mount namespace per invocation.
type shellSlotOps struct{}

func (shellSlotOps) AddNamespace(ctx context.Context, ns string) error {
	return run(ctx, "ip", "netns", "add", ns)
}

func (shellSlotOps) DelNamespace(ctx context.Context, ns string) error {
	return run(ctx, "ip", "netns", "del", ns)
}

func (shellSlotOps) BuildSlotVeth(ctx context.Context, ns, veth, vpeer, vpeerCIDR string) error {
	if err := nsRun(ctx, ns, "ip", "link", "add", veth, "type", "veth", "peer", "name", vpeer); err != nil {
		return fmt.Errorf("create veth pair: %w", err)
	}
	if err := nsRun(ctx, ns, "ip", "link", "set", vpeer, "up"); err != nil {
		return fmt.Errorf("bring up vpeer: %w", err)
	}
	if err := nsRun(ctx, ns, "ip", "link", "set", vpeer, "mtu", ifaceMTU); err != nil {
		return fmt.Errorf("set vpeer MTU: %w", err)
	}
	if err := nsRun(ctx, ns, "ip", "addr", "add", vpeerCIDR, "dev", vpeer); err != nil {
		return fmt.Errorf("assign vpeer IP: %w", err)
	}
	return nil
}

func (shellSlotOps) MoveVethToHost(ctx context.Context, ns, veth string) error {
	return nsRun(ctx, ns, "ip", "link", "set", veth, "netns", "1")
}

func (shellSlotOps) ConfigureHostVeth(ctx context.Context, veth, vethCIDR string) error {
	if err := run(ctx, "ip", "link", "set", veth, "up"); err != nil {
		return fmt.Errorf("bring up veth: %w", err)
	}
	if err := run(ctx, "ip", "link", "set", veth, "mtu", ifaceMTU); err != nil {
		return fmt.Errorf("set veth MTU: %w", err)
	}
	if err := run(ctx, "ip", "addr", "add", vethCIDR, "dev", veth); err != nil {
		return fmt.Errorf("assign veth IP: %w", err)
	}
	return nil
}

// One exec for the whole rebuild: per-command `ip netns exec` invocations fork
// twice each and serialize on the kernel's netlink lock under concurrent
// resets. Interpolants are shell-quoted package constants.
func (shellSlotOps) RebuildTap(ctx context.Context, ns string) error {
	script := fmt.Sprintf(
		"ip link del %[1]s 2>/dev/null; ip tuntap add dev %[1]s mode tap && ip link set %[1]s up && ip link set %[1]s mtu %[2]s && ip addr add %[3]s dev %[1]s",
		shellquote.Single(TAPName), shellquote.Single(ifaceMTU), shellquote.Single(tapCIDR))
	return nsRun(ctx, ns, "sh", "-c", script)
}

func (shellSlotOps) EnableLoopback(ctx context.Context, ns string) error {
	return nsRun(ctx, ns, "ip", "link", "set", "lo", "up")
}

func (shellSlotOps) AddDefaultRoute(ctx context.Context, ns, gateway string) error {
	return nsRun(ctx, ns, "ip", "route", "add", "default", "via", gateway)
}

func (shellSlotOps) ReplaceDefaultRoute(ctx context.Context, ns, gateway string) error {
	return nsRun(ctx, ns, "ip", "route", "replace", "default", "via", gateway)
}

func (shellSlotOps) AddHostRoute(ctx context.Context, cidr, gateway, dev string) error {
	return run(ctx, "ip", "route", "add", cidr, "via", gateway, "dev", dev)
}

func (shellSlotOps) ReplaceHostRoute(ctx context.Context, cidr, gateway, dev string) error {
	return run(ctx, "ip", "route", "replace", cidr, "via", gateway, "dev", dev)
}

func (shellSlotOps) DelHostRoute(ctx context.Context, cidr, gateway, dev string) error {
	return run(ctx, "ip", "route", "del", cidr, "via", gateway, "dev", dev)
}

func (shellSlotOps) DelHostLink(ctx context.Context, name string) error {
	return run(ctx, "ip", "link", "del", name)
}
