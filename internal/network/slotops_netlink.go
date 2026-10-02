package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// netlinkSlotOps is the netlink backend: slot operations are direct kernel
// calls issued from a thread temporarily joined to the target network
// namespace. Unlike `ip netns exec`, joining a network namespace touches no
// mount state, so concurrent slot builds no longer serialize on the kernel's
// global mount lock — the only mount operations left in a slot's lifetime are
// the namespace bind mount at create and its unmount at delete.
type netlinkSlotOps struct {
	// Namespace lifecycle deliberately stays on iproute2. Creating a named
	// namespace is the one slot operation whose mount work is irreducible —
	// it must bind-mount the namespace under /run/netns — and it happens
	// once per slot. The namespace-scoped operations this backend does
	// replace run several times per build and clone the mount table on every
	// call, so converting creation trades away the smaller cost and takes on
	// the harder correctness problem below.
	//
	// It also costs correctness. `ip netns add` initializes /run/netns as a
	// shared mount and serializes that initialization under flock, and
	// `ip netns del` unlinks the name even when the unmount fails; a
	// hand-rolled equivalent has to reproduce both or it strands slots. And
	// creation is the one operation that cannot use inNamespace's
	// restore-or-terminate discipline, because the namespace does not exist
	// until the call that enters it — so its failure paths are the only ones
	// that can hand a tainted thread back to the scheduler.
	//
	// Embedding the shell backend keeps those two operations on the code
	// iproute2 has hardened, and confines this backend to what it is for:
	// replacing the namespace-scoped `ip netns exec` invocations.
	shellSlotOps

	mtu int
}

func newNetlinkSlotOps() (*netlinkSlotOps, error) {
	mtu, err := strconv.Atoi(ifaceMTU)
	if err != nil {
		return nil, fmt.Errorf("parse interface MTU %q: %w", ifaceMTU, err)
	}
	return &netlinkSlotOps{mtu: mtu}, nil
}

// socketTimeout bounds each netlink request so a caller deadline cannot be
// outlived by more than one in-flight request. Netlink requests are local
// kernel round-trips; the floor keeps a nearly-spent deadline from turning a
// healthy request into a spurious timeout.
func socketTimeout(ctx context.Context) time.Duration {
	const (
		def   = 10 * time.Second
		floor = time.Second
	)
	dl, ok := ctx.Deadline()
	if !ok {
		return def
	}
	d := time.Until(dl)
	if d < floor {
		return floor
	}
	if d > def {
		return def
	}
	return d
}

// inNamespace runs fn on an OS thread joined to the named network namespace,
// with a netlink handle whose sockets are created inside that namespace.
// It always waits for fn to finish — a cancelled caller never leaves a worker
// still mutating the slot — and bounds fn's requests via the socket timeout.
// If the thread cannot be restored to the host namespace it is terminated
// rather than returned to the scheduler pool tainted.
func inNamespace(ctx context.Context, nsName string, fn func(h *netlink.Handle) error) error {
	errCh := make(chan error, 1)
	go func() {
		runtime.LockOSThread()

		hostNS, err := netns.Get()
		if err != nil {
			runtime.UnlockOSThread()
			errCh <- fmt.Errorf("get current netns: %w", err)
			return
		}
		defer hostNS.Close()

		targetNS, err := netns.GetFromName(nsName)
		if err != nil {
			runtime.UnlockOSThread()
			errCh <- fmt.Errorf("get netns %q: %w", nsName, err)
			return
		}
		defer targetNS.Close()

		if err := netns.Set(targetNS); err != nil {
			runtime.UnlockOSThread()
			errCh <- fmt.Errorf("set netns to %q: %w", nsName, err)
			return
		}

		fnErr := runWithHandle(ctx, fn)

		if err := netns.Set(hostNS); err != nil {
			// The thread is still inside the sandbox's namespace. Exiting
			// with the thread locked makes the runtime terminate it instead
			// of handing it, tainted, to another goroutine.
			errCh <- fmt.Errorf("restore host netns: %w (op error: %v)", err, fnErr)
			return
		}

		runtime.UnlockOSThread()
		errCh <- fnErr
	}()
	return <-errCh
}

// runWithHandle gives fn a netlink handle bound to the calling thread's
// current namespace. A fresh handle per operation keeps socket ownership
// single-threaded; opening one is a socket syscall, negligible next to the
// fork+exec it replaces.
func runWithHandle(ctx context.Context, fn func(h *netlink.Handle) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	h, err := netlink.NewHandle()
	if err != nil {
		return fmt.Errorf("netlink handle: %w", err)
	}
	defer h.Close()
	if err := h.SetSocketTimeout(socketTimeout(ctx)); err != nil {
		return fmt.Errorf("netlink socket timeout: %w", err)
	}
	return fn(h)
}

// onHost runs fn with a handle in the host namespace. Only threads inside
// inNamespace ever leave the host namespace, and they restore or terminate,
// so any ordinary thread is a host-namespace thread.
func onHost(ctx context.Context, fn func(h *netlink.Handle) error) error {
	return runWithHandle(ctx, fn)
}

// AddNamespace and DelNamespace are inherited from the embedded shellSlotOps;
// see the type comment for why namespace lifecycle stays on iproute2.

func (o *netlinkSlotOps) BuildSlotVeth(ctx context.Context, ns, veth, vpeer, vpeerCIDR string) error {
	return inNamespace(ctx, ns, func(h *netlink.Handle) error {
		link := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: veth},
			PeerName:  vpeer,
		}
		if err := h.LinkAdd(link); err != nil {
			return fmt.Errorf("create veth pair: %w", err)
		}
		peer, err := h.LinkByName(vpeer)
		if err != nil {
			return fmt.Errorf("find vpeer: %w", err)
		}
		if err := h.LinkSetUp(peer); err != nil {
			return fmt.Errorf("bring up vpeer: %w", err)
		}
		if err := h.LinkSetMTU(peer, o.mtu); err != nil {
			return fmt.Errorf("set vpeer MTU: %w", err)
		}
		addr, err := netlink.ParseAddr(vpeerCIDR)
		if err != nil {
			return fmt.Errorf("parse vpeer CIDR: %w", err)
		}
		if err := h.AddrAdd(peer, addr); err != nil {
			return fmt.Errorf("assign vpeer IP: %w", err)
		}
		return nil
	})
}

func (o *netlinkSlotOps) MoveVethToHost(ctx context.Context, ns, veth string) error {
	return inNamespace(ctx, ns, func(h *netlink.Handle) error {
		link, err := h.LinkByName(veth)
		if err != nil {
			return fmt.Errorf("find veth: %w", err)
		}
		// PID 1 is always in the host's namespaces.
		return h.LinkSetNsPid(link, 1)
	})
}

func (o *netlinkSlotOps) ConfigureHostVeth(ctx context.Context, veth, vethCIDR string) error {
	return onHost(ctx, func(h *netlink.Handle) error {
		link, err := h.LinkByName(veth)
		if err != nil {
			return fmt.Errorf("find veth: %w", err)
		}
		if err := h.LinkSetUp(link); err != nil {
			return fmt.Errorf("bring up veth: %w", err)
		}
		if err := h.LinkSetMTU(link, o.mtu); err != nil {
			return fmt.Errorf("set veth MTU: %w", err)
		}
		addr, err := netlink.ParseAddr(vethCIDR)
		if err != nil {
			return fmt.Errorf("parse veth CIDR: %w", err)
		}
		if err := h.AddrAdd(link, addr); err != nil {
			return fmt.Errorf("assign veth IP: %w", err)
		}
		return nil
	})
}

func (o *netlinkSlotOps) RebuildTap(ctx context.Context, ns string) error {
	return inNamespace(ctx, ns, func(h *netlink.Handle) error {
		if link, err := h.LinkByName(TAPName); err == nil {
			if err := h.LinkDel(link); err != nil {
				return fmt.Errorf("delete stale tap: %w", err)
			}
		} else if !isLinkNotFound(err) {
			return fmt.Errorf("look up tap: %w", err)
		}
		// IFF_TAP | IFF_NO_PI, persistent — the flag set `ip tuntap add dev
		// <tap> mode tap` produces, which the VMM and the nftables rules that
		// match the tap by name both depend on.
		tap := &netlink.Tuntap{
			LinkAttrs: netlink.LinkAttrs{Name: TAPName},
			Mode:      netlink.TUNTAP_MODE_TAP,
			Flags:     netlink.TUNTAP_NO_PI,
		}
		if err := h.LinkAdd(tap); err != nil {
			return fmt.Errorf("create tap: %w", err)
		}
		link, err := h.LinkByName(TAPName)
		if err != nil {
			return fmt.Errorf("find tap: %w", err)
		}
		if err := h.LinkSetUp(link); err != nil {
			return fmt.Errorf("bring up tap: %w", err)
		}
		if err := h.LinkSetMTU(link, o.mtu); err != nil {
			return fmt.Errorf("set tap MTU: %w", err)
		}
		addr, err := netlink.ParseAddr(tapCIDR)
		if err != nil {
			return fmt.Errorf("parse tap CIDR: %w", err)
		}
		if err := h.AddrAdd(link, addr); err != nil {
			return fmt.Errorf("assign tap IP: %w", err)
		}
		return nil
	})
}

func (o *netlinkSlotOps) EnableLoopback(ctx context.Context, ns string) error {
	return inNamespace(ctx, ns, func(h *netlink.Handle) error {
		lo, err := h.LinkByName("lo")
		if err != nil {
			return fmt.Errorf("find lo: %w", err)
		}
		return h.LinkSetUp(lo)
	})
}

func (o *netlinkSlotOps) AddDefaultRoute(ctx context.Context, ns, gateway string) error {
	return o.defaultRoute(ctx, ns, gateway, false)
}

func (o *netlinkSlotOps) ReplaceDefaultRoute(ctx context.Context, ns, gateway string) error {
	return o.defaultRoute(ctx, ns, gateway, true)
}

func (o *netlinkSlotOps) defaultRoute(ctx context.Context, ns, gateway string, replace bool) error {
	gw := net.ParseIP(gateway)
	if gw == nil {
		return fmt.Errorf("parse gateway %q", gateway)
	}
	return inNamespace(ctx, ns, func(h *netlink.Handle) error {
		route := &netlink.Route{Gw: gw}
		if replace {
			return h.RouteReplace(route)
		}
		return h.RouteAdd(route)
	})
}

func (o *netlinkSlotOps) AddHostRoute(ctx context.Context, cidr, gateway, dev string) error {
	return o.hostRoute(ctx, cidr, gateway, dev, routeAdd)
}

func (o *netlinkSlotOps) ReplaceHostRoute(ctx context.Context, cidr, gateway, dev string) error {
	return o.hostRoute(ctx, cidr, gateway, dev, routeReplace)
}

func (o *netlinkSlotOps) DelHostRoute(ctx context.Context, cidr, gateway, dev string) error {
	return o.hostRoute(ctx, cidr, gateway, dev, routeDel)
}

type routeVerb int

const (
	routeAdd routeVerb = iota
	routeReplace
	routeDel
)

func (o *netlinkSlotOps) hostRoute(ctx context.Context, cidr, gateway, dev string, verb routeVerb) error {
	_, dst, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse route CIDR %q: %w", cidr, err)
	}
	gw := net.ParseIP(gateway)
	if gw == nil {
		return fmt.Errorf("parse gateway %q", gateway)
	}
	return onHost(ctx, func(h *netlink.Handle) error {
		link, err := h.LinkByName(dev)
		if err != nil {
			if verb == routeDel && isLinkNotFound(err) {
				// The device is gone, and its routes died with it.
				return nil
			}
			return fmt.Errorf("find device %q: %w", dev, err)
		}
		route := &netlink.Route{Dst: dst, Gw: gw, LinkIndex: link.Attrs().Index}
		switch verb {
		case routeReplace:
			return h.RouteReplace(route)
		case routeDel:
			if err := h.RouteDel(route); err != nil && !errors.Is(err, syscall.ESRCH) {
				return err
			}
			return nil
		default:
			return h.RouteAdd(route)
		}
	})
}

func (o *netlinkSlotOps) DelHostLink(ctx context.Context, name string) error {
	return onHost(ctx, func(h *netlink.Handle) error {
		link, err := h.LinkByName(name)
		if err != nil {
			if isLinkNotFound(err) {
				return nil
			}
			return err
		}
		return h.LinkDel(link)
	})
}

func isLinkNotFound(err error) bool {
	var lnf netlink.LinkNotFoundError
	return errors.As(err, &lnf)
}
