package proxy

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type SandboxRoute struct{ HostID, ProxyAddr string }

type OwnershipResolver interface {
	ResolveSandbox(context.Context, string) (SandboxRoute, error)
}

type RouteLookupFunc func(context.Context, string) (SandboxRoute, error)

func (f RouteLookupFunc) ResolveSandbox(ctx context.Context, id string) (SandboxRoute, error) {
	return f(ctx, id)
}

// NormalizeSandboxRoute trims persisted fields and validates the peer endpoint
// before it is used for forwarding.
func NormalizeSandboxRoute(r SandboxRoute) (SandboxRoute, error) {
	r.HostID = strings.TrimSpace(r.HostID)
	r.ProxyAddr = strings.TrimSpace(r.ProxyAddr)
	if err := validateSandboxRoute(r); err != nil {
		return SandboxRoute{}, err
	}
	return r, nil
}

func ValidateSandboxRoute(r SandboxRoute) error {
	_, err := NormalizeSandboxRoute(r)
	return err
}

func validateSandboxRoute(r SandboxRoute) error {
	if r.HostID == "" || r.ProxyAddr == "" {
		return fmt.Errorf("incomplete sandbox ownership route")
	}
	host, port, err := net.SplitHostPort(r.ProxyAddr)
	if err != nil || strings.TrimSpace(host) == "" || strings.ContainsAny(host, " \t\r\n") {
		if err == nil {
			err = fmt.Errorf("missing host")
		}
		return fmt.Errorf("invalid sandbox peer address: %w", err)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("invalid sandbox peer address: invalid port")
	}
	return nil
}
