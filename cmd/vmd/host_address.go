package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"time"
)

type hostRoute struct {
	Dev      string            `json:"dev"`
	Gateway  string            `json:"gateway"`
	Source   string            `json:"prefsrc"`
	Metric   int               `json:"metric"`
	Type     string            `json:"type"`
	Flags    []string          `json:"flags"`
	Nexthops []json.RawMessage `json:"nexthops"`
}

// discoverHostRoute performs only local routing queries, never a network probe.
// It runs once before firewall setup, not on sandbox start/resume or heartbeats.
func discoverHostRoute(ctx context.Context) (string, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return resolveHostRoute(func(args ...string) ([]byte, error) {
		out, err := exec.CommandContext(ctx, "ip", args...).Output()
		if err != nil {
			return nil, fmt.Errorf("query host routing table: %w", err)
		}
		return out, nil
	})
}

func resolveHostRoute(query func(...string) ([]byte, error)) (string, string, error) {
	data, err := query("-j", "-4", "route", "show", "default")
	if err != nil {
		return "", "", err
	}
	var routes []hostRoute
	if err := json.Unmarshal(data, &routes); err != nil {
		return "", "", fmt.Errorf("decode default routes: %w", err)
	}
	if len(routes) == 0 {
		return "", "", fmt.Errorf("no IPv4 default route; configure HOST_INTERFACE")
	}
	best := routes[0]
	for _, route := range routes {
		if route.Metric < best.Metric {
			best = route
		}
	}
	count := 0
	for _, route := range routes {
		if route.Metric == best.Metric {
			count++
		}
	}
	if count != 1 || best.Dev == "" || len(best.Nexthops) != 0 || (best.Type != "" && best.Type != "unicast") {
		return "", "", fmt.Errorf("no unique usable default route; configure HOST_INTERFACE")
	}
	for _, flag := range best.Flags {
		if flag == "dead" || flag == "linkdown" {
			return "", "", fmt.Errorf("default route interface is unavailable")
		}
	}
	gateway := net.ParseIP(best.Gateway)
	if gateway == nil || gateway.To4() == nil || !gateway.IsGlobalUnicast() {
		return "", "", fmt.Errorf("default route has no usable IPv4 gateway; configure HOST_INTERFACE")
	}
	// Ask the kernel for the source used to reach the selected gateway. This
	// honors preferred source selection without enumerating per-sandbox addresses.
	data, err = query("-j", "-4", "route", "get", gateway.String())
	if err != nil {
		return "", "", err
	}
	var selected []hostRoute
	if err := json.Unmarshal(data, &selected); err != nil {
		return "", "", fmt.Errorf("decode source route: %w", err)
	}
	if len(selected) != 1 || selected[0].Dev != best.Dev || len(selected[0].Nexthops) != 0 ||
		(selected[0].Type != "" && selected[0].Type != "unicast") ||
		(best.Source != "" && best.Source != selected[0].Source) || !privateHostIPv4(net.ParseIP(selected[0].Source)) {
		return "", "", fmt.Errorf("default route does not resolve a unique private host source address")
	}
	return best.Dev, net.ParseIP(selected[0].Source).String(), nil
}

func privateHostIPv4(ip net.IP) bool {
	return ip != nil && ip.To4() != nil && ip.IsPrivate() && ip.IsGlobalUnicast()
}

func uniquePrivateHostAddress(addrs []net.Addr) (string, error) {
	found := ""
	for _, addr := range addrs {
		var ip net.IP
		switch value := addr.(type) {
		case *net.IPNet:
			ip = value.IP
		case *net.IPAddr:
			ip = value.IP
		}
		if !privateHostIPv4(ip) {
			continue
		}
		if found != "" && found != ip.String() {
			return "", fmt.Errorf("interface has multiple private IPv4 addresses")
		}
		found = ip.String()
	}
	if found == "" {
		return "", fmt.Errorf("interface has no private IPv4 address")
	}
	return found, nil
}
