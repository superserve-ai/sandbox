package main

import (
	"fmt"
	"net"
	"reflect"
	"testing"
)

func TestDefaultRouteHostAddress(t *testing.T) {
	cases := []struct {
		name, defaults, selected string
		wantErr                  bool
	}{
		{"non eth0 GCE NIC", `[{"dev":"enp0s6","gateway":"10.0.0.1","metric":100}]`, `[{"dev":"enp0s6","prefsrc":"10.0.0.3"}]`, false},
		{"lowest metric", `[{"dev":"backup0","gateway":"10.1.0.1","metric":200},{"dev":"enp0s6","gateway":"10.0.0.1","metric":100}]`, `[{"dev":"enp0s6","prefsrc":"10.0.0.3"}]`, false},
		{"no route", `[]`, `[]`, true},
		{"ambiguous routes", `[{"dev":"a","gateway":"10.0.0.1"},{"dev":"b","gateway":"10.1.0.1"}]`, `[]`, true},
		{"multipath", `[{"dev":"enp0s6","gateway":"10.0.0.1","nexthops":[{}]}]`, `[]`, true},
		{"down NIC", `[{"dev":"enp0s6","gateway":"10.0.0.1","flags":["linkdown"]}]`, `[]`, true},
		{"public source", `[{"dev":"enp0s6","gateway":"10.0.0.1"}]`, `[{"dev":"enp0s6","prefsrc":"8.8.8.8"}]`, true},
		{"wildcard source", `[{"dev":"enp0s6","gateway":"10.0.0.1"}]`, `[{"dev":"enp0s6","prefsrc":"0.0.0.0"}]`, true},
		{"link local source", `[{"dev":"enp0s6","gateway":"10.0.0.1"}]`, `[{"dev":"enp0s6","prefsrc":"169.254.1.2"}]`, true},
		{"missing source", `[{"dev":"enp0s6","gateway":"10.0.0.1"}]`, `[{"dev":"enp0s6"}]`, true},
		{"route interface mismatch", `[{"dev":"enp0s6","gateway":"10.0.0.1"}]`, `[{"dev":"backup0","prefsrc":"10.0.0.3"}]`, true},
		{"multiple sources", `[{"dev":"enp0s6","gateway":"10.0.0.1"}]`, `[{"dev":"enp0s6","prefsrc":"10.0.0.3"},{"dev":"enp0s6","prefsrc":"10.0.0.4"}]`, true},
		{"conflicting preferred source", `[{"dev":"enp0s6","gateway":"10.0.0.1","prefsrc":"10.0.0.4"}]`, `[{"dev":"enp0s6","prefsrc":"10.0.0.3"}]`, true},
		{"invalid json", `{`, `[]`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			dev, ip, err := resolveHostRoute(func(args ...string) ([]byte, error) {
				calls++
				want := []string{"-j", "-4", "route", "show", "default"}
				data := tc.defaults
				if calls == 2 {
					want = []string{"-j", "-4", "route", "get", "10.0.0.1"}
					data = tc.selected
				}
				if !reflect.DeepEqual(args, want) {
					t.Fatalf("query %v want %v", args, want)
				}
				return []byte(data), nil
			})
			if (err != nil) != tc.wantErr {
				t.Fatalf("got %s %s %v", dev, ip, err)
			}
			if err != nil {
				if dev != "" || ip != "" {
					t.Fatal("failure returned usable address")
				}
				return
			}
			if dev != "enp0s6" || ip != "10.0.0.3" || calls != 2 {
				t.Fatalf("got %s %s calls=%d", dev, ip, calls)
			}
			lookup := func() (string, error) { return ip, nil }
			vmd, err := advertisedVMDAddr(lookup, 50051, "")
			if err != nil || vmd != "10.0.0.3:50051" {
				t.Fatalf("VMD: %s %v", vmd, err)
			}
			proxy, err := advertisedProxyAddr(lookup, "http://127.0.0.1:5007/health", "")
			if err != nil || proxy != "10.0.0.3:5007" {
				t.Fatalf("proxy: %s %v", proxy, err)
			}
		})
	}
}

func TestRouteQueryFailureIsClosed(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		calls := 0
		dev, ip, err := resolveHostRoute(func(...string) ([]byte, error) {
			calls++
			if calls == failAt {
				return nil, fmt.Errorf("query failed")
			}
			return []byte(`[{"dev":"nic0","gateway":"10.0.0.1"}]`), nil
		})
		if err == nil || dev != "" || ip != "" {
			t.Fatalf("got %s %s %v", dev, ip, err)
		}
	}
}

func TestConfiguredHostInterfaceAndAutomaticDefault(t *testing.T) {
	t.Setenv("KERNEL_PATH", "/tmp/kernel")
	t.Setenv("BASE_ROOTFS_PATH", "/tmp/base")
	t.Setenv("HOST_ID", "host-a")
	for _, iface := range []string{"", "ens4", "eth0"} {
		t.Setenv("HOST_INTERFACE", iface)
		cfg, err := loadConfig()
		if err != nil || cfg.HostInterface != iface {
			t.Fatalf("override %q: %q %v", iface, cfg.HostInterface, err)
		}
	}
}

func TestOverrideAddressMustBeUniqueAndPrivate(t *testing.T) {
	for _, tc := range []struct {
		ips  []string
		want string
	}{
		{[]string{"10.0.0.3", "fe80::1"}, "10.0.0.3"},
		{[]string{"10.0.0.3", "10.0.0.4"}, ""},
		{[]string{"127.0.0.1", "0.0.0.0", "8.8.8.8"}, ""},
	} {
		var addrs []net.Addr
		for _, ip := range tc.ips {
			addrs = append(addrs, &net.IPAddr{IP: net.ParseIP(ip)})
		}
		got, err := uniquePrivateHostAddress(addrs)
		if got != tc.want || (err != nil) != (tc.want == "") {
			t.Fatalf("got %q %v", got, err)
		}
	}
}

func TestAutomaticProxyAdvertisementRejectsUnusableHealthAddress(t *testing.T) {
	lookup := func() (string, error) { return "10.0.0.3", nil }
	for _, host := range []string{"0.0.0.0", "127.0.0.1", "localhost"} {
		got, err := advertisedProxyAddr(lookup, "http://"+host+":5007/health", "")
		if err != nil || got != "10.0.0.3:5007" {
			t.Fatalf("%s: %s %v", host, got, err)
		}
	}
	for _, host := range []string{"8.8.8.8", "169.254.1.2", "unknown.example"} {
		got, err := advertisedProxyAddr(lookup, "http://"+host+":5007/health", "")
		if err == nil || got != "" {
			t.Fatalf("%s: %s %v", host, got, err)
		}
	}
}

func TestMissingExplicitInterfaceDoesNotFallBack(t *testing.T) {
	if got, err := hostInterfaceAddress("missing-vmd-nic"); err == nil || got != "" {
		t.Fatalf("explicit missing interface resolved %q, %v", got, err)
	}
}
