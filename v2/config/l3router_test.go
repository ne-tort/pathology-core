package config

import (
	"net/netip"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

func l3RouterTestEndpoint(tag string, opts *option.L3RouterEndpointOptions) option.Endpoint {
	return option.Endpoint{Type: "l3router", Tag: tag, Options: opts}
}

func l3RouterSpokeV4(tag string) option.Endpoint {
	return l3RouterTestEndpoint(tag, &option.L3RouterEndpointOptions{
		Subnet:   netip.MustParsePrefix("10.200.0.0/24"),
		Address:  netip.MustParseAddr("10.200.0.5"),
		User:     "alice",
		Password: "secret",
		Detour:   "l3router-underlay",
	})
}

func l3RouterSpokeV6(tag string) option.Endpoint {
	return l3RouterTestEndpoint(tag, &option.L3RouterEndpointOptions{
		Subnet:   netip.MustParsePrefix("fd00:200::/64"),
		Address:  netip.MustParseAddr("fd00:200::5"),
		User:     "alice",
		Password: "secret",
		Detour:   "l3router-underlay",
	})
}

// The TUN address must keep the host bits: PrefixFrom/ParsePrefix do, and the
// mesh prefix length comes from subnet. A masked address (10.200.0.0/24) is not
// assignable to an interface.
func TestL3RouterSpokePrefixKeepsHostBits(t *testing.T) {
	ep := l3RouterSpokeV4("l3router")
	got := l3routerSpokePrefix(&ep)
	want := netip.MustParsePrefix("10.200.0.5/24")
	if got != want {
		t.Fatalf("prefix = %v, want %v", got, want)
	}
	if got.Addr() != netip.MustParseAddr("10.200.0.5") {
		t.Fatalf("host bits lost: %v", got.Addr())
	}
}

func TestL3RouterSpokePrefixRejectsHub(t *testing.T) {
	hub := l3RouterTestEndpoint("mesh-hub", &option.L3RouterEndpointOptions{
		Subnet: netip.MustParsePrefix("10.200.0.0/24"),
		Peers:  []option.L3RouterPeerOptions{{User: "alice", Password: "x", Address: netip.MustParseAddr("10.200.0.5")}},
	})
	if p := l3routerSpokePrefix(&hub); p.IsValid() {
		t.Fatalf("hub endpoint produced a spoke prefix: %v", p)
	}
	if l3routerIsSpoke(&hub) {
		t.Fatal("hub endpoint reported as spoke")
	}
}

func TestL3RouterFamilyDetection(t *testing.T) {
	v4 := l3RouterSpokeV4("l3router")
	v6 := l3RouterSpokeV6("l3router6")
	if isV6, known := l3routerFamilyV6(&v4); !known || isV6 {
		t.Fatalf("v4 endpoint family: known=%v isV6=%v", known, isV6)
	}
	if isV6, known := l3routerFamilyV6(&v6); !known || !isV6 {
		t.Fatalf("v6 endpoint family: known=%v isV6=%v", known, isV6)
	}
}

func TestL3RouterTunPrefixesFamilyAndMode(t *testing.T) {
	endpoints := []option.Endpoint{l3RouterSpokeV4("l3router"), l3RouterSpokeV6("l3router6")}
	v4Only := netip.MustParsePrefix("10.200.0.5/24")
	v6Only := netip.MustParsePrefix("fd00:200::5/64")

	cases := []struct {
		name       string
		mode       option.DomainStrategy
		ipv6       bool
		wantCount  int
		wantPrefix netip.Prefix
		dropPrefix netip.Prefix
	}{
		{"ipv4-only mode drops v6 overlay", option.DomainStrategy(C.DomainStrategyIPv4Only), true, 1, v4Only, v6Only},
		{"ipv6-only mode with OS v6 drops v4 overlay", option.DomainStrategy(C.DomainStrategyIPv6Only), true, 1, v6Only, v4Only},
		{"ipv6-only mode without OS v6 falls back to v4", option.DomainStrategy(C.DomainStrategyIPv6Only), false, 1, v4Only, v6Only},
		{"default mode with OS v6 keeps both", option.DomainStrategy(C.DomainStrategyAsIS), true, 2, v6Only, netip.Prefix{}},
		{"default mode without OS v6 keeps v4", option.DomainStrategy(C.DomainStrategyAsIS), false, 1, v4Only, v6Only},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := l3routerTunPrefixes(endpoints, tc.mode, tc.ipv6)
			if len(got) != tc.wantCount {
				t.Fatalf("prefixes = %v, want %d entries", got, tc.wantCount)
			}
			found := false
			for _, p := range got {
				if p == tc.wantPrefix {
					found = true
				}
				if tc.dropPrefix.IsValid() && p == tc.dropPrefix {
					t.Fatalf("unexpected prefix %v in %v", p, got)
				}
			}
			if !found {
				t.Fatalf("missing %v in %v", tc.wantPrefix, got)
			}
		})
	}
}

func TestApplyL3RouterTunAddresses(t *testing.T) {
	base := tunAddressesForIPv6Mode(option.DomainStrategy(C.DomainStrategyAsIS), true)
	options := &option.Options{
		Inbounds: []option.Inbound{{
			Type: C.TypeTun,
			Tag:  InboundTUNTag,
			Options: &option.TunInboundOptions{
				Address: append(badoption.Listable[netip.Prefix](nil), base...),
			},
		}},
		Endpoints: []option.Endpoint{l3RouterSpokeV4("l3router"), l3RouterSpokeV6("l3router6")},
	}
	hopts := DefaultClientOptions()
	hopts.EnableTun = true

	applyL3RouterTunAddresses(options, hopts)
	applyL3RouterTunAddresses(options, hopts) // idempotent

	tunOpts, ok := options.Inbounds[0].Options.(*option.TunInboundOptions)
	if !ok {
		t.Fatal("tun options lost")
	}
	got := map[netip.Prefix]int{}
	for _, prefix := range tunOpts.Address {
		got[prefix]++
	}
	for _, want := range []netip.Prefix{netip.MustParsePrefix("10.200.0.5/24")} {
		if got[want] != 1 {
			t.Fatalf("tun address %v count = %d, want 1 (all: %v)", want, got[want], tunOpts.Address)
		}
	}
	if len(got) != len(base)+1 {
		// v6 overlay only when the OS really has IPv6; the base TUN address
		// list already follows the same probe.
		t.Logf("tun addresses: %v (OS ipv6=%v)", tunOpts.Address, isIPv6Supported())
	}
}

func TestApplyL3RouterTunAddressesNeedsTun(t *testing.T) {
	options := &option.Options{
		Endpoints: []option.Endpoint{l3RouterSpokeV4("l3router")},
	}
	hopts := DefaultClientOptions()
	hopts.EnableTun = false
	applyL3RouterTunAddresses(options, hopts)
	if len(options.Inbounds) != 0 {
		t.Fatalf("no TUN inbound expected, got %v", options.Inbounds)
	}
}

func ruleCIDRs(rule option.Rule) []netip.Prefix {
	var out []netip.Prefix
	for _, prefixable := range rule.DefaultOptions.IPCIDR {
		if prefixable == nil {
			continue
		}
		out = append(out, prefixable.Build(netip.Prefix{}))
	}
	return out
}

func ruleOutbound(rule option.Rule) string {
	return rule.DefaultOptions.RouteOptions.Outbound
}

func TestL3RouterOverlayRulesRouteSubnetToEndpoint(t *testing.T) {
	rules := l3routerOverlayRules([]option.Endpoint{l3RouterSpokeV4("l3router"), l3RouterSpokeV6("l3router6")})
	if len(rules) != 2 {
		t.Fatalf("rules = %d, want 2", len(rules))
	}
	want := map[string]netip.Prefix{
		"l3router":  netip.MustParsePrefix("10.200.0.5/24"),
		"l3router6": netip.MustParsePrefix("fd00:200::5/64"),
	}
	for _, rule := range rules {
		tag := ruleOutbound(rule)
		prefixes := ruleCIDRs(rule)
		if len(prefixes) != 1 || prefixes[0] != want[tag] {
			t.Fatalf("rule for %q carries %v, want %v", tag, prefixes, want[tag])
		}
	}
}

func TestL3RouterExitRulesPerFamily(t *testing.T) {
	exitV4 := l3RouterSpokeV4("l3router")
	exitV4.Options.(*option.L3RouterEndpointOptions).UseExitNode = true
	exitV6 := l3RouterSpokeV6("l3router6")
	exitV6.Options.(*option.L3RouterEndpointOptions).UseExitNode = true
	plain := l3RouterSpokeV4("l3router-plain")

	rules := l3routerExitRules([]option.Endpoint{exitV4, exitV6, plain})
	if len(rules) != 2 {
		t.Fatalf("rules = %d, want 2", len(rules))
	}
	got := map[string]netip.Prefix{}
	for _, rule := range rules {
		prefixes := ruleCIDRs(rule)
		if len(prefixes) != 1 {
			t.Fatalf("rule %q carries %v", ruleOutbound(rule), prefixes)
		}
		got[ruleOutbound(rule)] = prefixes[0]
	}
	if got["l3router"] != netip.MustParsePrefix("0.0.0.0/0") {
		t.Fatalf("v4 exit rule = %v", got["l3router"])
	}
	if got["l3router6"] != netip.MustParsePrefix("::/0") {
		t.Fatalf("v6 exit rule = %v", got["l3router6"])
	}
	if _, ok := got["l3router-plain"]; ok {
		t.Fatal("endpoint without use_exit_node got an exit rule")
	}
}

// The exit node is a system spoke: its OS TUN owns the overlay address, so the
// box TUN must not claim it and the route must not point at the endpoint
// (SPEC 078 mutual exclusion). A userspace sibling stays wired as before.
func TestL3RouterSystemSpokeKeepsOutOfTunWiring(t *testing.T) {
	system := l3RouterSpokeV4("l3router-exit")
	system.Options.(*option.L3RouterEndpointOptions).System = true
	system.Options.(*option.L3RouterEndpointOptions).Name = "l3r4"
	userspace := l3RouterSpokeV6("l3router6")

	endpoints := []option.Endpoint{system, userspace}

	prefixes := l3routerTunPrefixes(endpoints, option.DomainStrategy(C.DomainStrategyAsIS), true)
	for _, p := range prefixes {
		if p == netip.MustParsePrefix("10.200.0.5/24") {
			t.Fatalf("system spoke leaked into TUN prefixes: %v", prefixes)
		}
	}

	for _, rule := range l3routerOverlayRules(endpoints) {
		if ruleOutbound(rule) == "l3router-exit" {
			t.Fatalf("system spoke got an overlay route rule: %v", ruleCIDRs(rule))
		}
	}

	useExit := system
	useExit.Options.(*option.L3RouterEndpointOptions).UseExitNode = true
	for _, rule := range l3routerExitRules([]option.Endpoint{useExit}) {
		if ruleOutbound(rule) == "l3router-exit" {
			t.Fatalf("system spoke got an exit route rule: %v", ruleCIDRs(rule))
		}
	}
}

func TestL3RouterUnderlayTags(t *testing.T) {
	endpoints := []option.Endpoint{
		l3RouterSpokeV4("l3router"),
		l3RouterSpokeV6("l3router6"),
		l3RouterTestEndpoint("direct-spoke", &option.L3RouterEndpointOptions{
			Subnet:  netip.MustParsePrefix("10.201.0.0/24"),
			Address: netip.MustParseAddr("10.201.0.5"),
		}),
	}
	tags := l3routerUnderlayTags(endpoints)
	if !isMeshUnderlayTag(tags, "l3router-underlay") {
		t.Fatalf("underlay tag missing: %v", tags)
	}
	if isMeshUnderlayTag(tags, "l3router") || isMeshUnderlayTag(tags, "node-a") {
		t.Fatalf("unexpected underlay tag in %v", tags)
	}
}

func TestDropL3RouterEndpointsWithDeadDetour(t *testing.T) {
	live := []option.Outbound{{Type: C.TypeDirect, Tag: "node-a"}}
	endpoints := []option.Endpoint{l3RouterSpokeV4("l3router")}
	got := dropL3RouterEndpointsWithDeadDetour(endpoints, live)
	if len(got) != 0 {
		t.Fatalf("endpoint with dead underlay kept: %v", got)
	}

	withUnderlay := []option.Outbound{
		{Type: C.TypeDirect, Tag: "node-a"},
		{Type: C.TypeVLESS, Tag: "l3router-underlay"},
	}
	got = dropL3RouterEndpointsWithDeadDetour(endpoints, withUnderlay)
	if len(got) != 1 || got[0].Tag != "l3router" {
		t.Fatalf("endpoint with live underlay dropped: %v", got)
	}
}
