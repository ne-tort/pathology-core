// l3router smoke tests: the CP hands a client a spoke endpoint plus the mesh
// transport outbound it dials through. The built config must (a) keep the
// endpoint tag out of every pool — it is a network, not a proxy leaf, (b) route
// the overlay subnet into it before the private-space BypassLAN rules, and
// (c) still be accepted by the real engine (box.New).
package config_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/ne-tort/pathology-core/v2/config"
	"github.com/sagernet/sing-box/option"
)

const l3routerSmokeProfile = `{
  "outbounds": [
    {"type":"vless","tag":"l3router-underlay","server":"198.51.100.20","server_port":443,"uuid":"` + smokeUUID + `"},
    {"type":"vless","tag":"node-a","server":"198.51.100.9","server_port":443,"uuid":"` + smokeUUID + `"},
    {"type":"vless","tag":"node-b","server":"198.51.100.10","server_port":443,"uuid":"` + smokeUUID + `"}
  ],
  "endpoints": [
    {"type":"l3router","tag":"l3router","subnet":"10.200.0.0/24","address":"10.200.0.5",
     "user":"alice","password":"secret","detour":"l3router-underlay"}
  ],
  "route": {"final": "node-a"}
}`

func buildProfileWith(t *testing.T, ctx context.Context, hopts *config.ClientOptions, raw string) *option.Options {
	t.Helper()
	opts, err := config.ParseBuildConfig(ctx, hopts, &config.ReadOptions{Content: raw})
	if err != nil {
		t.Fatalf("ParseBuildConfig: %v", err)
	}
	if opts == nil {
		t.Fatal("ParseBuildConfig returned a nil config")
	}
	return opts
}

func l3RouterEndpoint(t *testing.T, opts *option.Options, tag string) *option.L3RouterEndpointOptions {
	t.Helper()
	for i := range opts.Endpoints {
		if opts.Endpoints[i].Tag != tag {
			continue
		}
		l3, ok := opts.Endpoints[i].Options.(*option.L3RouterEndpointOptions)
		if !ok {
			t.Fatalf("endpoint %q is not l3router", tag)
		}
		return l3
	}
	t.Fatalf("endpoint %q missing (have %v)", tag, opts.Endpoints)
	return nil
}

func rulePrefixes(rule option.Rule) []netip.Prefix {
	var out []netip.Prefix
	for _, prefixable := range rule.DefaultOptions.IPCIDR {
		if prefixable == nil {
			continue
		}
		out = append(out, prefixable.Build(netip.Prefix{}))
	}
	return out
}

// findRule returns the index of the first rule whose route outbound is outbound
// and whose ip_cidr contains prefix.
func findRule(opts *option.Options, outbound string, prefix netip.Prefix) int {
	for i, rule := range opts.Route.Rules {
		if rule.DefaultOptions.RouteOptions.Outbound != outbound {
			continue
		}
		for _, got := range rulePrefixes(rule) {
			if got == prefix {
				return i
			}
		}
	}
	return -1
}

func firstPrivateRule(opts *option.Options) int {
	for i, rule := range opts.Route.Rules {
		if rule.DefaultOptions.IPIsPrivate {
			return i
		}
	}
	return -1
}

func TestSmokeL3RouterSpokeIsNotAProbeLeaf(t *testing.T) {
	ctx := smokeContext(t)
	opts := buildProfileWith(t, ctx, config.DefaultClientOptions(), l3routerSmokeProfile)
	l3RouterEndpoint(t, opts, "l3router")

	groups := []string{config.OutboundSelectTag, config.OutboundURLTestTag, config.OutboundRoundRobinTag}
	for _, group := range groups {
		for _, member := range members(opts, group) {
			if member == "l3router" {
				t.Fatalf("%s probes the l3router endpoint as a proxy leaf: %v", group, members(opts, group))
			}
			if member == "l3router-underlay" {
				t.Fatalf("%s probes the mesh underlay outbound: %v", group, members(opts, group))
			}
		}
	}
	// The real leaves must still be there.
	select0 := members(opts, config.OutboundSelectTag)
	sawNode := false
	for _, member := range select0 {
		if member == "node-a" || member == "node-b" {
			sawNode = true
		}
	}
	if !sawNode {
		t.Fatalf("selector lost the real leaves: %v", select0)
	}

	assertNoDanglingReferences(t, opts)
	assertGroupsNonEmpty(t, opts)
	if _, err := newBox(t, opts); err != nil {
		t.Fatalf("box.New rejected the l3router spoke profile: %v", err)
	}
}

func TestSmokeL3RouterOverlayRulePrecedesBypassLAN(t *testing.T) {
	ctx := smokeContext(t)
	hopts := config.DefaultClientOptions()
	hopts.BypassLAN = true
	opts := buildProfileWith(t, ctx, hopts, l3routerSmokeProfile)

	overlay := netip.MustParsePrefix("10.200.0.5/24")
	overlayRule := findRule(opts, "l3router", overlay)
	if overlayRule < 0 {
		t.Fatalf("no route rule sends %v to the l3router endpoint (rules: %v)", overlay, opts.Route.Rules)
	}
	if privateRule := firstPrivateRule(opts); privateRule >= 0 && overlayRule > privateRule {
		t.Fatalf("overlay rule at %d is behind the BypassLAN rule at %d: overlay traffic would go Direct", overlayRule, privateRule)
	}
	if dnsRule := findRule(opts, config.OutboundMainDetour, netip.MustParsePrefix("10.10.34.0/24")); dnsRule >= 0 && overlayRule > dnsRule {
		t.Fatalf("overlay rule at %d is behind the 10.10.34.0/24 rule at %d", overlayRule, dnsRule)
	}
}

func TestSmokeL3RouterExitNodeRoutesWANAfterLAN(t *testing.T) {
	ctx := smokeContext(t)
	hopts := config.DefaultClientOptions()
	hopts.BypassLAN = true
	profile := `{
  "outbounds": [
    {"type":"vless","tag":"l3router-underlay","server":"198.51.100.20","server_port":443,"uuid":"` + smokeUUID + `"},
    {"type":"vless","tag":"node-a","server":"198.51.100.9","server_port":443,"uuid":"` + smokeUUID + `"},
    {"type":"vless","tag":"node-b","server":"198.51.100.10","server_port":443,"uuid":"` + smokeUUID + `"}
  ],
  "endpoints": [
    {"type":"l3router","tag":"l3router","subnet":"10.200.0.0/24","address":"10.200.0.5",
     "user":"alice","password":"secret","detour":"l3router-underlay","use_exit_node":true}
  ],
  "route": {"final": "node-a"}
}`
	opts := buildProfileWith(t, ctx, hopts, profile)
	if l3 := l3RouterEndpoint(t, opts, "l3router"); !l3.UseExitNode {
		t.Fatal("use_exit_node lost in the build")
	}

	wanRule := findRule(opts, "l3router", netip.MustParsePrefix("0.0.0.0/0"))
	if wanRule < 0 {
		t.Fatalf("no 0.0.0.0/0 rule to the l3router exit (rules: %v)", opts.Route.Rules)
	}
	if privateRule := firstPrivateRule(opts); privateRule >= 0 && wanRule < privateRule {
		t.Fatalf("WAN exit rule at %d precedes the BypassLAN rule at %d: LAN traffic would enter the mesh", wanRule, privateRule)
	}
	if overlayRule := findRule(opts, "l3router", netip.MustParsePrefix("10.200.0.5/24")); overlayRule < 0 || overlayRule > wanRule {
		t.Fatalf("overlay rule %d must precede the WAN exit rule %d", overlayRule, wanRule)
	}

	if _, err := newBox(t, opts); err != nil {
		t.Fatalf("box.New rejected the l3router exit profile: %v", err)
	}
}

// A v6 overlay endpoint follows the subscription's IPv6 decision; with the
// default options (subscription-ipv6=false) it must be dropped instead of
// starting a mesh interface the device cannot use.
func TestSmokeL3RouterIPv6SpokeFollowsSubscriptionIPv6(t *testing.T) {
	ctx := smokeContext(t)
	profile := `{
  "outbounds": [
    {"type":"vless","tag":"l3router-underlay","server":"198.51.100.20","server_port":443,"uuid":"` + smokeUUID + `"},
    {"type":"vless","tag":"node-a","server":"198.51.100.9","server_port":443,"uuid":"` + smokeUUID + `"}
  ],
  "endpoints": [
    {"type":"l3router","tag":"l3router6","subnet":"fd00:200::/64","address":"fd00:200::5",
     "user":"alice","password":"secret","detour":"l3router-underlay"}
  ],
  "route": {"final": "node-a"}
}`
	opts := buildProfileWith(t, ctx, config.DefaultClientOptions(), profile)
	for _, endpoint := range opts.Endpoints {
		if endpoint.Tag == "l3router6" {
			t.Fatal("v6 l3router endpoint kept while subscription IPv6 is off")
		}
	}
}
