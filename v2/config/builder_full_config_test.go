package config

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// builder_full_config_test.go — FINDING 1.10: EnableFullConfig must honour the
// profile's route block. These tests drive BuildConfig end to end and assert
// both halves of the contract:
//
//   - the profile's own route-level fields (final, auto_detect_interface,
//     default_domain_resolver, find_process) survive the build;
//   - the client's guarantees still hold: route.final always names an outbound
//     that exists after the build, and a profile reference to a tag that the
//     build dropped is repaired instead of left dangling.
//
// The profile's own selector group is the dropped tag used below: setOutbounds
// owns the outbound plane (it synthesizes select/lowest/balance), so a group the
// profile declares never reaches the built config even though its member leaves
// do — exactly the "final names a tag the build dropped" case.

// fullConfigProfile is a full sing-box document: a dns block with two servers, a
// profile-declared selector group, and a route block that sets every field the
// finding names.
const fullConfigProfile = `{
  "dns": {
    "servers": [
      {"type":"udp","tag":"dns-user","server":"9.9.9.9"},
      {"type":"udp","tag":"dns-alt","server":"1.0.0.1"}
    ],
    "final": "dns-user"
  },
  "outbounds": [
    {"type":"direct","tag":"node-a"},
    {"type":"direct","tag":"node-b"},
    {"type":"selector","tag":"my-group","outbounds":["node-a","node-b"],"default":"node-a"}
  ],
  "route": {
    "auto_detect_interface": true,
    "find_process": true,
    "final": "node-b",
    "default_domain_resolver": {"server": "dns-alt"},
    "rules": [
      {"domain_suffix": ["corp.example"], "outbound": "node-a"},
      {"domain_suffix": ["dead.example"], "outbound": "my-group"},
      {"domain_suffix": ["tunnel.example"], "outbound": "proxy"}
    ]
  }
}`

// fullConfigClient returns default client options with the full-config switch in
// the requested position.
func fullConfigClient(fullConfig bool) *ClientOptions {
	h := DefaultClientOptions()
	h.EnableFullConfig = fullConfig
	// Keep the legacy subscription overlay out of the control case so it
	// measures full-config behaviour only.
	h.IgnoreSubscriptionRoute = true
	return h
}

// fullConfigLiveTags mirrors the tags that exist once box.New has run its
// expansion passes (pathology legends, then punnel services): a reference to any
// other tag is a start failure.
func fullConfigLiveTags(t *testing.T, built *option.Options) map[string]bool {
	t.Helper()
	outbounds := built.Outbounds
	expanded, err := option.ExpandPathologyOutbounds(outbounds)
	if err != nil {
		t.Fatalf("engine expansion of pathology outbounds failed: %v", err)
	}
	outbounds = expanded
	expanded, err = option.ExpandPunnelOutbounds(outbounds)
	if err != nil {
		t.Fatalf("engine expansion of punnel outbounds failed: %v", err)
	}
	outbounds = expanded
	live := make(map[string]bool, len(outbounds)+len(built.Endpoints))
	for _, outbound := range outbounds {
		live[outbound.Tag] = true
	}
	for _, endpoint := range built.Endpoints {
		live[endpoint.Tag] = true
	}
	return live
}

// fullConfigRouteTargets collects every outbound tag the built route can dial
// through: route.final plus every rule's route action (logical children too).
func fullConfigRouteTargets(built *option.Options) []string {
	if built.Route == nil {
		return nil
	}
	targets := make([]string, 0, len(built.Route.Rules)+1)
	if built.Route.Final != "" {
		targets = append(targets, built.Route.Final)
	}
	var collect func(rules []option.Rule)
	collect = func(rules []option.Rule) {
		for _, rule := range rules {
			switch rule.Type {
			case "", C.RuleTypeDefault:
				if action := rule.DefaultOptions.Action; action != "" && action != C.RuleActionTypeRoute {
					continue
				}
				if tag := rule.DefaultOptions.RouteOptions.Outbound; tag != "" {
					targets = append(targets, tag)
				}
			case C.RuleTypeLogical:
				if rule.LogicalOptions.Action == C.RuleActionTypeRoute {
					if tag := rule.LogicalOptions.RouteOptions.Outbound; tag != "" {
						targets = append(targets, tag)
					}
				}
				collect(rule.LogicalOptions.Rules)
			}
		}
	}
	collect(built.Route.Rules)
	return targets
}

// assertFullConfigNoDanglingRefs is the invariant that keeps the built profile
// startable: nothing the route points at may be missing after expansion.
func assertFullConfigNoDanglingRefs(t *testing.T, built *option.Options) {
	t.Helper()
	if built.Route == nil || built.Route.Final == "" {
		t.Fatal("route.final is empty — box.New rejects a route without a default outbound")
	}
	live := fullConfigLiveTags(t, built)
	for _, tag := range fullConfigRouteTargets(built) {
		if !live[tag] {
			t.Fatalf("dangling outbound reference %q; live tags: %v", tag, liveTagList(live))
		}
	}
}

func liveTagList(live map[string]bool) []string {
	tags := make([]string, 0, len(live))
	for tag := range live {
		tags = append(tags, tag)
	}
	return tags
}

// fullConfigFindRule returns the profile rule matching domain (by domain_suffix),
// or nil.
func fullConfigFindRule(built *option.Options, domain string) *option.Rule {
	if built.Route == nil {
		return nil
	}
	for i := range built.Route.Rules {
		rule := built.Route.Rules[i]
		if rule.Type != "" && rule.Type != C.RuleTypeDefault {
			continue
		}
		for _, candidate := range rule.DefaultOptions.DomainSuffix {
			if candidate == domain {
				return &built.Route.Rules[i]
			}
		}
	}
	return nil
}

// A full config's route-level knobs must survive the build: they are the user's
// own sing-box document, and the switch is named after exactly that.
func TestBuildConfigFullConfigCarriesRouteFields(t *testing.T) {
	if C.IsAndroid || C.IsIos {
		t.Skip("auto_detect_interface is dropped on mobile by design (see setRoutingOptions)")
	}
	built, err := BuildConfig(testCtx(), fullConfigClient(true), &ReadOptions{Content: fullConfigProfile})
	if err != nil {
		t.Fatal(err)
	}
	if built.Route == nil {
		t.Fatal("nil route")
	}
	if built.Route.Final != "node-b" {
		t.Fatalf("final=%q want the profile's own final node-b", built.Route.Final)
	}
	if !built.Route.AutoDetectInterface {
		t.Fatal("auto_detect_interface from the profile was dropped")
	}
	if !built.Route.FindProcess {
		t.Fatal("find_process from the profile was dropped")
	}
	if built.Route.DefaultDomainResolver == nil || built.Route.DefaultDomainResolver.Server != "dns-alt" {
		t.Fatalf("default_domain_resolver=%+v want the profile's dns-alt", built.Route.DefaultDomainResolver)
	}
	rule := fullConfigFindRule(built, "corp.example")
	if rule == nil {
		t.Fatal("profile route rule for corp.example was dropped")
	}
	if rule.DefaultOptions.RouteOptions.Outbound != "node-a" {
		t.Fatalf("rule outbound=%q want node-a", rule.DefaultOptions.RouteOptions.Outbound)
	}
	assertFullConfigNoDanglingRefs(t, built)
}

// The client still owns the plane: its sniff/hijack rules come first, and the
// profile's own rules follow them.
func TestBuildConfigFullConfigKeepsClientRulesFirst(t *testing.T) {
	built, err := BuildConfig(testCtx(), fullConfigClient(true), &ReadOptions{Content: fullConfigProfile})
	if err != nil {
		t.Fatal(err)
	}
	if len(built.Route.Rules) == 0 {
		t.Fatal("no rules")
	}
	first := built.Route.Rules[0]
	if first.Type != C.RuleTypeDefault || first.DefaultOptions.Action != C.RuleActionTypeSniff {
		t.Fatalf("first rule=%+v want the client's sniff rule", first.DefaultOptions)
	}
	corpIdx, sniffIdx := -1, -1
	for i, rule := range built.Route.Rules {
		if rule.Type != "" && rule.Type != C.RuleTypeDefault {
			continue
		}
		if rule.DefaultOptions.Action == C.RuleActionTypeSniff {
			sniffIdx = i
		}
		for _, suffix := range rule.DefaultOptions.DomainSuffix {
			if suffix == "corp.example" {
				corpIdx = i
			}
		}
	}
	if corpIdx < 0 {
		t.Fatal("profile rule missing")
	}
	if sniffIdx < 0 || sniffIdx > corpIdx {
		t.Fatalf("sniff rule index=%d must precede the profile rule index=%d", sniffIdx, corpIdx)
	}
}

// A route.final naming a tag the build dropped must be repaired to the client
// final — never left dangling, which would make box.New refuse the profile.
func TestBuildConfigFullConfigRepairsDroppedFinal(t *testing.T) {
	profile := `{
  "outbounds": [
    {"type":"direct","tag":"node-a"},
    {"type":"selector","tag":"my-group","outbounds":["node-a"],"default":"node-a"}
  ],
  "route": {"final": "my-group"}
}`
	built, err := BuildConfig(testCtx(), fullConfigClient(true), &ReadOptions{Content: profile})
	if err != nil {
		t.Fatal(err)
	}
	for _, outbound := range built.Outbounds {
		if outbound.Tag == "my-group" {
			t.Fatal("the profile's own selector group should not reach the built outbounds")
		}
	}
	if built.Route.Final == "my-group" {
		t.Fatal("route.final still names the dropped group")
	}
	if built.Route.Final != OutboundSelectTag {
		t.Fatalf("final=%q want the client final %q", built.Route.Final, OutboundSelectTag)
	}
	assertFullConfigNoDanglingRefs(t, built)
}

// Same repair for a rule: a profile rule routed at a dropped tag would fail the
// router at request time ("outbound not found"), so it is pruned.
func TestBuildConfigFullConfigPrunesDroppedRuleTarget(t *testing.T) {
	built, err := BuildConfig(testCtx(), fullConfigClient(true), &ReadOptions{Content: fullConfigProfile})
	if err != nil {
		t.Fatal(err)
	}
	if rule := fullConfigFindRule(built, "dead.example"); rule != nil {
		t.Fatalf("rule targeting the dropped group survived: %+v", rule.DefaultOptions)
	}
	assertFullConfigNoDanglingRefs(t, built)
}

// A panel spelling ("proxy") is remapped onto the client selector like every
// other rule the client normalizes.
func TestBuildConfigFullConfigRemapsLogicalRuleTarget(t *testing.T) {
	built, err := BuildConfig(testCtx(), fullConfigClient(true), &ReadOptions{Content: fullConfigProfile})
	if err != nil {
		t.Fatal(err)
	}
	rule := fullConfigFindRule(built, "tunnel.example")
	if rule == nil {
		t.Fatal("profile rule for tunnel.example was dropped")
	}
	if rule.DefaultOptions.RouteOptions.Outbound != OutboundSelectTag {
		t.Fatalf("outbound=%q want the client selector tag", rule.DefaultOptions.RouteOptions.Outbound)
	}
	assertFullConfigNoDanglingRefs(t, built)
}

// A resolver naming a DNS server the build did not emit must fall back to the
// client resolver, not survive as a dangling dns_server reference.
func TestBuildConfigFullConfigRepairsUnknownResolver(t *testing.T) {
	profile := `{
  "dns": {"servers": [{"type":"udp","tag":"dns-user","server":"9.9.9.9"}], "final": "dns-user"},
  "outbounds": [{"type":"direct","tag":"node-a"}],
  "route": {"default_domain_resolver": {"server": "dns-does-not-exist"}}
}`
	built, err := BuildConfig(testCtx(), fullConfigClient(true), &ReadOptions{Content: profile})
	if err != nil {
		t.Fatal(err)
	}
	if built.Route.DefaultDomainResolver == nil {
		t.Fatal("nil default_domain_resolver")
	}
	if got := built.Route.DefaultDomainResolver.Server; got != "dns-user" {
		t.Fatalf("default_domain_resolver=%q want the client resolver dns-user", got)
	}
}

// When the app's own routing policy is configured it owns `final`: honouring the
// profile's final there would silently disable "route everything direct".
func TestBuildConfigFullConfigKeepsClientFinalWithRoutingPolicy(t *testing.T) {
	h := fullConfigClient(true)
	globalProxy := false
	h.RoutingGlobalProxy = &globalProxy
	h.RoutingProfiles = []*RoutingProfile{{Name: "p", Enabled: true}}

	built, err := BuildConfig(testCtx(), h, &ReadOptions{Content: fullConfigProfile})
	if err != nil {
		t.Fatal(err)
	}
	if built.Route.Final != OutboundDirectTag {
		t.Fatalf("final=%q want %q while routing-global-proxy is off", built.Route.Final, OutboundDirectTag)
	}
	assertFullConfigNoDanglingRefs(t, built)
}

// Control: without the switch the client ignores the profile's route block, which
// is the documented behaviour for ordinary profiles.
func TestBuildConfigWithoutFullConfigIgnoresRouteBlock(t *testing.T) {
	built, err := BuildConfig(testCtx(), fullConfigClient(false), &ReadOptions{Content: fullConfigProfile})
	if err != nil {
		t.Fatal(err)
	}
	if built.Route.Final != OutboundSelectTag {
		t.Fatalf("final=%q want %q", built.Route.Final, OutboundSelectTag)
	}
	if built.Route.AutoDetectInterface {
		t.Fatal("auto_detect_interface must not be taken from the profile without EnableFullConfig")
	}
	if fullConfigFindRule(built, "corp.example") != nil {
		t.Fatal("profile rule leaked into a non-full-config build")
	}
}

// Only one copy of the profile's rules may reach the route: the subscription
// overlay and the full-config merge must never both append them.
func TestBuildConfigFullConfigMergesRulesOnce(t *testing.T) {
	h := fullConfigClient(true)
	h.IgnoreSubscriptionRoute = false // the overlay would otherwise also run
	built, err := BuildConfig(testCtx(), h, &ReadOptions{Content: fullConfigProfile})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, rule := range built.Route.Rules {
		if rule.Type != "" && rule.Type != C.RuleTypeDefault {
			continue
		}
		for _, suffix := range rule.DefaultOptions.DomainSuffix {
			if suffix == "corp.example" {
				count++
			}
		}
	}
	if count != 1 {
		t.Fatalf("corp.example rule appears %d times, want 1", count)
	}
}
