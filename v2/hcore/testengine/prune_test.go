package testengine

import (
	"fmt"
	"sort"
	"testing"

	"github.com/ne-tort/pathology-core/v2/config"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// legendAuth is the demux auth a legend needs to become a {parent}-{legend}
// virtual outbound; the engine expands a legend only when auth exists for it.
func legendAuth() map[string]option.PathologyLegendAuth {
	return map[string]option.PathologyLegendAuth{
		"dns":  {Method: option.DemuxAuthMethodPadHMAC, PSK: "00112233445566778899aabbccddeeff"},
		"stun": {Method: option.DemuxAuthMethodPadHMAC, PSK: "00112233445566778899aabbccddeeff"},
	}
}

// TestModeLayout reproduces what config.setOutbounds emits for opt.TestMode:
// select(=leaves+rotation groups) first, then the plain outbounds, then the two
// direct exits. No lowest/balance in TestMode. Keeping the fixtures in that
// exact shape is what makes the prune tests meaningful — the defect was a
// mismatch between this layout and the prune allowlist.
func selectorFirst(selectMembers []string, defaultTag string, rest ...option.Outbound) []option.Outbound {
	out := []option.Outbound{
		{Type: C.TypeSelector, Tag: config.OutboundSelectTag, Options: &option.SelectorOutboundOptions{
			Outbounds: selectMembers,
			Default:   defaultTag,
		}},
	}
	out = append(out, rest...)
	return append(out,
		option.Outbound{Type: C.TypeDirect, Tag: config.OutboundDirectTag, Options: &option.DirectOutboundOptions{}},
		option.Outbound{Type: C.TypeDirect, Tag: config.OutboundDirectFragmentTag, Options: &option.DirectOutboundOptions{}},
	)
}

// resolvedOutboundTags lists the tags that exist after the engine's expand
// pass, computed from the post-prune config. Pathology legend parents are
// replaced by their {parent}-{legend} virtuals (only for legends with auth), so
// a parent tag must not be treated as existing.
func resolvedOutboundTags(opts *option.Options) map[string]bool {
	tags := make(map[string]bool, len(opts.Outbounds)+len(opts.Endpoints))
	for _, ob := range opts.Outbounds {
		tags[ob.Tag] = true
	}
	for _, ep := range opts.Endpoints {
		tags[ep.Tag] = true
	}
	for _, ob := range opts.Outbounds {
		ids, isParent := outboundVirtualIDs(ob)
		if !isParent {
			continue
		}
		delete(tags, ob.Tag) // box.ExpandPathologyOutbounds drops the parent
		for id := range ids {
			tags[ob.Tag+"-"+id] = true
		}
	}
	return tags
}

// assertClosedGraph walks the pruned options and fails on any reference no
// surviving outbound/endpoint satisfies once the engine-side expand pass has
// run. It is the invariant pruneToAllowlist exists to keep: the pruned graph
// must be closed; TestMode's allowlist bounds *dialed leaves*, it must never
// break a group's member list. Test-only by design.
func assertClosedGraph(t *testing.T, opts *option.Options) {
	t.Helper()
	if len(opts.Outbounds) == 0 {
		t.Fatal("graph not closed: every outbound was pruned")
	}
	exists := resolvedOutboundTags(opts)
	check := func(owner string, refs []string) {
		for _, ref := range refs {
			if ref == "" {
				continue
			}
			if !exists[ref] {
				t.Fatalf("graph not closed: %s references %q, which does not exist after pruning (have %v)",
					owner, ref, sortedTags(exists))
			}
		}
	}
	for _, ob := range opts.Outbounds {
		owner := fmt.Sprintf("outbound/%s[%s]", ob.Type, ob.Tag)
		members, isGroup := groupMemberList(ob)
		// selector/urltest/balancer all reject "missing tags"; failover's
		// validator rejects an empty outbounds list too. Any group left with
		// no members is a config box.New will refuse.
		if isGroup && len(members) == 0 {
			t.Fatalf("graph not closed: %s survived with zero members", owner)
		}
		check(owner, outboundReferenceTags(ob))
	}
	for _, ep := range opts.Endpoints {
		check(fmt.Sprintf("endpoint/%s[%s]", ep.Type, ep.Tag), endpointReferenceTags(ep))
	}
	hasDirect := false
	for _, ob := range opts.Outbounds {
		if ob.Type == C.TypeDirect {
			hasDirect = true
		}
	}
	if !hasDirect {
		t.Fatal("graph not closed: no direct outbound left (route/dns fallbacks reference it)")
	}
}

func sortedTags(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for tag := range set {
		out = append(out, tag)
	}
	sort.Strings(out)
	return out
}

func prunedTags(opts *option.Options) map[string]bool {
	return resolvedOutboundTags(opts)
}

func mustFindOutbound(t *testing.T, opts *option.Options, tag string) option.Outbound {
	t.Helper()
	for _, ob := range opts.Outbounds {
		if ob.Tag == tag {
			return ob
		}
	}
	t.Fatalf("outbound %q missing after pruning (have %v)", tag, sortedTags(prunedTags(opts)))
	return option.Outbound{}
}

func selectorMembers(t *testing.T, opts *option.Options, tag string) []string {
	t.Helper()
	ob := mustFindOutbound(t, opts, tag)
	sel, ok := ob.Options.(*option.SelectorOutboundOptions)
	if !ok {
		t.Fatalf("%q: expected SelectorOutboundOptions, got %T", tag, ob.Options)
	}
	return sel.Outbounds
}

func assertMembers(t *testing.T, what string, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s=%v want %v", what, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s=%v want %v", what, got, want)
		}
	}
}

func assertWeights(t *testing.T, got []int, want ...int) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("path_weights=%v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("path_weights=%v want %v", got, want)
		}
	}
}

// TestPruneToAllowlistReachability is the regression table for the two
// confirmed prune defects — group wrappers (failover/scatter) dropped out of
// TestMode `select`, and pathology legend parents dropped out from under their
// synthesized `-auto` balancer — plus the boundary cases the reachability pass
// must still honour.
func TestPruneToAllowlistReachability(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		build  func() *option.Options
		leaves []string
		// verify runs after the generic graph-closure assert.
		verify func(t *testing.T, opts *option.Options)
	}{
		{
			// Defect 1: failover/scatter fall through setOutbounds' default
			// branch, so their tags are members of TestMode select — but the
			// old prune had no type fallback for them and dropped them.
			name: "group wrappers in select survive pruning",
			build: func() *option.Options {
				return &option.Options{Outbounds: selectorFirst(
					[]string{"leaf-a", "leaf-wrapper", "fail-over", "scatter-g"},
					"leaf-a",
					option.Outbound{Type: C.TypeVLESS, Tag: "leaf-a", Options: &option.VLESSOutboundOptions{}},
					option.Outbound{Type: C.TypeVLESS, Tag: "leaf-wrapper", Options: &option.VLESSOutboundOptions{}},
					option.Outbound{Type: C.TypeVLESS, Tag: "leaf-gone", Options: &option.VLESSOutboundOptions{}},
					option.Outbound{Type: C.TypeFailover, Tag: "fail-over", Options: &option.FailoverOutboundOptions{
						Outbounds:   []string{"leaf-wrapper", "leaf-gone"},
						ControlAuth: "none",
					}},
					option.Outbound{Type: C.TypeScatter, Tag: "scatter-g", Options: &option.ScatterOutboundOptions{
						Paths:       []string{"leaf-a", "leaf-wrapper"},
						PathWeights: []int{7, 3},
						Strategy:    "weighted",
					}},
				)}
			},
			leaves: []string{"leaf-a", "leaf-wrapper"},
			verify: func(t *testing.T, opts *option.Options) {
				t.Helper()
				// select keeps the wrappers (they are leaves of the side box)
				// and is narrowed to what still exists.
				assertMembers(t, "select", selectorMembers(t, opts, config.OutboundSelectTag),
					"leaf-a", "leaf-wrapper", "fail-over", "scatter-g")
				fo := mustFindOutbound(t, opts, "fail-over")
				// leaf-gone survives: the failover still references it, and the
				// closure outranks the allowlist.
				assertMembers(t, "fail-over", fo.Options.(*option.FailoverOutboundOptions).Outbounds,
					"leaf-wrapper", "leaf-gone")
				sc := mustFindOutbound(t, opts, "scatter-g")
				scOpts := sc.Options.(*option.ScatterOutboundOptions)
				assertMembers(t, "scatter paths", scOpts.Paths, "leaf-a", "leaf-wrapper")
				// path_weights is positional and must shrink with paths, or the
				// scatter group fails validation.
				assertWeights(t, scOpts.PathWeights, 7, 3)
			},
		},
		{
			// Defect 2: the legend parent is not in the UI allowlist (the UI
			// lists the -auto rotation group), but the engine builds the
			// virtuals from the parent. Dropping the parent left the balancer
			// naming tags nothing would ever create.
			name: "pathology legend parent and its -auto balancer survive",
			build: func() *option.Options {
				return &option.Options{Outbounds: selectorFirst(
					[]string{"path-parent-auto"},
					"path-parent-auto",
					option.Outbound{Type: C.TypePathology, Tag: "path-parent", Options: &option.PathologyOutboundOptions{
						ServerOptions: option.ServerOptions{Server: "1.2.3.4", ServerPort: 443},
						Legends: map[string]option.PathologyLegendEntry{
							"dns":  {},
							"stun": {},
						},
						Auth: legendAuth(),
					}},
					option.Outbound{Type: C.TypeBalancer, Tag: "path-parent-auto", Options: &option.BalancerOutboundOptions{
						Strategy:  "first-alive",
						Outbounds: []string{"path-parent-dns", "path-parent-stun"},
					}},
				)}
			},
			leaves: []string{"path-parent-auto"},
			verify: func(t *testing.T, opts *option.Options) {
				t.Helper()
				parent := mustFindOutbound(t, opts, "path-parent")
				if parent.Type != C.TypePathology {
					t.Fatalf("path-parent type=%q want %q", parent.Type, C.TypePathology)
				}
				po, ok := parent.Options.(*option.PathologyOutboundOptions)
				if !ok || len(po.Legends) != 2 {
					t.Fatalf("path-parent lost its legends: %#v", parent.Options)
				}
				group := mustFindOutbound(t, opts, "path-parent-auto")
				bo, ok := group.Options.(*option.BalancerOutboundOptions)
				if !ok {
					t.Fatalf("path-parent-auto options=%T", group.Options)
				}
				assertMembers(t, "path-parent-auto", bo.Outbounds, "path-parent-dns", "path-parent-stun")
				if bo.Strategy != "first-alive" {
					t.Fatalf("path-parent-auto strategy=%q want first-alive", bo.Strategy)
				}
			},
		},
		{
			name: "leaf outside the allowlist and referenced by nothing is dropped",
			build: func() *option.Options {
				return &option.Options{Outbounds: selectorFirst(
					[]string{"keep-a"},
					"keep-a",
					option.Outbound{Type: C.TypeVLESS, Tag: "keep-a", Options: &option.VLESSOutboundOptions{}},
					option.Outbound{Type: C.TypeVLESS, Tag: "drop-me", Options: &option.VLESSOutboundOptions{}},
					option.Outbound{Type: C.TypeVLESS, Tag: "drop-me-too", Options: &option.VLESSOutboundOptions{}},
				)}
			},
			leaves: []string{"keep-a"},
			verify: func(t *testing.T, opts *option.Options) {
				t.Helper()
				tags := prunedTags(opts)
				for _, gone := range []string{"drop-me", "drop-me-too"} {
					if tags[gone] {
						t.Fatalf("%q should be pruned, have %v", gone, sortedTags(tags))
					}
				}
				if !tags["keep-a"] {
					t.Fatalf("keep-a should survive, have %v", sortedTags(tags))
				}
				assertMembers(t, "select", selectorMembers(t, opts, config.OutboundSelectTag), "keep-a")
			},
		},
		{
			name: "leaf outside the allowlist but referenced by a kept failover survives",
			build: func() *option.Options {
				return &option.Options{Outbounds: selectorFirst(
					[]string{"leaf-kept", "fail-over"},
					"leaf-kept",
					option.Outbound{Type: C.TypeVLESS, Tag: "leaf-kept", Options: &option.VLESSOutboundOptions{}},
					// Not in leaves; only the kept failover names it.
					option.Outbound{Type: C.TypeVLESS, Tag: "leaf-via-group", Options: &option.VLESSOutboundOptions{}},
					option.Outbound{Type: C.TypeVLESS, Tag: "leaf-unused", Options: &option.VLESSOutboundOptions{}},
					option.Outbound{Type: C.TypeFailover, Tag: "fail-over", Options: &option.FailoverOutboundOptions{
						Outbounds:   []string{"leaf-kept", "leaf-via-group"},
						ControlAuth: "none",
					}},
				)}
			},
			leaves: []string{"leaf-kept"},
			verify: func(t *testing.T, opts *option.Options) {
				t.Helper()
				tags := prunedTags(opts)
				if !tags["leaf-via-group"] {
					t.Fatalf("leaf-via-group is referenced by the kept failover and must survive, have %v", sortedTags(tags))
				}
				if tags["leaf-unused"] {
					t.Fatalf("leaf-unused is unreferenced and must be pruned, have %v", sortedTags(tags))
				}
				fo := mustFindOutbound(t, opts, "fail-over")
				assertMembers(t, "fail-over", fo.Options.(*option.FailoverOutboundOptions).Outbounds,
					"leaf-kept", "leaf-via-group")
			},
		},
		{
			// IPv6/disabled filtering already ran upstream, so a user-authored
			// wrapper can name members that never made it into the built
			// config. The old type fallback kept such a group and box.New then
			// failed on its dangling member list; the prune has to drop it.
			name: "kept group whose only members are gone is itself dropped",
			build: func() *option.Options {
				return &option.Options{Outbounds: selectorFirst(
					[]string{"leaf-kept"},
					"leaf-kept",
					option.Outbound{Type: C.TypeVLESS, Tag: "leaf-kept", Options: &option.VLESSOutboundOptions{}},
					// Allowlisted, but no member of it exists in the config.
					option.Outbound{Type: C.TypeFailover, Tag: "stale-failover", Options: &option.FailoverOutboundOptions{
						Outbounds:   []string{"filtered-ipv6-a", "filtered-ipv6-b"},
						ControlAuth: "none",
					}},
				)}
			},
			leaves: []string{"leaf-kept", "stale-failover"},
			verify: func(t *testing.T, opts *option.Options) {
				t.Helper()
				tags := prunedTags(opts)
				if tags["stale-failover"] {
					t.Fatalf("stale-failover has no usable members and must be dropped, have %v", sortedTags(tags))
				}
				// select is a service tag: it stays, repointed at what exists.
				if !tags[config.OutboundSelectTag] {
					t.Fatalf("select must survive, have %v", sortedTags(tags))
				}
				assertMembers(t, "select", selectorMembers(t, opts, config.OutboundSelectTag), "leaf-kept")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := tc.build()
			pruneToAllowlist(opts, tc.leaves)
			// Whatever a case keeps, the result must be buildable.
			assertClosedGraph(t, opts)
			tc.verify(t, opts)
		})
	}
}

// Endpoints are reachable through detour/underlay_detour, not through a member
// list: they must survive the same closure a group member does.
func TestPruneToAllowlistKeepsReferencedEndpoints(t *testing.T) {
	t.Parallel()
	opts := &option.Options{
		Outbounds: selectorFirst(
			[]string{"leaf-via-ep"},
			"leaf-via-ep",
			option.Outbound{Type: C.TypeVLESS, Tag: "leaf-via-ep", Options: &option.VLESSOutboundOptions{
				DialerOptions: option.DialerOptions{Detour: "wg-ep"},
			}},
			option.Outbound{Type: C.TypeVLESS, Tag: "leaf-plain", Options: &option.VLESSOutboundOptions{}},
		),
		Endpoints: []option.Endpoint{
			{Type: C.TypeWireGuard, Tag: "wg-ep", Options: &option.WireGuardEndpointOptions{}},
			{Type: C.TypeWireGuard, Tag: "wg-unused", Options: &option.WireGuardEndpointOptions{}},
		},
	}
	pruneToAllowlist(opts, []string{"leaf-via-ep"})

	assertClosedGraph(t, opts)
	if len(opts.Endpoints) != 1 || opts.Endpoints[0].Tag != "wg-ep" {
		t.Fatalf("endpoints=%v want [wg-ep]", opts.Endpoints)
	}
}

// A punnel provider must never come back in TestMode, even when a kept group
// names one of its virtuals: setOutbounds drops providers because the side box
// must not run a second provider.
func TestPruneToAllowlistNeverResurrectsPunnel(t *testing.T) {
	t.Parallel()
	opts := &option.Options{
		Outbounds: selectorFirst(
			[]string{"leaf-a"},
			"leaf-a",
			option.Outbound{Type: C.TypeVLESS, Tag: "leaf-a", Options: &option.VLESSOutboundOptions{}},
			option.Outbound{Type: C.TypePunnel, Tag: "punnel-provider", Options: &option.PunnelOutboundOptions{
				Role:      option.PunnelRoleProvider,
				ParentTag: "punnel-provider",
				Services: map[string]option.PunnelProviderServiceEntry{
					"grpc": {Local: "127.0.0.1:9000"},
				},
			}},
			// Allowlisted, but its only member is the provider virtual.
			option.Outbound{Type: C.TypeSelector, Tag: "listed-in-leaves", Options: &option.SelectorOutboundOptions{
				Outbounds: []string{"punnel-provider-grpc"},
			}},
		),
	}
	pruneToAllowlist(opts, []string{"leaf-a", "listed-in-leaves"})

	tags := prunedTags(opts)
	if tags["punnel-provider"] {
		t.Fatalf("punnel provider must stay excluded in TestMode, have %v", sortedTags(tags))
	}
	if tags["listed-in-leaves"] {
		t.Fatalf("group over a punnel virtual must be dropped, have %v", sortedTags(tags))
	}
	assertClosedGraph(t, opts)
}
