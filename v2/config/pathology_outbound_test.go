package config

import (
	"context"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// testLegendPSK is valid morph auth material (hex, ≥16 bytes) so the engine's
// own legend expansion accepts the fixture.
const testLegendPSK = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"

// pathologyLegendOutbound builds a legend parent as the CP emits it: server +
// legends (per-legend underlay) + auth for the legends whose id is in authIDs.
// A legend present in legends but absent from authIDs is exactly the shape that
// used to break start (the engine skips it, the builder still named it).
func pathologyLegendOutbound(tag string, legendIDs, authIDs []string) option.Outbound {
	legends := make(map[string]option.PathologyLegendEntry, len(legendIDs))
	for _, id := range legendIDs {
		legends[id] = option.PathologyLegendEntry{
			Underlay: option.PathologyUnderlayOptions{Branch: "udp"},
		}
	}
	var auth map[string]option.PathologyLegendAuth
	if len(authIDs) > 0 {
		auth = make(map[string]option.PathologyLegendAuth, len(authIDs))
		for _, id := range authIDs {
			auth[id] = option.PathologyLegendAuth{Method: "morph", PSK: testLegendPSK}
		}
	}
	return option.Outbound{
		Type: C.TypePathology,
		Tag:  tag,
		Options: &option.PathologyOutboundOptions{
			ServerOptions: option.ServerOptions{Server: "1.2.3.4", ServerPort: 10443},
			UUID:          "387c6b84-2e30-4b67-83c9-aa5692550e65",
			Legends:       legends,
			Auth:          auth,
		},
	}
}

func testVLESSLeaf(tag string) option.Outbound {
	return option.Outbound{
		Type:    C.TypeVLESS,
		Tag:     tag,
		Options: &option.VLESSOutboundOptions{DialerOptions: option.DialerOptions{}},
	}
}

// buildOutbounds runs setOutbounds with a parse-warning collector so tests can
// assert both the emitted outbounds and the UI-facing drop reasons.
func buildOutbounds(t *testing.T, input *option.Options) (option.Options, *ParseWarningsCollector) {
	t.Helper()
	ctx, collector := WithParseWarnings(context.Background())
	var out option.Options
	if err := setOutboundsContext(ctx, &out, input, DefaultClientOptions(), &map[string][]string{}); err != nil {
		t.Fatalf("setOutbounds: %v", err)
	}
	return out, collector
}

// findRotationGroup returns the "{parent}-auto" balancer, or nil.
func findRotationGroup(out option.Options, parent string) *option.BalancerOutboundOptions {
	for i := range out.Outbounds {
		if out.Outbounds[i].Tag != parent+"-auto" {
			continue
		}
		opts, _ := out.Outbounds[i].Options.(*option.BalancerOutboundOptions)
		return opts
	}
	return nil
}

// assertGroupsReferenceLiveTags expands the pathology parents exactly as
// box.New does and fails if any group member names a tag that does not exist
// afterwards. This is the P0 invariant: a member naming a skipped legend made
// balancer.Start() fail with "outbound N not found" and box.New killed the whole
// profile. It covers selector/lowest/balance and the rotation groups alike.
func assertGroupsReferenceLiveTags(t *testing.T, out option.Options) {
	t.Helper()
	expanded, err := option.ExpandPathologyOutbounds(out.Outbounds)
	if err != nil {
		t.Fatalf("engine expansion of the built outbounds failed: %v", err)
	}
	live := make(map[string]bool, len(expanded))
	for _, o := range expanded {
		live[o.Tag] = true
	}
	for _, o := range expanded {
		var members []string
		switch opts := o.Options.(type) {
		case *option.BalancerOutboundOptions:
			members = opts.Outbounds
		case *option.SelectorOutboundOptions:
			members = opts.Outbounds
		}
		for _, member := range members {
			if !live[member] {
				t.Fatalf("outbound %q (%s) references missing outbound %q; live tags: %v", o.Tag, o.Type, member, live)
			}
		}
	}
}

// Legend parent: box.ExpandPathologyOutbounds replaces it with
// {parent}-{legend} virtuals at engine start, so the parent tag must stay out
// of lowest/balance (same dangling-dependency trap as punnel).
func TestPathologyLegendParentExcludedFromBalancerLeaves(t *testing.T) {
	input := &option.Options{
		Outbounds: []option.Outbound{
			testVLESSLeaf("node-a"),
			pathologyLegendOutbound("path-parent", []string{"stun"}, []string{"stun"}),
		},
	}
	out, _ := buildOutbounds(t, input)

	foundParent := false
	for _, o := range out.Outbounds {
		if o.Tag == "path-parent" && o.Type == C.TypePathology {
			foundParent = true
		}
		if o.Tag != OutboundRoundRobinTag && o.Tag != OutboundURLTestTag {
			continue
		}
		opts, ok := o.Options.(*option.BalancerOutboundOptions)
		if !ok {
			t.Fatalf("%s: expected balancer options", o.Tag)
		}
		for _, tag := range opts.Outbounds {
			if tag == "path-parent" || tag == "path-parent-auto" {
				t.Fatalf("%s includes legend-parent tag %q", o.Tag, tag)
			}
		}
		if len(opts.Outbounds) != 1 || opts.Outbounds[0] != "node-a" {
			t.Fatalf("%s outbounds=%v want [node-a]", o.Tag, opts.Outbounds)
		}
	}
	if !foundParent {
		t.Fatal("path-parent outbound missing from built config")
	}
	assertGroupsReferenceLiveTags(t, out)
}

// A pathology outbound WITHOUT legends is an ordinary dialable leaf.
func TestPathologyWithoutLegendsIsLeaf(t *testing.T) {
	opt := DefaultClientOptions()
	input := &option.Options{
		Outbounds: []option.Outbound{
			{
				Type: C.TypePathology,
				Tag:  "path-leaf",
				Options: &option.PathologyOutboundOptions{
					ServerOptions: option.ServerOptions{Server: "1.2.3.4"},
				},
			},
		},
	}
	var out option.Options
	if err := setOutbounds(&out, input, opt, &map[string][]string{}); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, o := range out.Outbounds {
		if o.Tag != OutboundRoundRobinTag && o.Tag != OutboundURLTestTag {
			continue
		}
		opts := o.Options.(*option.BalancerOutboundOptions)
		for _, tag := range opts.Outbounds {
			if tag == "path-leaf" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("pathology leaf without legends must join lowest/balance")
	}
}

// failover/scatter are group wrappers: valid chain TARGETS, never MEMBERS
// (setting a detour on a wrapper is meaningless).
func TestChainNeverDetoursGroupWrappers(t *testing.T) {
	for _, typ := range []string{C.TypeFailover, C.TypeScatter, C.TypePunnel} {
		if !isNonLeafOutboundType(typ) {
			t.Fatalf("%s must be non-leaf (no detour applied to it)", typ)
		}
	}
}

// A legend parent gets a synthesized first-alive rotation group over the
// {parent}-{legend} virtuals the engine actually materialises — i.e. only the
// legends that carry an auth entry. Naming a legend without auth was the P0:
// balancer.Start() then reports a missing outbound and box.New fails, so the
// profile cannot start at all.
func TestPathologyLegendParentSynthesizesRotationGroup(t *testing.T) {
	input := &option.Options{
		Outbounds: []option.Outbound{
			testVLESSLeaf("node-a"),
			pathologyLegendOutbound("path-auto", []string{"stun", "dns"}, []string{"stun", "dns"}),
		},
	}
	out, _ := buildOutbounds(t, input)

	group := findRotationGroup(out, "path-auto")
	if group == nil {
		t.Fatal("rotation group path-auto-auto not synthesized")
	}
	if group.Strategy != "first-alive" {
		t.Fatalf("want first-alive, got %q", group.Strategy)
	}
	if !group.InterruptExistConnections {
		t.Fatal("rotation group must interrupt dead-pick connections")
	}
	want := []string{"path-auto-dns", "path-auto-stun"} // sorted
	if len(group.Outbounds) != len(want) || group.Outbounds[0] != want[0] || group.Outbounds[1] != want[1] {
		t.Fatalf("rotation group members = %v, want %v", group.Outbounds, want)
	}

	for _, o := range out.Outbounds {
		if o.Tag != OutboundRoundRobinTag && o.Tag != OutboundURLTestTag {
			continue
		}
		opts, ok := o.Options.(*option.BalancerOutboundOptions)
		if !ok {
			continue
		}
		for _, tag := range opts.Outbounds {
			if tag == "path-auto" || tag == "path-auto-auto" {
				t.Fatalf("%s must not contain the legend parent or its rotation group (got %v)", o.Tag, opts.Outbounds)
			}
		}
	}

	// Selector lists the rotation group (user-selectable).
	foundInSelector := false
	for _, o := range out.Outbounds {
		if o.Tag != OutboundSelectTag {
			continue
		}
		sel, ok := o.Options.(*option.SelectorOutboundOptions)
		if !ok {
			continue
		}
		for _, tag := range sel.Outbounds {
			if tag == "path-auto-auto" {
				foundInSelector = true
			}
		}
	}
	if !foundInSelector {
		t.Fatal("selector must list the rotation group")
	}
	assertGroupsReferenceLiveTags(t, out)
}

// Table over the legend/auth shapes: the rotation group must name exactly the
// virtuals the engine materialises, and every case must leave a config with no
// dangling reference (the old code emitted "path-t-auto" and "path-t-stun" while
// the engine only created "path-t-dns").
func TestPathologyRotationGroupMembership(t *testing.T) {
	tests := []struct {
		name       string
		legends    []string
		auth       []string
		wantGroup  bool
		wantMember []string
		wantWarn   string
	}{
		{
			name:       "every legend authorised",
			legends:    []string{"dns", "stun"},
			auth:       []string{"dns", "stun"},
			wantGroup:  true,
			wantMember: []string{"path-t-dns", "path-t-stun"},
		},
		{
			name:       "legend without auth is excluded",
			legends:    []string{"dns", "stun"},
			auth:       []string{"dns"},
			wantGroup:  true,
			wantMember: []string{"path-t-dns"},
		},
		{
			name:      "no auth at all emits no group",
			legends:   []string{"dns", "stun"},
			auth:      nil,
			wantGroup: false,
			wantWarn:  "no legend has an auth entry",
		},
		{
			name:      "reserved auto legend emits no group",
			legends:   []string{"auto", "dns"},
			auth:      []string{"auto", "dns"},
			wantGroup: false,
			wantWarn:  "reserved for the synthesized rotation group",
		},
		{
			// auth "ssh" has no legends entry: the engine rejects the parent
			// at box.New, so it must never reach the built config.
			name:      "orphan auth emits no group",
			legends:   []string{"dns"},
			auth:      []string{"dns", "ssh"},
			wantGroup: false,
			wantWarn:  "has no legends entry",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// A second, independent leaf keeps the profile non-empty so the
			// builder cannot short-circuit into the Direct-fallback guard.
			input := &option.Options{
				Outbounds: []option.Outbound{
					testVLESSLeaf("node-a"),
					pathologyLegendOutbound("path-t", tc.legends, tc.auth),
				},
			}
			out, warns := buildOutbounds(t, input)
			group := findRotationGroup(out, "path-t")

			if !tc.wantGroup {
				if group != nil {
					t.Fatalf("rotation group must not be emitted, got members %v", group.Outbounds)
				}
				msg := warns.MessageJSON()
				if !strings.Contains(msg, tc.wantWarn) {
					t.Fatalf("warning %q missing from parse warnings %s", tc.wantWarn, msg)
				}
				// The parent is dropped whole, not just left ungrouped: the
				// engine rejects it at box.New (no auth) or its virtual would
				// collide with the group tag ("auto"). Nothing may reference it.
				for _, o := range out.Outbounds {
					if o.Tag == "path-t" {
						t.Fatal("unusable legend parent must be dropped, not emitted")
					}
				}
				assertNoGroupReferences(t, out, "path-t", "path-t-auto")
				// Every remaining group must still resolve after expansion.
				assertGroupsReferenceLiveTags(t, out)
				return
			}

			if group == nil {
				t.Fatal("rotation group path-t-auto not synthesized")
			}
			if len(group.Outbounds) != len(tc.wantMember) {
				t.Fatalf("members = %v, want %v", group.Outbounds, tc.wantMember)
			}
			for i, want := range tc.wantMember {
				if group.Outbounds[i] != want {
					t.Fatalf("members = %v, want %v", group.Outbounds, tc.wantMember)
				}
			}
			if msg := warns.MessageJSON(); msg != "" {
				t.Fatalf("unexpected parse warning for a clean legend parent: %s", msg)
			}
			assertGroupsReferenceLiveTags(t, out)
		})
	}
}

// assertNoGroupReferences fails when selector/lowest/balance name any of tags.
func assertNoGroupReferences(t *testing.T, out option.Options, tags ...string) {
	t.Helper()
	for _, o := range out.Outbounds {
		var members []string
		switch opts := o.Options.(type) {
		case *option.SelectorOutboundOptions:
			members = opts.Outbounds
		case *option.BalancerOutboundOptions:
			members = opts.Outbounds
		}
		for _, member := range members {
			for _, banned := range tags {
				if member == banned {
					t.Fatalf("outbound %q references %q, which cannot dial", o.Tag, banned)
				}
			}
		}
	}
}

// A pathology-only profile whose legend parent has no authorised legend has no
// dialable outbound at all: the engine expands zero virtuals. The builder must
// refuse loudly and by name instead of the generic Direct-fallback message, and
// must never synthesize a group over virtuals that will not exist.
func TestPathologyNoAuthorisedLegendRefusesStart(t *testing.T) {
	input := &option.Options{
		Outbounds: []option.Outbound{
			pathologyLegendOutbound("path-only", []string{"stun"}, nil),
		},
	}
	var out option.Options
	err := setOutbounds(&out, input, DefaultClientOptions(), &map[string][]string{})
	if err == nil {
		t.Fatal("expected a build error: nothing in this profile can dial")
	}
	if !strings.Contains(err.Error(), "path-only") || !strings.Contains(err.Error(), "no legend has an auth entry") {
		t.Fatalf("error must name the parent and the cause, got %v", err)
	}
}

// With a healthy sibling leaf the profile must build: the unusable legend
// parent contributes no group, no selector reference, no outbound at all, and a
// warning the UI can surface — never a start-breaking member list.
func TestPathologyNoAuthorisedLegendWarnsInsteadOfEmittingGroup(t *testing.T) {
	input := &option.Options{
		Outbounds: []option.Outbound{
			testVLESSLeaf("node-a"),
			pathologyLegendOutbound("path-only", []string{"stun"}, nil),
		},
	}
	out, warns := buildOutbounds(t, input)
	if g := findRotationGroup(out, "path-only"); g != nil {
		t.Fatalf("rotation group must not be emitted, got %v", g.Outbounds)
	}
	for _, o := range out.Outbounds {
		if o.Tag == "path-only" {
			t.Fatal("legend parent the engine would reject must not be emitted")
		}
	}
	if !strings.Contains(warns.MessageJSON(), "no legend has an auth entry") {
		t.Fatalf("missing warning: %s", warns.MessageJSON())
	}
	assertNoGroupReferences(t, out, "path-only", "path-only-auto")
	// The healthy leaf still drives the profile.
	for _, o := range out.Outbounds {
		if o.Tag != OutboundSelectTag {
			continue
		}
		sel := o.Options.(*option.SelectorOutboundOptions)
		if len(sel.Outbounds) != 1 || sel.Outbounds[0] != "node-a" {
			t.Fatalf("selector outbounds = %v, want [node-a]", sel.Outbounds)
		}
	}
}


// A failover/scatter wrapper is a VALID chain target and may be selected, but it
// is never a dialable leaf: putting its tag into lowest/balance makes the config
// agent treat a wrapper as an exit address that can never be dialed directly.
func TestGroupWrappersAreNotLeaves(t *testing.T) {
	input := &option.Options{
		Outbounds: []option.Outbound{
			testVLESSLeaf("node-a"),
			{
				Type: C.TypeFailover,
				Tag:  "fo",
				Options: &option.FailoverOutboundOptions{
					Outbounds: []string{"node-a"},
				},
			},
			{
				Type: C.TypeScatter,
				Tag:  "sc",
				Options: &option.ScatterOutboundOptions{
					Paths: []string{"node-a"},
				},
			},
		},
	}
	out, _ := buildOutbounds(t, input)

	present := map[string]bool{}
	for _, o := range out.Outbounds {
		present[o.Tag] = true
	}
	if !present["fo"] || !present["sc"] {
		t.Fatalf("wrappers must stay in outbounds (selectable / chain-addressable): %v", present)
	}
	for _, o := range out.Outbounds {
		if o.Type != C.TypeBalancer {
			continue
		}
		if o.Tag != OutboundURLTestTag && o.Tag != OutboundRoundRobinTag {
			continue
		}
		members, _ := o.Options.(*option.BalancerOutboundOptions)
		if members == nil {
			continue
		}
		for _, tag := range members.Outbounds {
			if tag == "fo" || tag == "sc" {
				t.Fatalf("%s must not dial a group wrapper %q directly", o.Tag, tag)
			}
		}
	}
}

// A wrapper naming a legend PARENT is the same dangling-tag trap the engine
// proves in TestPathologyLegendParentInGroupMemberList_LX: expansion deletes the
// parent, so box.New cannot resolve `fo -> path-auto`. The builder rewrites the
// reference to the virtuals that will exist.
func TestWrapperOverLegendParentIsRewrittenToVirtuals(t *testing.T) {
	input := &option.Options{
		Outbounds: []option.Outbound{
			pathologyLegendOutbound("path-auto", []string{"stun", "dns"}, []string{"stun", "dns"}),
			{
				Type: C.TypeFailover,
				Tag:  "fo",
				Options: &option.FailoverOutboundOptions{
					Outbounds: []string{"path-auto", "node-a"},
				},
			},
			testVLESSLeaf("node-a"),
		},
	}
	out, _ := buildOutbounds(t, input)

	var failover *option.FailoverOutboundOptions
	for _, o := range out.Outbounds {
		if o.Tag == "fo" {
			failover, _ = o.Options.(*option.FailoverOutboundOptions)
		}
	}
	if failover == nil {
		t.Fatal("failover wrapper missing from the built config")
	}
	want := []string{"path-auto-dns", "path-auto-stun", "node-a"}
	if len(failover.Outbounds) != len(want) {
		t.Fatalf("members = %v, want %v (parent expanded in place)", failover.Outbounds, want)
	}
	for i := range want {
		if failover.Outbounds[i] != want[i] {
			t.Fatalf("members = %v, want %v", failover.Outbounds, want)
		}
	}
	// The invariant that matters: after engine-side expansion nothing dangles.
	assertGroupsReferenceLiveTags(t, out)
}

// A wrapper over a parent that was dropped whole loses that member; with no
// members left the wrapper itself must go, not start with an empty list.
// A healthy leaf rides along so the pool is not "all dropped" (a pathology-only
// profile whose only parent died is a separate, already-covered error path).
func TestWrapperOverDroppedLegendParentIsDropped(t *testing.T) {
	input := &option.Options{
		Outbounds: []option.Outbound{
			testVLESSLeaf("node-a"),
			// Legends without any auth: the parent cannot be expanded at all.
			pathologyLegendOutbound("path-dead", []string{"stun"}, nil),
			{
				Type:    C.TypeFailover,
				Tag:     "fo",
				Options: &option.FailoverOutboundOptions{Outbounds: []string{"path-dead"}},
			},
		},
	}
	out, collector := buildOutbounds(t, input)
	for _, o := range out.Outbounds {
		if o.Tag == "fo" {
			t.Fatalf("a wrapper whose only member is a dropped parent must be dropped: %v", out.Outbounds)
		}
	}
	if !strings.Contains(collector.MessageJSON(), "path-dead") {
		t.Fatalf("the dropped reference must be reported: %s", collector.MessageJSON())
	}
}