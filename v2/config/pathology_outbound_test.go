package config

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// Legend parent: box.ExpandPathologyOutbounds replaces it with
// {parent}-{legend} virtuals at engine start, so the parent tag must stay out
// of lowest/balance (same dangling-dependency trap as punnel).
func TestPathologyLegendParentExcludedFromBalancerLeaves(t *testing.T) {
	opt := DefaultClientOptions()
	input := &option.Options{
		Outbounds: []option.Outbound{
			{
				Type: C.TypeVLESS,
				Tag:  "node-a",
				Options: &option.VLESSOutboundOptions{
					DialerOptions: option.DialerOptions{},
				},
			},
			{
				Type: C.TypePathology,
				Tag:  "path-parent",
				Options: &option.PathologyOutboundOptions{
					Legends: map[string]option.PathologyLegendEntry{
						"stun": {},
					},
				},
			},
		},
	}
	var out option.Options
	if err := setOutbounds(&out, input, opt, &map[string][]string{}); err != nil {
		t.Fatal(err)
	}

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
			if tag == "path-parent" {
				t.Fatalf("%s includes legend-parent tag path-parent", o.Tag)
			}
		}
		if len(opts.Outbounds) != 1 || opts.Outbounds[0] != "node-a" {
			t.Fatalf("%s outbounds=%v want [node-a]", o.Tag, opts.Outbounds)
		}
	}
	if !foundParent {
		t.Fatal("path-parent outbound missing from built config")
	}
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

// A legend parent gets a synthesized first-alive rotation group over its
// {parent}-{legend} virtuals: in the selector (user-selectable), never in
// lowest/balance member pools (a rotation group is not an exit leaf).
func TestPathologyLegendParentSynthesizesRotationGroup(t *testing.T) {
	opt := DefaultClientOptions()
	input := &option.Options{
		Outbounds: []option.Outbound{
			{
				Type: C.TypeVLESS,
				Tag:  "node-a",
				Options: &option.VLESSOutboundOptions{
					DialerOptions: option.DialerOptions{},
				},
			},
			{
				Type: C.TypePathology,
				Tag:  "path-auto",
				Options: &option.PathologyOutboundOptions{
					ServerOptions: option.ServerOptions{Server: "1.2.3.4"},
					Legends: map[string]option.PathologyLegendEntry{
						"stun": {}, "dns": {},
					},
				},
			},
		},
	}
	var out option.Options
	if err := setOutbounds(&out, input, opt, &map[string][]string{}); err != nil {
		t.Fatal(err)
	}

	var group *option.Outbound
	for i := range out.Outbounds {
		o := &out.Outbounds[i]
		if o.Tag == "path-auto-auto" {
			group = o
		}
		if o.Tag == OutboundRoundRobinTag || o.Tag == OutboundURLTestTag {
			opts := o.Options.(*option.BalancerOutboundOptions)
			for _, tag := range opts.Outbounds {
				if tag == "path-auto" || tag == "path-auto-auto" {
					t.Fatalf("%s must not contain the legend parent or its rotation group (got %v)", o.Tag, opts.Outbounds)
				}
			}
		}
	}
	if group == nil {
		t.Fatal("rotation group path-auto-auto not synthesized")
	}
	opts := group.Options.(*option.BalancerOutboundOptions)
	if opts.Strategy != "first-alive" {
		t.Fatalf("want first-alive, got %q", opts.Strategy)
	}
	if !opts.InterruptExistConnections {
		t.Fatal("rotation group must interrupt dead-pick connections")
	}
	want := []string{"path-auto-dns", "path-auto-stun"} // sorted
	if len(opts.Outbounds) != 2 || opts.Outbounds[0] != want[0] || opts.Outbounds[1] != want[1] {
		t.Fatalf("rotation group members = %v, want %v", opts.Outbounds, want)
	}

	// Selector lists the rotation group (user-selectable).
	for _, o := range out.Outbounds {
		if o.Tag != OutboundSelectTag {
			continue
		}
		sel := o.Options.(*option.SelectorOutboundOptions)
		found := false
		for _, tag := range sel.Outbounds {
			if tag == "path-auto-auto" {
				found = true
			}
		}
		if !found {
			t.Fatal("selector must list the rotation group")
		}
	}
}
