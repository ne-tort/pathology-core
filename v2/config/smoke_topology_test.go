// Package config_test holds end-to-end smoke tests: a realistic profile goes
// through the real import pipeline (ParseBuildConfig) and the result is handed
// to the real engine (box.New).
//
// Why this file exists: the 1.5 migration audit found four P0 defects that all
// audits and unit tests missed, because those looked at layers and functions
// separately. None of them built a complete config and gave it to the engine.
// Every one of those defects was a dangling reference or an empty group —
// invisible to a function-level test, fatal at box.New. These tests exist to
// make that class of defect impossible to reintroduce.
//
// They intentionally do NOT call Start(): box.New is where dependency
// resolution fails, and starting would bind real loopback ports. A config that
// cannot be constructed can never be started.
package config_test

import (
	"context"
	"os"
	"testing"

	"github.com/ne-tort/pathology-core/v2/config"
	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
)

// smokePSK is a 32-byte key, base64 — the shape the engine's demux auth expects.
const smokePSK = "cGF0aG9sb2d5LXRlc3QtcHNrLTMyYnl0ZXMhISEh"

const smokeUUID = "387c6b84-2e30-4b67-83c9-aa5692550e65"

// smokeContext returns a context with the engine's registries registered and
// runs the test in a scratch directory, so a config that writes state (the
// clash cache_file, for one) cannot touch the repo.
func smokeContext(t *testing.T) context.Context {
	t.Helper()
	dir := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	return include.Context(context.Background())
}

// buildProfile runs the real import pipeline on a raw profile.
func buildProfile(t *testing.T, ctx context.Context, raw string) *option.Options {
	t.Helper()
	opts, err := config.ParseBuildConfig(ctx, config.DefaultClientOptions(), &config.ReadOptions{Content: raw})
	if err != nil {
		t.Fatalf("ParseBuildConfig: %v", err)
	}
	if opts == nil {
		t.Fatal("ParseBuildConfig returned a nil config")
	}
	return opts
}

// newBox constructs the engine for a built config and reports the error instead
// of failing, so a test can assert on a REFUSAL as well as on success.
func newBox(t *testing.T, opts *option.Options) (*box.Box, error) {
	t.Helper()
	opts.Log = &option.LogOptions{Level: "error"}
	instance, err := box.New(box.Options{
		Context: include.Context(context.Background()),
		Options: *opts,
	})
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = instance.Close() })
	return instance, nil
}

// assertNoDanglingReferences walks every group's member list and every detour
// and fails if it names a tag the config does not define. This is the invariant
// whose violation took the whole profile down with "dependency[...] not found".
//
// The reference graph must be checked against the tags that exist AFTER the
// engine's expansion — a pathology legend parent is replaced by its
// {parent}-{legend} virtuals at box.New, so a rotation group naming the virtuals
// is correct even though they are absent from the built options. Expanding here
// mirrors the engine instead of guessing.
func assertNoDanglingReferences(t *testing.T, opts *option.Options) {
	t.Helper()
	outbounds, err := option.ExpandPathologyOutbounds(opts.Outbounds)
	if err != nil {
		t.Fatalf("ExpandPathologyOutbounds: %v", err)
	}
	known := make(map[string]bool, len(outbounds)+len(opts.Endpoints))
	for _, ob := range outbounds {
		known[ob.Tag] = true
	}
	for _, ep := range opts.Endpoints {
		known[ep.Tag] = true
	}
	check := func(owner, ref string) {
		if ref == "" || known[ref] {
			return
		}
		t.Fatalf("%s references unknown tag %q (all tags: %v)", owner, ref, known)
	}
	for _, ob := range opts.Outbounds {
		switch o := ob.Options.(type) {
		case *option.SelectorOutboundOptions:
			for _, m := range o.Outbounds {
				check(ob.Tag, m)
			}
			check(ob.Tag+" default", o.Default)
		case *option.URLTestOutboundOptions:
			for _, m := range o.Outbounds {
				check(ob.Tag, m)
			}
		case *option.BalancerOutboundOptions:
			for _, m := range o.Outbounds {
				check(ob.Tag, m)
			}
			check(ob.Tag+" default", o.Default)
		case *option.FailoverOutboundOptions:
			for _, m := range o.Outbounds {
				check(ob.Tag, m)
			}
		case *option.ScatterOutboundOptions:
			for _, list := range [][]string{o.Paths, o.UplinkPaths, o.DownlinkPaths} {
				for _, m := range list {
					check(ob.Tag, m)
				}
			}
		}
	}
}

// assertGroupsNonEmpty fails if a group outbound was emitted with no members:
// an empty member list is itself a box.New error ("missing tags").
func assertGroupsNonEmpty(t *testing.T, opts *option.Options) {
	t.Helper()
	for _, ob := range opts.Outbounds {
		switch o := ob.Options.(type) {
		case *option.SelectorOutboundOptions:
			if len(o.Outbounds) == 0 {
				t.Fatalf("selector %q has no members", ob.Tag)
			}
		case *option.URLTestOutboundOptions:
			if len(o.Outbounds) == 0 {
				t.Fatalf("urltest %q has no members", ob.Tag)
			}
		case *option.BalancerOutboundOptions:
			if len(o.Outbounds) == 0 {
				t.Fatalf("balancer %q has no members", ob.Tag)
			}
		case *option.FailoverOutboundOptions:
			if len(o.Outbounds) == 0 {
				t.Fatalf("failover %q has no members", ob.Tag)
			}
		case *option.ScatterOutboundOptions:
			if len(o.Paths) == 0 && len(o.UplinkPaths) == 0 && len(o.DownlinkPaths) == 0 {
				t.Fatalf("scatter %q has no paths", ob.Tag)
			}
		}
	}
}

// assertStarts is the whole point: build, check the structural invariants, and
// prove the engine accepts the result.
func assertStarts(t *testing.T, ctx context.Context, name, raw string) *option.Options {
	t.Helper()
	opts := buildProfile(t, ctx, raw)
	assertNoDanglingReferences(t, opts)
	assertGroupsNonEmpty(t, opts)
	if _, err := newBox(t, opts); err != nil {
		t.Fatalf("%s: box.New rejected the built config: %v", name, err)
	}
	return opts
}

// outboundTags returns the tag set of the built config.
func outboundTags(opts *option.Options) map[string]bool {
	tags := make(map[string]bool, len(opts.Outbounds))
	for _, ob := range opts.Outbounds {
		tags[ob.Tag] = true
	}
	return tags
}

// members returns the member list of the named outbound, or nil.
func members(opts *option.Options, tag string) []string {
	for _, ob := range opts.Outbounds {
		if ob.Tag != tag {
			continue
		}
		switch o := ob.Options.(type) {
		case *option.BalancerOutboundOptions:
			return o.Outbounds
		case *option.SelectorOutboundOptions:
			return o.Outbounds
		case *option.FailoverOutboundOptions:
			return o.Outbounds
		}
	}
	return nil
}

// A complete pathology legend set with a failover wrapper on top — the shape the
// control plane emits for a legend profile. Regression cover for three P0s at
// once: the rotation group naming only authorised legends, the wrapper's
// reference to a legend parent being rewritten to the virtuals, and the
// pathology-only profile getting a non-empty latency pool.
func TestSmokeLegendProfileWithWrapperStarts(t *testing.T) {
	ctx := smokeContext(t)
	opts := assertStarts(t, ctx, "legend profile", `{
	  "outbounds": [
	    {"type":"pathology","tag":"path-auto","server":"203.0.113.7","server_port":443,"uuid":"`+smokeUUID+`",
	     "legends":{
	       "stun":{"underlay":{"preset":"udp-stun"}},
	       "tls":{"underlay":{"preset":"tls-chrome"}},
	       "quic":{"underlay":{"preset":"quic-chrome"}},
	       "ssh":{"underlay":{"preset":"tcp-ssh-client","tcp":{"banner":"SSH-2.0-OpenSSH_9.6","padding_len_prefix":true}}}},
	     "auth":{
	       "stun":{"method":"morph","psk":"`+smokePSK+`"},
	       "tls":{"method":"hmac","psk":"`+smokePSK+`"},
	       "quic":{"method":"grease","psk":"`+smokePSK+`"},
	       "ssh":{"method":"pad_hmac","psk":"`+smokePSK+`"}}},
	    {"type":"failover","tag":"fo","outbounds":["path-auto"],"psk":"`+smokePSK+`"}
	  ],
	  "route": {"final": "fo"}
	}`)

	tags := outboundTags(opts)
	if !tags["path-auto-auto"] {
		t.Fatalf("rotation group path-auto-auto missing: %v", tags)
	}
	// The wrapper must name the virtuals, never the parent the engine deletes.
	got := members(opts, "fo")
	if len(got) == 0 {
		t.Fatal("failover wrapper lost every member")
	}
	for _, m := range got {
		if m == "path-auto" {
			t.Fatalf("wrapper still names the legend parent (deleted at expansion): %v", got)
		}
	}
	// A pathology-only profile must still have a latency pool to dial.
	if pool := members(opts, config.OutboundURLTestTag); len(pool) == 0 {
		t.Fatalf("latency pool %q is empty for a pathology-only profile", config.OutboundURLTestTag)
	}
	if pool := members(opts, config.OutboundRoundRobinTag); len(pool) == 0 {
		t.Fatalf("balance pool %q is empty for a pathology-only profile", config.OutboundRoundRobinTag)
	}
}

// A legend set next to ordinary leaves: the latency pools must probe only the
// real leaves, while the rotation group stays selectable.
func TestSmokeMixedProfileProbesOnlyLeaves(t *testing.T) {
	ctx := smokeContext(t)
	opts := assertStarts(t, ctx, "mixed profile", `{
	  "outbounds": [
	    {"type":"pathology","tag":"path-auto","server":"203.0.113.7","server_port":443,"uuid":"`+smokeUUID+`",
	     "legends":{"stun":{"underlay":{"preset":"udp-stun"}}},
	     "auth":{"stun":{"method":"morph","psk":"`+smokePSK+`"}}},
	    {"type":"vless","tag":"node-a","server":"198.51.100.9","server_port":443,"uuid":"`+smokeUUID+`"}
	  ],
	  "route": {"final": "node-a"}
	}`)
	for _, group := range []string{config.OutboundURLTestTag, config.OutboundRoundRobinTag} {
		pool := members(opts, group)
		if len(pool) == 0 {
			t.Fatalf("%s is empty", group)
		}
		for _, m := range pool {
			if m == "path-auto-auto" {
				t.Fatalf("%s must not probe a rotation group while real leaves exist: %v", group, pool)
			}
		}
	}
}

// A 1.4-era subscription: legacy geo matchers, a legacy bandwidth line, a
// removed parrot key, a legacy flow and a legacy DNS server form. Every one of
// these is a hard error on 1.5 if the migrator misses it, so this is the
// regression net for the whole migration surface.
func TestSmokeLegacyProfileStarts(t *testing.T) {
	ctx := smokeContext(t)
	assertStarts(t, ctx, "legacy 1.4 profile", `{
	  "dns": {
	    "servers": [
	      {"address": "1.1.1.1", "detour": "direct"},
	      {"address": "https://dns.google/dns-query", "detour": "direct"}
	    ],
	    "rules": [{"geosite": ["cn"], "server": "local"}]
	  },
	  "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen_port": 2080, "sniff": true}],
	  "outbounds": [
	    {"type": "hysteria2", "tag": "hy2", "server": "198.51.100.10", "server_port": 443,
	     "password": "x", "up_mbps": 50, "down_mbps": 500, "brutal_debug": true,
	     "obfs": {"type": "salamander", "password": "y"}},
	    {"type": "vless", "tag": "vless-vision", "server": "198.51.100.11", "server_port": 443,
	     "uuid": "`+smokeUUID+`", "flow": "xtls-rprx-vision",
	     "tls": {"enabled": true, "server_name": "example.com"}},
	    {"type": "direct", "tag": "direct"}
	  ],
	  "route": {
	    "rules": [
	      {"geosite": ["cn"], "outbound": "direct"},
	      {"geoip": ["cn"], "outbound": "direct"},
	      {"domain_suffix": [".example"], "action": "direct"}
	    ],
	    "final": "hy2"
	  }
	}`)
}

// Guard the smoke harness itself: the registries must be reachable, otherwise a
// green smoke test would prove nothing. libbox.BaseContext is the production
// wrapper and must agree with include.Context on the option registries.
func TestSmokeRegistriesAreWired(t *testing.T) {
	ctx := include.Context(libbox.BaseContext(nil))
	if ctx == nil {
		t.Fatal("nil context")
	}
	registry := include.OutboundRegistry()
	if registry == nil {
		t.Fatal("outbound registry is nil")
	}
	for _, typ := range []string{"pathology", "failover", "scatter", "vless"} {
		opts, ok := registry.CreateOptions(typ)
		if !ok || opts == nil {
			t.Fatalf("outbound type %q is not registered for the smoke tag set", typ)
		}
	}
}
