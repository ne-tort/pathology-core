package config_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ne-tort/pathology-core/v2/config"
	"github.com/hiddify/ray2sing/ray2sing"
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	_ "github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
)

func testCtx() context.Context {
	return libbox.BaseContext(nil)
}

func TestParseRetainsDNSAndRoute(t *testing.T) {
	raw := `{
  "dns": {
    "servers": [{"type":"udp","tag":"sub-dns","server":"8.8.8.8"}],
    "final": "sub-dns"
  },
  "route": {
    "rules": [{"action":"sniff"}]
  },
  "outbounds": [
    {"type":"direct","tag":"proxy-node"}
  ]
}`
	opts, err := config.ParseConfig(testCtx(), &config.ReadOptions{Content: raw}, false, config.DefaultClientOptions(), false)
	if err != nil {
		t.Fatal(err)
	}
	if opts.DNS == nil || len(opts.DNS.Servers) == 0 {
		t.Fatal("expected dns retained")
	}
	if opts.DNS.Servers[0].Tag != "sub-dns" {
		t.Fatalf("dns tag=%s", opts.DNS.Servers[0].Tag)
	}
	if opts.Route == nil || len(opts.Route.Rules) == 0 {
		t.Fatal("expected route retained")
	}
	if len(opts.Outbounds) == 0 {
		t.Fatal("expected outbounds")
	}
}

func TestBuildUsesSubscriptionDNSRaw(t *testing.T) {
	profile := `{
  "dns": {
    "servers": [{"type":"udp","tag":"sub-dns","server":"9.9.9.9"}],
    "final": "sub-dns"
  },
  "outbounds": [
    {"type":"direct","tag":"node-a"}
  ]
}`
	h := config.DefaultClientOptions()
	h.IgnoreSubscriptionDNS = false
	h.EnableDnsHijack = false
	built, err := config.BuildConfig(testCtx(), h, &config.ReadOptions{Content: profile})
	if err != nil {
		t.Fatal(err)
	}
	if built.DNS == nil || built.DNS.Final != "sub-dns" {
		t.Fatalf("want raw sub dns, got final=%v servers=%v", built.DNS.Final, len(built.DNS.Servers))
	}
	for _, s := range built.DNS.Servers {
		if s.Tag == "dns-bootstrap" || s.Tag == "dns-remote" {
			t.Fatalf("template server leaked into raw mode: %s", s.Tag)
		}
	}
	if hasHijack(built) {
		t.Fatal("hijack should be off by default")
	}
}

func TestBuildIgnoresSubscriptionDNSWhenFlagged(t *testing.T) {
	profile := `{
  "dns": {
    "servers": [{"type":"udp","tag":"sub-dns","server":"9.9.9.9"}],
    "final": "sub-dns"
  },
  "outbounds": [
    {"type":"direct","tag":"node-a"}
  ]
}`
	h := config.DefaultClientOptions()
	h.IgnoreSubscriptionDNS = true
	h.DirectDnsServers = []string{"udp://1.1.1.1"}
	h.RemoteDnsServers = []string{"udp://8.8.8.8"}
	built, err := config.BuildConfig(testCtx(), h, &config.ReadOptions{Content: profile})
	if err != nil {
		t.Fatal(err)
	}
	if built.DNS == nil || built.DNS.Final != "dns-remote" {
		t.Fatalf("want template final dns-remote, got %+v", built.DNS)
	}
	tags := map[string]bool{}
	for _, s := range built.DNS.Servers {
		tags[s.Tag] = true
	}
	if !tags["dns-bootstrap"] || !tags["dns-remote"] {
		t.Fatalf("missing template tags: %v", tags)
	}
}

func TestBuildTemplateWhenNoSubscriptionDNS(t *testing.T) {
	profile := `{"outbounds":[{"type":"direct","tag":"node-a"}]}`
	h := config.DefaultClientOptions()
	h.DirectDnsServers = []string{"udp://1.1.1.1"}
	h.RemoteDnsServers = []string{"udp://8.8.8.8"}
	built, err := config.BuildConfig(testCtx(), h, &config.ReadOptions{Content: profile})
	if err != nil {
		t.Fatal(err)
	}
	if built.DNS == nil || built.DNS.Final != "dns-remote" {
		t.Fatalf("template dns missing: %+v", built.DNS)
	}
	if built.Route == nil || built.Route.DefaultDomainResolver == nil || built.Route.DefaultDomainResolver.Server != "dns-bootstrap" {
		t.Fatalf("default_domain_resolver=%v", built.Route.DefaultDomainResolver)
	}
}

func TestBuildDnsHijackToggle(t *testing.T) {
	profile := `{"outbounds":[{"type":"direct","tag":"node-a"}]}`
	h := config.DefaultClientOptions()
	h.EnableDnsHijack = true
	built, err := config.BuildConfig(testCtx(), h, &config.ReadOptions{Content: profile})
	if err != nil {
		t.Fatal(err)
	}
	if !hasHijack(built) {
		t.Fatal("expected hijack-dns rule")
	}
}

func TestMierusMultiValidate(t *testing.T) {
	ctx := testCtx()
	raw := "mierus://user:pass@1.2.3.4?port=6666&protocol=TCP&port=7777&protocol=UDP#m"
	opts, err := ray2sing.Ray2SingboxOptions(ctx, raw, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(opts.Outbounds) != 2 {
		t.Fatalf("want 2 outbounds, got %d", len(opts.Outbounds))
	}
	if err := config.CheckConfigOptions(ctx, opts); err != nil {
		t.Fatal(err)
	}
}

func hasHijack(opts *option.Options) bool {
	if opts.Route == nil {
		return false
	}
	for _, r := range opts.Route.Rules {
		if r.DefaultOptions.Action == constant.RuleActionTypeHijackDNS {
			return true
		}
	}
	return false
}

func TestLXNewTypesParseAndValidate(t *testing.T) {
	cases := []string{
		"mieru://user:pass@127.0.0.1:8964/?transport=TCP#m1",
		"mierus://user:pass@127.0.0.1?port=8964&protocol=TCP#m2",
		"carrier://jitsi/?room=room1&password=secret&device_id=dev1&transport=datachannel#c1",
		"derp://127.0.0.1:443/?pk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=&peer=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=&websocket=1#d1",
		"wg://127.0.0.1:51820/?pk=YNXtAzepDqRv9H52osJVDQnznT5AM11eCK3ESpwSt04=&peer_public_key=Z1XXLsKYkYxuiYjJIkRvtIKFepCYHTgON%2BGwPq7SOV4=&local_address=10.0.0.2/32&jc=4&jmin=40&jmax=70#w1",
	}
	ctx := testCtx()
	for _, raw := range cases {
		opts, err := ray2sing.Ray2SingboxOptions(ctx, raw, false)
		if err != nil {
			t.Fatalf("parse %s: %v", raw, err)
		}
		if err := config.CheckConfigOptions(ctx, opts); err != nil {
			t.Fatalf("validate %s: %v", raw, err)
		}
	}
}

func TestPathologyDNSFlagsJSON(t *testing.T) {
	h := config.DefaultClientOptions()
	h.IgnoreSubscriptionDNS = true
	h.EnableDnsHijack = true
	b, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "ignore-subscription-dns") || !strings.Contains(s, "enable-dns-hijack") {
		t.Fatalf("flags missing in json: %s", s)
	}
}
