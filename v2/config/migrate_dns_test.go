package config

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/experimental/libbox"
)

// dnsServers returns dns.servers of a migrated document.
func dnsServers(t *testing.T, root map[string]interface{}) []interface{} {
	t.Helper()
	dns, ok := root["dns"].(map[string]interface{})
	if !ok {
		t.Fatalf("no dns block: %v", root)
	}
	list, _ := dns["servers"].([]interface{})
	return list
}

// dnsRules returns dns.rules of a migrated document.
func dnsRules(t *testing.T, root map[string]interface{}) []interface{} {
	t.Helper()
	dns, ok := root["dns"].(map[string]interface{})
	if !ok {
		t.Fatalf("no dns block: %v", root)
	}
	list, _ := dns["rules"].([]interface{})
	return list
}

func serverAt(t *testing.T, root map[string]interface{}, index int) map[string]interface{} {
	t.Helper()
	list := dnsServers(t, root)
	if index >= len(list) {
		t.Fatalf("dns.servers[%d] missing (len %d): %v", index, len(list), list)
	}
	server, _ := list[index].(map[string]interface{})
	if server == nil {
		t.Fatalf("dns.servers[%d] is not an object: %v", index, list[index])
	}
	return server
}

// TestMigrateLegacyDNSServerAddresses covers the documented 1.4→1.5 address
// table (vendor/sing-box-pathology/docs/migration.md, "Migrate to new DNS
// server formats"): every form with an unambiguous counterpart must be
// rewritten, because the 1.5 option.DNSOptions does not decode the 1.4 form at
// all and one such line used to fail the whole import.
func TestMigrateLegacyDNSServerAddresses(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		address string
		want    map[string]interface{}
		// resolver is the bootstrap the migrator must add for a
		// domain-addressed server (1.5 refuses one without a resolver when
		// there is no detour); empty means none is expected.
		resolver string
	}{
		{"local", "local", map[string]interface{}{"type": "local"}, ""},
		{"dhcp auto", "dhcp://auto", map[string]interface{}{"type": "dhcp"}, ""},
		{"dhcp iface", "dhcp://en0", map[string]interface{}{"type": "dhcp", "interface": "en0"}, ""},
		{"plain ip", "1.1.1.1", map[string]interface{}{"type": "udp", "server": "1.1.1.1"}, ""},
		{"ip port", "1.1.1.1:5353", map[string]interface{}{"type": "udp", "server": "1.1.1.1", "server_port": 5353}, ""},
		{"udp scheme", "udp://8.8.8.8", map[string]interface{}{"type": "udp", "server": "8.8.8.8"}, ""},
		{"tcp scheme", "tcp://1.1.1.1:53", map[string]interface{}{"type": "tcp", "server": "1.1.1.1", "server_port": 53}, ""},
		{"tls scheme", "tls://1.1.1.1", map[string]interface{}{"type": "tls", "server": "1.1.1.1"}, ""},
		{"tls domain", "tls://dot.example", map[string]interface{}{"type": "tls", "server": "dot.example"}, "local"},
		{"quic scheme", "quic://dns.adguard.com", map[string]interface{}{"type": "quic", "server": "dns.adguard.com"}, "local"},
		{"https default path", "https://dns.google/dns-query", map[string]interface{}{"type": "https", "server": "dns.google"}, "local"},
		{"https custom path", "https://doh.example/q", map[string]interface{}{"type": "https", "server": "doh.example", "path": "/q"}, "local"},
		{"h3 scheme", "h3://dns.google/dns-query", map[string]interface{}{"type": "h3", "server": "dns.google"}, "local"},
		{"ipv6 literal", "[2606:4700:4700::1111]:853", map[string]interface{}{"type": "udp", "server": "2606:4700:4700::1111", "server_port": 853}, ""},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			root, _ := migrateDoc(t, `{"dns":{"servers":[{"address":"`+testCase.address+`","tag":"s"}]}}`)
			server := serverAt(t, root, 0)
			if server["tag"] != "s" {
				t.Fatalf("tag must survive the rewrite: %v", server)
			}
			for key, want := range testCase.want {
				if server[key] != want {
					t.Fatalf("%s: want %v=%v, got %v (%v)", testCase.address, key, want, server[key], server)
				}
			}
			wantCount := len(testCase.want) + 1 // + tag
			if testCase.resolver != "" {
				wantCount++
				if server["domain_resolver"] != testCase.resolver {
					t.Fatalf("%s: want domain_resolver=%s, got %v", testCase.address, testCase.resolver, server["domain_resolver"])
				}
			}
			if len(server) != wantCount {
				t.Fatalf("%s: unexpected keys survived: %v", testCase.address, server)
			}
		})
	}
}

// TestMigrateLegacyDNSServerCarriesOverKeys keeps everything the 1.5 options do
// accept (a detour, a chain, headers…) and only removes what they reject.
func TestMigrateLegacyDNSServerCarriesOverKeys(t *testing.T) {
	root, warnings := migrateDoc(t, `{"dns":{"servers":[
		{"address":"https://dns.google/dns-query","tag":"g","detour":"proxy","headers":{"x":"y"}}
	]}}`)
	server := serverAt(t, root, 0)
	if server["detour"] != "proxy" || server["type"] != "https" || server["server"] != "dns.google" {
		t.Fatalf("detour/type/server wrong: %v", server)
	}
	headers, _ := server["headers"].(map[string]interface{})
	if headers["x"] != "y" {
		t.Fatalf("headers lost: %v", server)
	}
	if _, ok := server["address"]; ok {
		t.Fatalf("legacy address survived: %v", server)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "dns.servers[0]") {
		t.Fatalf("want one rewrite warning, got %v", warnings)
	}
}

// TestMigrateLegacyDNSServerUnmigratableDropped: one unusable entry must cost
// that entry only, and must be reported by name — not silently, and not by
// failing the import.
func TestMigrateLegacyDNSServerUnmigratableDropped(t *testing.T) {
	root, warnings := migrateDoc(t, `{"dns":{"servers":[
		{"address":"1.1.1.1","tag":"keep"},
		{"address":"ftp://files.example/dns","tag":"ftp"},
		{"address":"rcode://bogus","tag":"rc"},
		{"address":"not a host","tag":"junk"},
		{"address":"8.8.8.8","tag":"keep2"}
	]}}`)
	list := dnsServers(t, root)
	if len(list) != 2 {
		t.Fatalf("want the two usable servers, got %v", list)
	}
	if serverAt(t, root, 0)["tag"] != "keep" || serverAt(t, root, 1)["tag"] != "keep2" {
		t.Fatalf("wrong survivors: %v", list)
	}
	joined := strings.Join(warnings, "\n")
	for _, want := range []string{`"ftp"`, `"rc"`, `"junk"`, "unsupported DNS scheme", "unknown rcode"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("warning missing %q: %v", want, warnings)
		}
	}
}

// TestMigrateLegacyDNSFakeIPBlock: 1.5 has no dns.fakeip object at all (decoding
// it is a hard error), the block is dropped with a warning, and a legacy
// `address: fakeip` server becomes a typed fakeip server carrying the ranges.
func TestMigrateLegacyDNSFakeIPBlock(t *testing.T) {
	root, warnings := migrateDoc(t, `{"dns":{
		"servers":[{"address":"1.1.1.1","tag":"u"},{"address":"fakeip","tag":"fk"}],
		"rules":[{"query_type":["A","AAAA"],"server":"fk"}],
		"fakeip":{"enabled":true,"inet4_range":"198.19.0.0/15","inet6_range":"fc00::/18"},
		"final":"u"
	}}`)
	dns, _ := root["dns"].(map[string]interface{})
	if _, ok := dns["fakeip"]; ok {
		t.Fatalf("dns.fakeip must be gone: %v", dns)
	}
	if !strings.Contains(strings.Join(warnings, "\n"), "dns.fakeip") {
		t.Fatalf("the fakeip drop must be named: %v", warnings)
	}
	fakeip := serverAt(t, root, 1)
	if fakeip["type"] != "fakeip" || fakeip["tag"] != "fk" {
		t.Fatalf("fakeip server not migrated: %v", fakeip)
	}
	if fakeip["inet4_range"] != "198.19.0.0/15" || fakeip["inet6_range"] != "fc00::/18" {
		t.Fatalf("ranges from dns.fakeip must be carried over: %v", fakeip)
	}
	// The client builds its own fakeip rules; the migrator must not invent any.
	rules := dnsRules(t, root)
	if len(rules) != 1 {
		t.Fatalf("rules must be untouched: %v", rules)
	}
}

// TestMigrateLegacyDNSFakeIPDisabled: addresses of a disabled fakeip setup are
// not resurrected as working servers.
func TestMigrateLegacyDNSFakeIPDisabled(t *testing.T) {
	root, warnings := migrateDoc(t, `{"dns":{"servers":[
		{"address":"1.1.1.1","tag":"u"},
		{"address":"fakeip","tag":"fk"}
	],"fakeip":{"enabled":false}}}`)
	list := dnsServers(t, root)
	if len(list) != 1 || serverAt(t, root, 0)["tag"] != "u" {
		t.Fatalf("disabled fakeip server must be dropped, got %v", list)
	}
	if !strings.Contains(strings.Join(warnings, "\n"), `"fk"`) {
		t.Fatalf("the drop must name the tag: %v", warnings)
	}
}

// TestMigrateLegacyFakeIPServerRanges: a bare fakeip server (no dns.fakeip)
// needs a range, otherwise the transport manager refuses to build it.
func TestMigrateLegacyFakeIPServerRanges(t *testing.T) {
	root, _ := migrateDoc(t, `{"dns":{"servers":[{"address":"1.1.1.1","tag":"u"},{"address":"fakeip","tag":"fk"}]}}`)
	fakeip := serverAt(t, root, 1)
	if fakeip["inet4_range"] != legacyFakeIPInet4 || fakeip["inet6_range"] != legacyFakeIPInet6 {
		t.Fatalf("fakeip server needs the client's default ranges, got %v", fakeip)
	}
}

// TestMigrateLegacyRCodeServerBecomesPredefinedRule: 1.5 has no rcode DNS
// transport; the equivalent is a predefined rule action, so a rule that named
// the removed server keeps blocking instead of being dropped.
func TestMigrateLegacyRCodeServerBecomesPredefinedRule(t *testing.T) {
	root, warnings := migrateDoc(t, `{"dns":{
		"servers":[{"address":"1.1.1.1","tag":"u"},{"address":"rcode://refused","tag":"blocked"}],
		"rules":[{"domain":["ads.example"],"server":"blocked"}],
		"final":"u"
	}}`)
	list := dnsServers(t, root)
	if len(list) != 1 || serverAt(t, root, 0)["tag"] != "u" {
		t.Fatalf("rcode server must be dropped: %v", list)
	}
	rules := dnsRules(t, root)
	if len(rules) != 1 {
		t.Fatalf("the rule must survive as a predefined action: %v", rules)
	}
	rule, _ := rules[0].(map[string]interface{})
	if rule["action"] != "predefined" || rule["rcode"] != "REFUSED" {
		t.Fatalf("want action=predefined rcode=REFUSED, got %v", rule)
	}
	if _, ok := rule["server"]; ok {
		t.Fatalf("the removed server must not be referenced: %v", rule)
	}
	if !strings.Contains(strings.Join(warnings, "\n"), "predefined") {
		t.Fatalf("the conversion must be reported: %v", warnings)
	}
}

// TestMigrateLegacyDNSDanglingRuleDropped: the 1.5 router refuses to build a
// rule naming an undeclared server ("server not found"), which fails the whole
// import — so the rule goes, with a warning naming both the rule and the tag.
func TestMigrateLegacyDNSDanglingRuleDropped(t *testing.T) {
	root, warnings := migrateDoc(t, `{"dns":{
		"servers":[{"type":"udp","tag":"u","server":"1.1.1.1"}],
		"rules":[{"domain":["a.example"],"server":"gone"},{"domain":["b.example"],"server":"u"}]
	}}`)
	rules := dnsRules(t, root)
	if len(rules) != 1 {
		t.Fatalf("want the dangling rule dropped, got %v", rules)
	}
	if rule, _ := rules[0].(map[string]interface{}); rule["server"] != "u" {
		t.Fatalf("wrong survivor: %v", rules)
	}
	if !strings.Contains(strings.Join(warnings, "\n"), "gone") {
		t.Fatalf("the dangling tag must be named: %v", warnings)
	}
}

// TestMigrateLegacyDNSFinalDropped: a dns.final naming a tag the block does not
// declare fails the transport manager at Start; it is dropped instead.
func TestMigrateLegacyDNSFinalDropped(t *testing.T) {
	root, warnings := migrateDoc(t, `{"dns":{"servers":[{"type":"udp","tag":"u","server":"1.1.1.1"}],"final":"gone"}}`)
	dns, _ := root["dns"].(map[string]interface{})
	if _, ok := dns["final"]; ok {
		t.Fatalf("dangling final must be dropped: %v", dns)
	}
	if !strings.Contains(strings.Join(warnings, "\n"), "gone") {
		t.Fatalf("the dangling final must be named: %v", warnings)
	}
}

// TestMigrateImplicitLocalServerDeclared: 1.4 profiles say `server: "local"` in
// a DNS rule without declaring a local server; the 1.5 router rejects that
// ("server not found: local"), so the implicit server is declared.
func TestMigrateImplicitLocalServerDeclared(t *testing.T) {
	root, warnings := migrateDoc(t, `{"dns":{
		"servers":[{"type":"udp","tag":"u","server":"1.1.1.1"}],
		"rules":[{"domain":["lan"],"server":"local"}]
	}}`)
	list := dnsServers(t, root)
	if len(list) != 2 {
		t.Fatalf("want a declared local server, got %v", list)
	}
	local := serverAt(t, root, 1)
	if local["type"] != "local" || local["tag"] != "local" {
		t.Fatalf("wrong implicit local server: %v", local)
	}
	if len(dnsRules(t, root)) != 1 {
		t.Fatal("the rule must survive")
	}
	if !strings.Contains(strings.Join(warnings, "\n"), "local") {
		t.Fatalf("the insertion must be reported: %v", warnings)
	}
}

// TestMigrateLegacyDNSDomainServerGetsResolver: 1.5 needs an explicit resolver
// for a domain-addressed DNS server when there is no detour; 1.4 resolved via
// the system resolver. Without this the import dies at CheckConfigOptions with
// "missing domain resolver for domain server address".
func TestMigrateLegacyDNSDomainServerGetsResolver(t *testing.T) {
	root, warnings := migrateDoc(t, `{"dns":{"servers":[
		{"address":"https://dns.google/dns-query","tag":"g"},
		{"address":"1.1.1.1","tag":"plain"},
		{"address":"tls://dot.example","tag":"dot","detour":"proxy"}
	]}}`)
	google := serverAt(t, root, 0)
	if google["domain_resolver"] != "local" {
		t.Fatalf("want domain_resolver=local, got %v", google)
	}
	if _, ok := serverAt(t, root, 1)["domain_resolver"]; ok {
		t.Fatalf("an IP-addressed server needs no resolver: %v", serverAt(t, root, 1))
	}
	if _, ok := serverAt(t, root, 2)["domain_resolver"]; ok {
		t.Fatalf("a detour resolves the name itself: %v", serverAt(t, root, 2))
	}
	local := serverAt(t, root, 3)
	if local["type"] != "local" || local["tag"] != "local" {
		t.Fatalf("the bootstrap local server must be declared: %v", local)
	}
	if !strings.Contains(strings.Join(warnings, "\n"), "domain_resolver=local") {
		t.Fatalf("the resolver insertion must be reported: %v", warnings)
	}
}

// TestMigrateDomainServerWithoutResolverNative: the same defect exists in a
// hand-written 1.5 block — a domain-addressed server without a detour and
// without a resolver fails to start — so the fix is not limited to entries the
// migrator itself produced.
func TestMigrateDomainServerWithoutResolverNative(t *testing.T) {
	root, _ := migrateDoc(t, `{"dns":{"servers":[{"type":"udp","tag":"g","server":"dns.google"}]}}`)
	server := serverAt(t, root, 0)
	if server["domain_resolver"] != "local" {
		t.Fatalf("want domain_resolver=local, got %v", server)
	}
	if len(dnsServers(t, root)) != 2 {
		t.Fatalf("the bootstrap local server must be declared: %v", dnsServers(t, root))
	}
}

// TestMigrateLegacyDNSReusesExistingLocalServer: the bootstrap must reuse the
// profile's own local server rather than declare a second one.
func TestMigrateLegacyDNSReusesExistingLocalServer(t *testing.T) {
	root, _ := migrateDoc(t, `{"dns":{"servers":[
		{"address":"local","tag":"system"},
		{"address":"https://dns.google/dns-query","tag":"g"}
	]}}`)
	list := dnsServers(t, root)
	if len(list) != 2 {
		t.Fatalf("no second local server expected: %v", list)
	}
	if serverAt(t, root, 1)["domain_resolver"] != "system" {
		t.Fatalf("want the existing local tag, got %v", serverAt(t, root, 1))
	}
}

// TestMigrateFakeIPServerOutOfDefaultSlot: the engine resolves the default DNS
// server from dns.final, else servers[0], and refuses a fakeip default
// ("default server cannot be fakeip").
func TestMigrateFakeIPServerOutOfDefaultSlot(t *testing.T) {
	t.Run("reordered", func(t *testing.T) {
		root, warnings := migrateDoc(t, `{"dns":{"servers":[
			{"address":"fakeip","tag":"fk"},
			{"address":"1.1.1.1","tag":"u"}
		]}}`)
		list := dnsServers(t, root)
		if serverAt(t, root, 0)["tag"] != "u" {
			t.Fatalf("a non-fakeip server must lead: %v", list)
		}
		if !strings.Contains(strings.Join(warnings, "\n"), "default slot") {
			t.Fatalf("the reorder must be reported: %v", warnings)
		}
	})
	t.Run("final names fakeip", func(t *testing.T) {
		root, warnings := migrateDoc(t, `{"dns":{
			"servers":[{"address":"1.1.1.1","tag":"u"},{"address":"fakeip","tag":"fk"}],
			"final":"fk"
		}}`)
		dns, _ := root["dns"].(map[string]interface{})
		if _, ok := dns["final"]; ok {
			t.Fatalf("a fakeip final must be dropped: %v", dns)
		}
		if !strings.Contains(strings.Join(warnings, "\n"), "cannot be the default") {
			t.Fatalf("the drop must be explained: %v", warnings)
		}
	})
}

// TestMigrateLegacyDNSServerKeys: the server-level keys option.DNSServerOptions
// rejects are renamed where the mapping is exact and removed where it is not.
func TestMigrateLegacyDNSServerKeys(t *testing.T) {
	root, warnings := migrateDoc(t, `{"dns":{"servers":[{"address":"1.1.1.1","tag":"s",
		"address_resolver":"boot","address_strategy":"ipv4_only","strategy":"prefer_ipv6",
		"client_subnet":"1.2.3.0/24","outbound":"proxy"}]}}`)
	server := serverAt(t, root, 0)
	if server["domain_resolver"] != "boot" {
		t.Fatalf("address_resolver → domain_resolver: %v", server)
	}
	if server["detour"] != "proxy" {
		t.Fatalf("outbound → detour: %v", server)
	}
	for _, removed := range []string{"address_resolver", "outbound", "address_strategy", "strategy", "client_subnet"} {
		if _, ok := server[removed]; ok {
			t.Fatalf("%s must be removed: %v", removed, server)
		}
	}
	joined := strings.Join(warnings, "\n")
	for _, want := range []string{"address_resolver → domain_resolver", "outbound → detour", "address_strategy", "strategy", "client_subnet"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("warning missing %q: %v", want, warnings)
		}
	}
}

// TestMigrateLegacyDNSIsIdempotent: a second pass must be silent — the Start
// path and the import path both run the migrator on the same document.
func TestMigrateLegacyDNSIsIdempotent(t *testing.T) {
	root, first := migrateDoc(t, `{"dns":{
		"servers":[
			{"address":"1.1.1.1","tag":"u"},
			{"address":"https://dns.google/dns-query","tag":"g","address_resolver":"u"},
			{"address":"fakeip","tag":"fk"},
			{"address":"rcode://refused","tag":"blocked"}
		],
		"rules":[{"domain":["ads.example"],"server":"blocked"},{"domain":["x"],"server":"u"}],
		"fakeip":{"enabled":true},
		"final":"g"
	}}`)
	if len(first) == 0 {
		t.Fatal("expected migrations on the first pass")
	}
	if again := MigrateLegacyJSON(root); len(again) != 0 {
		t.Fatalf("second pass must be silent, got %v", again)
	}
}

// TestMigrateModernDNSTouched: a 1.5-native dns block must come out byte-equal.
func TestMigrateModernDNSUntouched(t *testing.T) {
	// Keys are in the order encoding/json emits them, so a byte comparison also
	// catches an accidental re-serialisation of the block.
	raw := `{"dns":{"final":"u","servers":[{"server":"1.1.1.1","tag":"u","type":"udp"},{"tag":"l","type":"local"}],"strategy":"ipv4_only"}}`
	var root map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &root); err != nil {
		t.Fatal(err)
	}
	if warnings := MigrateLegacyJSON(root); len(warnings) != 0 {
		t.Fatalf("no warning expected, got %v", warnings)
	}
	got, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != raw {
		t.Fatalf("modern dns block was rewritten:\n got %s\nwant %s", got, raw)
	}
}

// TestIsolateDNSBlockDropsOnlyBadServer: a server the engine cannot decode is
// dropped on its own (with a parse warning) while the rest of the block — and
// of the subscription — survives.
func TestIsolateDNSBlockDropsOnlyBadServer(t *testing.T) {
	raw := `{
	  "dns": {"servers": [
	    {"type": "udp", "tag": "good", "server": "1.1.1.1"},
	    {"type": "udp", "tag": "bad", "server": "8.8.8.8", "bogus": 1},
	    {"type": "not-a-transport", "tag": "weird"}
	  ], "final": "good"},
	  "outbounds": [{"type": "direct", "tag": "direct"}],
	  "route": {"final": "direct"}
	}`
	ctx, collector := WithParseWarnings(libbox.BaseContext(nil))
	filtered, err := filterValidLeavesJSON(ctx, []byte(raw), false)
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	var root map[string]interface{}
	if err := json.Unmarshal(filtered, &root); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	list := dnsServers(t, root)
	if len(list) != 1 || serverAt(t, root, 0)["tag"] != "good" {
		t.Fatalf("want only the good server, got %v", list)
	}
	summary := collectorSummary(t, collector)
	if summary.Dropped != 2 {
		t.Fatalf("want 2 dns drops, got %d (%+v)", summary.Dropped, summary)
	}
	for _, sample := range summary.DropSamples {
		if !strings.HasPrefix(sample, "dns ") {
			t.Fatalf("dns drops must be labelled kind=dns: %q", sample)
		}
	}
}

// TestIsolateDNSBlockDropsWholeBlock: a defect with no per-entry form (an
// unknown block-level key) costs the block, not the import, and is reported.
func TestIsolateDNSBlockDropsWholeBlock(t *testing.T) {
	raw := `{
	  "dns": {"servers": [{"type": "udp", "tag": "u", "server": "1.1.1.1"}], "bogus": true},
	  "outbounds": [{"type": "direct", "tag": "direct"}]
	}`
	ctx, collector := WithParseWarnings(libbox.BaseContext(nil))
	filtered, err := filterValidLeavesJSON(ctx, []byte(raw), false)
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	var root map[string]interface{}
	if err := json.Unmarshal(filtered, &root); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := root["dns"]; ok {
		t.Fatalf("the unusable dns block must be dropped: %v", root["dns"])
	}
	if _, ok := root["outbounds"]; !ok {
		t.Fatal("outbounds must survive a dns-only defect")
	}
	summary := collectorSummary(t, collector)
	if summary.Dropped != 1 || !strings.Contains(summary.TopDrop, "bogus") {
		t.Fatalf("the whole-block drop must be reported with its cause, got %+v", summary)
	}
}

// TestIsolateDNSBlockLeavesRuleDangling drops a rule whose server was removed by
// the isolation pass: the router would refuse the block otherwise.
func TestIsolateDNSBlockLeavesRuleDangling(t *testing.T) {
	raw := `{
	  "dns": {
	    "servers": [{"type": "udp", "tag": "u", "server": "1.1.1.1"}, {"type": "weird", "tag": "gone"}],
	    "rules": [{"domain": ["a.example"], "server": "gone"}, {"domain": ["b.example"], "server": "u"}]
	  },
	  "outbounds": [{"type": "direct", "tag": "direct"}]
	}`
	ctx, _ := WithParseWarnings(libbox.BaseContext(nil))
	filtered, err := filterValidLeavesJSON(ctx, []byte(raw), false)
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	var root map[string]interface{}
	if err := json.Unmarshal(filtered, &root); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rules := dnsRules(t, root)
	if len(rules) != 1 {
		t.Fatalf("the dangling rule must be pruned, got %v", rules)
	}
	if rule, _ := rules[0].(map[string]interface{}); rule["server"] != "u" {
		t.Fatalf("wrong survivor: %v", rules)
	}
	if len(dnsServers(t, root)) != 1 {
		t.Fatalf("the unknown transport must be dropped: %v", dnsServers(t, root))
	}
}

// TestIsolateDNSBlockAcceptsHealthyBlock: a fully valid block is not rewritten.
func TestIsolateDNSBlockAcceptsHealthyBlock(t *testing.T) {
	raw := `{
	  "dns": {"servers": [{"type": "udp", "tag": "u", "server": "1.1.1.1"}], "final": "u"},
	  "outbounds": [{"type": "direct", "tag": "direct"}]
	}`
	root := map[string]interface{}{}
	if err := json.Unmarshal([]byte(raw), &root); err != nil {
		t.Fatal(err)
	}
	if isolateDNSBlock(libbox.BaseContext(nil), root) {
		t.Fatalf("healthy block reported as changed: %v", root)
	}
}

// collectorSummary decodes the collector payload for assertions.
func collectorSummary(t *testing.T, collector *ParseWarningsCollector) ParseWarningsSummary {
	t.Helper()
	message := collector.MessageJSON()
	if message == "" {
		t.Fatal("expected a warnings payload")
	}
	var decoded map[string]ParseWarningsSummary
	if err := json.Unmarshal([]byte(message), &decoded); err != nil {
		t.Fatalf("payload is not JSON: %v (%s)", err, message)
	}
	return decoded[parseWarningsMessageKey]
}

// TestMigrateLegacyDNSJSONArrayValue: dns.servers carrying a single object (or a
// non-list) is left for the engine to reject — the migrator must not panic on it.
func TestMigrateLegacyDNSServersNotAList(t *testing.T) {
	root, warnings := migrateDoc(t, `{"dns":{"servers":{"address":"1.1.1.1"}}}`)
	dns, _ := root["dns"].(map[string]interface{})
	server, _ := dns["servers"].(map[string]interface{})
	if server["address"] != "1.1.1.1" {
		t.Fatalf("a non-list servers value must be left alone: %v", dns)
	}
	if len(warnings) != 0 {
		t.Fatalf("no warning expected, got %v", warnings)
	}
}

// TestMigrateLegacyDNSThroughParseConfigBytes is the end-to-end regression: a
// 1.4 subscription whose dns block would not decode on 1.5 now imports, keeps
// its outbounds, and reports what was migrated.
func TestMigrateLegacyDNSThroughParseConfigBytes(t *testing.T) {
	raw := `{
	  "dns": {
	    "servers": [
	      {"address": "1.1.1.1", "tag": "bootstrap"},
	      {"address": "https://dns.google/dns-query", "tag": "remote", "detour": "direct"},
	      {"address": "fakeip", "tag": "fake"}
	    ],
	    "rules": [{"query_type": ["A", "AAAA"], "server": "fake"}],
	    "fakeip": {"enabled": true, "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18"},
	    "final": "remote"
	  },
	  "outbounds": [{"type": "direct", "tag": "direct"}],
	  "route": {"final": "direct"}
	}`
	ctx, collector := WithParseWarnings(libbox.BaseContext(nil))
	parsed, err := ParseConfigBytes(ctx, &ReadOptions{Content: raw}, true, DefaultClientOptions(), false)
	if err != nil {
		t.Fatalf("a legacy dns block must not fail the import any more: %v", err)
	}
	if !strings.Contains(string(parsed), `"direct"`) {
		t.Fatalf("outbounds lost: %s", parsed)
	}
	if !strings.Contains(string(parsed), `"type":"https"`) {
		t.Fatalf("legacy server not migrated: %s", parsed)
	}
	summary := collectorSummary(t, collector)
	if summary.Migrated == 0 {
		t.Fatal("the migrations must be reported to the UI")
	}
	if !strings.Contains(strings.Join(summary.MigrateSamples, "\n"), "dns.fakeip") {
		t.Fatalf("the fakeip drop must be sampled: %v", summary.MigrateSamples)
	}
}

// TestMigrateLegacyDNSWithoutCollector exercises the same path without a parse
// collector attached (Start path / CLI / tests): a nil collector must be a no-op
// rather than a panic.
func TestMigrateLegacyDNSWithoutCollector(t *testing.T) {
	raw := `{"dns":{"servers":[{"address":"1.1.1.1","tag":"u"}],"fakeip":{"enabled":true}},"outbounds":[{"type":"direct","tag":"direct"}]}`
	if _, err := filterValidLeavesJSON(libbox.BaseContext(nil), []byte(raw), false); err != nil {
		t.Fatalf("filter without collector: %v", err)
	}
}

// TestIsolateDNSBlockWithoutRegistryInContext: the parser is also called with a
// bare context (CLI, tests, smoke helpers). The DNS decoders need a transport
// registry, so determineDNSCtx supplies one instead of failing the import with
// "missing DNS transport options registry in context".
func TestIsolateDNSBlockWithoutRegistryInContext(t *testing.T) {
	root := map[string]interface{}{}
	raw := `{"servers":[{"type":"udp","tag":"good","server":"1.1.1.1"},{"type":"nope","tag":"bad"}]}`
	if err := json.Unmarshal([]byte(raw), &root); err != nil {
		t.Fatal(err)
	}
	if !isolateDNSBlock(context.Background(), map[string]interface{}{"dns": root}) {
		t.Fatal("the unknown transport must be isolated even without a registry in ctx")
	}
	list, _ := root["servers"].([]interface{})
	if len(list) != 1 {
		t.Fatalf("want only the good server, got %v", list)
	}
}
