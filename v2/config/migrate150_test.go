package config

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/experimental/libbox"
)

func migrateDoc(t *testing.T, raw string) (map[string]interface{}, []string) {
	t.Helper()
	var root map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &root); err != nil {
		t.Fatal(err)
	}
	return root, MigrateLegacyJSON(root)
}

// stageBundledRuleSets puts `<tag>.srs` files into a temp cwd's rules/ dir for
// the lifetime of the test and restores the previous cwd afterwards.
//
// The geo migrator only rewrites a legacy geosite/geoip matcher when the code
// resolves to a local file (resolveLocalRuleSetFile — the same function
// BuildConfig's fail-closed sanitizer uses, so the two can never disagree)
// instead of synthesizing a remote rule_set that would kill the start.
func stageBundledRuleSets(t *testing.T, tags ...string) {
	t.Helper()
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rules, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tag := range tags {
		if err := os.WriteFile(filepath.Join(rules, tag+".srs"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
}

func firstOutbound(t *testing.T, root map[string]interface{}) map[string]interface{} {
	t.Helper()
	list, _ := root["outbounds"].([]interface{})
	if len(list) == 0 {
		t.Fatal("no outbounds")
	}
	m, _ := list[0].(map[string]interface{})
	return m
}

func TestMigrateParrotKeys(t *testing.T) {
	root, warnings := migrateDoc(t, `{"outbounds":[
		{"type":"tuic","tag":"a","disable_chrome_parrot":true},
		{"type":"hysteria2","tag":"b","chrome_parrot":true},
		{"type":"tuic","tag":"c","chrome_parrot":true,"utls":{"enabled":true,"fingerprint":"firefox"}}
	]}`)
	if len(warnings) < 3 {
		t.Fatalf("want parrot+tls migrations reported, got %v", warnings)
	}
	list, _ := root["outbounds"].([]interface{})
	a := list[0].(map[string]interface{})
	utls, _ := a["utls"].(map[string]interface{})
	if utls["fingerprint"] != "quic-go" || utls["enabled"] != true {
		t.Fatalf("disable_chrome_parrot → quic-go, got %v", utls)
	}
	if _, ok := a["disable_chrome_parrot"]; ok {
		t.Fatal("legacy key not removed")
	}
	b := list[1].(map[string]interface{})
	utls, _ = b["utls"].(map[string]interface{})
	if utls["fingerprint"] != "chrome" {
		t.Fatalf("chrome_parrot → chrome, got %v", utls)
	}
	c := list[2].(map[string]interface{})
	utls, _ = c["utls"].(map[string]interface{})
	if utls["fingerprint"] != "firefox" {
		t.Fatalf("existing utls must not be clobbered, got %v", utls)
	}
}

func TestMigrateHysteriaBandwidth(t *testing.T) {
	root, _ := migrateDoc(t, `{"outbounds":[
		{"type":"hysteria2","tag":"a","up_mbps":100,"down_mbps":200,"brutal_debug":true},
		{"type":"hysteria","tag":"b","up":"50 Mbps","down":"100 Mbps","ignore_client_bandwidth":true},
		{"type":"hysteria2","tag":"c","brutal_debug":false}
	]}`)
	list, _ := root["outbounds"].([]interface{})
	a := list[0].(map[string]interface{})
	if a["congestion_control"] != "brutal" {
		t.Fatalf("want brutal, got %v", a["congestion_control"])
	}
	// brutal_mbps is the fixed send rate, so the uplink (up_mbps) is the axis;
	// max(up, down) would have put a 200 Mbps send rate on a 100 Mbps uplink.
	if a["brutal_mbps"] != 100 {
		t.Fatalf("want send-rate cap up=100, got %v", a["brutal_mbps"])
	}
	for _, k := range []string{"up_mbps", "down_mbps", "brutal_debug"} {
		if _, ok := a[k]; ok {
			t.Fatalf("key %s not removed", k)
		}
	}
	b := list[1].(map[string]interface{})
	// Same axis for the string form: up="50 Mbps" is the send cap, so the
	// 100 Mbps downlink must not win.
	if b["brutal_mbps"] != 50 {
		t.Fatalf("string Mbps parse: want send-rate cap up=50, got %v", b["brutal_mbps"])
	}
	if _, ok := b["ignore_client_bandwidth"]; ok {
		t.Fatal("ignore_client_bandwidth not removed")
	}
	c := list[2].(map[string]interface{})
	if _, ok := c["brutal_mbps"]; ok {
		t.Fatal("no-cap config must not gain brutal_mbps")
	}
	if _, ok := c["brutal_debug"]; ok {
		t.Fatal("brutal_debug not removed")
	}
}

func TestMigrateTrustTunnel(t *testing.T) {
	root, warnings := migrateDoc(t, `{"outbounds":[{"type":"trusttunnel","tag":"tt",
		"tls":{"server_name":"x","skip_verification":true,"remote_id":"rid","private_key":"pk"},
		"transport":{"max_idle_timeout":"30s","utls":{"enabled":true},"quic_auth":{"psk":"s"}}}]}`)
	if len(warnings) != 6 {
		t.Fatalf("want 6 warnings, got %v", warnings)
	}
	m := firstOutbound(t, root)
	tls, _ := m["tls"].(map[string]interface{})
	if tls["insecure"] != true {
		t.Fatalf("skip_verification→insecure, got %v", tls["insecure"])
	}
	if _, ok := tls["skip_verification"]; ok {
		t.Fatal("skip_verification not removed")
	}
	if _, ok := tls["private_key"]; ok {
		t.Fatal("private_key not removed from tls")
	}
	if tls["key"] != "pk" {
		t.Fatalf("private_key→key, got %v", tls["key"])
	}
	if m["remote_id"] != "rid" {
		t.Fatalf("remote_id → root, got %v", m["remote_id"])
	}
	if m["idle_timeout"] != "30s" {
		t.Fatalf("max_idle_timeout→idle_timeout, got %v", m["idle_timeout"])
	}
	if _, ok := m["utls"].(map[string]interface{}); !ok {
		t.Fatal("transport.utls not lifted to root")
	}
	transport, _ := m["transport"].(map[string]interface{})
	if len(transport) != 0 {
		t.Fatalf("transport not emptied, got %v", transport)
	}
}

func TestMigrateVLESSFlowAndMasque(t *testing.T) {
	root, warnings := migrateDoc(t, `{"outbounds":[
		{"type":"vless","tag":"a","flow":"xtls-rprx-vision"},
		{"type":"vless","tag":"b","flow":"xtls-rprx-vision-udp443"},
		{"type":"vless","tag":"c","flow":"xray"},
		{"type":"masque","tag":"d"},
		{"type":"mesh_underlay","tag":"e"}
	]}`)
	list, _ := root["outbounds"].([]interface{})
	if list[0].(map[string]interface{})["flow"] != "xray" || list[1].(map[string]interface{})["flow"] != "xray" {
		t.Fatalf("vision flows not migrated: %v %v", list[0], list[1])
	}
	if list[2].(map[string]interface{})["flow"] != "xray" {
		t.Fatal("xray must stay xray")
	}
	if list[3].(map[string]interface{})["type"] != "warpsque" {
		t.Fatalf("masque→warpsque, got %v", list[3].(map[string]interface{})["type"])
	}
	var sawMeshWarning bool
	for _, w := range warnings {
		if strings.Contains(w, "mesh_underlay") {
			sawMeshWarning = true
		}
	}
	if !sawMeshWarning {
		t.Fatal("mesh_underlay must produce a warning")
	}
}

func TestMigrateRouteDirectAction(t *testing.T) {
	root, warnings := migrateDoc(t, `{"route":{"rules":[
		{"action":"direct"},
		{"action":"direct","outbound":"my-direct"},
		{"action":"reject"}
	]}}`)
	if len(warnings) != 2 {
		t.Fatalf("want 2 warnings, got %v", warnings)
	}
	route, _ := root["route"].(map[string]interface{})
	rules, _ := route["rules"].([]interface{})
	r0 := rules[0].(map[string]interface{})
	if r0["action"] != "route" || r0["outbound"] != "direct" {
		t.Fatalf("bare direct action not migrated: %v", r0)
	}
	r1 := rules[1].(map[string]interface{})
	if r1["action"] != "route" || r1["outbound"] != "my-direct" {
		t.Fatalf("existing outbound must be kept: %v", r1)
	}
	r2 := rules[2].(map[string]interface{})
	if r2["action"] != "reject" {
		t.Fatal("reject rule must stay untouched")
	}
}

func TestMigrateIdempotent(t *testing.T) {
	raw := `{"outbounds":[
		{"type":"hysteria2","tag":"a","up_mbps":100,"chrome_parrot":true},
		{"type":"vless","tag":"b","flow":"xtls-rprx-vision"},
		{"type":"masque","tag":"c"}
	],"route":{"rules":[{"action":"direct"}]}}`
	var root map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &root); err != nil {
		t.Fatal(err)
	}
	MigrateLegacyJSON(root)
	first, _ := json.Marshal(root)
	if warnings := MigrateLegacyJSON(root); len(warnings) != 0 {
		t.Fatalf("second run must be a no-op, got %v", warnings)
	}
	second, _ := json.Marshal(root)
	if string(first) != string(second) {
		t.Fatal("not idempotent")
	}
}

// End-to-end: a 1.4-era leaf must survive the soft filter (and validate under
// the 1.5 engine) instead of being dropped.
func TestMigrateThenSoftFilterKeepsLegacyLeaf(t *testing.T) {
	raw := `{"outbounds":[
		{"type":"tuic","tag":"legacy-tuic","server":"1.2.3.4","server_port":443,
		 "uuid":"00000000-0000-0000-0000-000000000001","password":"x",
		 "disable_chrome_parrot":true},
		{"type":"hysteria2","tag":"legacy-hy2","server":"1.2.3.4","server_port":443,
		 "password":"x","up_mbps":50,"down_mbps":100}
	]}`
	filtered, err := filterValidLeavesJSON(context.Background(), []byte(raw), false)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]interface{}
	if err := json.Unmarshal(filtered, &root); err != nil {
		t.Fatal(err)
	}
	list, _ := root["outbounds"].([]interface{})
	if len(list) != 2 {
		t.Fatalf("both migrated leaves must survive, got %d: %s", len(list), filtered)
	}
	hy2 := list[1].(map[string]interface{})
	// up_mbps=50 is the client's send cap; the 100 Mbps downlink is not.
	if hy2["brutal_mbps"] != float64(50) || hy2["congestion_control"] != "brutal" {
		t.Fatalf("hy2 not migrated: %v", hy2)
	}
}

// Start path: a stale profile with 1.4-era keys must still read under the 1.5
// engine (ReadSingOptions migrates before unmarshal).
func TestReadSingOptionsMigratesLegacyContent(t *testing.T) {
	content := `{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],
		"route":{"final":"direct","rules":[{"action":"direct"}]}}`
	opts, err := ReadSingOptions(libbox.BaseContext(nil), &ReadOptions{Content: content})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Route == nil || len(opts.Route.Rules) == 0 {
		t.Fatal("route rules lost")
	}
}

func TestMigratePadProfileAndNestedHysteriaBandwidth(t *testing.T) {
	root, warnings := migrateDoc(t, `{"outbounds":[
		{"type":"pathologywg","tag":"wg","pad_profile":"paranoid"},
		{"type":"hysteria2","tag":"hy","up_mbps":100,"down_mbps":200,"congestion_control":"bbr2"}
	],"endpoints":[{"type":"wireguard","tag":"ep","pad_profile":"stealth"}]}`)
	var sawPad, sawDroppedCC bool
	for _, w := range warnings {
		switch {
		case strings.Contains(w, "pad_profile dropped"):
			sawPad = true
		case strings.Contains(w, "is not brutal"):
			sawDroppedCC = true
		}
	}
	if !sawPad || !sawDroppedCC {
		t.Fatalf("missing expected warnings, got %v", warnings)
	}
	wg := firstOutbound(t, root)
	if _, ok := wg["pad_profile"]; ok {
		t.Fatal("pad_profile must be removed")
	}
	list, _ := root["outbounds"].([]interface{})
	hy := list[1].(map[string]interface{})
	if hy["brutal_mbps"] != nil {
		t.Fatalf("brutal_mbps requires congestion_control=brutal: %v", hy)
	}
	if hy["congestion_control"] != "bbr2" {
		t.Fatalf("explicit CC must be preserved, got %v", hy["congestion_control"])
	}
	if hy["up_mbps"] != nil || hy["down_mbps"] != nil {
		t.Fatalf("legacy bandwidth keys must be dropped: %v", hy)
	}
	eps, _ := root["endpoints"].([]interface{})
	ep := eps[0].(map[string]interface{})
	if _, ok := ep["pad_profile"]; ok {
		t.Fatalf("endpoint pad_profile must be dropped: %v", ep)
	}
}

func TestMigrateV2RayTransportHysteriaBandwidth(t *testing.T) {
	root, warnings := migrateDoc(t, `{"outbounds":[
		{"type":"vless","tag":"a","server":"1.2.3.4","server_port":443,
		 "uuid":"00000000-0000-0000-0000-000000000001",
		 "transport":{"type":"http","method":"hysteria","up":"1.5 Gbps","down_mbps":900}}
	]}`)
	tr, _ := firstOutbound(t, root)["transport"].(map[string]interface{})
	if tr["brutal_mbps"] != 1500 {
		t.Fatalf("want brutal_mbps=1500, got %v (%v)", tr["brutal_mbps"], warnings)
	}
	if tr["congestion_control"] != "brutal" {
		t.Fatalf("want brutal CC, got %v", tr["congestion_control"])
	}
	if tr["up"] != nil || tr["down_mbps"] != nil {
		t.Fatalf("legacy keys must be gone: %v", tr)
	}
}

func TestMigrateLogicalRouteRuleDirect(t *testing.T) {
	root, warnings := migrateDoc(t, `{"route":{"rules":[
		{"type":"logical","mode":"and","rules":[{"action":"direct"},{"action":"reject"}]},
		{"action":"direct"}
	]}}`)
	if len(warnings) != 2 {
		t.Fatalf("want 2 warnings (top-level + nested), got %v", warnings)
	}
	route, _ := root["route"].(map[string]interface{})
	rules, _ := route["rules"].([]interface{})
	nested, _ := rules[0].(map[string]interface{})["rules"].([]interface{})
	if len(nested) != 2 {
		t.Fatalf("nested rules lost: %v", nested)
	}
	inner := nested[0].(map[string]interface{})
	if inner["action"] != "route" || inner["outbound"] != "direct" {
		t.Fatalf("nested direct not migrated: %v", inner)
	}
	if nested[1].(map[string]interface{})["action"] != "reject" {
		t.Fatal("nested reject must stay untouched")
	}
}

// The mesh_underlay sentinel must keep the leaf droppable downstream while
// making a second migrator pass a no-op.
func TestMigrateMeshUnderlaySentinelIdempotent(t *testing.T) {
	root, warnings := migrateDoc(t, `{"outbounds":[{"type":"mesh_underlay","tag":"mesh"}]}`)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "mesh_underlay") {
		t.Fatalf("want one mesh warning, got %v", warnings)
	}
	if got := firstOutbound(t, root)["type"]; got != meshUnderlayDroppedType {
		t.Fatalf("want sentinel type, got %v", got)
	}
	if again := MigrateLegacyJSON(root); len(again) != 0 {
		t.Fatalf("second run must be silent, got %v", again)
	}
}

// Masque→warpsque applies to endpoints and inbounds too (1.4 had all three).
func TestMigrateMasqueRenameEverywhere(t *testing.T) {
	root, warnings := migrateDoc(t, `{"outbounds":[{"type":"masque","tag":"o"}],
		"endpoints":[{"type":"masque","tag":"e"}],
		"inbounds":[{"type":"masque","tag":"i"}]}`)
	if len(warnings) != 3 {
		t.Fatalf("want 3 rename warnings, got %v", warnings)
	}
	for _, key := range []string{"outbounds", "endpoints", "inbounds"} {
		list, _ := root[key].([]interface{})
		if len(list) != 1 {
			t.Fatalf("%s lost: %v", key, root[key])
		}
		if got := list[0].(map[string]interface{})["type"]; got != "warpsque" {
			t.Fatalf("%s: want warpsque, got %v", key, got)
		}
	}
}

// 1.3-era profiles say none; that must not block the parrot migration.
func TestMigrateParrotFingerprintNone(t *testing.T) {
	root, warnings := migrateDoc(t, `{"outbounds":[
		{"type":"tuic","tag":"a","chrome_parrot":true,"utls":{"enabled":false,"fingerprint":"none"}}
	]}`)
	if len(warnings) == 0 {
		t.Fatal("none fingerprint must still be migrated")
	}
	utls, _ := firstOutbound(t, root)["utls"].(map[string]interface{})
	if utls["fingerprint"] != "chrome" {
		t.Fatalf("want chrome, got %v", utls)
	}
	if utls["enabled"] != true {
		t.Fatalf("utls must be enabled, got %v", utls)
	}
}

// A real fingerprint wins: the parrot key is dropped, persona untouched.
func TestMigrateParrotRespectsExistingFingerprint(t *testing.T) {
	root, warnings := migrateDoc(t, `{"outbounds":[
		{"type":"tuic","tag":"a","disable_chrome_parrot":true,"utls":{"enabled":true,"fingerprint":"firefox"}}
	]}`)
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "already set") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want 'already set' warning, got %v", warnings)
	}
	utls, _ := firstOutbound(t, root)["utls"].(map[string]interface{})
	if utls["fingerprint"] != "firefox" {
		t.Fatalf("fingerprint must not be clobbered, got %v", utls)
	}
}

func TestMigrateTrustTunnelInboundDrops(t *testing.T) {
	root, warnings := migrateDoc(t, `{"inbounds":[{"type":"trusttunnel","tag":"tt-in",
		"tls":{"remote_id":"rid"},
		"transport":{"quic_auth":{"psk":"s"}}}]}`)
	if len(warnings) != 2 {
		t.Fatalf("want 2 drop warnings, got %v", warnings)
	}
	list, _ := root["inbounds"].([]interface{})
	m := list[0].(map[string]interface{})
	if _, ok := m["remote_id"]; ok {
		t.Fatal("inbound must not gain remote_id")
	}
	if _, ok := m["quic_auth"]; ok {
		t.Fatal("inbound must not gain quic_auth")
	}
	tls, _ := m["tls"].(map[string]interface{})
	if _, ok := tls["remote_id"]; ok {
		t.Fatal("tls.remote_id must be removed")
	}
	tr, _ := m["transport"].(map[string]interface{})
	if len(tr) != 0 {
		t.Fatalf("transport must be emptied, got %v", tr)
	}
}

func TestBandwidthMbpsParsing(t *testing.T) {
	cases := []struct {
		in   []interface{}
		want int
	}{
		{[]interface{}{float64(200)}, 200},
		{[]interface{}{"100 Mbps"}, 100},
		{[]interface{}{"100Mbps"}, 100},
		{[]interface{}{"1 Gbps"}, 1000},
		{[]interface{}{"1.5G"}, 1500},
		{[]interface{}{"800 kbps"}, 0},
		{[]interface{}{"junk"}, 0},
		{[]interface{}{nil, "50 Mbps"}, 50},
		{[]interface{}{float64(10), "1 Gbps"}, 1000},
	}
	for _, c := range cases {
		if got := bandwidthMbps(c.in...); got != c.want {
			t.Fatalf("bandwidthMbps(%v)=%d, want %d", c.in, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Defect 1: geosite / geoip / source_geoip
// ---------------------------------------------------------------------------

// jsonStrings renders a decoded JSON string-or-array as []string, failing the
// test on any other shape (a rule_set list must be strings).
func jsonStrings(t *testing.T, value interface{}) []string {
	t.Helper()
	switch typed := value.(type) {
	case nil:
		return nil
	case string:
		return []string{typed}
	case []interface{}:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			s, ok := item.(string)
			if !ok {
				t.Fatalf("want string entries, got %v", value)
			}
			out = append(out, s)
		}
		return out
	}
	t.Fatalf("want string or array, got %T (%v)", value, value)
	return nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// routeRuleSets indexes route.rule_set by tag for assertions.
func routeRuleSets(t *testing.T, root map[string]interface{}) map[string]map[string]interface{} {
	t.Helper()
	out := map[string]map[string]interface{}{}
	route, _ := root["route"].(map[string]interface{})
	if route == nil {
		return out
	}
	sets, _ := route["rule_set"].([]interface{})
	for _, item := range sets {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		for _, tag := range jsonStrings(t, m["tag"]) {
			out[tag] = m
		}
	}
	return out
}

func routeRules(t *testing.T, root map[string]interface{}) []interface{} {
	t.Helper()
	route, _ := root["route"].(map[string]interface{})
	if route == nil {
		t.Fatal("route missing")
	}
	rules, _ := route["rules"].([]interface{})
	return rules
}

// A rule carrying geosite+geoip must not reach the 1.5 engine (it hard-errors
// inside router.Initialize, which box.New calls, so the whole import dies).
// Both are rewritten to rule_set references backed by synthesized remote sets,
// and the existing entries of the rule's rule_set stay first.
func TestMigrateGeoRuleMatchers(t *testing.T) {
	stageBundledRuleSets(t, "geosite-cn", "geosite-ads", "geoip-cn")
	root, warnings := migrateDoc(t, `{"route":{"rules":[
		{"domain_suffix":[".example"],"outbound":"direct"},
		{"geosite":["cn","ads"],"geoip":["cn"],"rule_set":["custom"],"outbound":"proxy"}
	]}}`)
	rules := routeRules(t, root)
	if len(rules) != 2 {
		t.Fatalf("rule count changed: %v", rules)
	}
	if _, ok := rules[0].(map[string]interface{})["rule_set"]; ok {
		t.Fatalf("rule without geo matchers must stay untouched: %v", rules[0])
	}
	rule := rules[1].(map[string]interface{})
	for _, key := range []string{"geosite", "geoip"} {
		if _, ok := rule[key]; ok {
			t.Fatalf("%s must be removed (1.5 hard-rejects it): %v", key, rule)
		}
	}
	if got, want := jsonStrings(t, rule["rule_set"]), []string{"custom", "geosite-cn", "geosite-ads", "geoip-cn"}; !equalStrings(got, want) {
		t.Fatalf("rule_set = %v, want %v (existing first, then appended)", got, want)
	}
	if rule["outbound"] != "proxy" {
		t.Fatalf("other conditions must survive: %v", rule)
	}

	sets := routeRuleSets(t, root)
	if len(sets) != 3 {
		t.Fatalf("want 3 synthesized rule-sets, got %v", sets)
	}
	for _, tc := range []struct{ tag, tmpl, code string }{
		{"geosite-cn", DefaultGeoSiteRuleSetURL, "cn"},
		{"geosite-ads", DefaultGeoSiteRuleSetURL, "ads"},
		{"geoip-cn", DefaultGeoIPRuleSetURL, "cn"},
	} {
		rs, ok := sets[tc.tag]
		if !ok {
			t.Fatalf("missing rule-set %q: %v", tc.tag, sets)
		}
		if rs["type"] != "remote" || rs["format"] != "binary" {
			t.Fatalf("%q must be a remote binary rule-set, got %v", tc.tag, rs)
		}
		if want := strings.ReplaceAll(tc.tmpl, "{tag}", tc.code); rs["url"] != want {
			t.Fatalf("%q url = %v, want %v", tc.tag, rs["url"], want)
		}
	}
	if len(warnings) != 3 {
		t.Fatalf("want one warning per migrated code, got %v", warnings)
	}

	before, _ := json.Marshal(root)
	if again := MigrateLegacyJSON(root); len(again) != 0 {
		t.Fatalf("second run must be silent, got %v", again)
	}
	after, _ := json.Marshal(root)
	if string(before) != string(after) {
		t.Fatal("geo migration is not idempotent")
	}
	if n := len(routeRuleSets(t, root)); n != 3 {
		t.Fatalf("second run added rule-sets: %d", n)
	}
}

// Two rules asking for the same code share one rule-set: the engine rejects a
// duplicate rule-set tag outright.
func TestMigrateGeoRuleSetDedupAcrossRules(t *testing.T) {
	stageBundledRuleSets(t, "geosite-cn")
	root, _ := migrateDoc(t, `{"route":{"rules":[
		{"geosite":["cn"],"outbound":"direct"},
		{"geosite":["cn"],"outbound":"proxy"}
	]}}`)
	sets := routeRuleSets(t, root)
	if len(sets) != 1 {
		t.Fatalf("want a single geosite-cn rule-set, got %v", sets)
	}
	for _, rule := range routeRules(t, root) {
		if got := jsonStrings(t, rule.(map[string]interface{})["rule_set"]); !equalStrings(got, []string{"geosite-cn"}) {
			t.Fatalf("rule_set = %v, want [geosite-cn]", got)
		}
	}
}

// source_geoip cannot be expressed as a rule_set (a rule_set matcher compares
// the destination, and rule_set_ip_cidr_match_source is rule-wide), so it is
// dropped with a warning that says so. The rest of the rule must survive.
func TestMigrateSourceGeoIPDropped(t *testing.T) {
	root, warnings := migrateDoc(t, `{"route":{"rules":[
		{"source_geoip":["cn"],"port":443,"outbound":"proxy"}
	]}}`)
	rule := routeRules(t, root)[0].(map[string]interface{})
	if _, ok := rule["source_geoip"]; ok {
		t.Fatalf("source_geoip must be removed: %v", rule)
	}
	if _, ok := rule["rule_set"]; ok {
		t.Fatalf("source_geoip must not become a destination rule_set match: %v", rule)
	}
	if _, ok := root["route"].(map[string]interface{})["rule_set"]; ok {
		t.Fatal("no rule-set may be synthesized for source_geoip")
	}
	if rule["port"] != float64(443) {
		t.Fatalf("other conditions must survive: %v", rule)
	}
	if len(warnings) != 1 {
		t.Fatalf("want one warning, got %v", warnings)
	}
	if !strings.Contains(warnings[0], "source_geoip") || !strings.Contains(warnings[0], "not carried over") {
		t.Fatalf("warning must document the limitation, got %q", warnings[0])
	}
	if again := MigrateLegacyJSON(root); len(again) != 0 {
		t.Fatalf("second run must be silent, got %v", again)
	}
}

// A rule whose only matcher is source_geoip would arrive at the engine without
// conditions ("missing conditions") and kill the import, so the rule itself is
// dropped — after the keys are gone there is nothing faithful left to keep.
func TestMigrateSourceGeoIPOnlyRuleDropped(t *testing.T) {
	root, warnings := migrateDoc(t, `{"route":{"rules":[
		{"source_geoip":["cn"],"outbound":"proxy"},
		{"port":53,"outbound":"dns-out"}
	]}}`)
	rules := routeRules(t, root)
	if len(rules) != 1 {
		t.Fatalf("the conditionless rule must be dropped, got %v", rules)
	}
	if rules[0].(map[string]interface{})["outbound"] != "dns-out" {
		t.Fatalf("unrelated rules must survive: %v", rules)
	}
	var sawDrop bool
	for _, w := range warnings {
		if strings.Contains(w, "rule dropped") {
			sawDrop = true
		}
	}
	if !sawDrop {
		t.Fatalf("dropping the rule must be reported, got %v", warnings)
	}
	if again := MigrateLegacyJSON(root); len(again) != 0 {
		t.Fatalf("second run must be silent, got %v", again)
	}
	if n := len(routeRules(t, root)); n != 1 {
		t.Fatalf("second run changed the rule list: %d", n)
	}
}

// A geosite nested in a logical rule fails box.New exactly like a top-level
// one, so the recursion has to reach it.
func TestMigrateGeoInLogicalRule(t *testing.T) {
	stageBundledRuleSets(t, "geosite-cn")
	root, warnings := migrateDoc(t, `{"route":{"rules":[
		{"type":"logical","mode":"and","rules":[
			{"geosite":["cn"]},
			{"port":443}
		],"outbound":"proxy"}
	]}}`)
	logical := routeRules(t, root)[0].(map[string]interface{})
	if _, ok := logical["rule_set"]; ok {
		t.Fatalf("the logical rule itself must not gain rule_set: %v", logical)
	}
	children, _ := logical["rules"].([]interface{})
	if len(children) != 2 {
		t.Fatalf("children lost: %v", children)
	}
	child := children[0].(map[string]interface{})
	if _, ok := child["geosite"]; ok {
		t.Fatalf("nested geosite must be removed: %v", child)
	}
	if got := jsonStrings(t, child["rule_set"]); !equalStrings(got, []string{"geosite-cn"}) {
		t.Fatalf("child rule_set = %v, want [geosite-cn]", got)
	}
	if _, ok := children[1].(map[string]interface{})["rule_set"]; ok {
		t.Fatalf("sibling without geo matchers must stay untouched: %v", children[1])
	}
	if len(routeRuleSets(t, root)) != 1 {
		t.Fatalf("want one synthesized rule-set, got %v", root["route"])
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "geosite") {
		t.Fatalf("want the nested rewrite reported, got %v", warnings)
	}
}

// DNS rules share option.RawDefaultRule's rule_set field and resolve it through
// the same route router (route.Router.Initialize runs before
// dns.Router.Initialize in box.New), so geosite is rewritten there too. A DNS
// rule-set entry matches the queried domain, which is what geosite did.
func TestMigrateGeoDNSRule(t *testing.T) {
	stageBundledRuleSets(t, "geosite-cn")
	root, warnings := migrateDoc(t, `{"dns":{"rules":[
		{"geosite":["cn"],"server":"local"}
	]}}`)
	dns, _ := root["dns"].(map[string]interface{})
	rules, _ := dns["rules"].([]interface{})
	rule := rules[0].(map[string]interface{})
	if _, ok := rule["geosite"]; ok {
		t.Fatalf("dns rule geosite must be removed: %v", rule)
	}
	if got := jsonStrings(t, rule["rule_set"]); !equalStrings(got, []string{"geosite-cn"}) {
		t.Fatalf("dns rule_set = %v, want [geosite-cn]", got)
	}
	if rule["server"] != "local" {
		t.Fatalf("dns action must survive: %v", rule)
	}
	sets := routeRuleSets(t, root)
	rs, ok := sets["geosite-cn"]
	if !ok {
		t.Fatalf("route.rule_set must back the dns reference: %v", root)
	}
	if want := strings.ReplaceAll(DefaultGeoSiteRuleSetURL, "{tag}", "cn"); rs["url"] != want {
		t.Fatalf("url = %v, want %v", rs["url"], want)
	}
	// The geo rewrite must be REPORTED; the DNS migrator may add warnings of its
	// own here (this rule names `local`, a server 1.4 resolved implicitly), so
	// assert presence rather than an exact count.
	foundGeo := false
	for _, w := range warnings {
		if strings.Contains(w, "dns rule") && strings.Contains(w, "geosite") {
			foundGeo = true
		}
	}
	if !foundGeo {
		t.Fatalf("want the dns geosite rewrite reported, got %v", warnings)
	}
	if again := MigrateLegacyJSON(root); len(again) != 0 {
		t.Fatalf("second run must be silent, got %v", again)
	}
}

// A geo code with no bundled rule_set must NOT become a synthesized remote set:
// BuildConfig runs every subscription rule_set through the fail-closed local
// sanitizer, so a remote entry with no local file turns an import-time rewrite
// into a start-time failure. The matcher is dropped (and reported) instead, and
// the rest of the rule survives.
func TestMigrateGeoCodeWithoutBundledRulesetIsDropped(t *testing.T) {
	// Only -cn is staged; "-zz" has no file.
	stageBundledRuleSets(t, "geosite-cn")
	root, warnings := migrateDoc(t, `{"route":{"rules":[
		{"geosite":["zz"],"domain_suffix":[".example"],"outbound":"proxy"}
	]}}`)
	rule := routeRules(t, root)[0].(map[string]interface{})
	if _, ok := rule["geosite"]; ok {
		t.Fatalf("geosite must be removed either way: %v", rule)
	}
	if _, ok := rule["rule_set"]; ok {
		t.Fatalf("no rule_set must be synthesized for an unbundled code: %v", rule)
	}
	if len(routeRuleSets(t, root)) != 0 {
		t.Fatalf("route.rule_set must stay empty: %v", routeRuleSets(t, root))
	}
	// The rule keeps its other matcher, so it is not dropped.
	if got := jsonStrings(t, rule["domain_suffix"]); !equalStrings(got, []string{".example"}) {
		t.Fatalf("other conditions must survive: %v", rule)
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, `"zz"`) && strings.Contains(w, "dropped") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the dropped matcher must be reported: %v", warnings)
	}
}


// ---------------------------------------------------------------------------
// Defect 2: the brutal_mbps axis
// ---------------------------------------------------------------------------

// brutal_mbps is the fixed send rate (option.QUICOptions.BrutalMbps), and 1.4
// up_mbps/up was the client's send cap — so the uplink is the axis, and down is
// only a fallback when no uplink cap was declared.
func TestMigrateHysteriaBrutalSendRate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fields string
		want   int
	}{
		{"uplink wins over downlink", `"up_mbps":100,"down_mbps":200`, 100},
		{"uplink only", `"up_mbps":80`, 80},
		{"downlink only falls back", `"down_mbps":500`, 500},
		{"string uplink", `"up":"50 Mbps","down":"1 Gbps"`, 50},
		{"no cap", `"brutal_debug":true`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, _ := migrateDoc(t, `{"outbounds":[{"type":"hysteria2","tag":"hy",`+tc.fields+`}]}`)
			m := firstOutbound(t, root)
			if tc.want == 0 {
				if _, ok := m["brutal_mbps"]; ok {
					t.Fatalf("no cap must not gain brutal_mbps: %v", m)
				}
				if _, ok := m["congestion_control"]; ok {
					t.Fatalf("no cap must not gain congestion_control: %v", m)
				}
				return
			}
			// The migrator writes an int; only a JSON round-trip would make it
			// a float64, so compare against the int directly.
			if m["brutal_mbps"] != tc.want {
				t.Fatalf("brutal_mbps = %v, want send-rate %d", m["brutal_mbps"], tc.want)
			}
			if m["congestion_control"] != "brutal" {
				t.Fatalf("want brutal congestion control, got %v", m["congestion_control"])
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Defect 4: legacy inbound fields
// ---------------------------------------------------------------------------

// countSniffActionRules counts the top-level route rules that sniff.
func countSniffActionRules(t *testing.T, root map[string]interface{}) int {
	t.Helper()
	route, _ := root["route"].(map[string]interface{})
	if route == nil {
		return 0
	}
	rules, _ := route["rules"].([]interface{})
	n := 0
	for _, item := range rules {
		rule, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if action, _ := rule["action"].(string); strings.TrimSpace(action) == "sniff" {
			n++
		}
	}
	return n
}

// 1.5 rejects every legacy inbound sniff field (option.Inbound.UnmarshalJSON),
// which used to cost the inbound on import and the whole profile on Start.
// sniff:true is lifted into the documented route action instead.
func TestMigrateInboundSniffFields(t *testing.T) {
	root, warnings := migrateDoc(t, `{"inbounds":[
		{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":7890,
		 "sniff":true,"sniff_timeout":"300ms","sniff_override_destination":true,
		 "domain_strategy":"prefer_ipv4"}
	]}`)
	list, _ := root["inbounds"].([]interface{})
	in := list[0].(map[string]interface{})
	for _, key := range []string{"sniff", "sniff_timeout", "sniff_override_destination", "domain_strategy"} {
		if _, ok := in[key]; ok {
			t.Fatalf("%s must be removed (1.5 hard-rejects it): %v", key, in)
		}
	}
	if in["listen_port"] != float64(7890) || in["listen"] != "127.0.0.1" {
		t.Fatalf("listen fields must survive: %v", in)
	}
	if got := countSniffActionRules(t, root); got != 1 {
		t.Fatalf("want exactly one sniff action rule, got %d (%v)", got, root["route"])
	}
	// The sniff rule has to run before any route/reject rule, or it never fires.
	if routeRules(t, root)[0].(map[string]interface{})["action"] != "sniff" {
		t.Fatalf("sniff rule must be first: %v", routeRules(t, root))
	}
	var named int
	for _, w := range warnings {
		if strings.Contains(w, "sniff_timeout") || strings.Contains(w, "domain_strategy") || strings.Contains(w, "sniff_override_destination") {
			named++
		}
	}
	if named != 3 {
		t.Fatalf("each dropped key must be reported, got %v", warnings)
	}

	if again := MigrateLegacyJSON(root); len(again) != 0 {
		t.Fatalf("second run must be silent, got %v", again)
	}
	if got := countSniffActionRules(t, root); got != 1 {
		t.Fatalf("second run must not add a sniff rule, got %d", got)
	}
}

// sniff:false was already accepted by 1.5 (zero value), so it must not produce
// a sniff action — but the key itself still has to go.
func TestMigrateInboundSniffFalseNoRule(t *testing.T) {
	root, warnings := migrateDoc(t, `{"inbounds":[
		{"type":"mixed","tag":"in","sniff":false}
	]}`)
	if warnings != nil {
		t.Fatalf("sniff:false must not warn, got %v", warnings)
	}
	if _, ok := root["route"]; ok {
		t.Fatalf("no sniff rule may be synthesized: %v", root["route"])
	}
	in := root["inbounds"].([]interface{})[0].(map[string]interface{})
	if _, ok := in["sniff"]; ok {
		t.Fatalf("sniff key must be dropped: %v", in)
	}
}

// A document that already carries an action=sniff rule keeps just that one.
func TestMigrateInboundSniffKeepsExistingRule(t *testing.T) {
	root, warnings := migrateDoc(t, `{"inbounds":[{"type":"mixed","tag":"in","sniff":true}],
		"route":{"rules":[{"action":"sniff"},{"action":"reject"}]}}`)
	if got := countSniffActionRules(t, root); got != 1 {
		t.Fatalf("want one sniff rule, got %d", got)
	}
	if len(routeRules(t, root)) != 2 {
		t.Fatalf("existing rules must not be duplicated: %v", routeRules(t, root))
	}
	var sniffWarning bool
	for _, w := range warnings {
		if strings.Contains(w, "sniff") {
			sniffWarning = true
		}
	}
	if !sniffWarning {
		t.Fatalf("the lifted sniff must still be reported, got %v", warnings)
	}
}

// protocol/tun/inbound.go rejects the inet4_/inet6_ address fields outright, so
// a 1.4 tun inbound was dropped by the soft filter on import (losing the whole
// tunnel) and failed the profile on Start.
func TestMigrateTunLegacyAddresses(t *testing.T) {
	root, warnings := migrateDoc(t, `{"inbounds":[{"type":"tun","tag":"tun-in",
		"interface_name":"tun0",
		"inet4_address":"172.19.0.1/30",
		"inet6_address":["fdfe:dcba:9876::1/126"],
		"inet4_route_address":["0.0.0.0/1","128.0.0.0/1"],
		"inet6_route_address":"::/1",
		"inet4_route_exclude_address":["192.168.0.0/16"],
		"gso":true}]}`)
	m := root["inbounds"].([]interface{})[0].(map[string]interface{})
	for _, key := range []string{
		"inet4_address", "inet6_address",
		"inet4_route_address", "inet6_route_address",
		"inet4_route_exclude_address", "inet6_route_exclude_address",
		"gso",
	} {
		if _, ok := m[key]; ok {
			t.Fatalf("%s must be removed: %v", key, m)
		}
	}
	for _, tc := range []struct {
		key  string
		want []string
	}{
		{"address", []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"}},
		{"route_address", []string{"0.0.0.0/1", "128.0.0.0/1", "::/1"}},
		{"route_exclude_address", []string{"192.168.0.0/16"}},
	} {
		if got := jsonStrings(t, m[tc.key]); !equalStrings(got, tc.want) {
			t.Fatalf("%s = %v, want %v", tc.key, got, tc.want)
		}
	}
	if m["interface_name"] != "tun0" {
		t.Fatalf("unrelated tun fields must survive: %v", m)
	}
	var sawGSO bool
	for _, w := range warnings {
		if strings.Contains(w, "gso") {
			sawGSO = true
		}
	}
	if !sawGSO {
		t.Fatalf("dropping gso must be reported, got %v", warnings)
	}

	before, _ := json.Marshal(root)
	if again := MigrateLegacyJSON(root); len(again) != 0 {
		t.Fatalf("second run must be silent, got %v", again)
	}
	after, _ := json.Marshal(root)
	if string(before) != string(after) {
		t.Fatal("tun migration is not idempotent")
	}
}

// Re-running the merge must not duplicate entries when address already exists.
func TestMigrateTunAddressMergeIsIdempotentWithExistingAddress(t *testing.T) {
	root, _ := migrateDoc(t, `{"inbounds":[{"type":"tun","tag":"tun-in",
		"address":["172.19.0.1/30"],
		"inet4_address":["172.19.0.1/30","172.19.0.5/30"],
		"inet6_address":["fdfe::1/126"]}]}`)
	m := root["inbounds"].([]interface{})[0].(map[string]interface{})
	want := []string{"172.19.0.1/30", "172.19.0.5/30", "fdfe::1/126"}
	if got := jsonStrings(t, m["address"]); !equalStrings(got, want) {
		t.Fatalf("address = %v, want %v (existing first, duplicates skipped)", got, want)
	}
	if again := MigrateLegacyJSON(root); len(again) != 0 {
		t.Fatalf("second run must be silent, got %v", again)
	}
	if got := jsonStrings(t, m["address"]); !equalStrings(got, want) {
		t.Fatalf("second run changed address: %v", got)
	}
}
