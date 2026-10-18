package config

import (
	"context"
	"encoding/json"
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
	if a["brutal_mbps"] != 200 {
		t.Fatalf("want max(up,down)=200, got %v", a["brutal_mbps"])
	}
	for _, k := range []string{"up_mbps", "down_mbps", "brutal_debug"} {
		if _, ok := a[k]; ok {
			t.Fatalf("key %s not removed", k)
		}
	}
	b := list[1].(map[string]interface{})
	if b["brutal_mbps"] != 100 {
		t.Fatalf("string Mbps parse: want 100, got %v", b["brutal_mbps"])
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
	if hy2["brutal_mbps"] != float64(100) || hy2["congestion_control"] != "brutal" {
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
