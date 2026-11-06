package config_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ne-tort/pathology-core/v2/config"
	"github.com/sagernet/sing-box/experimental/libbox"
)

func config_test_libboxCtx() context.Context {
	return libbox.BaseContext(nil)
}

func TestSoftParseKeepsDirectOutbound(t *testing.T) {
	raw := `{
  "outbounds": [
    {"type": "direct", "tag": "direct"},
    {"type": "vless", "tag": "plain", "server": "1.2.3.4", "server_port": 443, "uuid": "387c6b84-2e30-4b67-83c9-aa5692550e65"}
  ]
}`
	parsed, err := config.ParseConfigBytes(softParseCtx(), &config.ReadOptions{Content: raw}, true, config.DefaultClientOptions(), false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	s := string(parsed)
	if !strings.Contains(s, `"tag":"direct"`) && !strings.Contains(s, `"tag": "direct"`) {
		t.Fatalf("direct outbound must be kept (no duplicate-tag false negative): %s", s)
	}
	if !strings.Contains(s, "plain") {
		t.Fatalf("plain outbound missing: %s", s)
	}
}

func TestSoftParseAllDroppedReturnsError(t *testing.T) {
	// Reality without public_key is invalid — soft filter drops it. With no other
	// protocol leaves left, filter must error (not return {"outbounds":[]}).
	raw := `{
  "outbounds": [
    {
      "type": "vless",
      "tag": "reality-bad",
      "server": "1.2.3.4",
      "server_port": 443,
      "uuid": "387c6b84-2e30-4b67-83c9-aa5692550e65",
      "tls": {
        "enabled": true,
        "reality": {"enabled": true, "short_id": "fcce710b121881d3"},
        "server_name": "www.example.com",
        "utls": {"enabled": true, "fingerprint": "chrome"}
      }
    }
  ]
}`
	_, err := config.ParseConfigBytes(softParseCtx(), &config.ReadOptions{Content: raw}, true, config.DefaultClientOptions(), false)
	if err == nil {
		t.Fatal("expected error when soft parse drops all protocol leaves")
	}
	if !strings.Contains(err.Error(), "dropped all") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSoftParseAllDroppedAttachesFilteredPayload(t *testing.T) {
	// P9: the all-dropped error must not discard the filtered document — the
	// caller can persist the stub pool instead of falling back to the raw
	// import that the engine would hard-reject.
	raw := `{
  "outbounds": [
    {
      "type": "vless",
      "tag": "reality-bad",
      "server": "1.2.3.4",
      "server_port": 443,
      "uuid": "387c6b84-2e30-4b67-83c9-aa5692550e65",
      "tls": {
        "enabled": true,
        "reality": {"enabled": true, "short_id": "fcce710b121881d3"},
        "server_name": "www.example.com",
        "utls": {"enabled": true, "fingerprint": "chrome"}
      }
    }
  ]
}`
	filtered, err := config.FilterValidLeavesJSONForTest(softParseCtx(), []byte(raw))
	if err == nil {
		t.Fatal("expected error when soft parse drops all protocol leaves")
	}
	if len(filtered) == 0 {
		t.Fatal("expected the filtered document attached to the error, got nil payload")
	}
	var doc map[string]interface{}
	if jErr := json.Unmarshal(filtered, &doc); jErr != nil {
		t.Fatalf("attached payload is not JSON: %v", jErr)
	}
	out, _ := doc["outbounds"].([]interface{})
	if len(out) != 0 {
		t.Fatalf("expected empty outbounds in attached payload, got %v", doc["outbounds"])
	}
}

// A repeated tag used to reach the engine, which rejects the whole profile with
// "duplicate outbound tag". The soft filter must keep the first leaf and report
// the duplicate instead.
func TestSoftParseDropsDuplicateOutboundTag(t *testing.T) {
	ctx, collector := config.WithParseWarnings(config_test_libboxCtx())
	raw := `{"outbounds":[
		{"type":"vless","tag":"dup","server":"1.2.3.4","server_port":443,"uuid":"387c6b84-2e30-4b67-83c9-aa5692550e65"},
		{"type":"vless","tag":"dup","server":"5.6.7.8","server_port":443,"uuid":"387c6b84-2e30-4b67-83c9-aa5692550e65"}
	]}`
	parsed, err := config.ParseConfigBytes(ctx, &config.ReadOptions{Content: raw}, true, config.DefaultClientOptions(), false)
	if err != nil {
		t.Fatalf("duplicate tag must not fail the import: %v", err)
	}
	if n := strings.Count(string(parsed), `"tag":"dup"`) + strings.Count(string(parsed), `"tag": "dup"`); n != 1 {
		t.Fatalf("want exactly one surviving leaf, got %d: %s", n, parsed)
	}
	msg := collector.MessageJSON()
	if !strings.Contains(msg, "duplicate tag") {
		t.Fatalf("drop reason missing from %s", msg)
	}
	if !strings.Contains(string(parsed), "1.2.3.4") {
		t.Fatalf("first occurrence must win: %s", parsed)
	}
}

// failover/scatter are 1.5 group wrappers the client build enables
// (with_failover, with_scatter), so the soft filter must route them through the
// GROUP validator and keep them. It used to validate them as leaves against a
// stub config that has none of their members, so every wrapper was dropped with
// a bogus dependency warning — the 1.5 group-wrapper feature was dead in the
// app.
//
// The fixtures carry what the engine's own Validate() requires (failover: a
// control-protocol psk; scatter: two paths, or an uplink/downlink pair), so a
// surviving wrapper proves the filter, not the fixture.
func TestSoftParseKeepsRegisteredGroupWrappers(t *testing.T) {
	const psk = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	for _, tc := range []struct {
		name  string
		typ   string
		group string
	}{
		{"failover", "failover", `{"type":"failover","tag":"fo","outbounds":["vless-1","vless-2"],"psk":"` + psk + `"}`},
		{"scatter", "scatter", `{"type":"scatter","tag":"sc","paths":["vless-1","vless-2"]}`},
		{"scatter split paths", "scatter", `{"type":"scatter","tag":"sc","uplink_paths":["vless-1"],"downlink_paths":["vless-2"]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, collector := config.WithParseWarnings(config_test_libboxCtx())
			raw := `{"outbounds":[` + tc.group + `,
				{"type":"vless","tag":"vless-1","server":"1.2.3.4","server_port":443,"uuid":"387c6b84-2e30-4b67-83c9-aa5692550e65"},
				{"type":"vless","tag":"vless-2","server":"5.6.7.8","server_port":443,"uuid":"387c6b84-2e30-4b67-83c9-aa5692550e65"}]}`
			parsed, err := config.ParseConfigBytes(ctx, &config.ReadOptions{Content: raw}, true, config.DefaultClientOptions(), false)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			s := string(parsed)
			if !strings.Contains(s, "vless-1") {
				t.Fatalf("leaf lost: %s", s)
			}
			msg := collector.MessageJSON()
			if strings.Contains(s, `"type":"`+tc.typ+`"`) || strings.Contains(s, `"type": "`+tc.typ+`"`) {
				if msg != "" {
					t.Fatalf("surviving %s must not be reported as dropped: %s", tc.typ, msg)
				}
				return
			}
			// Not kept: only acceptable if this test binary was built without
			// the wrapper's include tag (the stub constructor refuses with a
			// "rebuild with -tags ..." message). Any other reason is the
			// regression this test exists for.
			if strings.Contains(msg, "not included in this build") {
				t.Skipf("test binary lacks -tags with_%s; wrapper survived reference validation but cannot be constructed: %s", tc.typ, msg)
			}
			t.Fatalf("%s dropped by the soft filter: %s", tc.typ, msg)
		})
	}
}

// The guard itself must stay covered: a group type that is genuinely not part
// of this build is dropped with a warning instead of reaching the engine.
func TestSoftParseDropsUnknownGroupWrapper(t *testing.T) {
	ctx, collector := config.WithParseWarnings(config_test_libboxCtx())
	raw := `{
	  "outbounds": [
	    {"type":"relay-chain","tag":"rc","outbounds":["vless-1"]},
	    {"type":"vless","tag":"vless-1","server":"1.2.3.4","server_port":443,"uuid":"387c6b84-2e30-4b67-83c9-aa5692550e65"}
	  ]
	}`
	parsed, err := config.ParseConfigBytes(ctx, &config.ReadOptions{Content: raw}, true, config.DefaultClientOptions(), false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	s := string(parsed)
	if !strings.Contains(s, "vless-1") {
		t.Fatalf("leaf lost: %s", s)
	}
	if strings.Contains(s, `"tag":"relay-chain"`) || strings.Contains(s, `"tag": "relay-chain"`) {
		t.Fatalf("unknown group wrapper must be dropped, not emitted: %s", s)
	}
	msg := collector.MessageJSON()
	if !strings.Contains(msg, "relay-chain") {
		t.Fatalf("unknown wrapper drop must be reported: %s", msg)
	}
}

// A wrapper that names a tag this config does not have is still dropped with a
// warning naming the missing tag: otherwise the engine fails the whole profile
// at box.New. Same dangling-reference class as Defect A.
func TestSoftParseDropsWrapperWithMissingMember(t *testing.T) {
	const psk = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	for _, tc := range []struct {
		name  string
		group string
	}{
		{"failover", `{"type":"failover","tag":"fo","outbounds":["vless-1","gone"],"psk":"` + psk + `"}`},
		{"scatter", `{"type":"scatter","tag":"sc","paths":["vless-1","gone"]}`},
		{"scatter uplink", `{"type":"scatter","tag":"sc","paths":["vless-1","vless-2"],"uplink_paths":["gone"],"downlink_paths":["vless-2"]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, collector := config.WithParseWarnings(config_test_libboxCtx())
			raw := `{"outbounds":[` + tc.group + `,
				{"type":"vless","tag":"vless-1","server":"1.2.3.4","server_port":443,"uuid":"387c6b84-2e30-4b67-83c9-aa5692550e65"},
				{"type":"vless","tag":"vless-2","server":"5.6.7.8","server_port":443,"uuid":"387c6b84-2e30-4b67-83c9-aa5692550e65"}]}`
			parsed, err := config.ParseConfigBytes(ctx, &config.ReadOptions{Content: raw}, true, config.DefaultClientOptions(), false)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			s := string(parsed)
			if !strings.Contains(s, "vless-1") {
				t.Fatalf("unrelated leaves must be kept: %s", s)
			}
			if strings.Contains(s, `"tag":"fo"`) || strings.Contains(s, `"tag":"sc"`) {
				t.Fatalf("dangling wrapper must be dropped: %s", s)
			}
			msg := collector.MessageJSON()
			if !strings.Contains(msg, "gone") {
				t.Fatalf("missing-member drop must name the missing tag: %s", msg)
			}
			if strings.Contains(msg, "declares no member outbounds") {
				t.Fatalf("drop reason must be about the missing reference, not an empty member list: %s", msg)
			}
		})
	}
}

// A subscription may carry the "{parent}-auto" tag itself; the builder
// synthesizes that name for the legend parent, so it must be resolved here.
func TestSoftParseDropsAutoGroupTagCollision(t *testing.T) {
	ctx, collector := config.WithParseWarnings(config_test_libboxCtx())
	raw := `{
	  "outbounds": [
	    {"type":"pathology","tag":"cp-pathology-morph","server":"1.2.3.4","server_port":10443,
	     "uuid":"387c6b84-2e30-4b67-83c9-aa5692550e65",
	     "legends":{
	       "stun":{"underlay":{"branch":"udp","udp":{"frame":"stun"}}},
	       "ssh":{"underlay":{"branch":"tcp","tcp":{"banner":"SSH-2.0-x\r\n","padding_len_prefix":true}}}},
	     "auth":{
	       "stun":{"method":"morph","psk":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"},
	       "ssh":{"method":"pad_hmac","psk":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"}}},
	    {"type":"vless","tag":"cp-pathology-morph-auto","server":"1.2.3.4","server_port":443,"uuid":"387c6b84-2e30-4b67-83c9-aa5692550e65"}
	  ]
	}`
	parsed, err := config.ParseConfigBytes(ctx, &config.ReadOptions{Content: raw}, true, config.DefaultClientOptions(), false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if strings.Contains(string(parsed), `"cp-pathology-morph-auto"`) {
		t.Fatalf("colliding leaf must be dropped: %s", parsed)
	}
	if !strings.Contains(collector.MessageJSON(), "cp-pathology-morph-auto") {
		t.Fatalf("collision must be reported: %s", collector.MessageJSON())
	}
	if !strings.Contains(string(parsed), `"cp-pathology-morph"`) {
		t.Fatalf("legend parent lost: %s", parsed)
	}
}

// pathologyLegendJSON renders a legend parent with the given legend ids and the
// subset of them that also carries an auth entry.
func pathologyLegendJSON(tag string, legendIDs, authIDs []string) string {
	legends := make([]string, 0, len(legendIDs))
	for _, id := range legendIDs {
		legends = append(legends, `"`+id+`":{"underlay":{"branch":"udp","udp":{"frame":"stun"}}}`)
	}
	auth := make([]string, 0, len(authIDs))
	for _, id := range authIDs {
		auth = append(auth, `"`+id+`":{"method":"morph","psk":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"}`)
	}
	return `{"type":"pathology","tag":"` + tag + `","server":"1.2.3.4","server_port":10443,` +
		`"uuid":"387c6b84-2e30-4b67-83c9-aa5692550e65",` +
		`"legends":{` + strings.Join(legends, ",") + `}` +
		`,"auth":{` + strings.Join(auth, ",") + `}}`
}

// A legend without an auth entry is accepted by the engine's own validation but
// never expanded, so the rotation group named a virtual that does not exist and
// box.New failed the whole profile with no warning at all. Parse must reject the
// leaf with an actionable reason instead of passing a config that cannot start.
func TestSoftParseDropsPathologyLegendWithoutAuth(t *testing.T) {
	ctx, collector := config.WithParseWarnings(config_test_libboxCtx())
	raw := `{"outbounds":[` +
		pathologyLegendJSON("cp-morph", []string{"dns", "stun"}, []string{"dns"}) + `,
		{"type":"vless","tag":"vless-1","server":"1.2.3.4","server_port":443,"uuid":"387c6b84-2e30-4b67-83c9-aa5692550e65"}]}`
	parsed, err := config.ParseConfigBytes(ctx, &config.ReadOptions{Content: raw}, true, config.DefaultClientOptions(), false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if strings.Contains(string(parsed), "cp-morph") {
		t.Fatalf("legend parent with an unauthorised legend must be dropped: %s", parsed)
	}
	msg := collector.MessageJSON()
	if !strings.Contains(msg, "stun") || !strings.Contains(msg, "no auth entry") {
		t.Fatalf("drop reason must name the unmatched legend: %s", msg)
	}
}

// auth without a legend is the mirror case the engine rejects outright; the
// soft filter must warn instead of letting box.New fail the profile.
func TestSoftParseDropsPathologyAuthWithoutLegend(t *testing.T) {
	ctx, collector := config.WithParseWarnings(config_test_libboxCtx())
	raw := `{"outbounds":[` +
		pathologyLegendJSON("cp-morph", []string{"dns"}, []string{"dns", "ssh"}) + `,
		{"type":"vless","tag":"vless-1","server":"1.2.3.4","server_port":443,"uuid":"387c6b84-2e30-4b67-83c9-aa5692550e65"}]}`
	parsed, err := config.ParseConfigBytes(ctx, &config.ReadOptions{Content: raw}, true, config.DefaultClientOptions(), false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if strings.Contains(string(parsed), "cp-morph") {
		t.Fatalf("legend parent with an orphan auth must be dropped: %s", parsed)
	}
	msg := collector.MessageJSON()
	if !strings.Contains(msg, "ssh") || !strings.Contains(msg, "no legends entry") {
		t.Fatalf("drop reason must name the orphan auth: %s", msg)
	}
}

// A legend named "auto" makes the {parent}-{legend} virtual tag identical to the
// synthesized {parent}-auto rotation group. outbound.Manager replaces duplicate
// tags instead of erroring, so the group used to name itself and self-dial.
func TestSoftParseDropsReservedAutoLegend(t *testing.T) {
	for _, id := range []string{"auto", "AUTO"} {
		t.Run(id, func(t *testing.T) {
			ctx, collector := config.WithParseWarnings(config_test_libboxCtx())
			raw := `{"outbounds":[` +
				pathologyLegendJSON("cp-morph", []string{id, "dns"}, []string{id, "dns"}) + `,
				{"type":"vless","tag":"vless-1","server":"1.2.3.4","server_port":443,"uuid":"387c6b84-2e30-4b67-83c9-aa5692550e65"}]}`
			parsed, err := config.ParseConfigBytes(ctx, &config.ReadOptions{Content: raw}, true, config.DefaultClientOptions(), false)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if strings.Contains(string(parsed), "cp-morph") {
				t.Fatalf("legend id %q must be rejected: %s", id, parsed)
			}
			msg := collector.MessageJSON()
			if !strings.Contains(msg, "reserved for the synthesized rotation group") {
				t.Fatalf("drop reason must explain the reservation: %s", msg)
			}
			if !strings.Contains(msg, "cp-morph-auto") {
				t.Fatalf("drop reason must name the colliding tag: %s", msg)
			}
		})
	}
}

// A fully authorised legend parent must still pass the soft filter unchanged.
func TestSoftParseKeepsAuthorisedPathologyLegendParent(t *testing.T) {
	ctx, collector := config.WithParseWarnings(config_test_libboxCtx())
	raw := `{"outbounds":[` +
		pathologyLegendJSON("cp-morph", []string{"dns", "stun"}, []string{"dns", "stun"}) + `,
		{"type":"vless","tag":"vless-1","server":"1.2.3.4","server_port":443,"uuid":"387c6b84-2e30-4b67-83c9-aa5692550e65"}]}`
	parsed, err := config.ParseConfigBytes(ctx, &config.ReadOptions{Content: raw}, true, config.DefaultClientOptions(), false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !strings.Contains(string(parsed), "cp-morph") {
		t.Fatalf("legend parent lost: %s", parsed)
	}
	if msg := collector.MessageJSON(); msg != "" {
		t.Fatalf("valid legend parent must not warn: %s", msg)
	}
}

// Defect 3: inbounds live in their own tag namespace in the engine
// (option/options.go:151 checkInbounds vs :166 checkOutbounds), so an inbound
// may reuse an outbound's tag. filterInboundLeaves used to run the inbound tag
// through the cross-namespace duplicate index and dropped the listener.
func TestSoftParseKeepsInboundTagSharedWithOutbound(t *testing.T) {
	ctx, collector := config.WithParseWarnings(config_test_libboxCtx())
	raw := `{
	  "inbounds": [
	    {"type":"mixed","tag":"proxy","listen":"127.0.0.1","listen_port":7890}
	  ],
	  "outbounds": [
	    {"type":"vless","tag":"proxy","server":"1.2.3.4","server_port":443,"uuid":"387c6b84-2e30-4b67-83c9-aa5692550e65"}
	  ]
	}`
	parsed, err := config.ParseConfigBytes(ctx, &config.ReadOptions{Content: raw}, true, config.DefaultClientOptions(), true)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var doc map[string]interface{}
	if jErr := json.Unmarshal(parsed, &doc); jErr != nil {
		t.Fatalf("not JSON: %v", jErr)
	}
	inbounds, _ := doc["inbounds"].([]interface{})
	if len(inbounds) != 1 {
		t.Fatalf("inbound sharing an outbound tag must survive, got %v: %s", doc["inbounds"], parsed)
	}
	if msg := collector.MessageJSON(); strings.Contains(msg, "duplicate tag") {
		t.Fatalf("cross-namespace tag must not be reported as a duplicate: %s", msg)
	}
	if !strings.Contains(string(parsed), `"tag":"proxy"`) && !strings.Contains(string(parsed), `"tag": "proxy"`) {
		t.Fatalf("the outbound must survive too: %s", parsed)
	}
}

// The inbound-local check still has to catch the collision the engine does
// enforce ("duplicate inbound tag").
func TestSoftParseDropsDuplicateInboundTag(t *testing.T) {
	ctx, collector := config.WithParseWarnings(config_test_libboxCtx())
	raw := `{
	  "inbounds": [
	    {"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":7890},
	    {"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":7891}
	  ],
	  "outbounds": [
	    {"type":"vless","tag":"plain","server":"1.2.3.4","server_port":443,"uuid":"387c6b84-2e30-4b67-83c9-aa5692550e65"}
	  ]
	}`
	parsed, err := config.ParseConfigBytes(ctx, &config.ReadOptions{Content: raw}, true, config.DefaultClientOptions(), true)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var doc map[string]interface{}
	if jErr := json.Unmarshal(parsed, &doc); jErr != nil {
		t.Fatalf("not JSON: %v", jErr)
	}
	inbounds, _ := doc["inbounds"].([]interface{})
	if len(inbounds) != 1 {
		t.Fatalf("want exactly one surviving inbound, got %d: %s", len(inbounds), parsed)
	}
	if !strings.Contains(collector.MessageJSON(), "duplicate tag") {
		t.Fatalf("duplicate inbound must be reported: %s", collector.MessageJSON())
	}
	if !strings.Contains(string(parsed), "7890") {
		t.Fatalf("first occurrence must win: %s", parsed)
	}
}

// Endpoints share the outbound namespace, not the inbound one: an endpoint tag
// equal to an inbound tag is legal and must not be dropped.
func TestSoftParseKeepsEndpointTagSharedWithInbound(t *testing.T) {
	ctx, collector := config.WithParseWarnings(config_test_libboxCtx())
	raw := `{
	  "inbounds": [
	    {"type":"mixed","tag":"wg","listen":"127.0.0.1","listen_port":7890}
	  ],
	  "endpoints": [{
	    "type":"wireguard","tag":"wg",
	    "private_key":"cIPq1kWIIPewXHtEWmuyQKFTFmQwv8D5iH6g+K7b1Ec=",
	    "address":["10.8.10.2"],
	    "peers":[{"address":"31.58.171.145","port":47684,"public_key":"6KTid8OUZl2hoVmFKp48bAwnr5UImjLMRf6EajCENUI="}]
	  }],
	  "outbounds": [
	    {"type":"vless","tag":"plain","server":"1.2.3.4","server_port":443,"uuid":"387c6b84-2e30-4b67-83c9-aa5692550e65"}
	  ]
	}`
	parsed, err := config.ParseConfigBytes(ctx, &config.ReadOptions{Content: raw}, true, config.DefaultClientOptions(), true)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var doc map[string]interface{}
	if jErr := json.Unmarshal(parsed, &doc); jErr != nil {
		t.Fatalf("not JSON: %v", jErr)
	}
	endpoints, _ := doc["endpoints"].([]interface{})
	if len(endpoints) != 1 {
		t.Fatalf("endpoint sharing an inbound tag must survive, got %v: %s", doc["endpoints"], parsed)
	}
	if msg := collector.MessageJSON(); strings.Contains(msg, "duplicate tag") {
		t.Fatalf("inbound/endpoint tag reuse is legal: %s", msg)
	}
}
