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

// failover/scatter are group wrappers, not dialable leaves: they must never be
// counted as proxy leaves (that count guards the Direct-fallback refusal).
func TestSoftParseGroupsAreNotProtocolLeaves(t *testing.T) {
	ctx := config_test_libboxCtx()
	raw := `{
	  "outbounds": [
	    {"type":"failover","tag":"fo","outbounds":["vless-1"]},
	    {"type":"scatter","tag":"sc","outbounds":["vless-1"]},
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
	if strings.Contains(s, `"tag":"fo"`) || strings.Contains(s, `"tag":"sc"`) {
		t.Fatalf("unregistered group wrappers must be dropped, not emitted: %s", s)
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
