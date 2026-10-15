package config

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/experimental/libbox"
	_ "github.com/sagernet/sing-box/include"
)

// TestParseWarningsCollectedOnDrop feeds the soft filter a config with one
// unknown outbound type and one invalid leaf and asserts the collector sees
// both drops with kind/type/tag/reason.
func TestParseWarningsCollectedOnDrop(t *testing.T) {
	raw := `{
  "outbounds": [
    {"type": "vless", "tag": "ok", "server": "1.2.3.4", "server_port": 443, "uuid": "387c6b84-2e30-4b67-83c9-aa5692550e65"},
    {"type": "not-a-real-protocol", "tag": "bad-type", "server": "1.2.3.4"},
    {"type": "vless", "tag": "bad-leaf", "server": "1.2.3.4", "server_port": 443,
     "uuid": "387c6b84-2e30-4b67-83c9-aa5692550e65",
     "tls": {"enabled": true, "reality": {"enabled": true, "short_id": "fcce710b121881d3"},
             "server_name": "www.example.com", "utls": {"enabled": true, "fingerprint": "chrome"}}}
  ]
}`
	ctx, wc := WithParseWarnings(libbox.BaseContext(nil))
	filtered, err := filterValidLeavesJSON(ctx, []byte(raw), false)
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	var root map[string]interface{}
	if err := json.Unmarshal(filtered, &root); err != nil {
		t.Fatalf("unmarshal filtered: %v", err)
	}
	outbounds, _ := root["outbounds"].([]interface{})
	if len(outbounds) != 1 {
		t.Fatalf("expected 1 surviving outbound, got %d", len(outbounds))
	}

	msg := wc.MessageJSON()
	if msg == "" {
		t.Fatal("expected warnings payload, got empty message")
	}
	var decoded map[string]ParseWarningsSummary
	if err := json.Unmarshal([]byte(msg), &decoded); err != nil {
		t.Fatalf("payload is not JSON: %v (%s)", err, msg)
	}
	summary, ok := decoded["parseWarnings"]
	if !ok {
		t.Fatalf("payload missing parseWarnings key: %s", msg)
	}
	if summary.Dropped != 2 {
		t.Fatalf("expected 2 drops, got %d (%s)", summary.Dropped, msg)
	}
	if summary.TopDrop == "" {
		t.Fatal("expected topDrop reason")
	}
	if !strings.Contains(summary.TopDrop, `unknown type "not-a-real-protocol"`) {
		t.Fatalf("topDrop should headline the first drop, got %q", summary.TopDrop)
	}
	if len(summary.DropSamples) != 2 {
		t.Fatalf("expected 2 drop samples, got %v", summary.DropSamples)
	}
	found := map[string]bool{}
	for _, s := range summary.DropSamples {
		if strings.Contains(s, `"bad-type"`) {
			found["bad-type"] = true
		}
		if strings.Contains(s, `"bad-leaf"`) {
			found["bad-leaf"] = true
		}
	}
	if !found["bad-type"] || !found["bad-leaf"] {
		t.Fatalf("drop samples must name both dropped tags, got %v", summary.DropSamples)
	}
}

// TestParseWarningsCollectedOnMigrate asserts legacy-key rewrites are counted
// as migrations and reported in the payload.
func TestParseWarningsCollectedOnMigrate(t *testing.T) {
	raw := `{
  "outbounds": [
    {"type": "hysteria2", "tag": "hy2", "server": "1.2.3.4", "server_port": 443,
     "up_mbps": 100, "down_mbps": 50,
     "tls": {"enabled": true, "server_name": "example.com"}}
  ]
}`
	ctx, wc := WithParseWarnings(libbox.BaseContext(nil))
	if _, err := filterValidLeavesJSON(ctx, []byte(raw), false); err != nil {
		t.Fatalf("filter: %v", err)
	}
	msg := wc.MessageJSON()
	if msg == "" {
		t.Fatal("expected migration payload, got empty message")
	}
	var decoded map[string]ParseWarningsSummary
	if err := json.Unmarshal([]byte(msg), &decoded); err != nil {
		t.Fatalf("payload is not JSON: %v", err)
	}
	summary := decoded["parseWarnings"]
	if summary.Migrated == 0 {
		t.Fatalf("expected migrations, got %s", msg)
	}
	if summary.Dropped != 0 {
		t.Fatalf("no drops expected, got %s", msg)
	}
	joined := strings.Join(summary.MigrateSamples, " | ")
	if !strings.Contains(joined, "brutal_mbps") {
		t.Fatalf("bandwidth migration should be reported, got %v", summary.MigrateSamples)
	}
}

// TestParseWarningsEmptyWhenClean keeps the OK message empty for a fully valid
// config — Dart treats empty Message as "no warnings".
func TestParseWarningsEmptyWhenClean(t *testing.T) {
	raw := `{
  "outbounds": [
    {"type": "vless", "tag": "ok", "server": "1.2.3.4", "server_port": 443, "uuid": "387c6b84-2e30-4b67-83c9-aa5692550e65"}
  ]
}`
	ctx, wc := WithParseWarnings(libbox.BaseContext(nil))
	if _, err := filterValidLeavesJSON(ctx, []byte(raw), false); err != nil {
		t.Fatalf("filter: %v", err)
	}
	if msg := wc.MessageJSON(); msg != "" {
		t.Fatalf("expected empty message for clean config, got %s", msg)
	}
}

// TestParseWarningsSampleCap bounds sample lists while keeping full counts.
func TestParseWarningsSampleCap(t *testing.T) {
	_, wc := WithParseWarnings(libbox.BaseContext(nil))
	for i := 0; i < 7; i++ {
		wc.addDrop("outbound", "bogus", "tag", "reason")
	}
	msg := wc.MessageJSON()
	var decoded map[string]ParseWarningsSummary
	if err := json.Unmarshal([]byte(msg), &decoded); err != nil {
		t.Fatal(err)
	}
	summary := decoded["parseWarnings"]
	if summary.Dropped != 7 {
		t.Fatalf("dropped count must be full, got %d", summary.Dropped)
	}
	if len(summary.DropSamples) != 3 {
		t.Fatalf("drop samples must cap at 3, got %d", len(summary.DropSamples))
	}
}

// TestParseWarningsThroughParseConfigBytes exercises the full Parse path the
// gRPC handler uses: collector attached to ctx survives ParseConfigBytes.
func TestParseWarningsThroughParseConfigBytes(t *testing.T) {
	raw := `{
  "outbounds": [
    {"type": "vless", "tag": "ok", "server": "1.2.3.4", "server_port": 443, "uuid": "387c6b84-2e30-4b67-83c9-aa5692550e65"},
    {"type": "not-a-real-protocol", "tag": "gone", "server": "1.2.3.4"}
  ]
}`
	ctx, wc := WithParseWarnings(libbox.BaseContext(nil))
	parsed, err := ParseConfigBytes(ctx, &ReadOptions{Content: raw}, true, DefaultClientOptions(), false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if strings.Contains(string(parsed), "gone") {
		t.Fatalf("unknown leaf must be dropped: %s", parsed)
	}
	msg := wc.MessageJSON()
	if !strings.Contains(msg, `"dropped":1`) {
		t.Fatalf("expected dropped:1 in payload, got %s", msg)
	}
}

// TestParseWarningsRecordedWhenAllLeavesDropped: even when the soft parse
// errors out (everything dropped), the collector keeps the drop list so the
// caller can still explain why.
func TestParseWarningsRecordedWhenAllLeavesDropped(t *testing.T) {
	raw := `{"outbounds": [{"type": "not-a-real-protocol", "tag": "gone", "server": "1.2.3.4"}]}`
	ctx, wc := WithParseWarnings(libbox.BaseContext(nil))
	_, err := filterValidLeavesJSON(ctx, []byte(raw), false)
	if err == nil {
		t.Fatal("expected all-dropped error")
	}
	var decoded map[string]ParseWarningsSummary
	if jerr := json.Unmarshal([]byte(wc.MessageJSON()), &decoded); jerr != nil {
		t.Fatal(jerr)
	}
	if decoded["parseWarnings"].Dropped != 1 {
		t.Fatalf("expected 1 recorded drop, got %+v", decoded["parseWarnings"])
	}
}

// TestSanitizeParseWarningReason flattens multiline engine errors.
func TestSanitizeParseWarningReason(t *testing.T) {
	got := sanitizeParseWarningReason("first line\nsecond line\n")
	if got != "first line" {
		t.Fatalf("multiline reason not flattened: %q", got)
	}
	long := strings.Repeat("x", 500)
	if got := sanitizeParseWarningReason(long); len([]rune(got)) > 200 {
		t.Fatalf("long reason not capped: %d runes", len([]rune(got)))
	}
}
