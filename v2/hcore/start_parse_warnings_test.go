package hcore

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ne-tort/pathology-core/v2/config"
	"github.com/sagernet/sing-box/experimental/libbox"
)

// start_parse_warnings_test.go — the Start path re-parses/re-builds the profile,
// so it raises the same non-fatal warnings as import (soft-parse drops and
// 1.4→1.5 migrations). They used to land on a nil collector and were silently
// discarded; StartService now attaches one via buildStartOptions and returns
// its payload in CoreInfoResponse.parse_warnings.

// legacyHysteria2Profile carries 1.4-era bandwidth keys, which the migrator
// rewrites to congestion_control=brutal + brutal_mbps on every parse.
const legacyHysteria2Profile = `{
  "outbounds": [
    {"type": "hysteria2", "tag": "hy2-legacy", "server": "1.2.3.4", "server_port": 443,
     "up_mbps": 100, "down_mbps": 50,
     "tls": {"enabled": true, "server_name": "example.com"}}
  ]
}`

// TestStartPathCollectsParseWarnings is the regression for the lost-diagnostics
// hole: a profile whose 1.4 keys get migrated at Start must produce a reportable
// payload, not "".
func TestStartPathCollectsParseWarnings(t *testing.T) {
	prev := static.ClientOptions
	static.ClientOptions = config.DefaultClientOptions()
	t.Cleanup(func() { static.ClientOptions = prev })

	// Same context shape StartService uses (BaseContext -> collector -> build).
	ctx := libbox.BaseContext(nil)
	options, warnings, err := buildStartOptions(ctx, &StartRequest{ConfigContent: legacyHysteria2Profile})
	if err != nil {
		t.Fatalf("buildStartOptions: %v", err)
	}
	if options == nil {
		t.Fatal("expected built options")
	}
	if warnings == "" {
		t.Fatal("start-path migration produced no parse_warnings payload (the nil-collector regression)")
	}

	// The payload is the same contract ParseResponse.Message carries, so the
	// Dart renderer can consume both channels unchanged.
	var decoded map[string]config.ParseWarningsSummary
	if err := json.Unmarshal([]byte(warnings), &decoded); err != nil {
		t.Fatalf("payload is not JSON: %v (%s)", err, warnings)
	}
	summary, ok := decoded["parseWarnings"]
	if !ok {
		t.Fatalf("payload missing parseWarnings key: %s", warnings)
	}
	if summary.Migrated == 0 {
		t.Fatalf("expected at least one migration, got %s", warnings)
	}
	joined := strings.Join(summary.MigrateSamples, " | ")
	if !strings.Contains(joined, "brutal_mbps") {
		t.Fatalf("bandwidth migration should be reported, got %v", summary.MigrateSamples)
	}
}

// TestStartPathParseWarningsEmptyForCleanConfig keeps the field empty when
// nothing was dropped or migrated — Dart treats "" as "no warnings", which is
// what an older core (no field at all) also reports.
func TestStartPathParseWarningsEmptyForCleanConfig(t *testing.T) {
	prev := static.ClientOptions
	static.ClientOptions = config.DefaultClientOptions()
	t.Cleanup(func() { static.ClientOptions = prev })

	clean := `{
  "outbounds": [
    {"type": "vless", "tag": "ok", "server": "1.2.3.4", "server_port": 443,
     "uuid": "387c6b84-2e30-4b67-83c9-aa5692550e65"}
  ]
}`
	_, warnings, err := buildStartOptions(libbox.BaseContext(nil), &StartRequest{ConfigContent: clean})
	if err != nil {
		t.Fatalf("buildStartOptions: %v", err)
	}
	if warnings != "" {
		t.Fatalf("clean config must report no warnings, got %s", warnings)
	}
}

// TestStartSetCoreStatusCarriesParseWarnings pins the carrier: the STARTED
// response returns the payload the collector produced, and the planner's
// broadcast copy carries the same value (one constructor builds both).
func TestStartSetCoreStatusCarriesParseWarnings(t *testing.T) {
	resp := SetCoreStatusWithParseWarnings(CoreStates_STARTED, MessageType_EMPTY, "", `{"parseWarnings":{"dropped":1}}`)
	t.Cleanup(func() { SetCoreStatus(CoreStates_STOPPED, MessageType_EMPTY, "") })

	if resp.CoreState != CoreStates_STARTED {
		t.Fatalf("state not carried: %v", resp.CoreState)
	}
	if resp.ParseWarnings == "" {
		t.Fatal("SetCoreStatusWithParseWarnings must fill ParseWarnings")
	}
	if !strings.Contains(resp.ParseWarnings, `"dropped":1`) {
		t.Fatalf("unexpected payload: %s", resp.ParseWarnings)
	}

	// The legacy constructor keeps the field empty (no warnings known).
	plain := SetCoreStatus(CoreStates_STARTED, MessageType_EMPTY, "")
	if plain.ParseWarnings != "" {
		t.Fatalf("SetCoreStatus must leave ParseWarnings empty, got %s", plain.ParseWarnings)
	}
}

// TestBuildConfigWithoutCollectorStaysSilent guards the no-op contract: the same
// build outside Start (CLI, tests, other call sites) must not panic on the
// missing collector.
func TestBuildConfigWithoutCollectorStaysSilent(t *testing.T) {
	prev := static.ClientOptions
	static.ClientOptions = config.DefaultClientOptions()
	t.Cleanup(func() { static.ClientOptions = prev })

	if _, err := BuildConfig(libbox.BaseContext(nil), &StartRequest{ConfigContent: legacyHysteria2Profile}); err != nil {
		t.Fatalf("BuildConfig without a collector must still build: %v", err)
	}
}
