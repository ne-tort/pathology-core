package config

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/experimental/libbox"
)

// TestNullBodyRejected is the 1.18 regression: `null` is valid JSON, so the
// decoder happily produced a nil value, every branch of the type switch missed,
// and — before the fix — ReadSingOptions turned it into {} and the import
// "succeeded" with an empty profile. A body that declares no outbound is not a
// config and must be reported as such.
func TestNullBodyRejected(t *testing.T) {
	for _, body := range []string{"null", " null ", "NULL"} {
		ctx := libbox.BaseContext(nil)
		if _, err := ParseConfigBytes(ctx, &ReadOptions{Content: body}, true, DefaultClientOptions(), false); err == nil {
			t.Fatalf("%q must be rejected, got a successful parse", body)
		}
	}
}

// TestScalarAndEmptyArrayBodiesRejected: the same root cause as the null body —
// anything that is not an object, and an array that declares no outbound, is not
// a sing-box config. A two-character body must not produce a working profile.
func TestScalarAndEmptyArrayBodiesRejected(t *testing.T) {
	for _, body := range []string{`""`, `"abc"`, `0`, `true`, `[]`, `[1,2]`, `[null]`, `[{"tag":"a"},"x"]`} {
		ctx := libbox.BaseContext(nil)
		if _, err := ParseConfigBytes(ctx, &ReadOptions{Content: body}, true, DefaultClientOptions(), false); err == nil {
			t.Fatalf("%q must be rejected, got a successful parse", body)
		}
	}
}

// TestObjectBodiesStillAccepted guards the other side of the 1.18 fix: the new
// object check must not turn away legitimate shapes — a bare outbound array, an
// empty object, and a config whose outbounds list is empty but which carries
// other keys.
func TestObjectBodiesStillAccepted(t *testing.T) {
	for _, body := range []string{
		`[{"type":"direct","tag":"direct"}]`,
		`{}`,
		`{"outbounds":[]}`,
		`{"outbounds":[],"log":{"level":"info"}}`,
		`{"log":{"level":"info"},"inbounds":[],"outbounds":[]}`,
	} {
		ctx := libbox.BaseContext(nil)
		if _, err := ParseConfigBytes(ctx, &ReadOptions{Content: body}, true, DefaultClientOptions(), false); err != nil {
			t.Fatalf("%q must stay accepted: %v", body, err)
		}
	}
}

// TestNullBodyDoesNotSilentlyBecomeEmptyProfile pins the actual user-visible
// regression: before the fix a `null` subscription imported as {"outbounds":[]}
// (an empty profile that starts fine and does nothing), instead of failing.
func TestNullBodyDoesNotSilentlyBecomeEmptyProfile(t *testing.T) {
	ctx := libbox.BaseContext(nil)
	parsed, err := ParseConfigBytes(ctx, &ReadOptions{Content: "null"}, true, DefaultClientOptions(), false)
	if err == nil {
		t.Fatalf("null body imported as %s", parsed)
	}
	if parsed != nil {
		t.Fatalf("a rejected body must not carry output: %s", parsed)
	}
}

// TestEmptyOutboundsConfigStillValid: a config that really does have an empty
// outbounds list is still a CONFIG — the 1.18 fix must not fall through to
// "unable to determine config format".
//
// Note the assertion is on acceptance, not on the emitted body: ParseConfigBytes
// deliberately normalises a profile with no outbounds AND no endpoints to the
// stable `{"outbounds":[]}` placeholder (parser.go, the WARP-only/placeholder
// path), so other blocks do not survive that shape by design. Pinning `dns` here
// would have been pinning that pre-existing normalisation, not the 1.18 fix.
func TestEmptyOutboundsConfigStillValid(t *testing.T) {
	ctx := libbox.BaseContext(nil)
	for _, body := range []string{
		`{"outbounds":[]}`,
		`{"outbounds":[],"log":{"level":"info"}}`,
		`{}`,
	} {
		parsed, err := ParseConfigBytes(ctx, &ReadOptions{Content: body}, true, DefaultClientOptions(), false)
		if err != nil {
			t.Fatalf("an empty-but-real config must stay acceptable (%s): %v", body, err)
		}
		var root map[string]interface{}
		if err := json.Unmarshal(parsed, &root); err != nil {
			t.Fatalf("output is not JSON for %s: %v (%s)", body, err, parsed)
		}
		if _, ok := root["outbounds"]; !ok {
			t.Fatalf("the empty shape must still declare outbounds for %s: %s", body, parsed)
		}
	}
}

// The other half of the same contract: a live config keeps its other blocks. The
// 1.18 guard must not be so strict that it starts eating real profiles.
func TestRealConfigKeepsNonOutboundBlocks(t *testing.T) {
	ctx := libbox.BaseContext(nil)
	body := `{"outbounds":[{"type":"direct","tag":"direct"}],` +
		`"dns":{"servers":[{"type":"udp","tag":"u","server":"1.1.1.1"}]},"log":{"level":"info"}}`
	parsed, err := ParseConfigBytes(ctx, &ReadOptions{Content: body}, true, DefaultClientOptions(), false)
	if err != nil {
		t.Fatalf("ParseConfigBytes: %v", err)
	}
	var root map[string]interface{}
	if err := json.Unmarshal(parsed, &root); err != nil {
		t.Fatalf("output is not JSON: %v (%s)", err, parsed)
	}
	if _, ok := root["dns"]; !ok {
		t.Fatalf("the dns block was lost from a real config: %s", parsed)
	}
}

// TestObjectWrapperNotMutatedByArrayShorthand: the array shorthand is only for a
// top-level array; an object must never be treated as one.
func TestObjectWrapperNotMutatedByArrayShorthand(t *testing.T) {
	if _, ok := jsonArrayOfObjects([]interface{}{map[string]interface{}{"a": 1}}); !ok {
		t.Fatal("an array of objects is the shorthand")
	}
	for _, value := range []interface{}{
		nil,
		[]interface{}{},
		[]interface{}{1},
		[]interface{}{map[string]interface{}{"a": 1}, "x"},
		map[string]interface{}{"a": 1},
		"string",
		1.0,
		true,
	} {
		if _, ok := jsonArrayOfObjects(value); ok {
			t.Fatalf("%T %v must not be accepted as the array shorthand", value, value)
		}
	}
}

// TestMigrateRawJSONForV2Ray covers the raw-JSON pre-migration step of the
// v2ray branch (finding 1.9). ray2sing itself does not decode raw sing-box JSON,
// so the step is reached only through this helper; the point is that a 1.4 body
// comes out migrated, and that a non-JSON body (share link, base64) is returned
// untouched so ray2sing still sees exactly what the subscription contained.
func TestMigrateRawJSONForV2Ray(t *testing.T) {
	ctx, collector := WithParseWarnings(libbox.BaseContext(nil))
	legacy := []byte(`{"outbounds":[{"type":"hysteria","tag":"hy","server":"1.2.3.4","server_port":443,"up_mbps":50,"down_mbps":500,"chrome_parrot":true}]}`)
	migrated, changed := migrateRawJSONForV2Ray(ctx, legacy)
	if !changed {
		t.Fatal("a 1.4 body must be migrated")
	}
	text := string(migrated)
	for _, gone := range []string{"up_mbps", "down_mbps", "chrome_parrot"} {
		if strings.Contains(text, gone) {
			t.Fatalf("%s survived the pre-migration: %s", gone, text)
		}
	}
	if !strings.Contains(text, "brutal_mbps") || !strings.Contains(text, `"fingerprint":"chrome"`) {
		t.Fatalf("migrated body is missing the 1.5 form: %s", text)
	}
	var root map[string]interface{}
	if err := json.Unmarshal(migrated, &root); err != nil {
		t.Fatalf("migrated body is not JSON: %v", err)
	}
	summary := collectorSummary(t, collector)
	if summary.Migrated == 0 || len(summary.MigrateSamples) == 0 {
		t.Fatalf("the pre-migration must be reported: %+v", summary)
	}
}

func TestMigrateRawJSONForV2RayLeavesNonJSONAlone(t *testing.T) {
	for _, body := range []string{
		`vless://387c6b84-2e30-4b67-83c9-aa5692550e65@1.2.3.4:443?type=tcp#node`,
		`hysteria2://pass@1.2.3.4:443#node`,
		`dm1lc3M6Ly9leGFtcGxl`,
		`[{"type":"direct","tag":"a"}]`,
		`null`,
		``,
		`not json at all`,
	} {
		ctx := libbox.BaseContext(nil)
		out, changed := migrateRawJSONForV2Ray(ctx, []byte(body))
		if changed {
			t.Fatalf("%q must not be migrated", body)
		}
		if string(out) != body {
			t.Fatalf("%q was rewritten to %q", body, out)
		}
	}
}

// TestMigrateRawJSONForV2RayModernBodyUntouched: a 1.5 body must come back
// byte-identical, so the pre-migration never disturbs a healthy document.
func TestMigrateRawJSONForV2RayModernBodyUntouched(t *testing.T) {
	body := `{"outbounds":[{"type":"direct","tag":"direct"}]}`
	ctx := libbox.BaseContext(nil)
	out, changed := migrateRawJSONForV2Ray(ctx, []byte(body))
	if changed || string(out) != body {
		t.Fatalf("modern body rewritten: changed=%v out=%q", changed, out)
	}
}

// TestV2RayHysteriaLinkMigratesBandwidth is the finding-1.9 end state worth
// keeping: whatever ray2sing emits, the 1.4-era key has to be gone before the
// engine sees it. This exercises the post-decode migration that does the real
// work on the v2ray path.
func TestV2RayHysteriaLinkMigratesBandwidth(t *testing.T) {
	ctx := libbox.BaseContext(nil)
	link := `hysteria://203.0.113.9:443?auth=test&peer=example.com&upmbps=120&downmbps=500&insecure=1#hy`
	parsed, err := ParseConfigBytes(ctx, &ReadOptions{Content: link}, true, DefaultClientOptions(), false)
	if err != nil {
		t.Fatalf("hysteria link must import: %v", err)
	}
	text := string(parsed)
	for _, gone := range []string{"up_mbps", "down_mbps"} {
		if strings.Contains(text, gone) {
			t.Fatalf("%s reached the engine: %s", gone, text)
		}
	}
	if !strings.Contains(text, "brutal_mbps") {
		t.Fatalf("bandwidth not migrated: %s", text)
	}
}

// TestMigrateParrotKeysNonObjectUTLS is the 1.17 regression: a `utls` value that
// is not a JSON object used to be replaced wholesale, silently discarding what
// the user wrote. It must be left alone, and the drop must be explained.
func TestMigrateParrotKeysNonObjectUTLS(t *testing.T) {
	for _, testCase := range []struct {
		name string
		utls string
		want string
	}{
		{"string", `"chrome"`, "a string"},
		{"bool", `true`, "a boolean"},
		{"null", `null`, "null"},
		{"array", `[{"fingerprint":"chrome"}]`, "an array"},
		{"number", `7`, "a number"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			root, warnings := migrateDoc(t, `{"outbounds":[{"type":"tuic","tag":"t","chrome_parrot":true,"utls":`+testCase.utls+`}]}`)
			outbounds, _ := root["outbounds"].([]interface{})
			if len(outbounds) != 1 {
				t.Fatalf("outbound dropped: %v", root)
			}
			outbound, _ := outbounds[0].(map[string]interface{})
			if _, ok := outbound["chrome_parrot"]; ok {
				t.Fatalf("the 1.4 key must be removed: %v", outbound)
			}
			var wantValue interface{}
			if err := json.Unmarshal([]byte(testCase.utls), &wantValue); err != nil {
				t.Fatal(err)
			}
			got, _ := json.Marshal(outbound["utls"])
			want, _ := json.Marshal(wantValue)
			if string(got) != string(want) {
				t.Fatalf("utls was overwritten: want %s, got %s", want, got)
			}
			joined := strings.Join(warnings, "\n")
			if !strings.Contains(joined, "not an object") || !strings.Contains(joined, testCase.want) {
				t.Fatalf("the drop must explain why: %v", warnings)
			}
		})
	}
}

// TestMigrateParrotKeysIntoExistingUTLS: the normal path still folds the key into
// an existing utls object.
func TestMigrateParrotKeysIntoExistingUTLS(t *testing.T) {
	root, warnings := migrateDoc(t, `{"outbounds":[{"type":"tuic","tag":"t","chrome_parrot":true,"utls":{"enabled":true,"fingerprint":"none"}}]}`)
	outbound, _ := root["outbounds"].([]interface{})[0].(map[string]interface{})
	utls, _ := outbound["utls"].(map[string]interface{})
	if utls["fingerprint"] != "chrome" {
		t.Fatalf("a `none` fingerprint must be replaced by the persona: %v", utls)
	}
	if !strings.Contains(strings.Join(warnings, "\n"), "fingerprint=chrome") {
		t.Fatalf("the migration must be reported: %v", warnings)
	}
}
