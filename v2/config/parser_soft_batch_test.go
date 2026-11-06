package config

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
)

// parser_soft_batch_test.go -- proves the batched leaf validation (one engine
// instance per import instead of one box.New per leaf) is a pure speed change.
//
// The three properties pinned here:
//  1. a leaf the batch accepts is exactly a leaf the old per-leaf check accepted,
//     for every type in the outbound registry and for the invalid fixtures below;
//  2. a failing batch still attributes the failure to the individual leaf, with
//     the same error text (the drop reason the UI shows);
//  3. an import builds one engine instance, not one per node.
//
// Property 2 is what makes the bisect safe: a range of one reproduces the exact
// document the old checkOutboundLeaf built.

const batchTestUUID = "387c6b84-2e30-4b67-83c9-aa5692550e65"

// legacyCheckOutboundLeaf is the pre-batch per-leaf validation, kept verbatim as
// the oracle the batch is compared against.
func legacyCheckOutboundLeaf(leaf map[string]interface{}) (bool, error) {
	stub := map[string]interface{}{"type": "direct", "tag": stubTag}
	routeFinal := stubTag
	if leafTag(leaf) == stubTag {
		stub = map[string]interface{}{"type": "direct", "tag": stubTagAlt}
		routeFinal = stubTagAlt
	}
	cfg := map[string]interface{}{
		"outbounds": []interface{}{leaf, stub},
		"route":     map[string]interface{}{"final": routeFinal},
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return false, err
	}
	if err := libbox.CheckConfig(string(raw)); err != nil {
		return false, err
	}
	return true, nil
}

// softParseCheckCalls counts engine instances built through the production seam.
var softParseCheckCalls int

// swapSoftParseCheckJSON routes the production seam through a counter for the
// duration of one test.
func swapSoftParseCheckJSON(t *testing.T) func() {
	t.Helper()
	original := softParseCheckJSON
	softParseCheckCalls = 0
	softParseCheckJSON = func(raw []byte) error {
		softParseCheckCalls++
		return original(raw)
	}
	return func() { softParseCheckJSON = original }
}

func softParseCheckCount() int { return softParseCheckCalls }

func decodeLeaf(t *testing.T, content string) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(content), &m); err != nil {
		t.Fatalf("fixture is not JSON: %v (%s)", err, content)
	}
	return m
}

// batchLeafFixtures returns one fixture per registered outbound type, so the
// table cannot silently stop covering a protocol added to the registry later.
// A type with no hand-written fixture gets the generic one: the point is that
// both paths agree on it, not that the fixture is valid.
func batchLeafFixtures() map[string]string {
	fixtures := map[string]string{
		"direct":      `{"type":"direct","tag":"n1"}`,
		"block":       `{"type":"block","tag":"n1"}`,
		"vless":       `{"type":"vless","tag":"n1","server":"1.2.3.4","server_port":443,"uuid":"` + batchTestUUID + `"}`,
		"vmess":       `{"type":"vmess","tag":"n1","server":"1.2.3.4","server_port":443,"uuid":"` + batchTestUUID + `"}`,
		"trojan":      `{"type":"trojan","tag":"n1","server":"1.2.3.4","server_port":443,"password":"pw"}`,
		"shadowsocks": `{"type":"shadowsocks","tag":"n1","server":"1.2.3.4","server_port":8388,"method":"aes-128-gcm","password":"pw"}`,
		"socks":       `{"type":"socks","tag":"n1","server":"1.2.3.4","server_port":1080}`,
		"http":        `{"type":"http","tag":"n1","server":"1.2.3.4","server_port":8080}`,
		"anytls":      `{"type":"anytls","tag":"n1","server":"1.2.3.4","server_port":443,"password":"pw"}`,
		"snell":       `{"type":"snell","tag":"n1","server":"1.2.3.4","server_port":443,"psk":"pw","version":4}`,
		"ssh":         `{"type":"ssh","tag":"n1","server":"1.2.3.4","server_port":22,"user":"u","password":"pw"}`,
		"tor":         `{"type":"tor","tag":"n1","server":"1.2.3.4","server_port":9050}`,
		"hysteria":    `{"type":"hysteria","tag":"n1","server":"1.2.3.4","server_port":443,"auth_str":"pw","up_mbps":10,"down_mbps":10}`,
		"hysteria2":   `{"type":"hysteria2","tag":"n1","server":"1.2.3.4","server_port":443,"password":"pw"}`,
		"tuic":        `{"type":"tuic","tag":"n1","server":"1.2.3.4","server_port":443,"uuid":"` + batchTestUUID + `","password":"pw"}`,
		"selector":    `{"type":"selector","tag":"n1","outbounds":["direct"]}`,
		"urltest":     `{"type":"urltest","tag":"n1","outbounds":["direct"]}`,
	}
	generic := `{"type":"%s","tag":"n1","server":"1.2.3.4","server_port":443,"uuid":"` + batchTestUUID + `"}`
	for _, typ := range include.OutboundRegistry().OptionTypes() {
		if _, ok := fixtures[typ]; ok {
			continue
		}
		fixtures[typ] = fmt.Sprintf(generic, typ)
	}
	return fixtures
}

// TestBatchLeafCheckMatchesPerLeafCheck is requirement (i): the accepted set is
// unchanged, for every outbound type the registry exposes.
func TestBatchLeafCheckMatchesPerLeafCheck(t *testing.T) {
	ctx := context.Background()
	fixtures := batchLeafFixtures()
	if len(fixtures) < 20 {
		t.Fatalf("expected the whole registry, got %d fixtures", len(fixtures))
	}
	names := make([]string, 0, len(fixtures))
	for name := range fixtures {
		names = append(names, name)
	}
	// Deterministic order so a failure names a stable case.
	sort.Strings(names)
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			leaf := decodeLeaf(t, fixtures[name])
			wantOK, wantErr := legacyCheckOutboundLeaf(leaf)
			got := checkOutboundLeaves(ctx, []map[string]interface{}{leaf})
			if len(got) != 1 {
				t.Fatalf("expected one verdict, got %d", len(got))
			}
			if got[0].ok != wantOK {
				t.Fatalf("verdict changed: batch=%v per-leaf=%v (%v / %v)", got[0].ok, wantOK, got[0].reason, wantErr)
			}
			if !wantOK {
				assertSameReason(t, got[0].reason, wantErr)
			}
		})
	}
}

// TestBatchLeafCheckInvalidFixturesKeepsReason is requirement (ii) for the
// invalid leaves a real subscription carries, including the ones where the
// options-only fast path would have said "ok" while box.New says "invalid"
// (reality without public_key, out-of-enum packet_encoding, TLS fragment XOR,
// unknown transport). Those are exactly why the batch builds a real instance.
func TestBatchLeafCheckInvalidFixturesKeepsReason(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		leaf    string
		wantSub string
	}{
		{
			name: "reality without public_key",
			leaf: `{"type":"vless","tag":"n1","server":"1.2.3.4","server_port":443,"uuid":"` + batchTestUUID + `",` +
				`"tls":{"enabled":true,"reality":{"enabled":true,"short_id":"ab"},"server_name":"x",` +
				`"utls":{"enabled":true,"fingerprint":"chrome"}}}`,
			wantSub: "reality",
		},
		{
			name: "out-of-enum packet_encoding",
			leaf: `{"type":"vless","tag":"n1","server":"1.2.3.4","server_port":443,"uuid":"` + batchTestUUID + `",` +
				`"packet_encoding":"bogus"}`,
			wantSub: "unknown packet encoding: bogus",
		},
		{
			name: "tls fragment xor record_fragment",
			leaf: `{"type":"vless","tag":"n1","server":"1.2.3.4","server_port":443,"uuid":"` + batchTestUUID + `",` +
				`"tls":{"enabled":true,"fragment":true,"record_fragment":true,"insecure":true}}`,
			wantSub: "fragment and record_fragment are mutually exclusive",
		},
		{
			name: "unknown transport",
			leaf: `{"type":"vless","tag":"n1","server":"1.2.3.4","server_port":443,"uuid":"` + batchTestUUID + `",` +
				`"transport":{"type":"nope"}}`,
			wantSub: "unknown transport type: nope",
		},
		{
			name: "unknown field",
			leaf: `{"type":"vless","tag":"n1","server":"1.2.3.4","server_port":443,"uuid":"` + batchTestUUID + `",` +
				`"no_such_field":1}`,
			wantSub: `unknown field "no_such_field"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leaf := decodeLeaf(t, tc.leaf)
			wantOK, wantErr := legacyCheckOutboundLeaf(leaf)
			if wantOK {
				t.Fatalf("fixture is supposed to be invalid, per-leaf check accepted it")
			}
			got := checkOutboundLeaves(ctx, []map[string]interface{}{leaf})[0]
			if got.ok {
				t.Fatalf("batch accepted a leaf the per-leaf check rejected")
			}
			assertSameReason(t, got.reason, wantErr)
			if !strings.Contains(got.reason.Error(), tc.wantSub) {
				t.Fatalf("drop reason lost %q: %v", tc.wantSub, got.reason)
			}
		})
	}
}

// TestBatchLeafCheckBisectMatchesIsolatedVerdicts proves the bisect attributes
// failures correctly when good and bad leaves share one instance. One leaf is
// tagged "direct" so the shared-instance stub renaming is exercised too.
func TestBatchLeafCheckBisectMatchesIsolatedVerdicts(t *testing.T) {
	ctx := context.Background()
	contents := []string{
		`{"type":"vless","tag":"ok-1","server":"1.2.3.4","server_port":443,"uuid":"` + batchTestUUID + `"}`,
		`{"type":"vless","tag":"bad-1","server":"1.2.3.4","server_port":443,"uuid":"` + batchTestUUID + `","packet_encoding":"bogus"}`,
		`{"type":"vless","tag":"direct","server":"1.2.3.4","server_port":443,"uuid":"` + batchTestUUID + `"}`,
		`{"type":"vless","tag":"ok-2","server":"5.6.7.8","server_port":443,"uuid":"` + batchTestUUID + `"}`,
		`{"type":"vless","tag":"bad-2","server":"1.2.3.4","server_port":443,"uuid":"` + batchTestUUID + `","transport":{"type":"nope"}}`,
		`{"type":"vless","tag":"ok-3","server":"9.9.9.9","server_port":443,"uuid":"` + batchTestUUID + `"}`,
		`{"type":"vless","tag":"bad-3","server":"1.2.3.4","server_port":443,"uuid":"` + batchTestUUID + `","tls":{"enabled":true,"fragment":true,"record_fragment":true,"insecure":true}}`,
		`{"type":"vless","tag":"ok-4","server":"8.8.8.8","server_port":443,"uuid":"` + batchTestUUID + `"}`,
	}
	leaves := make([]map[string]interface{}, 0, len(contents))
	for _, content := range contents {
		leaves = append(leaves, decodeLeaf(t, content))
	}

	verdicts := checkOutboundLeaves(ctx, leaves)
	if len(verdicts) != len(leaves) {
		t.Fatalf("expected %d verdicts, got %d", len(leaves), len(verdicts))
	}
	for i, leaf := range leaves {
		wantOK, wantErr := legacyCheckOutboundLeaf(leaf)
		if verdicts[i].ok != wantOK {
			t.Fatalf("leaf %d (%s): batch=%v isolated=%v (%v / %v)",
				i, leafTag(leaf), verdicts[i].ok, wantOK, verdicts[i].reason, wantErr)
		}
		if !wantOK {
			assertSameReason(t, verdicts[i].reason, wantErr)
		}
	}
}

// TestBatchLeafCheckAllInvalidKeepsReason covers the one shape where bisecting
// costs more than checking each leaf: every candidate is broken. The verdicts
// must still be per-leaf correct.
func TestBatchLeafCheckAllInvalidKeepsReason(t *testing.T) {
	ctx := context.Background()
	const n = 8
	leaves := make([]map[string]interface{}, 0, n)
	for i := 0; i < n; i++ {
		leaves = append(leaves, decodeLeaf(t, fmt.Sprintf(
			`{"type":"vless","tag":"bad-%d","server":"1.2.3.4","server_port":443,"uuid":"%s","packet_encoding":"bogus"}`,
			i, batchTestUUID)))
	}
	verdicts := checkOutboundLeaves(ctx, leaves)
	for i := range leaves {
		if verdicts[i].ok {
			t.Fatalf("leaf %d must be rejected", i)
		}
		if !strings.Contains(verdicts[i].reason.Error(), "unknown packet encoding") {
			t.Fatalf("leaf %d reason lost its detail: %v", i, verdicts[i].reason)
		}
	}
}

// TestSoftParseBuildsOneEngineInstancePerLeafSet is the regression guard for the
// defect itself: a subscription of n valid leaves must not build n instances.
func TestSoftParseBuildsOneEngineInstancePerLeafSet(t *testing.T) {
	defer swapSoftParseCheckJSON(t)()

	parts := make([]string, 0, 60)
	for i := 0; i < 60; i++ {
		parts = append(parts, fmt.Sprintf(
			`{"type":"vless","tag":"n%03d","server":"10.0.0.%d","server_port":443,"uuid":"%s"}`,
			i, i%250+1, batchTestUUID))
	}
	doc := `{"outbounds":[` + strings.Join(parts, ",") + `]}`
	if _, err := FilterValidLeavesJSONForTest(context.Background(), []byte(doc)); err != nil {
		t.Fatalf("filter: %v", err)
	}
	if got := softParseCheckCount(); got != 1 {
		t.Fatalf("60 valid leaves must cost 1 engine instance, got %d", got)
	}
}

// TestSoftParseGroupCheckCountStaysLinear pins finding 1.14: accepting a group
// must not rebuild the tag set, and the engine work stays proportional to the
// number of groups, not to groups x nodes.
func TestSoftParseGroupCheckCountStaysLinear(t *testing.T) {
	defer swapSoftParseCheckJSON(t)()

	const nodes = 40
	parts := make([]string, 0, nodes+6)
	for i := 0; i < nodes; i++ {
		parts = append(parts, fmt.Sprintf(
			`{"type":"vless","tag":"n%03d","server":"10.0.0.%d","server_port":443,"uuid":"%s"}`,
			i, i%250+1, batchTestUUID))
	}
	// Six groups, each naming nodes that exist: all must be accepted.
	for i := 0; i < 6; i++ {
		parts = append(parts, fmt.Sprintf(
			`{"type":"selector","tag":"g%d","outbounds":["n%03d","n%03d"]}`, i, i, i+1))
	}
	doc := `{"outbounds":[` + strings.Join(parts, ",") + `]}`
	ctx, collector := WithParseWarnings(libbox.BaseContext(nil))
	if _, err := FilterValidLeavesJSONForTest(ctx, []byte(doc)); err != nil {
		t.Fatalf("filter: %v", err)
	}
	if msg := collector.MessageJSON(); msg != "" {
		t.Fatalf("valid groups must not be dropped: %s", msg)
	}
	// 1 batched leaf check + 1 per accepted group.
	if got, want := softParseCheckCount(), 1+6; got != want {
		t.Fatalf("engine instances: got %d, want %d", got, want)
	}
}

// Requirement (iii): a group that names a tag the document does not declare is
// still dropped, and the warning still names the missing tag.
func TestSoftParseDropsGroupWithUnknownMember(t *testing.T) {
	ctx, collector := WithParseWarnings(libbox.BaseContext(nil))
	raw := `{"outbounds":[
		{"type":"selector","tag":"sel","outbounds":["n1","gone"]},
		{"type":"vless","tag":"n1","server":"1.2.3.4","server_port":443,"uuid":"` + batchTestUUID + `"}]}`
	filtered, err := FilterValidLeavesJSONForTest(ctx, []byte(raw))
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if strings.Contains(string(filtered), `"sel"`) {
		t.Fatalf("group naming a missing tag must be dropped: %s", filtered)
	}
	if !strings.Contains(string(filtered), "n1") {
		t.Fatalf("unrelated leaf must survive: %s", filtered)
	}
	msg := collector.MessageJSON()
	if !strings.Contains(msg, "gone") {
		t.Fatalf("drop reason must name the missing tag: %s", msg)
	}
	if strings.Contains(msg, "declares no member outbounds") {
		t.Fatalf("drop reason must be about the dangling reference: %s", msg)
	}
}

// TestGroupAcceptedTagJoinsTagSetIncrementally proves the incremental tag-set
// update reaches the next group: g0 introduces "g0", and g1 references it.
func TestGroupAcceptedTagJoinsTagSetIncrementally(t *testing.T) {
	ctx, collector := WithParseWarnings(libbox.BaseContext(nil))
	raw := `{"outbounds":[
		{"type":"vless","tag":"n1","server":"1.2.3.4","server_port":443,"uuid":"` + batchTestUUID + `"},
		{"type":"selector","tag":"g0","outbounds":["n1"]},
		{"type":"selector","tag":"g1","outbounds":["g0"]}]}`
	filtered, err := FilterValidLeavesJSONForTest(ctx, []byte(raw))
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	for _, tag := range []string{`"g0"`, `"g1"`} {
		if !strings.Contains(string(filtered), tag) {
			t.Fatalf("group referencing an accepted group must survive (%s): %s", tag, filtered)
		}
	}
	if msg := collector.MessageJSON(); msg != "" {
		t.Fatalf("chain of groups must not be dropped: %s", msg)
	}
}

// TestOutboundServerHostReadsTypedOptions pins requirement 1.15.
//
// The removed implementation marshalled the outbound and looked for a "server"
// key. option.Outbound keeps the protocol fields in Options (json:"-") and only
// defines MarshalJSONContext, so that round-trip always produced
// {"type":..,"tag":..} with no "server" key: the function answered "" for every
// typed outbound, and IsIPv6Leaf's server-host half was dead — an IPv6-literal
// node survived into a build that cannot dial it. The typed read must return the
// host the engine will actually dial.
func TestOutboundServerHostReadsTypedOptions(t *testing.T) {
	for _, tc := range []struct {
		name string
		out  any
		want string
	}{
		{
			name: "vless ipv6 literal",
			out: option.Outbound{
				Type: "vless",
				Tag:  "n1",
				Options: &option.VLESSOutboundOptions{
					ServerOptions: option.ServerOptions{Server: " 2001:db8::1 ", ServerPort: 443},
					UUID:          batchTestUUID,
				},
			},
			want: "2001:db8::1",
		},
		{
			name: "bare options struct",
			out: &option.TrojanOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "fd00::1", ServerPort: 443},
			},
			want: "fd00::1",
		},
		{
			name: "hostname is not an ipv6 literal but must still be reported",
			out: option.Outbound{
				Type: "vless",
				Tag:  "n2",
				Options: &option.VLESSOutboundOptions{
					ServerOptions: option.ServerOptions{Server: "example.com", ServerPort: 443},
				},
			},
			want: "example.com",
		},
		{
			// A group has no server: the read must not invent one.
			name: "group has no server",
			out:  option.Outbound{Type: "selector", Tag: "g", Options: &option.SelectorOutboundOptions{}},
			want: "",
		},
		{
			name: "dynamic subscription object",
			out:  map[string]interface{}{"server": " 2001:db8::1 "},
			want: "2001:db8::1",
		},
		{
			name: "dynamic object with nested options",
			out:  map[string]interface{}{"options": map[string]interface{}{"server": "fd00::1"}},
			want: "fd00::1",
		},
	} {
		if got := outboundServerHost(tc.out); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// The consequence of the read above: a leaf whose server is an IPv6 literal must
// be filtered when IPv6 leaves are off, and kept otherwise. Before the fix only
// the "-ipv6" tag suffix could ever be filtered.
func TestIPv6LeafFilteredByServerHost(t *testing.T) {
	ipv6 := option.Outbound{
		Type: "vless",
		Tag:  "no-suffix",
		Options: &option.VLESSOutboundOptions{
			ServerOptions: option.ServerOptions{Server: "[2001:db8::1]", ServerPort: 443},
			UUID:          batchTestUUID,
		},
	}
	if !IsIPv6Leaf(ipv6.Tag, outboundServerHost(ipv6)) {
		t.Fatal("an IPv6-literal server must count as an IPv6 leaf")
	}
	ipv4 := option.Outbound{
		Type: "vless",
		Tag:  "no-suffix-v4",
		Options: &option.VLESSOutboundOptions{
			ServerOptions: option.ServerOptions{Server: "198.51.100.9", ServerPort: 443},
			UUID:          batchTestUUID,
		},
	}
	if IsIPv6Leaf(ipv4.Tag, outboundServerHost(ipv4)) {
		t.Fatal("an IPv4 server must not count as an IPv6 leaf")
	}
	// The tag-suffix rule still applies on its own.
	if !IsIPv6Leaf("node-ipv6", "") {
		t.Fatal("-ipv6 suffix must still mark an IPv6 leaf")
	}
}

func assertSameReason(t *testing.T, got, want error) {
	t.Helper()
	if want == nil {
		t.Fatalf("oracle produced no error but the verdict is a failure")
	}
	if got == nil {
		t.Fatalf("verdict has no reason, oracle said: %v", want)
	}
	if got.Error() != want.Error() {
		t.Fatalf("drop reason changed:\n  batch:   %q\n  per-leaf: %q", got.Error(), want.Error())
	}
}

// BenchmarkSoftParseLargeSubscription measures the stage this change targets:
// 300 nodes through the soft filter.
func BenchmarkSoftParseLargeSubscription(b *testing.B) {
	parts := make([]string, 0, 300)
	for i := 0; i < 300; i++ {
		parts = append(parts, fmt.Sprintf(
			`{"type":"vless","tag":"n%03d","server":"10.%d.%d.%d","server_port":443,"uuid":"%s"}`,
			i, i/65536%256, i/256%256, i%256, batchTestUUID))
	}
	doc := []byte(`{"outbounds":[` + strings.Join(parts, ",") + `]}`)
	ctx := libbox.BaseContext(nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := FilterValidLeavesJSONForTest(ctx, doc); err != nil {
			b.Fatal(err)
		}
	}
}
