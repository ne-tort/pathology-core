package config

import "testing"

// allGroupTypes is the set isGroupType must recognise: the classic
// selector/urltest/balancer plus the 1.5 wrappers failover and scatter, which
// the client build registers (include/failover.go, include/scatter.go) and
// build_tags.txt enables with_failover,with_scatter.
var allGroupTypes = []string{"selector", "urltest", "balancer", "failover", "scatter"}

// Defect B guard: the outbound filter's group predicate must agree with
// isGroupType. When it listed only selector/urltest/balancer, failover/scatter
// wrappers were validated as leaves in a stub config without their members and
// dropped with a bogus dependency warning, so the 1.5 wrapper feature never
// reached the engine.
func TestOutboundGroupTypeAgreesWithIsGroupType(t *testing.T) {
	for _, typ := range allGroupTypes {
		if !isGroupType(typ) {
			t.Fatalf("isGroupType(%q) = false, want true", typ)
		}
		if !isOutboundGroupType(typ) {
			t.Fatalf("isOutboundGroupType(%q) = false: the wrapper would be validated as a leaf and dropped", typ)
		}
		// Case/space tolerant: subscription JSON is not guaranteed tidy, and
		// leafType lowercases but does not strip spaces.
		if !isOutboundGroupType(" " + upper(typ) + " ") {
			t.Fatalf("isOutboundGroupType must normalise %q", typ)
		}
	}
	for _, typ := range []string{"vless", "pathology", "direct", "wireguard", ""} {
		if isOutboundGroupType(typ) {
			t.Fatalf("%q must not be treated as a group", typ)
		}
		if isGroupType(typ) {
			t.Fatalf("isGroupType(%q) must be false", typ)
		}
	}
}

// Groups are containers, never user-pickable protocol leaves: counting them as
// leaves would disable the Direct-fallback refusal that stops an all-dropped
// import from silently becoming a Direct-only profile.
func TestGroupTypesAreNotProtocolLeaves(t *testing.T) {
	for _, typ := range allGroupTypes {
		items := []interface{}{map[string]interface{}{"type": typ, "tag": "g-" + typ}}
		if n := countProtocolLeaves(items); n != 0 {
			t.Fatalf("%s counted as %d protocol leaves", typ, n)
		}
	}
	items := []interface{}{map[string]interface{}{"type": "vless", "tag": "v"}}
	if n := countProtocolLeaves(items); n != 1 {
		t.Fatalf("vless must count as exactly one leaf, got %d", n)
	}
}

// upper avoids importing strings just for a three-line guard.
func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}
