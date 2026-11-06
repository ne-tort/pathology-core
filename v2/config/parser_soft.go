package config

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
)

// filterValidLeavesJSON drops invalid or unknown outbounds/endpoints (and optionally
// inbounds) so one bad leaf does not fail an entire subscription import.
//
// If the input had outbounds/endpoints and the filter removes every one, returns
// an error so callers (Flutter compile fallback / validate soft-fail) can keep
// the raw body instead of persisting {"outbounds":[]}.
func filterValidLeavesJSON(ctx context.Context, content []byte, filterInbounds bool) ([]byte, error) {
	var root map[string]interface{}
	if err := json.Unmarshal(content, &root); err != nil {
		return content, nil
	}

	// 1.5 hard-rejects a set of 1.4-era keys (QUIC parrot, hy bandwidth,
	// trusttunnel legacy TLS, route action "direct", legacy vision flow).
	// Rewrite them up front so one legacy leaf does not fail the whole import.
	changed := false
	warns := parseWarningsFrom(ctx)
	if warnings := MigrateLegacyJSON(root); len(warnings) > 0 {
		changed = true
		for _, w := range warnings {
			fmt.Printf("[SingboxParser] migrate 1.4→1.5: %s\n", w)
			warns.addMigration(w)
		}
	}

	inOut, _ := root["outbounds"].([]interface{})
	inEp, _ := root["endpoints"].([]interface{})
	// Tags owned by any emitted leaf, group, endpoint or inbound. The engine
	// synthesizes {parent}-auto for pathology legend parents, so a subscription
	// carrying its own "{parent}-auto" would collide at engine start.
	index := newTagIndex(root)

	if len(inOut) > 0 {
		filtered := filterOutboundLeaves(ctx, inOut, index)
		if len(filtered) != len(inOut) {
			changed = true
		}
		if len(filtered) == 0 {
			root["outbounds"] = []interface{}{}
		} else {
			root["outbounds"] = filtered
		}
	}

	if len(inEp) > 0 {
		filtered := filterEndpointLeaves(ctx, inEp, index)
		if len(filtered) != len(inEp) {
			changed = true
		}
		if len(filtered) == 0 {
			delete(root, "endpoints")
		} else {
			root["endpoints"] = filtered
		}
	}

	if filterInbounds {
		if raw, ok := root["inbounds"].([]interface{}); ok && len(raw) > 0 {
			filtered := filterInboundLeaves(ctx, raw, index)
			if len(filtered) != len(raw) {
				changed = true
			}
			if len(filtered) == 0 {
				delete(root, "inbounds")
			} else {
				root["inbounds"] = filtered
			}
		}
	}

	outOut, _ := root["outbounds"].([]interface{})
	outEp, _ := root["endpoints"].([]interface{})
	inLeafCount := countEmittedLeaves(inOut, inEp)
	outLeafCount := countEmittedLeaves(outOut, outEp)
	if inLeafCount > 0 && outLeafCount == 0 {
		// Attach the surviving filtered document (usually a Direct stub pool) so
		// callers can persist it instead of falling back to the uncut import —
		// the error still prevents the silent "all dropped" success.
		err := fmt.Errorf("[SingboxParser] soft parse dropped all %d leaves", inLeafCount)
		filtered, mErr := json.Marshal(root)
		if mErr != nil {
			return nil, err
		}
		return filtered, err
	}

	if !changed {
		return content, nil
	}

	out, err := json.Marshal(root)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// FilterValidLeavesJSONForTest exposes filterValidLeavesJSON (outbounds +
// endpoints only) so external test packages can assert on the payload attached
// to the all-dropped error.
func FilterValidLeavesJSONForTest(ctx context.Context, content []byte) ([]byte, error) {
	return filterValidLeavesJSON(ctx, content, false)
}

// tagIndex records which tags the document declares more than once
// (shared==true: the engine's "duplicate outbound/endpoint tag" is fatal) and
// which are pathology legend parents that will acquire a "{tag}-auto" sibling
// (pathParent==true). seen records every declared tag so a synthesized
// "{tag}-auto" collision is caught even when the tag occurs only once.
type tagIndex struct {
	shared     map[string]bool
	pathParent map[string]bool
	seen       map[string]bool
}

func newTagIndex(root map[string]interface{}) *tagIndex {
	idx := &tagIndex{shared: map[string]bool{}, pathParent: map[string]bool{}, seen: map[string]bool{}}
	visit := func(key string) {
		list, _ := root[key].([]interface{})
		for _, item := range list {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			tag := leafTag(m)
			if tag != "" {
				if idx.seen[tag] {
					idx.shared[tag] = true
				}
				idx.seen[tag] = true
			}
			if leafType(m) == C.TypePathology && pathologyLegendParent(m) {
				idx.pathParent[tag] = true
			}
		}
	}
	for _, key := range []string{"outbounds", "endpoints", "inbounds"} {
		visit(key)
	}
	return idx
}

// isGroupType reports whether the type names a group rather than a dialable
// leaf. Subscriptions carry selector/urltest/balancer plus the 1.5 wrappers
// failover (L4 session restore) and scatter (L4 multipath); none of them is a
// leaf, so they must never be counted or validated as one.
func isGroupType(typ string) bool {
	switch strings.ToLower(strings.TrimSpace(typ)) {
	case "selector", "urltest", "balancer", "failover", "scatter":
		return true
	default:
		return false
	}
}

// pathologyLegendParent reports whether a pathology outbound declares a legend
// set (it is then expanded by the engine, not dialed directly).
func pathologyLegendParent(m map[string]interface{}) bool {
	legends, _ := m["legends"].(map[string]interface{})
	return len(legends) > 0
}

// autoGroupCollision checks the "{tag}-auto" name the builder synthesizes for a
// pathology legend parent (the engine is handed the parent tag and derives its
// own {parent}-{legend} virtual tags, which the group member list must match).
// Returns the reason when the leaf must be dropped. A leaf that itself carries
// the reserved "{parent}-auto" name while the legend parent is also present
// would shadow the synthesized group, so it is dropped too.
func (idx *tagIndex) autoGroupCollision(m map[string]interface{}) (string, bool) {
	if idx == nil {
		return "", false
	}
	tag := leafTag(m)
	if tag == "" {
		return "", false
	}
	typ := leafType(m)
	if typ == C.TypePathology && pathologyLegendParent(m) {
		auto := tag + "-auto"
		// A subscription can ship its own "{parent}-auto" leaf; it must lose
		// to the legend parent (the builder synthesizes the group from the
		// parent, not from the stray leaf), so only a *group* or *another
		// legend parent* holding that name forces us to drop the parent.
		if idx.pathParent[auto] {
			return fmt.Sprintf("synthesized group tag %q collides with another legend parent in the profile", auto), true
		}
		return "", false
	}
	if strings.HasSuffix(tag, "-auto") {
		parent := strings.TrimSuffix(tag, "-auto")
		if idx.pathParent[parent] {
			return fmt.Sprintf("tag %q shadows the group synthesized for pathology legend parent %q", tag, parent), true
		}
	}
	return "", false
}

// countEmittedLeaves counts the leaves a caller can actually pick: protocol
// outbounds (not group containers) plus endpoints.
func countEmittedLeaves(outbounds, endpoints []interface{}) int {
	return countProtocolLeaves(outbounds) + len(endpoints)
}

// countProtocolLeaves counts outbounds that are meant as user proxies (not
// direct/block/dns stubs used only for routing, and not group containers).
func countProtocolLeaves(items []interface{}) int {
	n := 0
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		typ := leafType(m)
		switch typ {
		case "", "direct", "block", "dns":
			continue
		}
		if isGroupType(typ) {
			continue
		}
		n++
	}
	return n
}

func filterOutboundLeaves(ctx context.Context, items []interface{}, index *tagIndex) []interface{} {
	var leaves []interface{}
	var groups []interface{}
	warns := parseWarningsFrom(ctx)
	// Duplicate tags are fatal downstream: the engine rejects the whole config
	// with "duplicate outbound/endpoint tag". Drop the later duplicates here so
	// one repeated node costs a warning instead of the entire profile.
	seenTags := make(map[string]bool)

	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		typ := leafType(m)
		if typ == "" {
			continue
		}
		if isOutboundGroupType(typ) {
			groups = append(groups, item)
			continue
		}
		tag := leafTag(m)
		if tag != "" && seenTags[tag] {
			fmt.Printf("[SingboxParser] skip duplicate outbound tag %q type=%q\n", tag, typ)
			warns.addDrop("outbound", typ, tag, "duplicate tag")
			continue
		}
		if !outboundTypeRegistered(typ) {
			fmt.Printf("[SingboxParser] skip unknown outbound type %q tag=%q\n", typ, tag)
			warns.addDrop("outbound", typ, tag, fmt.Sprintf("unknown type %q", typ))
			continue
		}
		if reason, collides := index.autoGroupCollision(m); collides {
			fmt.Printf("[SingboxParser] skip outbound type=%q tag=%q: %s\n", typ, tag, reason)
			warns.addDrop("outbound", typ, tag, reason)
			continue
		}
		if ok, reason := checkOutboundLeaf(ctx, m); ok {
			leaves = append(leaves, item)
			if tag != "" {
				seenTags[tag] = true
			}
		} else {
			fmt.Printf("[SingboxParser] skip invalid outbound type=%q tag=%q: %v\n", typ, tag, reason)
			warns.addDrop("outbound", typ, tag, reason)
		}
	}

	if len(groups) == 0 {
		return leaves
	}

	// Validate selector/urltest/balancer against the kept leaf set.
	pool := append([]interface{}{}, leaves...)
	pool = append(pool, stubDirectOutbound())
	tagSet := leafTagSet(pool)

	for _, item := range groups {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		typ := leafType(m)
		if !outboundTypeRegistered(typ) {
			fmt.Printf("[SingboxParser] skip unknown outbound group type %q tag=%q\n", typ, leafTag(m))
			warns.addDrop("group", typ, leafTag(m), fmt.Sprintf("unknown group type %q", typ))
			continue
		}
		if ok, reason := checkOutboundGroup(ctx, m, pool, tagSet); ok {
			leaves = append(leaves, item)
			pool = append(pool, item)
			tagSet = leafTagSet(pool)
		} else {
			fmt.Printf("[SingboxParser] skip invalid outbound group type=%q tag=%q: %v\n", typ, leafTag(m), reason)
			warns.addDrop("group", typ, leafTag(m), reason)
		}
	}

	return leaves
}

func filterEndpointLeaves(ctx context.Context, items []interface{}, index *tagIndex) []interface{} {
	out := make([]interface{}, 0, len(items))
	warns := parseWarningsFrom(ctx)
	// Same duplicate-tag guard as the outbound filter: endpoints share the tag
	// namespace with outbounds, so a repeated tag is fatal downstream.
	seenTags := make(map[string]bool)
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		typ := leafType(m)
		if typ == "" {
			continue
		}
		tag := leafTag(m)
		duplicate := seenTags[tag] || (tag != "" && index.shared[tag])
		if duplicate && tag != "" {
			fmt.Printf("[SingboxParser] skip duplicate endpoint tag %q type=%q\n", tag, typ)
			warns.addDrop("endpoint", typ, tag, "duplicate tag")
			continue
		}
		if !endpointTypeRegistered(typ) {
			fmt.Printf("[SingboxParser] skip unknown endpoint type %q tag=%q\n", typ, tag)
			warns.addDrop("endpoint", typ, tag, fmt.Sprintf("unknown type %q", typ))
			continue
		}
		if ok, reason := checkEndpointLeaf(ctx, m); ok {
			out = append(out, item)
			if tag != "" {
				seenTags[tag] = true
			}
		} else {
			fmt.Printf("[SingboxParser] skip invalid endpoint type=%q tag=%q: %v\n", typ, tag, reason)
			warns.addDrop("endpoint", typ, tag, reason)
		}
	}
	return out
}

func filterInboundLeaves(ctx context.Context, items []interface{}, index *tagIndex) []interface{} {
	out := make([]interface{}, 0, len(items))
	warns := parseWarningsFrom(ctx)
	seenTags := make(map[string]bool)
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		typ := leafType(m)
		if typ == "" {
			continue
		}
		tag := leafTag(m)
		if (seenTags[tag] || (tag != "" && index.shared[tag])) && tag != "" {
			fmt.Printf("[SingboxParser] skip duplicate inbound tag %q type=%q\n", tag, typ)
			warns.addDrop("inbound", typ, tag, "duplicate tag")
			continue
		}
		if !inboundTypeRegistered(typ) {
			fmt.Printf("[SingboxParser] skip unknown inbound type %q tag=%q\n", typ, tag)
			warns.addDrop("inbound", typ, tag, fmt.Sprintf("unknown type %q", typ))
			continue
		}
		if ok, reason := checkInboundLeaf(ctx, m); ok {
			out = append(out, item)
		} else {
			fmt.Printf("[SingboxParser] skip invalid inbound type=%q tag=%q: %v\n", typ, leafTag(m), reason)
			warns.addDrop("inbound", typ, leafTag(m), reason)
		}
	}
	return out
}

func checkOutboundLeaf(ctx context.Context, leaf map[string]interface{}) (bool, error) {
	if ok, reason := checkPathologyLegends(leaf); !ok {
		return false, reason
	}
	stub := stubDirectOutbound()
	routeFinal := stubTag
	// Avoid duplicate tag when the leaf itself is already tagged "direct".
	if leafTag(leaf) == stubTag {
		stub = map[string]interface{}{"type": "direct", "tag": stubTagAlt}
		routeFinal = stubTagAlt
	}
	cfg := map[string]interface{}{
		"outbounds": []interface{}{leaf, stub},
		"route":     map[string]interface{}{"final": routeFinal},
	}
	return checkConfigMap(ctx, cfg)
}

// checkPathologyLegends validates a pathology legend parent at parse time the
// way the engine will at start time. Validating the leaf in isolation (the
// generic checkConfigMap below) cannot catch either defect, because both only
// appear once the engine materialises the virtuals and the builder's rotation
// group names them:
//
//   - legends/auth mismatch. option/pathology_expand.go expands a virtual only
//     for a legend that has an auth entry ("if !hasAuth { continue }"), but its
//     own validation only proves the reverse direction (every auth has a
//     legend). So legends:{dns,stun} + auth:{dns} is accepted, yields a single
//     {parent}-dns, and then balancer.Start() fails with
//     "outbound 1 not found: {parent}-stun" — the whole profile cannot start,
//     with no warning anywhere. Reject the mismatch here instead, naming the
//     unmatched legend ids.
//   - a legend named "auto". Legend ids match ^[a-zA-Z0-9_-]+$ and the virtual
//     tag is parent+"-"+legend, so "auto" makes the virtual and the synthesized
//     group the same tag. outbound.Manager replaces duplicate tags instead of
//     erroring, so the group would name itself and self-dial.
func checkPathologyLegends(leaf map[string]interface{}) (bool, error) {
	if leafType(leaf) != C.TypePathology {
		return true, nil
	}
	legends, _ := leaf["legends"].(map[string]interface{})
	if len(legends) == 0 {
		return true, nil
	}
	auth, _ := leaf["auth"].(map[string]interface{})
	var noAuth, noLegend []string
	for id := range legends {
		if _, ok := auth[id]; !ok {
			noAuth = append(noAuth, id)
		}
	}
	for id := range auth {
		if _, ok := legends[id]; !ok {
			noLegend = append(noLegend, id)
		}
	}
	sort.Strings(noAuth)
	sort.Strings(noLegend)
	if len(noAuth) > 0 {
		return false, fmt.Errorf("legend %s has no auth entry: the engine expands no %q virtual for it, so the rotation group would name a missing outbound and the profile would fail to start (add auth for every legend, or remove the legend)",
			quoteTagList(noAuth), leafTag(leaf)+"-"+noAuth[0])
	}
	if len(noLegend) > 0 {
		return false, fmt.Errorf("auth %s has no legends entry: the engine rejects an auth without a legend (remove the auth entry or add the legend)",
			quoteTagList(noLegend))
	}
	for id := range legends {
		if strings.EqualFold(strings.TrimSpace(id), reservedAutoLegendID) {
			return false, fmt.Errorf("legend id %q is reserved for the synthesized rotation group %q: its virtual tag would be the same string (rename the legend, e.g. %q)", id, leafTag(leaf)+"-"+reservedAutoLegendID, "auto-1")
		}
	}
	return true, nil
}

// quoteTagList renders ids as `"a", "b"` for drop reasons.
func quoteTagList(ids []string) string {
	quoted := make([]string, 0, len(ids))
	for _, id := range ids {
		quoted = append(quoted, fmt.Sprintf("%q", id))
	}
	return strings.Join(quoted, ", ")
}

func checkOutboundGroup(ctx context.Context, group map[string]interface{}, pool []interface{}, tagSet map[string]bool) (bool, error) {
	refs, unknown := groupMemberRefs(group, tagSet)
	if len(refs) == 0 {
		return false, fmt.Errorf("group declares no member outbounds")
	}
	if len(unknown) > 0 {
		return false, fmt.Errorf("group references unknown outbound tags: %s", quoteTagList(unknown))
	}
	out := append([]interface{}{}, pool...)
	out = append(out, group)
	if _, ok := tagSet[stubTag]; !ok {
		out = append(out, stubDirectOutbound())
	}
	cfg := map[string]interface{}{
		"outbounds": out,
		"route":     map[string]interface{}{"final": firstRoutableTag(out)},
	}
	return checkConfigMap(ctx, cfg)
}

func checkEndpointLeaf(ctx context.Context, leaf map[string]interface{}) (bool, error) {
	cfg := map[string]interface{}{
		"endpoints": []interface{}{leaf},
		"outbounds": []interface{}{stubDirectOutbound()},
		"route":     map[string]interface{}{"final": stubTag},
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return false, err
	}
	opts := option.Options{}
	if err := opts.UnmarshalJSONContext(ctx, raw); err != nil {
		return false, err
	}
	// User WG endpoints often fail full-config validation in isolation (no dial/runtime).
	if leafType(leaf) == "wireguard" {
		return true, nil
	}
	if err := libbox.CheckConfig(string(raw)); err != nil {
		return false, err
	}
	return true, nil
}

func checkInboundLeaf(ctx context.Context, leaf map[string]interface{}) (bool, error) {
	cfg := map[string]interface{}{
		"inbounds":  []interface{}{leaf},
		"outbounds": []interface{}{stubDirectOutbound()},
		"route":     map[string]interface{}{"final": stubTag},
	}
	return checkConfigMap(ctx, cfg)
}

func checkConfigMap(ctx context.Context, cfg map[string]interface{}) (bool, error) {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return false, err
	}
	_ = ctx // libbox.CheckConfig builds its own base context (1.5 replacement for CheckConfigOptions).
	if err := libbox.CheckConfig(string(raw)); err != nil {
		return false, err
	}
	return true, nil
}

const (
	stubTag    = "direct"
	stubTagAlt = "__soft_parse_direct__"
)

func stubDirectOutbound() map[string]interface{} {
	return map[string]interface{}{"type": "direct", "tag": stubTag}
}

// isOutboundGroupType is the outbound filter's view of isGroupType. Keeping one
// predicate is load-bearing: when this list was narrower, failover/scatter fell
// through to checkOutboundLeaf and were validated as leaves in a stub config
// that has none of their members — every wrapper was dropped with a bogus
// dependency warning. checkOutboundGroup is the right validator for them.
func isOutboundGroupType(typ string) bool {
	return isGroupType(typ)
}

func outboundTypeRegistered(typ string) bool {
	_, ok := include.OutboundRegistry().CreateOptions(strings.ToLower(typ))
	return ok
}

func endpointTypeRegistered(typ string) bool {
	_, ok := include.EndpointRegistry().CreateOptions(strings.ToLower(typ))
	return ok
}

func inboundTypeRegistered(typ string) bool {
	_, ok := include.InboundRegistry().CreateOptions(strings.ToLower(typ))
	return ok
}

// leafType/leafTag return "" for a missing or non-string key. fmt.Sprint on a
// missing map key yields "<nil>", which used to leak into warnings and made
// countProtocolLeaves treat tagless objects as real proxy leaves.
func leafType(m map[string]interface{}) string {
	v, ok := m["type"]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(s))
}

func leafTag(m map[string]interface{}) string {
	v, ok := m["tag"]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

func leafTagSet(items []interface{}) map[string]bool {
	set := make(map[string]bool, len(items))
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		tag := leafTag(m)
		if tag != "" {
			set[tag] = true
		}
	}
	return set
}

// groupMemberRefKeys lists the keys a group type uses to name its members,
// using the engine's own JSON field names:
//   - selector/urltest/balancer, and failover (option.FailoverOutboundOptions),
//     name them in "outbounds";
//   - scatter (option.ScatterOutboundOptions) names them in "paths", plus the
//     optional split "uplink_paths"/"downlink_paths" pair.
//
// A group referencing any other key only would otherwise look reference-free
// and be dropped as "no member outbounds".
func groupMemberRefKeys(typ string) []string {
	switch strings.ToLower(strings.TrimSpace(typ)) {
	case "scatter":
		return []string{"paths", "uplink_paths", "downlink_paths"}
	default:
		return []string{"outbounds"}
	}
}

// groupMemberRefs returns every tag the group references across its member keys
// and the subset the config does not declare. A key with the wrong JSON type is
// reported as a non-tag reference so the group is dropped rather than passed to
// the engine, which would reject it later.
func groupMemberRefs(group map[string]interface{}, tagSet map[string]bool) (refs []string, unknown []string) {
	typ := leafType(group)
	for _, key := range groupMemberRefKeys(typ) {
		raw, present := group[key]
		if !present {
			continue
		}
		list, ok := raw.([]interface{})
		if !ok {
			unknown = append(unknown, "<"+key+" must be an array>")
			continue
		}
		for _, ref := range list {
			tag := strings.TrimSpace(fmt.Sprint(ref))
			if tag == "" {
				continue
			}
			refs = append(refs, tag)
			if !tagSet[tag] {
				unknown = append(unknown, tag)
			}
		}
	}
	return refs, unknown
}

func firstRoutableTag(items []interface{}) string {
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		tag := leafTag(m)
		typ := leafType(m)
		if tag == "" {
			continue
		}
		switch typ {
		case "direct", "block", "dns":
			continue
		}
		return tag
	}
	return "direct"
}
