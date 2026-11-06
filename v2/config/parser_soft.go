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

	// The dns block is decoded as part of option.Options, so a single legacy
	// server entry or a dns.fakeip object failed the WHOLE import — there is no
	// per-leaf decode error to catch. Isolate it the same way the leaves below
	// are isolated: migrate what maps cleanly (above), drop the entries that
	// still cannot decode, and only drop the block itself when it is unusable.
	if isolateDNSBlock(ctx, root) {
		changed = true
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
			filtered := filterInboundLeaves(ctx, raw)
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
// (pathParent==true). seen is the running set duplicate detection is built
// from.
//
// shared covers the outbound+endpoint namespace only. The engine checks
// inbounds on their own (option/options.go:151 checkInbounds) and outbounds
// together with endpoints (:166 checkOutbounds) — so a tag used by both an
// inbound and an outbound is legal, and counting inbounds here made the filters
// drop it as a "duplicate tag".
type tagIndex struct {
	shared     map[string]bool
	pathParent map[string]bool
	seen       map[string]bool
}

func newTagIndex(root map[string]interface{}) *tagIndex {
	idx := &tagIndex{shared: map[string]bool{}, pathParent: map[string]bool{}, seen: map[string]bool{}}
	// duplicateNamespace reports whether the list's tags live in the outbound
	// tag namespace (outbounds and endpoints do; inbounds have their own).
	countTags := func(key string, duplicateNamespace bool) {
		list, _ := root[key].([]interface{})
		for _, item := range list {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			// Legend parents are collected from every list: the synthesized
			// "{tag}-auto" group collides with a leaf of that name regardless
			// of which list declared it.
			if leafType(m) == C.TypePathology && pathologyLegendParent(m) {
				idx.pathParent[leafTag(m)] = true
			}
			if !duplicateNamespace {
				continue
			}
			tag := leafTag(m)
			if tag == "" {
				continue
			}
			if idx.seen[tag] {
				idx.shared[tag] = true
			}
			idx.seen[tag] = true
		}
	}
	for _, key := range []string{"outbounds", "endpoints"} {
		countTags(key, true)
	}
	countTags("inbounds", false)
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

	// Leaves are collected first and then validated in ONE engine instance (see
	// checkOutboundLeaves): a 300-node subscription used to pay 300 box.New
	// calls. The results are replayed in document order below, so every drop
	// warning keeps the position and wording it had with the per-leaf check.
	pending := make([]outboundLeafCheck, 0, len(items))
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
		leaf := outboundLeafCheck{item: item, typ: typ, tag: leafTag(m)}
		// Pre-checks are order-independent, so they run here and stay out of the
		// batch. Same precedence as the single-pass version: registration, then
		// the synthesized-group collision, then the legend rules inside
		// checkOutboundLeaf. Duplicates cannot be decided here — a tag only
		// counts as taken once an earlier leaf was ACCEPTED — so they stay in the
		// replay below, where the accepted set is known.
		if !outboundTypeRegistered(typ) {
			leaf.preKind = leafPreUnknownType
			leaf.pre = fmt.Sprintf("unknown type %q", typ)
		} else if reason, collides := index.autoGroupCollision(m); collides {
			leaf.preKind = leafPreCollision
			leaf.pre = reason
		} else if ok, reason := checkPathologyLegends(m); !ok {
			leaf.preKind = leafPreLegend
			leaf.pre = reason.Error()
		}
		pending = append(pending, leaf)
	}

	// One engine instance for every candidate that still needs a verdict.
	candidates := make([]map[string]interface{}, 0, len(pending))
	candidateIndex := make([]int, 0, len(pending))
	for i, leaf := range pending {
		if leaf.pre != "" {
			continue
		}
		candidates = append(candidates, leaf.item.(map[string]interface{}))
		candidateIndex = append(candidateIndex, i)
	}
	for k, verdict := range checkOutboundLeaves(ctx, candidates) {
		pending[candidateIndex[k]].verdict = verdict
	}

	for _, leaf := range pending {
		if leaf.tag != "" && seenTags[leaf.tag] {
			fmt.Printf("[SingboxParser] skip duplicate outbound tag %q type=%q\n", leaf.tag, leaf.typ)
			warns.addDrop("outbound", leaf.typ, leaf.tag, "duplicate tag")
			continue
		}
		switch leaf.preKind {
		case leafPreUnknownType:
			fmt.Printf("[SingboxParser] skip unknown outbound type %q tag=%q\n", leaf.typ, leaf.tag)
			warns.addDrop("outbound", leaf.typ, leaf.tag, leaf.pre)
			continue
		case leafPreCollision:
			fmt.Printf("[SingboxParser] skip outbound type=%q tag=%q: %s\n", leaf.typ, leaf.tag, leaf.pre)
			warns.addDrop("outbound", leaf.typ, leaf.tag, leaf.pre)
			continue
		case leafPreLegend:
			fmt.Printf("[SingboxParser] skip invalid outbound type=%q tag=%q: %v\n", leaf.typ, leaf.tag, leaf.pre)
			warns.addDrop("outbound", leaf.typ, leaf.tag, leaf.pre)
			continue
		}
		if !leaf.verdict.ok {
			fmt.Printf("[SingboxParser] skip invalid outbound type=%q tag=%q: %v\n", leaf.typ, leaf.tag, leaf.verdict.reason)
			warns.addDrop("outbound", leaf.typ, leaf.tag, leaf.verdict.reason)
			continue
		}
		leaves = append(leaves, leaf.item)
		if leaf.tag != "" {
			seenTags[leaf.tag] = true
		}
	}

	if len(groups) == 0 {
		return leaves
	}

	// Validate selector/urltest/balancer against the kept leaf set. pool is
	// built once and grown as groups are accepted; the accepted-tag set is
	// updated incrementally instead of being rebuilt from the whole pool after
	// every accepted group (that was O(groups x nodes)).
	pool := make([]interface{}, 0, len(leaves)+1+len(groups))
	pool = append(pool, leaves...)
	pool = append(pool, stubDirectOutbound())
	tagSet := leafTagSet(pool)
	// scratch is reused by every group check so the pool is not re-copied into a
	// fresh slice per group.
	scratch := make([]interface{}, 0, len(pool)+2)

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
		if ok, reason := checkOutboundGroup(ctx, m, pool, tagSet, &scratch); ok {
			leaves = append(leaves, item)
			pool = append(pool, item)
			if tag := leafTag(m); tag != "" {
				tagSet[tag] = true
			}
		} else {
			fmt.Printf("[SingboxParser] skip invalid outbound group type=%q tag=%q: %v\n", typ, leafTag(m), reason)
			warns.addDrop("group", typ, leafTag(m), reason)
		}
	}

	return leaves
}

// outboundLeafCheck is one outbound leaf waiting for (or holding) its verdict.
type outboundLeafCheck struct {
	item interface{}
	typ  string
	tag  string
	// pre is a drop reason decided without the engine; "" means the leaf is
	// still a validation candidate. preKind keeps each reason on the log line it
	// used before the batch existed (the drop text the UI sees is pre either way).
	pre     string
	preKind leafPreKind
	verdict leafVerdict
}

// leafPreKind says which pre-check rejected a leaf, purely so the stdout
// log line stays worded exactly as the single-leaf path worded it.
type leafPreKind uint8

const (
	leafPreNone leafPreKind = iota
	leafPreUnknownType
	leafPreCollision
	leafPreLegend
)

// leafVerdict is the engine's verdict on one candidate leaf.
type leafVerdict struct {
	ok     bool
	reason error
}

func filterEndpointLeaves(ctx context.Context, items []interface{}, index *tagIndex) []interface{} {
	out := make([]interface{}, 0, len(items))
	warns := parseWarningsFrom(ctx)
	// Same duplicate-tag guard as the outbound filter: endpoints share the tag
	// namespace with outbounds, so a repeated tag is fatal downstream.
	seenTags := make(map[string]bool)
	// Same two-pass shape as filterOutboundLeaves: validate every candidate in
	// one engine instance, then replay in document order so warnings keep their
	// position. A duplicate can only be judged once the accepted set is known.
	type endpointLeafCheck struct {
		item interface{}
		typ  string
		tag  string
		// preUnknownType marks an endpoint type this build cannot construct;
		// everything else goes to the batch.
		preUnknownType bool
		verdict        leafVerdict
	}
	pending := make([]endpointLeafCheck, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		typ := leafType(m)
		if typ == "" {
			continue
		}
		leaf := endpointLeafCheck{item: item, typ: typ, tag: leafTag(m)}
		if !endpointTypeRegistered(typ) {
			leaf.preUnknownType = true
		}
		pending = append(pending, leaf)
	}
	candidates := make([]map[string]interface{}, 0, len(pending))
	candidateIndex := make([]int, 0, len(pending))
	for i, leaf := range pending {
		if leaf.preUnknownType {
			continue
		}
		candidates = append(candidates, leaf.item.(map[string]interface{}))
		candidateIndex = append(candidateIndex, i)
	}
	for k, verdict := range checkEndpointLeaves(ctx, candidates) {
		pending[candidateIndex[k]].verdict = verdict
	}
	for _, leaf := range pending {
		duplicate := seenTags[leaf.tag] || (leaf.tag != "" && index.shared[leaf.tag])
		if duplicate && leaf.tag != "" {
			fmt.Printf("[SingboxParser] skip duplicate endpoint tag %q type=%q\n", leaf.tag, leaf.typ)
			warns.addDrop("endpoint", leaf.typ, leaf.tag, "duplicate tag")
			continue
		}
		if leaf.preUnknownType {
			fmt.Printf("[SingboxParser] skip unknown endpoint type %q tag=%q\n", leaf.typ, leaf.tag)
			warns.addDrop("endpoint", leaf.typ, leaf.tag, fmt.Sprintf("unknown type %q", leaf.typ))
			continue
		}
		if !leaf.verdict.ok {
			fmt.Printf("[SingboxParser] skip invalid endpoint type=%q tag=%q: %v\n", leaf.typ, leaf.tag, leaf.verdict.reason)
			warns.addDrop("endpoint", leaf.typ, leaf.tag, leaf.verdict.reason)
			continue
		}
		out = append(out, leaf.item)
		if leaf.tag != "" {
			seenTags[leaf.tag] = true
		}
	}
	return out
}

// filterInboundLeaves drops inbounds the 1.5 engine cannot build. The
// duplicate check is inbound-local: the engine validates inbounds in a separate
// tag namespace (option/options.go:151 checkInbounds → "duplicate inbound tag"),
// so inbounds:[{tag:"proxy"}] next to outbounds:[{tag:"proxy"}] is a legal
// document and must survive. It used to consult index.shared, which is built
// across outbounds+endpoints+inbounds, and so dropped the inbound as a
// duplicate — the profile then imported without its listener.
func filterInboundLeaves(ctx context.Context, items []interface{}) []interface{} {
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
		if tag != "" && seenTags[tag] {
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
			// Recorded on the success path only: a dropped inbound must not
			// make a later valid one with the same tag look duplicated.
			if tag != "" {
				seenTags[tag] = true
			}
		} else {
			fmt.Printf("[SingboxParser] skip invalid inbound type=%q tag=%q: %v\n", typ, leafTag(m), reason)
			warns.addDrop("inbound", typ, leafTag(m), reason)
		}
	}
	return out
}

// checkOutboundLeaves validates a whole subscription's leaves in ONE engine
// instance instead of one box.New per leaf, and attributes a failure back to the
// individual leaf that caused it.
//
// A passing range accepts every member. A failing range is split in half and
// re-checked until the culprit stands alone, where the config is byte-for-byte
// the one the old per-leaf check built — so the reported error (and therefore
// the drop reason the UI shows) is unchanged. Cost is one box.New for a healthy
// subscription plus O(failed x log n) for the rare broken one, instead of n.
// See bisectLeafVerdicts for the loop.
//
// Per-leaf checks that the engine cannot express (pathology legend rules) and
// the ones that do not need it (registration, collisions) run in
// filterOutboundLeaves before this, exactly where they ran before.
func checkOutboundLeaves(ctx context.Context, leaves []map[string]interface{}) []leafVerdict {
	return bisectLeafVerdicts(len(leaves), func(lo, hi int) (bool, error) {
		return checkOutboundLeafRange(ctx, leaves[lo:hi])
	})
}

// checkOutboundLeafRange builds the stub document for one range of candidates.
//
// The stub's name follows the old single-leaf rule: a range that contains a leaf
// already tagged "direct" names the stub "__soft_parse_direct__" so the engine
// does not reject the config as a duplicate tag. A range of one therefore
// reproduces the exact document the old checkOutboundLeaf built.
func checkOutboundLeafRange(ctx context.Context, leaves []map[string]interface{}) (bool, error) {
	stub := stubDirectOutbound()
	routeFinal := stubTag
	for _, leaf := range leaves {
		if leafTag(leaf) == stubTag {
			stub = map[string]interface{}{"type": "direct", "tag": stubTagAlt}
			routeFinal = stubTagAlt
			break
		}
	}
	out := make([]interface{}, 0, len(leaves)+1)
	for _, leaf := range leaves {
		out = append(out, leaf)
	}
	out = append(out, stub)
	cfg := map[string]interface{}{
		"outbounds": out,
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

// checkOutboundGroup validates one group against the accepted pool. pool and
// tagSet are owned by the caller: the pool is grown as groups are accepted and
// the tag set is updated in place, so neither is rebuilt per group. scratch is
// the caller's reusable buffer, so assembling the candidate list does not
// allocate a fresh pool-sized slice for every group.
func checkOutboundGroup(ctx context.Context, group map[string]interface{}, pool []interface{}, tagSet map[string]bool, scratch *[]interface{}) (bool, error) {
	refs, unknown := groupMemberRefs(group, tagSet)
	if len(refs) == 0 {
		return false, fmt.Errorf("group declares no member outbounds")
	}
	if len(unknown) > 0 {
		return false, fmt.Errorf("group references unknown outbound tags: %s", quoteTagList(unknown))
	}
	out := (*scratch)[:0]
	out = append(out, pool...)
	out = append(out, group)
	if _, ok := tagSet[stubTag]; !ok {
		out = append(out, stubDirectOutbound())
	}
	*scratch = out
	cfg := map[string]interface{}{
		"outbounds": out,
		"route":     map[string]interface{}{"final": firstRoutableTag(out)},
	}
	return checkConfigMap(ctx, cfg)
}

// checkEndpointLeaves is checkEndpointLeaf for a whole subscription: one engine
// instance for every endpoint, bisected on failure so the verdict and the error
// text belong to the individual endpoint that failed.
func checkEndpointLeaves(ctx context.Context, leaves []map[string]interface{}) []leafVerdict {
	return bisectLeafVerdicts(len(leaves), func(lo, hi int) (bool, error) {
		return checkEndpointLeafRange(ctx, leaves[lo:hi])
	})
}

// bisectLeafVerdicts turns a set-level check into per-leaf verdicts.
//
// rangeOK reports whether the config built from leaves[lo:hi] passes. A passing
// range accepts every member; a failing range is halved and re-checked until the
// culprit stands alone. Singletons are therefore checked exactly the way the old
// per-leaf loop checked them, which is what keeps the error text -- and so the
// drop reason the UI shows -- identical.
//
// A healthy import costs exactly one call. A broken one costs O(failed x log n),
// which only matters for a subscription that is mostly invalid.
func bisectLeafVerdicts(n int, rangeOK func(lo, hi int) (bool, error)) []leafVerdict {
	verdicts := make([]leafVerdict, n)
	if n == 0 {
		return verdicts
	}
	// Explicit stack, not recursion: a subscription can carry thousands of
	// leaves and this must not depend on the goroutine stack growing.
	ranges := make([][2]int, 0, 8)
	ranges = append(ranges, [2]int{0, n})
	for len(ranges) > 0 {
		r := ranges[len(ranges)-1]
		ranges = ranges[:len(ranges)-1]
		ok, reason := rangeOK(r[0], r[1])
		if ok {
			for i := r[0]; i < r[1]; i++ {
				verdicts[i] = leafVerdict{ok: true}
			}
			continue
		}
		if r[1]-r[0] == 1 {
			verdicts[r[0]] = leafVerdict{ok: false, reason: reason}
			continue
		}
		mid := r[0] + (r[1]-r[0])/2
		ranges = append(ranges, [2]int{mid, r[1]}, [2]int{r[0], mid})
	}
	return verdicts
}

func checkEndpointLeafRange(ctx context.Context, leaves []map[string]interface{}) (bool, error) {
	endpoints := make([]interface{}, 0, len(leaves))
	for _, leaf := range leaves {
		endpoints = append(endpoints, leaf)
	}
	cfg := map[string]interface{}{
		"endpoints": endpoints,
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
	// User WG endpoints often fail full-config validation in isolation (no
	// dial/runtime). A range of one keeps the old short-circuit; a range that
	// also holds a broken endpoint fails here and is bisected, after which the
	// wireguard endpoint is judged on its own again.
	if len(leaves) == 1 && leafType(leaves[0]) == "wireguard" {
		return true, nil
	}
	if err := softParseCheckJSON(raw); err != nil {
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

// softParseCheckJSON is the one place the soft filter asks the engine to build a
// config. It is a variable so tests can count how many instances an import
// builds (the whole point of batching the leaf checks: one, not one per leaf).
// Nothing in production assigns it.
var softParseCheckJSON = func(raw []byte) error {
	// libbox.CheckConfig builds its own base context (1.5 replacement for CheckConfigOptions).
	return libbox.CheckConfig(string(raw))
}

func checkConfigMap(ctx context.Context, cfg map[string]interface{}) (bool, error) {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return false, err
	}
	_ = ctx
	if err := softParseCheckJSON(raw); err != nil {
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
