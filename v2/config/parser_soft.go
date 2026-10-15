package config

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

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
	if warnings := MigrateLegacyJSON(root); len(warnings) > 0 {
		changed = true
		for _, w := range warnings {
			fmt.Printf("[SingboxParser] migrate 1.4→1.5: %s\n", w)
		}
	}

	inOut, _ := root["outbounds"].([]interface{})
	inEp, _ := root["endpoints"].([]interface{})
	inLeafCount := countProtocolLeaves(inOut) + len(inEp)

	if len(inOut) > 0 {
		filtered := filterOutboundLeaves(ctx, inOut)
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
		filtered := filterEndpointLeaves(ctx, inEp)
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
	outLeafCount := countProtocolLeaves(outOut) + len(outEp)
	if inLeafCount > 0 && outLeafCount == 0 {
		return nil, fmt.Errorf("[SingboxParser] soft parse dropped all %d leaves", inLeafCount)
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

// countProtocolLeaves counts outbounds that are meant as user proxies (not
// direct/block/dns stubs used only for routing).
func countProtocolLeaves(items []interface{}) int {
	n := 0
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		switch leafType(m) {
		case "", "direct", "block", "dns":
			continue
		default:
			n++
		}
	}
	return n
}

func filterOutboundLeaves(ctx context.Context, items []interface{}) []interface{} {
	var leaves []interface{}
	var groups []interface{}

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
		if !outboundTypeRegistered(typ) {
			fmt.Printf("[SingboxParser] skip unknown outbound type %q tag=%q\n", typ, leafTag(m))
			continue
		}
		if ok, reason := checkOutboundLeaf(ctx, m); ok {
			leaves = append(leaves, item)
		} else {
			fmt.Printf("[SingboxParser] skip invalid outbound type=%q tag=%q: %v\n", typ, leafTag(m), reason)
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
			continue
		}
		if ok, reason := checkOutboundGroup(ctx, m, pool, tagSet); ok {
			leaves = append(leaves, item)
			pool = append(pool, item)
			tagSet = leafTagSet(pool)
		} else {
			fmt.Printf("[SingboxParser] skip invalid outbound group type=%q tag=%q: %v\n", typ, leafTag(m), reason)
		}
	}

	return leaves
}

func filterEndpointLeaves(ctx context.Context, items []interface{}) []interface{} {
	out := make([]interface{}, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		typ := leafType(m)
		if typ == "" {
			continue
		}
		if !endpointTypeRegistered(typ) {
			fmt.Printf("[SingboxParser] skip unknown endpoint type %q tag=%q\n", typ, leafTag(m))
			continue
		}
		if ok, reason := checkEndpointLeaf(ctx, m); ok {
			out = append(out, item)
		} else {
			fmt.Printf("[SingboxParser] skip invalid endpoint type=%q tag=%q: %v\n", typ, leafTag(m), reason)
		}
	}
	return out
}

func filterInboundLeaves(ctx context.Context, items []interface{}) []interface{} {
	out := make([]interface{}, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		typ := leafType(m)
		if typ == "" {
			continue
		}
		if !inboundTypeRegistered(typ) {
			fmt.Printf("[SingboxParser] skip unknown inbound type %q tag=%q\n", typ, leafTag(m))
			continue
		}
		if ok, reason := checkInboundLeaf(ctx, m); ok {
			out = append(out, item)
		} else {
			fmt.Printf("[SingboxParser] skip invalid inbound type=%q tag=%q: %v\n", typ, leafTag(m), reason)
		}
	}
	return out
}

func checkOutboundLeaf(ctx context.Context, leaf map[string]interface{}) (bool, error) {
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

func checkOutboundGroup(ctx context.Context, group map[string]interface{}, pool []interface{}, tagSet map[string]bool) (bool, error) {
	if !groupReferencesKnownTags(group, tagSet) {
		return false, fmt.Errorf("group references unknown outbound tags")
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

func isOutboundGroupType(typ string) bool {
	switch strings.ToLower(typ) {
	case "selector", "urltest", "balancer":
		return true
	default:
		return false
	}
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

func leafType(m map[string]interface{}) string {
	return strings.ToLower(strings.TrimSpace(fmt.Sprint(m["type"])))
}

func leafTag(m map[string]interface{}) string {
	return strings.TrimSpace(fmt.Sprint(m["tag"]))
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

func groupReferencesKnownTags(group map[string]interface{}, tagSet map[string]bool) bool {
	raw := group["outbounds"]
	list, ok := raw.([]interface{})
	if !ok || len(list) == 0 {
		return false
	}
	for _, ref := range list {
		tag := strings.TrimSpace(fmt.Sprint(ref))
		if tag == "" || !tagSet[tag] {
			return false
		}
	}
	return true
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
