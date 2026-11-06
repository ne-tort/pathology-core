package config

import (
	"fmt"
	"strconv"
	"strings"
)

// migrate150.go — pre-normalization of raw 1.4-era subscription/profile JSON
// before the sing-box 1.5 parser sees it.
//
// The 1.5 engine hard-rejects several legacy keys (option.RemovedParrotKeys,
// RemovedHyMbpsKeys, RemovedTrustTunnel*Keys, rule action "direct", vless
// legacy vision flow names, pad_profile, the geosite/geoip rule matchers, the
// inbound sniff fields and the tun inet4_/inet6_ address fields). A
// subscription carrying any of them would fail to import at all. The migrator
// rewrites them to their 1.5 equivalents and reports what it changed; unknown
// content passes through untouched. All transforms are idempotent (second run
// is a no-op).

// MigrateLegacyJSON rewrites legacy keys in a decoded config document
// (outbounds/endpoints/inbounds + route rules + dns servers) in place and
// returns human-readable warnings for the UI/log. Unknown shapes are left
// alone — validation downstream stays the source of truth.
func MigrateLegacyJSON(root map[string]interface{}) []string {
	var warnings []string
	walkMaps(root, func(m map[string]interface{}) {
		migrateParrotKeys(m, &warnings)
		migratePadProfile(m, &warnings)
		migrateNestedHysteriaBandwidth(m, &warnings)
	})
	for _, listKey := range []string{"outbounds", "endpoints", "inbounds"} {
		list, _ := root[listKey].([]interface{})
		for _, item := range list {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			switch leafType(m) {
			case "tun":
				if listKey == "inbounds" {
					migrateTunLegacyAddresses(m, &warnings)
				}
			case "hysteria", "hysteria2":
				migrateHysteriaBandwidth(m, &warnings)
				migrateImplicitTLS(m, &warnings)
			case "trusttunnel":
				migrateTrustTunnel(m, listKey == "inbounds", &warnings)
			case "vless":
				migrateVLESSFlow(m, &warnings)
			case "tuic", "anytls", "naive":
				migrateImplicitTLS(m, &warnings)
			}
			if leafType(m) == "masque" {
				m["type"] = "warpsque"
				warnings = append(warnings, fmt.Sprintf("%s %q: type masque renamed to warpsque", listKey[:len(listKey)-1], leafTag(m)))
			}
			if leafType(m) == "mesh_underlay" {
				// Rewrite to an unknown sentinel so the pass is idempotent: the
				// leaf still fails validation and is dropped by the soft filter
				// (with its own drop warning), but a second run sees no
				// mesh_underlay and stays silent instead of repeating the warning.
				m["type"] = meshUnderlayDroppedType
				warnings = append(warnings, fmt.Sprintf("%s %q: mesh_underlay was removed in 1.5 (use a tlspoint endpoint); the leaf will fail validation and be dropped", listKey[:len(listKey)-1], leafTag(m)))
			}
		}
	}
	migrateRouteDirectAction(root, &warnings)
	migrateGeoRules(root, &warnings)
	migrateLegacyInboundFields(root, &warnings)
	return warnings
}

// meshUnderlayDroppedType replaces a 1.4 mesh_underlay leaf type. It is not a
// registered type, so the soft filter drops the leaf exactly as the original
// would have, and the migrator no longer recognises it on a second pass.
const meshUnderlayDroppedType = "mesh_underlay_removed_in_1_5"

// walkMaps visits every nested map in a decoded JSON value.
func walkMaps(v interface{}, visit func(map[string]interface{})) {
	switch t := v.(type) {
	case map[string]interface{}:
		visit(t)
		for _, child := range t {
			walkMaps(child, visit)
		}
	case []interface{}:
		for _, child := range t {
			walkMaps(child, visit)
		}
	}
}

// migrateParrotKeys: 1.4 QUIC persona keys → 1.5 utls block.
// chrome_parrot:true → utls.fingerprint=chrome; disable_chrome_parrot:true →
// fingerprint=quic-go. Applies wherever the keys appear (protocol root,
// v2ray transport blocks, dns servers).
func migrateParrotKeys(m map[string]interface{}, warnings *[]string) {
	parrot, hasParrot := m["chrome_parrot"]
	disable, hasDisable := m["disable_chrome_parrot"]
	if !hasParrot && !hasDisable {
		return
	}
	delete(m, "chrome_parrot")
	delete(m, "disable_chrome_parrot")
	if hasParrot && hasDisable {
		*warnings = append(*warnings, "chrome_parrot + disable_chrome_parrot both set; migrated to utls.fingerprint=chrome")
	}
	var fp string
	switch {
	case hasParrot && parrot == true:
		fp = "chrome"
	case hasDisable && disable == true:
		fp = "quic-go"
	default:
		// Explicit false values carried no persona semantics; dropping is enough.
		return
	}
	if existing, ok := m["utls"].(map[string]interface{}); ok {
		cur, hasFP := existing["fingerprint"]
		// "none" is the documented way of saying "not set" (sing-box migrates
		// the zero value to it), so a parrot key must still override that.
		if hasFP && cur != nil && strings.TrimSpace(fmt.Sprint(cur)) != "" && strings.TrimSpace(fmt.Sprint(cur)) != "none" {
			// A real fingerprint is already configured: the parrot key is dead
			// weight, drop it but don't pretend we changed the persona.
			*warnings = append(*warnings, "legacy QUIC parrot key dropped (utls.fingerprint already set)")
			return
		}
		existing["enabled"] = true
		existing["fingerprint"] = fp
		*warnings = append(*warnings, "legacy QUIC parrot key migrated to utls.fingerprint="+fp)
		return
	}
	m["utls"] = map[string]interface{}{"enabled": true, "fingerprint": fp}
	*warnings = append(*warnings, "legacy QUIC parrot key migrated to utls.fingerprint="+fp)
}

// migrateHysteriaBandwidth: hy/hy2 up_mbps/down_mbps/up/down/brutal_debug/
// ignore_client_bandwidth are hard-rejected in 1.5. A positive bandwidth cap
// maps to congestion_control=brutal + brutal_mbps (the send rate: up, falling
// back to down).
func migrateHysteriaBandwidth(m map[string]interface{}, warnings *[]string) {
	legacyKeys := []string{"up_mbps", "down_mbps", "up", "down", "brutal_debug", "ignore_client_bandwidth"}
	present := false
	for _, k := range legacyKeys {
		if _, ok := m[k]; ok {
			present = true
		}
	}
	if !present {
		return
	}
	up := bandwidthMbps(m["up_mbps"], m["up"])
	down := bandwidthMbps(m["down_mbps"], m["down"])
	for _, k := range legacyKeys {
		delete(m, k)
	}
	label := fmt.Sprintf("%s %q", leafType(m), leafTag(m))
	applyHysteriaBandwidthCap(m, up, down, label, warnings)
}

// applyHysteriaBandwidthCap writes the 1.5 congestion_control/brutal_mbps pair
// for a legacy up/down bandwidth pair. The engine rejects brutal_mbps unless
// congestion_control is brutal (option.ValidateQUICCongestion), so an explicit
// non-brutal CC wins and the legacy cap is dropped with a warning.
func applyHysteriaBandwidthCap(m map[string]interface{}, up, down int, label string, warnings *[]string) {
	// brutal_mbps is the fixed *send* rate (option.QUICOptions.BrutalMbps,
	// option/http.go:43) and 1.4 up_mbps/up was the client's send cap, so the
	// uplink is the axis to carry over. max(up, down) turned a 50/500 line into
	// a 500 Mbps send rate on a 50 Mbps uplink. down is only a fallback for
	// profiles that never declared an uplink cap.
	capMbps := up
	if capMbps == 0 {
		capMbps = down
	}
	cc, _ := m["congestion_control"].(string)
	cc = strings.TrimSpace(cc)
	switch {
	case cc == "brutal":
		if capMbps > 0 {
			m["brutal_mbps"] = capMbps
			*warnings = append(*warnings, fmt.Sprintf("%s: up/down(_mbps) migrated to brutal_mbps=%d", label, capMbps))
		}
	case cc == "" && capMbps > 0:
		m["congestion_control"] = "brutal"
		m["brutal_mbps"] = capMbps
		*warnings = append(*warnings, fmt.Sprintf("%s: up/down(_mbps) migrated to brutal_mbps=%d", label, capMbps))
	case capMbps > 0:
		// congestion_control was set explicitly to something other than brutal;
		// keeping brutal_mbps would fail validation, so the legacy cap is lost.
		*warnings = append(*warnings, fmt.Sprintf("%s: legacy bandwidth keys dropped (congestion_control=%s is not brutal)", label, cc))
	default:
		*warnings = append(*warnings, fmt.Sprintf("%s: legacy bandwidth keys dropped (no cap set)", label))
	}
}

// bandwidthMbps parses numeric or string bandwidth values ("200", 200,
// "100 Mbps", "100Mbps", "1 Gbps"); the maximum wins (up/down pair). Values it
// cannot parse are ignored (0).
func bandwidthMbps(values ...interface{}) int {
	best := 0
	for _, v := range values {
		if n := parseMbpsValue(v); n > best {
			best = n
		}
	}
	return best
}

func parseMbpsValue(v interface{}) int {
	switch t := v.(type) {
	case nil:
		return 0
	case int:
		return t
	case int32:
		return int(t)
	case int64:
		return int(t)
	case float32:
		return int(t)
	case float64:
		return int(t)
	case string:
		return parseMbpsString(t)
	}
	return 0
}

// parseMbpsString accepts "100 Mbps", "100Mbps", "100mb/s", "1 Gbps", "1.5G".
func parseMbpsString(s string) int {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return 0
	}
	mult := 1.0
	switch {
	case strings.HasSuffix(s, "gbps"), strings.HasSuffix(s, "gbit"), strings.HasSuffix(s, "gb/s"):
		mult = 1000
		s = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(s, "gbps"), "gbit"), "gb/s")
	case strings.HasSuffix(s, "mbps"), strings.HasSuffix(s, "mbit"), strings.HasSuffix(s, "mb/s"):
		s = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(s, "mbps"), "mbit"), "mb/s")
	case strings.HasSuffix(s, "kbps"), strings.HasSuffix(s, "kbit"):
		s = strings.TrimSuffix(strings.TrimSuffix(s, "kbps"), "kbit")
		mult = 0.001
	case strings.HasSuffix(s, "gb"), strings.HasSuffix(s, "g"):
		s = strings.TrimSuffix(strings.TrimSuffix(s, "gb"), "g")
		mult = 1000
	case strings.HasSuffix(s, "mb"), strings.HasSuffix(s, "m"):
		s = strings.TrimSuffix(strings.TrimSuffix(s, "mb"), "m")
	case strings.HasSuffix(s, "kb"), strings.HasSuffix(s, "k"):
		s = strings.TrimSuffix(strings.TrimSuffix(s, "kb"), "k")
		mult = 0.001
	}
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), ","))
	if s == "" {
		return 0
	}
	n, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return int(n * mult)
}

// migrateImplicitTLS: in 1.5 the QUIC/TLS-mandatory protocols
// (hysteria, hysteria2, tuic, anytls, naive) fail with "TLS required" when the
// tls block is absent or disabled — 1.4 defaulted TLS on. Restore the implicit
// default explicitly.
func migrateImplicitTLS(m map[string]interface{}, warnings *[]string) {
	if tlsBlock, ok := m["tls"].(map[string]interface{}); ok {
		if enabled, _ := tlsBlock["enabled"].(bool); enabled {
			return
		}
		tlsBlock["enabled"] = true
	} else {
		m["tls"] = map[string]interface{}{"enabled": true}
	}
	*warnings = append(*warnings, fmt.Sprintf("%s %q: tls.enabled=true restored (1.5 requires an explicit tls block)", leafType(m), leafTag(m)))
}

// migrateTrustTunnel: 1.4 trusttunnel had a private TLS block shape; 1.5 uses
// the standard tls container + root-level QUIC knobs. Inbound trusttunnel
// rejects remote_id/quic_auth at root (option/trusttunnel_unmarshal.go), so
// those two are dropped rather than lifted when the leaf is an inbound.
func migrateTrustTunnel(m map[string]interface{}, isInbound bool, warnings *[]string) {
	tls, _ := m["tls"].(map[string]interface{})
	if tls != nil {
		if v, ok := tls["skip_verification"]; ok {
			delete(tls, "skip_verification")
			if _, set := tls["insecure"]; !set {
				tls["insecure"] = v
			}
			*warnings = append(*warnings, "trusttunnel tls.skip_verification → tls.insecure")
		}
		if v, ok := tls["private_key"]; ok {
			delete(tls, "private_key")
			if _, set := tls["key"]; !set {
				tls["key"] = v
			}
			*warnings = append(*warnings, "trusttunnel tls.private_key → tls.key")
		}
		if v, ok := tls["remote_id"]; ok {
			delete(tls, "remote_id")
			if isInbound {
				*warnings = append(*warnings, "trusttunnel inbound tls.remote_id dropped (inbound rejects remote_id)")
			} else if _, set := m["remote_id"]; !set {
				m["remote_id"] = v
				*warnings = append(*warnings, "trusttunnel tls.remote_id → remote_id")
			}
		}
	}
	transport, _ := m["transport"].(map[string]interface{})
	if transport != nil {
		for _, k := range []string{"utls", "zero_rtt_handshake", "session_tickets", "quic_auth"} {
			if v, ok := transport[k]; ok {
				delete(transport, k)
				if isInbound && k == "quic_auth" {
					*warnings = append(*warnings, "trusttunnel inbound transport.quic_auth dropped (inbound rejects quic_auth)")
					continue
				}
				if _, set := m[k]; !set {
					m[k] = v
				}
				*warnings = append(*warnings, "trusttunnel transport."+k+" → root "+k)
			}
		}
		if v, ok := transport["max_idle_timeout"]; ok {
			delete(transport, "max_idle_timeout")
			if _, set := m["idle_timeout"]; !set {
				m["idle_timeout"] = v
			}
			*warnings = append(*warnings, "trusttunnel transport.max_idle_timeout → idle_timeout")
		}
	}
}

// migratePadProfile: pathologywg/pathology pad_profile was removed in 1.5
// (hard reject in option/wireguard_pathology.go, hint: use persona + pad_budget).
// The profiles carry no mechanical translation, so the key is dropped and the
// leaf falls back to the engine's default persona.
func migratePadProfile(m map[string]interface{}, warnings *[]string) {
	if _, ok := m["pad_profile"]; !ok {
		return
	}
	delete(m, "pad_profile")
	*warnings = append(*warnings, "pathologywg: pad_profile dropped (removed in 1.5; persona/pad_budget take over, default persona applies)")
}

// migrateNestedHysteriaBandwidth covers hysteria bandwidth keys inside v2ray
// transports (vless/vmess/trojan method=hysteria), where the engine also
// hard-rejects RemovedHyMbpsKeys. The top-level leaf case is handled by the
// caller's type switch; this visitor handles any transport-shaped block.
func migrateNestedHysteriaBandwidth(m map[string]interface{}, warnings *[]string) {
	method, _ := m["method"].(string)
	if strings.ToLower(strings.TrimSpace(method)) != "hysteria" {
		return
	}
	legacyKeys := []string{"up_mbps", "down_mbps", "up", "down"}
	present := false
	for _, k := range legacyKeys {
		if _, ok := m[k]; ok {
			present = true
		}
	}
	if !present {
		return
	}
	up := bandwidthMbps(m["up_mbps"], m["up"])
	down := bandwidthMbps(m["down_mbps"], m["down"])
	for _, k := range legacyKeys {
		delete(m, k)
	}
	applyHysteriaBandwidthCap(m, up, down, "v2ray transport hysteria", warnings)
}

// migrateVLESSFlow: legacy vision flow names are rejected in 1.5; "xray" is
// the accepted sugar that the engine expands to tls.shaping.vision.
func migrateVLESSFlow(m map[string]interface{}, warnings *[]string) {
	flow, _ := m["flow"].(string)
	switch strings.ToLower(strings.TrimSpace(flow)) {
	case "xtls-rprx-vision", "xtls-rprx-vision-udp443":
		m["flow"] = "xray"
		*warnings = append(*warnings, fmt.Sprintf("vless %q: flow %q → xray", leafTag(m), flow))
	}
}

// migrateRouteDirectAction: route rule action "direct" was removed in 1.5
// (earlier than upstream); the equivalent is action "route" with the direct
// outbound tag. Logical rules carry a nested rules[] that must be walked too.
func migrateRouteDirectAction(root map[string]interface{}, warnings *[]string) {
	route, _ := root["route"].(map[string]interface{})
	if route == nil {
		return
	}
	migrateRuleListActionDirect(route["rules"], warnings)
}

// migrateRuleListActionDirect rewrites action "direct" in a rule list and
// recurses into logical rules (type "logical"), whose children live under
// "rules". Without the recursion a legacy "direct" nested in a logical rule
// survives into the 1.5 parser and fails the whole import.
func migrateRuleListActionDirect(list interface{}, warnings *[]string) {
	rules, _ := list.([]interface{})
	for _, item := range rules {
		rule, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if action, _ := rule["action"].(string); action == "direct" {
			rule["action"] = "route"
			if _, set := rule["outbound"]; !set {
				rule["outbound"] = "direct"
			}
			*warnings = append(*warnings, "route rule: action direct → route + outbound direct")
		}
		if nested, ok := rule["rules"]; ok {
			migrateRuleListActionDirect(nested, warnings)
		}
	}
}

// ---------------------------------------------------------------------------
// Legacy geo matchers: geosite / geoip / source_geoip
// ---------------------------------------------------------------------------

// These mirror constant.RuleSetTypeRemote / constant.RuleSetFormatBinary; the
// migrator works on raw JSON shapes and stays free of engine imports.
const (
	geoKindGeoSite   = "geosite"
	geoKindGeoIP     = "geoip"
	ruleSetRemote    = "remote"
	ruleSetBinFormat = "binary"
)

// migrateGeoRules rewrites the 1.4 geo matchers in route and dns rules into 1.5
// rule_set references.
//
// The 1.5 engine hard-errors on geosite/geoip/source_geoip (route/rule/
// rule_default.go:124-132 and route/rule/rule_dns.go:188-196: "geosite database
// is deprecated in sing-box 1.8.0 and removed in sing-box 1.12.0"). Rules are
// built inside router.Initialize, which box.New calls, so one legacy key fails
// the entire import; filterValidLeavesJSON has no per-rule drop path (it
// isolates outbounds/endpoints/inbounds only). The keys have to go here.
//
// geosite: ["cn","ads"] → the rule keeps its other conditions and gains
// rule_set ["geosite-cn","geosite-ads"]; each tag is backed by a synthesized
// remote rule-set in route.rule_set, built from the same URL template the
// routing-profile compiler uses (DefaultGeoSiteRuleSetURL). geoip: → geoip-<code>
// with DefaultGeoIPRuleSetURL. Existing rule_set entries are preserved and stay
// first.
//
// source_geoip: the geoip rule-sets cannot just be added — a rule_set matcher
// compares the *destination*, and the engine's only source-side switch
// (rule_set_ip_cidr_match_source) is rule-wide, so it would also turn a
// destination geoip/geosite entry of the same rule into a source match. Rather
// than change what the rule matches, source_geoip is dropped and the lost
// source scoping is reported: one legacy key must never fail the whole import.
func migrateGeoRules(root map[string]interface{}, warnings *[]string) {
	if route, ok := root["route"].(map[string]interface{}); ok {
		migrateRuleListGeo(route, "rules", root, "route rule", warnings)
	}
	// DNS rules declare the same rule_set field (option.RawDefaultDNSRule) and
	// resolve it through the same route router — route.Router.Initialize runs
	// before dns.Router.Initialize in box.New, so the tags already exist when
	// the DNS router builds its rules. The rewrite is therefore identical.
	if dns, ok := root["dns"].(map[string]interface{}); ok {
		migrateRuleListGeo(dns, "rules", root, "dns rule", warnings)
	}
}

// migrateRuleListGeo rewrites geo matchers in parent[key] and recurses into
// logical rules, whose children live under "rules": a geosite nested in a
// logical rule fails box.New just the same.
func migrateRuleListGeo(parent map[string]interface{}, key string, root map[string]interface{}, label string, warnings *[]string) {
	rules, ok := parent[key].([]interface{})
	if !ok {
		return
	}
	kept := make([]interface{}, 0, len(rules))
	dropped := false
	for _, item := range rules {
		rule, isRule := item.(map[string]interface{})
		if !isRule {
			kept = append(kept, item)
			continue
		}
		hadGeo := migrateRuleGeo(rule, root, label, warnings)
		if _, isList := rule["rules"].([]interface{}); isList {
			migrateRuleListGeo(rule, "rules", root, label, warnings)
		}
		// A rule whose only matcher was a dropped geo key would reach the
		// engine as "missing conditions" and fail the whole import. Dropping
		// the rule keeps the invariant (a legacy key never costs the import):
		// the traffic it used to match simply falls through to the rules after
		// it. Rules that arrived without matchers are left alone — they were
		// invalid in 1.4 too and stay the engine's business.
		if hadGeo && !ruleHasCondition(rule) {
			*warnings = append(*warnings, fmt.Sprintf("%s: rule dropped — its only matchers were legacy geo keys and a conditionless rule would fail the import", label))
			dropped = true
			continue
		}
		kept = append(kept, item)
	}
	if dropped {
		parent[key] = kept
	}
}

// migrateRuleGeo rewrites one rule map in place, reports what it changed and
// says whether the rule carried any geo key at all.
func migrateRuleGeo(rule map[string]interface{}, root map[string]interface{}, label string, warnings *[]string) bool {
	hadGeo := false
	var tags []string
	for _, kind := range []string{geoKindGeoSite, geoKindGeoIP} {
		raw, ok := rule[kind]
		if !ok {
			continue
		}
		hadGeo = true
		delete(rule, kind)
		codes := stringList(raw)
		if len(codes) == 0 {
			*warnings = append(*warnings, fmt.Sprintf("%s: empty %s dropped", label, kind))
			continue
		}
		for _, code := range codes {
			code = strings.ToLower(strings.TrimSpace(code))
			if code == "" {
				continue
			}
			tag := ensureGeoRuleSet(root, kind, code)
			tags = append(tags, tag)
			*warnings = append(*warnings, fmt.Sprintf("%s: %s %q → rule_set %q", label, kind, code, tag))
		}
	}
	if raw, ok := rule["source_geoip"]; ok {
		hadGeo = true
		delete(rule, "source_geoip")
		*warnings = append(*warnings, fmt.Sprintf("%s: source_geoip [%s] dropped — source-side geoip matching is not carried over (the geoip database was removed in 1.5; a rule_set matcher compares the destination)", label, strings.Join(stringList(raw), ", ")))
	}
	appendRuleSetRefs(rule, tags)
	return hadGeo
}

// isRuleNonMatcherKey reports whether a rule key carries no match condition:
// the rule kind and its action. A rule whose keys are all such keys matches
// nothing on its own, and the 1.5 engine rejects it with "missing conditions".
// Anything unknown counts as a condition (the safe direction: such a rule is
// left for the engine to judge instead of being thrown away here).
func isRuleNonMatcherKey(key string) bool {
	switch key {
	case "type", "mode", "invert", "rules",
		"action", "outbound", "server", "strategy",
		"method", "no_drop", "sniffer", "timeout",
		"override_address", "override_port",
		"disable_cache", "disable_optimistic_cache", "rewrite_ttl", "client_subnet",
		"rcode", "answer", "ns", "extra":
		return true
	}
	return false
}

// ruleHasCondition reports whether a rule still carries a matcher. A logical
// rule is matched by its children, so an empty children list is not a
// condition (and "and" over nothing matches everything).
func ruleHasCondition(rule map[string]interface{}) bool {
	if leafType(rule) == "logical" {
		children, _ := rule["rules"].([]interface{})
		return len(children) > 0
	}
	for key := range rule {
		if !isRuleNonMatcherKey(key) {
			return true
		}
	}
	return false
}

// ensureGeoRuleSet returns the rule-set tag for a geo code and makes sure
// route.rule_set declares it. The tag already being declared (by us on a
// previous rule, or by the subscription itself) is a no-op: the engine rejects
// a duplicate rule-set tag.
func ensureGeoRuleSet(root map[string]interface{}, kind, code string) string {
	tag := kind + "-" + code
	route, ok := root["route"].(map[string]interface{})
	if !ok {
		// A missing (or null) route is normal. A non-object route is already
		// invalid and cannot carry rule_set, so a fresh object is the only way
		// to keep the synthesized reference resolvable.
		route = map[string]interface{}{}
		root["route"] = route
	}
	sets, _ := route["rule_set"].([]interface{})
	for _, item := range sets {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		for _, existing := range stringList(m["tag"]) {
			if strings.TrimSpace(existing) == tag {
				return tag
			}
		}
	}
	url := DefaultGeoSiteRuleSetURL
	if kind == geoKindGeoIP {
		url = DefaultGeoIPRuleSetURL
	}
	route["rule_set"] = append(sets, map[string]interface{}{
		"type":   ruleSetRemote,
		"tag":    tag,
		"format": ruleSetBinFormat,
		"url":    strings.ReplaceAll(url, "{tag}", code),
	})
	return tag
}

// appendRuleSetRefs adds tags to a rule's rule_set list, keeping the existing
// entries first and skipping tags that are already there.
func appendRuleSetRefs(rule map[string]interface{}, tags []string) {
	if len(tags) == 0 {
		return
	}
	var existing []interface{}
	switch raw := rule["rule_set"].(type) {
	case []interface{}:
		existing = append(existing, raw...)
	case string:
		existing = append(existing, raw)
	}
	seen := make(map[string]bool, len(existing)+len(tags))
	for _, item := range existing {
		if s, ok := item.(string); ok {
			seen[strings.TrimSpace(s)] = true
		}
	}
	changed := false
	for _, tag := range tags {
		if seen[tag] {
			continue
		}
		seen[tag] = true
		existing = append(existing, tag)
		changed = true
	}
	if changed {
		rule["rule_set"] = existing
	}
}

// ---------------------------------------------------------------------------
// Legacy inbound fields: sniff / domain_strategy / tun addresses
// ---------------------------------------------------------------------------

// legacyInboundDropKeys are the 1.4 inbound fields the 1.5 engine rejects.
// option.InboundOptions is embedded in every inbound's listen options and
// option.Inbound.UnmarshalJSON rejects any non-zero instance ("legacy inbound
// fields are deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0"), so
// a single one of them makes the whole document unparsable — on the import path
// the leaf is dropped, on Start the profile fails outright.
var legacyInboundDropKeys = []string{
	"sniff_override_destination",
	"sniff_timeout",
	"domain_strategy",
	"udp_disable_domain_unmapping",
}

// migrateLegacyInboundFields strips the deprecated inbound fields and lifts
// sniff: true into a route rule action.
//
// 1.4 sniffed per inbound; 1.5 only sniffs where a rule asks for it
// (docs/migration.md, "Migrate legacy inbound fields to rule actions"). One
// match-all {"action":"sniff"} rule is emitted for the document: the action
// does not terminate matching, so a single rule reproduces per-inbound sniffing.
// It goes to the top of route.rules — appended after the route/reject rules it
// would never run, because the first matching route rule already sent the
// connection on its way.
func migrateLegacyInboundFields(root map[string]interface{}, warnings *[]string) {
	list, _ := root["inbounds"].([]interface{})
	needSniff := false
	for _, item := range list {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		label := fmt.Sprintf("%s %q", leafType(m), leafTag(m))
		if v, ok := m["sniff"]; ok {
			delete(m, "sniff")
			if enabled, _ := v.(bool); enabled {
				needSniff = true
			}
		}
		for _, key := range legacyInboundDropKeys {
			if _, ok := m[key]; !ok {
				continue
			}
			delete(m, key)
			*warnings = append(*warnings, fmt.Sprintf("%s: legacy %s dropped (1.5 rejects inbound sniff options; use a route rule action instead)", label, key))
		}
	}
	if needSniff {
		// Reported either way: a document that already sniffed through a rule
		// needs no new one, but the user should still learn that the inbound
		// switch was folded into it.
		if ensureSniffRouteRule(root) {
			*warnings = append(*warnings, "inbound sniff: true migrated to an action=sniff route rule at the top of route.rules")
		} else {
			*warnings = append(*warnings, "inbound sniff: true dropped (the document already has an action=sniff route rule)")
		}
	}
}

// ensureSniffRouteRule prepends the sniff action unless the document already
// carries one (the idempotency guard: a second migrator pass must not add a
// second copy). Reports whether a rule was added.
func ensureSniffRouteRule(root map[string]interface{}) bool {
	route, ok := root["route"].(map[string]interface{})
	if !ok {
		route = map[string]interface{}{}
		root["route"] = route
	}
	rules, _ := route["rules"].([]interface{})
	for _, item := range rules {
		rule, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if action, _ := rule["action"].(string); strings.TrimSpace(action) == "sniff" {
			return false
		}
	}
	route["rules"] = append([]interface{}{map[string]interface{}{"action": "sniff"}}, rules...)
	return true
}

// migrateTunLegacyAddresses merges the 1.4 tun address fields into the 1.5
// shape. protocol/tun/inbound.go rejects inet4_address/inet6_address and the
// four route_* variants outright ("legacy tun address fields are deprecated in
// sing-box 1.10.0 and removed in sing-box 1.12.0") and `gso` on its own line,
// so a 1.4 tun inbound cannot be built at all: on the import path the soft
// filter drops the inbound, taking the whole tunnel with it.
func migrateTunLegacyAddresses(m map[string]interface{}, warnings *[]string) {
	label := fmt.Sprintf("tun %q", leafTag(m))
	mergeTunAddressList(m, label, "address", "inet4_address", "inet6_address", warnings)
	mergeTunAddressList(m, label, "route_address", "inet4_route_address", "inet6_route_address", warnings)
	mergeTunAddressList(m, label, "route_exclude_address", "inet4_route_exclude_address", "inet6_route_exclude_address", warnings)
	if v, ok := m["gso"]; ok {
		delete(m, "gso")
		if enabled, _ := v.(bool); enabled {
			*warnings = append(*warnings, label+": gso dropped (removed in 1.5; the optimized path is always used)")
		}
	}
}

// mergeTunAddressList folds the legacy inet4_*/inet6_* pair into their 1.5
// list: existing entries first, then v4, then v6, exact duplicates skipped. The
// source keys are deleted even when they were the only entries, so a second
// pass finds nothing to merge.
func mergeTunAddressList(m map[string]interface{}, label, dst, v4, v6 string, warnings *[]string) {
	raw4, has4 := m[v4]
	raw6, has6 := m[v6]
	if !has4 && !has6 {
		return
	}
	delete(m, v4)
	delete(m, v6)
	merged := make([]interface{}, 0, 4)
	seen := make(map[string]bool)
	for _, item := range listValue(m[dst]) {
		key := fmt.Sprint(item)
		if seen[key] {
			continue
		}
		seen[key] = true
		merged = append(merged, item)
	}
	for _, raw := range []interface{}{raw4, raw6} {
		for _, entry := range stringList(raw) {
			entry = strings.TrimSpace(entry)
			if entry == "" || seen[entry] {
				continue
			}
			seen[entry] = true
			merged = append(merged, entry)
		}
	}
	if len(merged) > 0 {
		m[dst] = merged
	}
	var keys []string
	if has4 {
		keys = append(keys, v4)
	}
	if has6 {
		keys = append(keys, v6)
	}
	*warnings = append(*warnings, fmt.Sprintf("%s: %s merged into %s", label, strings.Join(keys, " + "), dst))
}

// listValue reads a decoded JSON list, unwrapping the bare-string shape.
func listValue(value interface{}) []interface{} {
	switch typed := value.(type) {
	case []interface{}:
		return typed
	case string:
		if typed == "" {
			return nil
		}
		return []interface{}{typed}
	}
	return nil
}

// stringList returns the string entries of a decoded JSON list. sing-box
// accepts a bare string wherever it accepts a list, so that shape is unwrapped
// too; anything else yields nil.
func stringList(value interface{}) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case []string:
		return typed
	case []interface{}:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
