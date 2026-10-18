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
// legacy vision flow names, pad_profile). A subscription carrying any of them
// would fail to import at all. The migrator rewrites them to their 1.5
// equivalents and reports what it changed; unknown content passes through
// untouched. All transforms are idempotent (second run is a no-op).

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
// maps to congestion_control=brutal + brutal_mbps (max of up/down).
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
	capMbps := up
	if down > capMbps {
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
