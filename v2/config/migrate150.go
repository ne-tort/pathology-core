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
				migrateTrustTunnel(m, &warnings)
			case "vless":
				migrateVLESSFlow(m, &warnings)
			case "tuic", "anytls", "naive":
				migrateImplicitTLS(m, &warnings)
			}
			if leafType(m) == "masque" && listKey == "outbounds" {
				m["type"] = "warpsque"
				warnings = append(warnings, fmt.Sprintf("outbound %q: type masque renamed to warpsque", leafTag(m)))
			}
			if leafType(m) == "mesh_underlay" {
				warnings = append(warnings, fmt.Sprintf("outbound %q: mesh_underlay was removed in 1.5 (use a tlspoint endpoint); the leaf will fail validation and be dropped", leafTag(m)))
			}
		}
	}
	migrateRouteDirectAction(root, &warnings)
	return warnings
}

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
		if _, set := existing["fingerprint"]; !set {
			existing["enabled"] = true
			existing["fingerprint"] = fp
			*warnings = append(*warnings, "legacy QUIC parrot key migrated to utls.fingerprint="+fp)
		}
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
	capMbps := up
	if down > capMbps {
		capMbps = down
	}
	if capMbps > 0 {
		if _, set := m["congestion_control"]; !set {
			m["congestion_control"] = "brutal"
		}
		m["brutal_mbps"] = capMbps
		*warnings = append(*warnings, fmt.Sprintf("%s %q: up/down(_mbps) migrated to brutal_mbps=%d", leafType(m), leafTag(m), capMbps))
	} else {
		*warnings = append(*warnings, fmt.Sprintf("%s %q: legacy bandwidth keys dropped (no cap set)", leafType(m), leafTag(m)))
	}
}

// bandwidthMbps parses numeric or "100 Mbps"-style bandwidth values; with
// several values the maximum wins (up/down pair).
func bandwidthMbps(values ...interface{}) int {
	max := 0
	for _, v := range values {
		var n int
		switch t := v.(type) {
		case float64:
			n = int(t)
		case string:
			fields := strings.Fields(t)
			if len(fields) == 0 {
				continue
			}
			parsed, err := strconv.Atoi(strings.TrimSuffix(fields[0], ","))
			if err != nil {
				continue
			}
			n = parsed
		}
		if n > max {
			max = n
		}
	}
	return max
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
// the standard tls container + root-level QUIC knobs.
func migrateTrustTunnel(m map[string]interface{}, warnings *[]string) {
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
			if _, set := m["remote_id"]; !set {
				m["remote_id"] = v
			}
			*warnings = append(*warnings, "trusttunnel tls.remote_id → remote_id")
		}
	}
	transport, _ := m["transport"].(map[string]interface{})
	if transport != nil {
		for _, k := range []string{"utls", "zero_rtt_handshake", "session_tickets", "quic_auth"} {
			if v, ok := transport[k]; ok {
				delete(transport, k)
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
// outbound tag.
func migrateRouteDirectAction(root map[string]interface{}, warnings *[]string) {
	route, _ := root["route"].(map[string]interface{})
	if route == nil {
		return
	}
	rules, _ := route["rules"].([]interface{})
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
	}
}
