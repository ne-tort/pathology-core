package config

import (
	"encoding/json"
	"net"
	"strings"

	"github.com/sagernet/sing-box/option"
)

// KeepIPv6Leaves reports whether IPv6 server leaves should stay in the build.
// Requires usable global OS IPv6 (see hasUsableGlobalIPv6) and subscription-ipv6=true.
func KeepIPv6Leaves(osIPv6OK, subscriptionIPv6 bool) bool {
	return osIPv6OK && subscriptionIPv6
}

// IsIPv6LeafTag reports tags produced by CP node expand (suffix -ipv6).
func IsIPv6LeafTag(tag string) bool {
	return strings.HasSuffix(tag, "-ipv6")
}

// IsIPv6Host reports whether host is an IPv6 literal (brackets optional).
func IsIPv6Host(host string) bool {
	h := strings.TrimSpace(host)
	if h == "" {
		return false
	}
	if strings.HasPrefix(h, "[") {
		if i := strings.IndexByte(h, ']'); i > 1 {
			h = h[1:i]
		}
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.To4() == nil
}

// IsIPv6Leaf reports whether a leaf should be treated as IPv6-only for filtering.
func IsIPv6Leaf(tag, serverHost string) bool {
	if IsIPv6LeafTag(tag) {
		return true
	}
	return IsIPv6Host(serverHost)
}

// dialerDetourIsIPv6Leaf reports whether opts expose a DialerOptions.Detour that
// is an IPv6 leaf tag (suffix -ipv6), including namespaced tags ("profile · x-ipv6").
func dialerDetourIsIPv6Leaf(opts any) bool {
	w, ok := opts.(option.DialerOptionsWrapper)
	if !ok {
		return false
	}
	return IsIPv6LeafTag(w.TakeDialerOptions().Detour)
}

// outboundServerHost extracts a best-effort server/peer host from an outbound via JSON.
func outboundServerHost(out any) string {
	raw, err := json.Marshal(out)
	if err != nil {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return ""
	}
	if s, ok := m["server"].(string); ok {
		return strings.TrimSpace(s)
	}
	opts, _ := m["options"].(map[string]any)
	if opts != nil {
		if s, ok := opts["server"].(string); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}
