package config

import (
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

// outboundServerHost extracts the dialed server host from an outbound.
//
// It used to marshal the value to JSON and unmarshal it into a map just to look
// for a "server" key, once per leaf. For the values builder.go actually passes
// that round-trip could NEVER succeed: option.Outbound keeps every protocol
// field in Options (json:"-") and defines MarshalJSONContext, not MarshalJSON,
// so encoding/json renders it as {"type":..,"tag":..} and there is no "server"
// key to find. The function therefore always returned "".
//
// That made the server-host half of IsIPv6Leaf dead: only the "-ipv6" TAG
// suffix ever filtered anything, so a node whose server is an IPv6 literal
// survived into a build that cannot dial it. Reading the host through the
// engine's own ServerOptionsWrapper fixes the filter without any marshalling —
// every outbound options struct embeds ServerOptions, so the interface covers
// them all and there is no type switch to keep in sync.
//
// A genuinely dynamic object still takes the map branch: decoded subscription
// JSON has not been turned into typed options yet at that point.
func outboundServerHost(out any) string {
	switch typed := out.(type) {
	case option.Outbound:
		return outboundServerHost(typed.Options)
	case map[string]interface{}:
		return serverHostFromMap(typed)
	case option.ServerOptionsWrapper:
		return strings.TrimSpace(typed.TakeServerOptions().Server)
	default:
		return ""
	}
}

// serverHostFromMap reads "server" from a decoded subscription object, top-level
// first and then under "options" (the shape option.Outbound would render if it
// ever gained a flattening MarshalJSON).
func serverHostFromMap(m map[string]interface{}) string {
	if s, ok := m["server"].(string); ok {
		return strings.TrimSpace(s)
	}
	if opts, ok := m["options"].(map[string]interface{}); ok {
		if s, ok := opts["server"].(string); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}
