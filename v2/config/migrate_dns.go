package config

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

// migrate_dns.go — 1.4 → 1.5 DNS migration and per-block isolation.
//
// The 1.5 DNS block has no legacy mode at all: option.DNSOptions rejects the
// 1.4 dns.fakeip object outright ("legacy DNS fakeip options are deprecated …
// and removed in sing-box 1.14.0") and option.DNSServerOptions rejects a server
// without a `type`, i.e. the whole 1.4 `address` form ("legacy DNS server
// formats are … removed"). DNSOptions is decoded as part of option.Options, so
// ONE stale DNS line failed the entire subscription import — there is no
// per-entry error to catch, the document simply does not decode.
//
// Two layers fix that, mirroring how outbounds are handled:
//
//   - migrateDNS rewrites the legacy forms that have an unambiguous 1.5
//     counterpart (runs inside MigrateLegacyJSON, so the JSON, Clash, v2ray and
//     Start-time re-parse paths all get it);
//   - isolateDNSBlock (called by filterValidLeavesJSON) drops the individual
//     servers/rules that still cannot be decoded, and only falls back to
//     dropping the whole block — the client then builds its own DNS template —
//     when the block itself is broken.
//
// Everything here is idempotent: a second pass finds no legacy form left and
// reports nothing.

// 1.4 defaults of the dns.fakeip block (option.LegacyDNSFakeIPOptions): the same
// ranges the client's own fakeip server uses (server_dns_fragment.dart).
const (
	legacyFakeIPInet4 = "198.18.0.0/15"
	legacyFakeIPInet6 = "fc00::/18"
)

// legacyRcodeNames maps the 1.4 rcode:// host to the 1.5 predefined-action rcode
// name. 1.5 has no rcode DNS transport (the type is gone from
// constant.DNSType*), the equivalent is a rule with action "predefined".
var legacyRcodeNames = map[string]string{
	"success":         "NOERROR",
	"format_error":    "FORMERR",
	"server_failure":  "SERVFAIL",
	"name_error":      "NXDOMAIN",
	"not_implemented": "NOTIMP",
	"refused":         "REFUSED",
}

// dnsMigrationState carries what one migration pass learned about the block:
// which rcode servers were removed, so the rules that referenced them can
// become predefined actions instead of dangling, and the ranges the dropped
// dns.fakeip block contributed.
type dnsMigrationState struct {
	rcodeServers   map[string]string
	fakeipInet4    string
	fakeipInet6    string
	fakeipDisabled bool
}

// migrateDNS rewrites the legacy DNS forms of root["dns"] in place and reports
// what it changed. A non-object dns value is left alone: isolateDNSBlock owns
// that defect (it needs the parse-warning collector).
func migrateDNS(root map[string]interface{}, warnings *[]string) {
	dns, ok := root["dns"].(map[string]interface{})
	if !ok || dns == nil {
		return
	}
	state := &dnsMigrationState{rcodeServers: map[string]string{}}
	migrateDNSFakeIPBlock(dns, state, warnings)
	migrateDNSServerList(dns, state, warnings)
	ensureDomainResolvers(dns, warnings)
	fixDNSServerOrder(dns, warnings)
	migrateDNSServerRefs(dns, state, warnings)
}

// ensureDomainResolvers supplies the bootstrap resolver that the 1.4 `address`
// form provided implicitly. 1.5 builds a DNS server's dialer with
// DirectResolver and refuses a domain-addressed server that has neither a detour
// nor a domain_resolver — CheckConfigOptions fails the import with "missing
// domain resolver for domain server address". 1.4 resolved such a name through
// the system resolver, so a `local` server is declared (unless the profile
// already has one) and named. This applies to 1.5-native entries too: the same
// profile written by hand is just as unbuildable.
func ensureDomainResolvers(dns map[string]interface{}, warnings *[]string) {
	list, ok := dns["servers"].([]interface{})
	if !ok {
		return
	}
	var pending []map[string]interface{}
	for _, item := range list {
		server, isMap := item.(map[string]interface{})
		if !isMap || hasNonEmptyString(server, "detour") || hasNonEmptyString(server, "domain_resolver") {
			continue
		}
		address, _ := server["server"].(string)
		if address == "" || net.ParseIP(strings.Trim(address, "[]")) != nil {
			continue
		}
		pending = append(pending, server)
	}
	if len(pending) == 0 {
		return
	}
	localTag := ""
	for _, item := range list {
		server, isMap := item.(map[string]interface{})
		if !isMap || leafType(server) != C.DNSTypeLocal {
			continue
		}
		if tag := leafTag(server); tag != "" {
			localTag = tag
			break
		}
	}
	if localTag == "" {
		list = append(list, map[string]interface{}{"type": C.DNSTypeLocal, "tag": C.DNSTypeLocal})
		dns["servers"] = list
		localTag = C.DNSTypeLocal
		*warnings = append(*warnings, "dns.servers: added type=local tag=local as the bootstrap resolver for domain-addressed servers")
	}
	for _, server := range pending {
		server["domain_resolver"] = localTag
		*warnings = append(*warnings, fmt.Sprintf("dns server %q: domain_resolver=%s added (1.5 requires an explicit resolver for a domain-addressed server)", leafTag(server), localTag))
	}
}

// hasNonEmptyString reports whether key holds a non-blank string.
func hasNonEmptyString(m map[string]interface{}, key string) bool {
	value, ok := m[key].(string)
	return ok && strings.TrimSpace(value) != ""
}

// migrateDNSFakeIPBlock drops the 1.4 dns.fakeip object. 1.5 has no block: the
// equivalent is a `fakeip` DNS server, and the client already builds its own
// fakeip setup, so the ranges are only remembered for a legacy `address:
// "fakeip"` server in the same block — no rule is synthesized here.
func migrateDNSFakeIPBlock(dns map[string]interface{}, state *dnsMigrationState, warnings *[]string) {
	raw, present := dns["fakeip"]
	if !present {
		return
	}
	delete(dns, "fakeip")
	enabled := true
	block, _ := raw.(map[string]interface{})
	if block != nil {
		if value, ok := block["enabled"].(bool); ok {
			enabled = value
		}
		state.fakeipInet4, _ = block["inet4_range"].(string)
		state.fakeipInet6, _ = block["inet6_range"].(string)
	}
	state.fakeipDisabled = !enabled
	if enabled {
		*warnings = append(*warnings, "dns.fakeip dropped (1.5 has no fakeip block; a fakeip DNS server carries the ranges instead)")
	} else {
		*warnings = append(*warnings, "dns.fakeip dropped (it was disabled; the client's own fakeip setup is not replaced)")
	}
}

// migrateDNSServerList rewrites the 1.4 `address` server entries into the 1.5
// typed form and drops the entries that cannot be mapped.
func migrateDNSServerList(dns map[string]interface{}, state *dnsMigrationState, warnings *[]string) {
	list, ok := dns["servers"].([]interface{})
	if !ok {
		return
	}
	kept := make([]interface{}, 0, len(list))
	changed := false
	for i, item := range list {
		server, mutated, drop, warns := migrateDNSServerEntry(i, item, state)
		for _, warn := range warns {
			*warnings = append(*warnings, warn)
		}
		if drop != "" {
			*warnings = append(*warnings, fmt.Sprintf("dns.servers[%d] %q: server dropped — %s", i, serverTagOf(item, i), drop))
			changed = true
			continue
		}
		if mutated {
			changed = true
		}
		kept = append(kept, server)
	}
	if changed {
		dns["servers"] = kept
	}
}

// serverTagOf renders a server's tag (or its index when it has none) for a
// warning.
func serverTagOf(item interface{}, index int) string {
	server, ok := item.(map[string]interface{})
	if !ok {
		return strconv.Itoa(index)
	}
	if tag := leafTag(server); tag != "" {
		return tag
	}
	return strconv.Itoa(index)
}

// migrateDNSServerEntry migrates one servers[] entry. mutated reports that the
// returned value differs from the input (the caller only rewrites the list when
// something changed, so an untouched document stays byte-identical); drop is a
// human-readable reason when the entry has no 1.5 form at all.
func migrateDNSServerEntry(index int, item interface{}, state *dnsMigrationState) (server interface{}, mutated bool, drop string, warns []string) {
	switch entry := item.(type) {
	case string:
		result := legacyDNSServerFromAddress(entry, state)
		warns = append(warns, result.warns...)
		if result.drop != "" {
			return nil, true, result.drop, warns
		}
		if result.rcode != "" {
			// An untagged rcode server cannot be referenced by any rule, so
			// there is nothing worth keeping — and no tag to convert onto.
			return nil, true, fmt.Sprintf("rcode:// server has no tag, so no rule could reference it (1.5 serves rcodes from a predefined rule action, not from a server)"), warns
		}
		warns = append(warns, fmt.Sprintf("dns.servers[%d]: legacy server %q migrated to type %s", index, entry, leafType(result.server)))
		return result.server, true, "", warns
	case map[string]interface{}:
		rawAddress, hasAddress := entry["address"]
		if !hasAddress {
			// Either a 1.5 entry, or one that never had a type. The latter is
			// the engine's business (it may simply be invalid).
			if mutate := cleanDNSServerKeys(entry, state, &warns); mutate {
				return entry, true, "", warns
			}
			return item, false, "", nil
		}
		address, ok := rawAddress.(string)
		if !ok {
			return nil, true, fmt.Sprintf("address is %s, not a string", jsonValueKind(rawAddress)), warns
		}
		if typ := leafType(entry); typ != "" {
			// A 1.5 document that also carries a stray 1.4 address: the
			// explicit type wins, the legacy key is dead weight.
			delete(entry, "address")
			warns = append(warns, fmt.Sprintf("dns server %q: legacy address %q dropped (explicit type %q wins)", leafTag(entry), address, typ))
			return entry, true, "", warns
		}
		result := legacyDNSServerFromAddress(address, state)
		warns = append(warns, result.warns...)
		if result.drop != "" {
			return nil, true, result.drop, warns
		}
		if result.rcode != "" {
			tag := leafTag(entry)
			if tag == "" {
				return nil, true, "rcode:// server has no tag, so no rule could reference it (1.5 serves rcodes from a predefined rule action, not from a server)", warns
			}
			state.rcodeServers[tag] = result.rcode
			return nil, true, fmt.Sprintf("rcode server %q has no 1.5 transport (rules using it become action=predefined rcode=%s)", tag, result.rcode), warns
		}
		server := result.server
		// Keep everything else the user wrote on the entry (tag, detour,
		// domain_resolver, …); the keys the 1.5 options reject are removed by
		// cleanDNSServerKeys with their own warnings.
		for key, value := range entry {
			if key == "address" || key == "type" {
				continue
			}
			if _, set := server[key]; set {
				continue
			}
			server[key] = value
		}
		cleanDNSServerKeys(server, state, &warns)
		warns = append(warns, fmt.Sprintf("dns.servers[%d] %q: legacy address %q migrated to type %s", index, serverTagOf(entry, index), address, leafType(server)))
		return server, true, "", warns
	}
	return item, false, "", nil
}

// cleanDNSServerKeys removes the server-level keys 1.5 rejects
// (option.DNSServerOptions is decoded with DisallowUnknownFields) and renames
// the two that have an exact counterpart.
func cleanDNSServerKeys(server map[string]interface{}, state *dnsMigrationState, warns *[]string) (mutated bool) {
	typ := leafType(server)
	if value, ok := server["address_resolver"]; ok {
		delete(server, "address_resolver")
		mutated = true
		if typ == C.DNSTypeFakeIP {
			*warns = append(*warns, fmt.Sprintf("dns server %q: address_resolver dropped (a fakeip server has no dialer)", leafTag(server)))
		} else if _, set := server["domain_resolver"]; set {
			*warns = append(*warns, fmt.Sprintf("dns server %q: address_resolver dropped (domain_resolver already set)", leafTag(server)))
		} else {
			server["domain_resolver"] = value
			*warns = append(*warns, fmt.Sprintf("dns server %q: address_resolver → domain_resolver", leafTag(server)))
		}
	}
	if value, ok := server["outbound"]; ok {
		delete(server, "outbound")
		mutated = true
		if typ == C.DNSTypeFakeIP {
			*warns = append(*warns, fmt.Sprintf("dns server %q: outbound dropped (a fakeip server has no dialer)", leafTag(server)))
		} else if _, set := server["detour"]; set {
			*warns = append(*warns, fmt.Sprintf("dns server %q: outbound dropped (detour already set)", leafTag(server)))
		} else {
			server["detour"] = value
			*warns = append(*warns, fmt.Sprintf("dns server %q: outbound → detour", leafTag(server)))
		}
	}
	// strategy / address_strategy / client_subnet moved to the DNS block and the
	// rules in 1.5; lifting them would change which queries they apply to, so
	// they are dropped and named instead.
	for _, key := range []string{"strategy", "address_strategy", "client_subnet"} {
		if _, ok := server[key]; !ok {
			continue
		}
		delete(server, key)
		mutated = true
		*warns = append(*warns, fmt.Sprintf("dns server %q: legacy %s dropped (1.5 sets it on the DNS block or a rule, not on a server)", leafTag(server), key))
	}
	if typ != C.DNSTypeFakeIP {
		return mutated
	}
	// option.FakeIPDNSServerOptions carries only the ranges.
	for _, key := range []string{"detour", "domain_resolver"} {
		if _, ok := server[key]; !ok {
			continue
		}
		delete(server, key)
		mutated = true
		*warns = append(*warns, fmt.Sprintf("dns server %q: %s dropped (a fakeip server has no dialer)", leafTag(server), key))
	}
	if _, ok := server["inet4_range"]; !ok {
		inet4 := state.fakeipInet4
		if inet4 == "" {
			inet4 = legacyFakeIPInet4
		}
		server["inet4_range"] = inet4
		mutated = true
	}
	if _, ok := server["inet6_range"]; !ok {
		inet6 := state.fakeipInet6
		if inet6 == "" {
			inet6 = legacyFakeIPInet6
		}
		server["inet6_range"] = inet6
		mutated = true
	}
	return mutated
}

// legacyDNSResult is the outcome of translating one 1.4 address: a 1.5 server,
// an rcode name (the address was an rcode:// pseudo server), a drop reason, or
// nothing at all.
type legacyDNSResult struct {
	server map[string]interface{}
	rcode  string
	warns  []string
	drop   string
}

// legacyDNSServerFromAddress maps one 1.4 address onto the 1.5 server options,
// following the upstream migration table (docs/migration.md, "Migrate to new
// DNS server formats"). Only the mappings that are unambiguous are applied; an
// address that cannot be read as a host:port is dropped rather than guessed.
func legacyDNSServerFromAddress(address string, state *dnsMigrationState) legacyDNSResult {
	var result legacyDNSResult
	addr := strings.TrimSpace(address)
	if addr == "" {
		result.drop = "empty address"
		return result
	}
	// 1.4 tolerated a #fragment= suffix (the client's own https helper reads it
	// for TLS record fragmentation); it has no place in a 1.5 server.
	if index := strings.Index(addr, "#"); index >= 0 {
		result.warns = append(result.warns, fmt.Sprintf("dns address %q: #fragment suffix dropped (1.5 configures fragmentation on the server's tls block)", addr))
		addr = strings.TrimSpace(addr[:index])
		if addr == "" {
			result.drop = "address is only a fragment"
			return result
		}
	}
	switch strings.ToLower(addr) {
	case "local":
		result.server = map[string]interface{}{"type": C.DNSTypeLocal}
		return result
	case "fakeip":
		if state.fakeipDisabled {
			result.drop = "legacy fakeip server dropped because dns.fakeip was disabled"
			return result
		}
		result.server = map[string]interface{}{"type": C.DNSTypeFakeIP}
		return result
	case "dhcp":
		result.server = map[string]interface{}{"type": C.DNSTypeDHCP}
		return result
	}
	if !strings.Contains(addr, "://") {
		host, port, ok := splitLegacyDNSHostPort(addr)
		if !ok {
			result.drop = fmt.Sprintf("address %q is not a host:port", addr)
			return result
		}
		result.server = udpServer(host, port)
		return result
	}
	parsed, err := url.Parse(addr)
	if err != nil || parsed.Host == "" {
		result.drop = fmt.Sprintf("address %q cannot be parsed as a URL", addr)
		return result
	}
	host, port, ok := splitLegacyDNSHostPort(parsed.Host)
	if !ok {
		result.drop = fmt.Sprintf("address %q has an invalid host:port", addr)
		return result
	}
	switch scheme := strings.ToLower(parsed.Scheme); scheme {
	case C.DNSTypeDHCP:
		server := map[string]interface{}{"type": C.DNSTypeDHCP}
		if iface := strings.TrimSpace(parsed.Host); iface != "" && !strings.EqualFold(iface, "auto") {
			server["interface"] = iface
		}
		result.server = server
	case "rcode":
		name, loaded := legacyRcodeNames[strings.ToLower(strings.TrimSpace(parsed.Host))]
		if !loaded {
			result.drop = fmt.Sprintf("unknown rcode %q", parsed.Host)
			return result
		}
		result.rcode = name
	case C.DNSTypeHTTPS, C.DNSTypeHTTP3:
		server := map[string]interface{}{"type": scheme}
		server["server"] = host
		if port != 0 && port != 443 {
			server["server_port"] = port
		}
		if path := parsed.Path; path != "" && path != "/dns-query" {
			server["path"] = path
		}
		result.server = server
	case C.DNSTypeTLS, C.DNSTypeQUIC, C.DNSTypeTCP, C.DNSTypeUDP:
		result.server = udpServer(host, port)
		result.server["type"] = scheme
	default:
		// An unknown scheme is not a 1.5 transport. Keep the host only when it
		// is a plain host:port, which is what the 1.5 udp transport would do
		// with it, and drop the entry otherwise.
		if parsed.Path != "" && parsed.Path != "/" {
			result.drop = fmt.Sprintf("unsupported DNS scheme %q", parsed.Scheme)
			return result
		}
		result.server = udpServer(host, port)
		result.warns = append(result.warns, fmt.Sprintf("dns address %q: unsupported scheme %q migrated to type udp (server %s:%d)", addr, parsed.Scheme, host, port))
	}
	return result
}

// udpServer builds the address half of a 1.5 remote server entry.
func udpServer(host string, port int) map[string]interface{} {
	server := map[string]interface{}{"type": C.DNSTypeUDP, "server": host}
	if port != 0 {
		server["server_port"] = port
	}
	return server
}

// splitLegacyDNSHostPort splits "host", "host:port", "[v6]:port" and a bare IPv6
// literal. ok is false when the port part is present but unusable.
func splitLegacyDNSHostPort(hostport string) (host string, port int, ok bool) {
	value := strings.TrimSpace(hostport)
	if value == "" {
		return "", 0, false
	}
	if strings.ContainsAny(value, " \t/?#@") {
		return "", 0, false
	}
	colons := strings.Count(value, ":")
	if strings.HasPrefix(value, "[") || colons == 1 {
		splitHost, splitPort, err := net.SplitHostPort(value)
		if err != nil {
			if strings.HasPrefix(value, "[") && colons == 0 {
				return strings.Trim(value, "[]"), 0, true
			}
			return "", 0, false
		}
		splitHost = strings.Trim(splitHost, "[]")
		if splitHost == "" {
			return "", 0, false
		}
		number, err := strconv.Atoi(splitPort)
		if err != nil || number <= 0 || number > 65535 {
			return "", 0, false
		}
		return splitHost, number, true
	}
	// No port (a bare IPv6 literal has several colons and no brackets).
	return value, 0, true
}

// fixDNSServerOrder keeps a fakeip server away from the default slot. The
// engine resolves the default server as dns.final, else the first entry, and
// rejects a fakeip default ("default server cannot be fakeip"), which would
// take the whole import down.
func fixDNSServerOrder(dns map[string]interface{}, warnings *[]string) {
	list, ok := dns["servers"].([]interface{})
	if !ok || len(list) == 0 {
		return
	}
	if isFakeIPServer(list[0]) {
		fakeIPTag := serverTagAt(list, 0)
		moved := -1
		for index, item := range list {
			if !isFakeIPServer(item) {
				moved = index
				break
			}
		}
		if moved > 0 {
			reordered := make([]interface{}, 0, len(list))
			reordered = append(reordered, list[moved])
			for index, item := range list {
				if index != moved {
					reordered = append(reordered, item)
				}
			}
			dns["servers"] = reordered
			list = reordered
			*warnings = append(*warnings, fmt.Sprintf("dns.servers: fakeip server %q moved out of the default slot (1.5 rejects a fakeip default server)", fakeIPTag))
		}
	}
	final, _ := dns["final"].(string)
	final = strings.TrimSpace(final)
	if final == "" {
		return
	}
	for _, item := range list {
		server, isMap := item.(map[string]interface{})
		if !isMap || leafTag(server) != final || !isFakeIPServer(item) {
			continue
		}
		delete(dns, "final")
		*warnings = append(*warnings, fmt.Sprintf("dns.final %q dropped (a fakeip server cannot be the default DNS server)", final))
		return
	}
}

func isFakeIPServer(item interface{}) bool {
	server, ok := item.(map[string]interface{})
	return ok && leafType(server) == C.DNSTypeFakeIP
}

// serverTagAt renders a server tag for a warning, falling back to its index the
// way the engine tags an unnamed server.
func serverTagAt(list []interface{}, index int) string {
	if index < 0 || index >= len(list) {
		return ""
	}
	server, ok := list[index].(map[string]interface{})
	if !ok {
		return strconv.Itoa(index)
	}
	if tag := leafTag(server); tag != "" {
		return tag
	}
	return strconv.Itoa(index)
}

// migrateDNSServerRefs drops the rules and the final that name a DNS server the
// block no longer declares. A dangling reference is not a warning upstream: the
// router refuses to build ("server not found: x"), i.e. the whole import fails.
// An rcode server that was just removed is the one case with a real 1.5
// equivalent — the rule becomes a predefined action with that rcode.
func migrateDNSServerRefs(dns map[string]interface{}, state *dnsMigrationState, warnings *[]string) {
	live := make(map[string]bool)
	list, _ := dns["servers"].([]interface{})
	for index, item := range list {
		server, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		tag := leafTag(server)
		if tag == "" {
			tag = strconv.Itoa(index)
		}
		live[tag] = true
	}
	// 1.4 documents resolve "local" through a declared server; a profile whose
	// rules (or final) name `local` without declaring it is common and the 1.5
	// router rejects it outright ("server not found: local"). The 1.5 equivalent
	// of that implicit server is a `local` server, so declare one instead of
	// dropping every rule that mentions it.
	if !live[C.DNSTypeLocal] && dnsReferencesServer(dns, C.DNSTypeLocal) {
		server := map[string]interface{}{"type": C.DNSTypeLocal, "tag": C.DNSTypeLocal}
		dns["servers"] = append(list, server)
		list = dns["servers"].([]interface{})
		live[C.DNSTypeLocal] = true
		*warnings = append(*warnings, "dns.servers: added type=local tag=local (rules reference it and 1.4 resolved it implicitly)")
	}
	if final, ok := dns["final"].(string); ok {
		final = strings.TrimSpace(final)
		if final != "" && !live[final] {
			delete(dns, "final")
			*warnings = append(*warnings, fmt.Sprintf("dns.final %q dropped — no surviving DNS server has that tag", final))
		}
	}
	rules, ok := dns["rules"].([]interface{})
	if !ok {
		return
	}
	kept := migrateDNSRuleList(rules, live, state, warnings, "dns rule")
	if len(kept) != len(rules) {
		dns["rules"] = kept
	}
}

// dnsReferencesServer reports whether dns.final or any rule (logical rules
// included) names tag as its server.
func dnsReferencesServer(dns map[string]interface{}, tag string) bool {
	if final, ok := dns["final"].(string); ok && strings.TrimSpace(final) == tag {
		return true
	}
	rules, _ := dns["rules"].([]interface{})
	return dnsRuleListReferencesServer(rules, tag)
}

func dnsRuleListReferencesServer(rules []interface{}, tag string) bool {
	for _, item := range rules {
		rule, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if server, ok := rule["server"].(string); ok && strings.TrimSpace(server) == tag {
			return true
		}
		if children, ok := rule["rules"].([]interface{}); ok && dnsRuleListReferencesServer(children, tag) {
			return true
		}
	}
	return false
}

func migrateDNSRuleList(rules []interface{}, live map[string]bool, state *dnsMigrationState, warnings *[]string, label string) []interface{} {
	kept := make([]interface{}, 0, len(rules))
	for _, item := range rules {
		rule, ok := item.(map[string]interface{})
		if !ok {
			kept = append(kept, item)
			continue
		}
		if children, isList := rule["rules"].([]interface{}); isList {
			pruned := migrateDNSRuleList(children, live, state, warnings, label)
			if len(pruned) != len(children) {
				rule["rules"] = pruned
			}
		}
		if _, ok := rule["address_resolver"]; ok {
			delete(rule, "address_resolver")
			*warnings = append(*warnings, label+": legacy address_resolver dropped (1.5 sets the resolver on the server or a route rule, not on a DNS rule)")
		}
		server, _ := rule["server"].(string)
		server = strings.TrimSpace(server)
		if server == "" || live[server] {
			kept = append(kept, item)
			continue
		}
		if rcode, converted := state.rcodeServers[server]; converted {
			delete(rule, "server")
			rule["action"] = C.RuleActionTypePredefined
			rule["rcode"] = rcode
			*warnings = append(*warnings, fmt.Sprintf("%s: server %q was a 1.4 rcode server → action=predefined rcode=%s", label, server, rcode))
			kept = append(kept, item)
			continue
		}
		*warnings = append(*warnings, fmt.Sprintf("%s: rule dropped — it names DNS server %q, which the dns block does not declare (the router refuses to build a dangling reference)", label, server))
	}
	return kept
}

// ---------------------------------------------------------------------------
// Isolation: one unusable dns entry must not cost the import
// ---------------------------------------------------------------------------

// isolateDNSBlock keeps a broken dns block from failing the whole import, the
// same way filterValidLeavesJSON isolates a broken outbound:
//
//  1. the block is checked as a whole (strict decode + the cross-reference and
//     fakeip rules the router enforces);
//  2. if that fails, servers and rules are checked one by one and the entries
//     that do not decode are dropped with a per-entry parse warning;
//  3. only if the block is still unusable is `dns` dropped wholesale — with a
//     warning naming the reason — so the client's own DNS template is used.
//
// Returns true when the document was modified.
func isolateDNSBlock(ctx context.Context, root map[string]interface{}) bool {
	raw, present := root["dns"]
	if !present || raw == nil {
		return false
	}
	dns, ok := raw.(map[string]interface{})
	if !ok {
		delete(root, "dns")
		reportDNSError(ctx, "", "", fmt.Sprintf("the dns block is %s, not an object", jsonValueKind(raw)))
		return true
	}
	decodeCtx := determineDNSCtx(ctx)
	problem := dnsBlockProblem(decodeCtx, dns)
	if problem == "" {
		return false
	}
	fmt.Printf("[SingboxParser] dns block needs isolation: %s\n", problem)
	changed := isolateDNSEntries(ctx, decodeCtx, dns)
	if changed {
		// A dropped server can leave a rule or the final dangling; pruning them
		// here (rather than failing the import) is the same trade the geo
		// migrator makes for its matchers.
		emptyState := &dnsMigrationState{rcodeServers: map[string]string{}}
		var refWarnings []string
		migrateDNSServerRefs(dns, emptyState, &refWarnings)
		for _, warn := range refWarnings {
			fmt.Printf("[SingboxParser] dns isolate: %s\n", warn)
			parseWarningsFrom(ctx).addMigration(warn)
		}
		if remaining := dnsBlockProblem(decodeCtx, dns); remaining == "" {
			return true
		} else {
			problem = remaining
		}
	}
	delete(root, "dns")
	reportDNSError(ctx, "", "", "the whole dns block was dropped ("+problem+"); the client's default DNS template is used instead")
	return true
}

// isolateDNSEntries drops the servers and rules that do not decode on their own.
func isolateDNSEntries(ctx context.Context, decodeCtx context.Context, dns map[string]interface{}) bool {
	changed := false
	warns := parseWarningsFrom(ctx)
	if list, ok := dns["servers"].([]interface{}); ok {
		kept := make([]interface{}, 0, len(list))
		for index, item := range list {
			tag := serverTagAt(list, index)
			typ := ""
			if server, ok := item.(map[string]interface{}); ok {
				typ = leafType(server)
			}
			raw, err := json.Marshal(item)
			if err == nil {
				var server option.DNSServerOptions
				err = server.UnmarshalJSONContext(decodeCtx, raw)
			}
			if err != nil {
				fmt.Printf("[SingboxParser] skip invalid dns server %q: %v\n", tag, err)
				warns.addDrop("dns", typ, tag, err)
				changed = true
				continue
			}
			kept = append(kept, item)
		}
		if changed {
			dns["servers"] = kept
		}
	}
	if list, ok := dns["rules"].([]interface{}); ok {
		pruned := isolateDNSRuleList(decodeCtx, list, warns)
		if len(pruned) != len(list) {
			dns["rules"] = pruned
			changed = true
		}
	}
	if changed {
		return true
	}
	// Nothing decodes badly on its own: the defect is inside the block-level
	// configuration (an unknown key, a bad optimistic/strategy value), which has
	// no per-entry form. Leaving changed=false lets the caller drop the block.
	return false
}

func isolateDNSRuleList(decodeCtx context.Context, rules []interface{}, warns *ParseWarningsCollector) []interface{} {
	kept := make([]interface{}, 0, len(rules))
	for index, item := range rules {
		rule, isMap := item.(map[string]interface{})
		if !isMap {
			kept = append(kept, item)
			continue
		}
		if children, isList := rule["rules"].([]interface{}); isList {
			pruned := isolateDNSRuleList(decodeCtx, children, warns)
			if len(pruned) != len(children) {
				rule["rules"] = pruned
			}
		}
		raw, err := json.Marshal(item)
		if err == nil {
			var decoded option.DNSRule
			err = decoded.UnmarshalJSONContext(decodeCtx, raw)
		}
		if err == nil && dnsRuleNeedsServer(rule) {
			err = fmt.Errorf("rule has no `server` and no explicit action (1.5 rejects a DNS rule that cannot answer)")
		}
		if err != nil {
			tag := ""
			if server, ok := rule["server"].(string); ok {
				tag = server
			}
			fmt.Printf("[SingboxParser] skip invalid dns rule[%d]: %v\n", index, err)
			warns.addDrop("dns", "rule", tag, err)
			continue
		}
		kept = append(kept, item)
	}
	return kept
}

// dnsRuleNeedsServer reports whether a rule is a route/evaluate action, which
// the router rejects without a server ("missing server field").
func dnsRuleNeedsServer(rule map[string]interface{}) bool {
	action, _ := rule["action"].(string)
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "", C.RuleActionTypeRoute, C.RuleActionTypeEvaluate:
		server, _ := rule["server"].(string)
		return strings.TrimSpace(server) == ""
	}
	return false
}

// dnsBlockProblem decodes the block the way option.Options will and reports the
// first defect, or "" when the engine can build it.
func dnsBlockProblem(decodeCtx context.Context, dns map[string]interface{}) string {
	raw, err := json.Marshal(dns)
	if err != nil {
		return err.Error()
	}
	var options option.DNSOptions
	if err := options.UnmarshalJSONContext(decodeCtx, raw); err != nil {
		return err.Error()
	}
	return dnsOptionsProblem(options)
}

// dnsOptionsProblem mirrors the checks the 1.5 DNS router and transport manager
// run on an already-decoded block: a fakeip server needs a range, the default
// server must not be fakeip, and every rule must name a server the block
// declares.
func dnsOptionsProblem(options option.DNSOptions) string {
	live := make(map[string]bool, len(options.Servers))
	defaultTag := strings.TrimSpace(options.Final)
	for index, server := range options.Servers {
		tag := server.Tag
		if tag == "" {
			tag = strconv.Itoa(index)
		}
		live[tag] = true
		if defaultTag == "" && index == 0 {
			defaultTag = tag
		}
		if fakeIP, isFakeIP := server.Options.(*option.FakeIPDNSServerOptions); isFakeIP {
			if fakeIP.Inet4Range == nil && fakeIP.Inet6Range == nil {
				return fmt.Sprintf("fakeip server %q has neither inet4_range nor inet6_range", tag)
			}
		}
	}
	for index, server := range options.Servers {
		tag := server.Tag
		if tag == "" {
			tag = strconv.Itoa(index)
		}
		if tag != defaultTag {
			continue
		}
		if _, isFakeIP := server.Options.(*option.FakeIPDNSServerOptions); isFakeIP {
			return fmt.Sprintf("fakeip server %q is the default DNS server", tag)
		}
		break
	}
	return dnsRuleListProblem(options.Rules, live, "dns rule")
}

func dnsRuleListProblem(rules []option.DNSRule, live map[string]bool, label string) string {
	for index, rule := range rules {
		server, action := decodeDNSRuleServer(rule)
		switch action {
		case "", C.RuleActionTypeRoute, C.RuleActionTypeEvaluate:
			if server == "" {
				return fmt.Sprintf("%s[%d] has no `server`", label, index)
			}
		}
		if server != "" && !live[server] {
			return fmt.Sprintf("%s[%d] names DNS server %q, which the block does not declare", label, index, server)
		}
		if rule.Type == C.RuleTypeLogical {
			if problem := dnsRuleListProblem(rule.LogicalOptions.Rules, live, label+"[].rules"); problem != "" {
				return problem
			}
		}
	}
	return ""
}

// decodeDNSRuleServer mirrors the engine's dnsRuleActionServer helper.
func decodeDNSRuleServer(rule option.DNSRule) (server string, action string) {
	if rule.Type == C.RuleTypeLogical {
		action = rule.LogicalOptions.Action
		if action == C.RuleActionTypeEvaluate {
			return rule.LogicalOptions.EvaluateOptions.Server, action
		}
		return rule.LogicalOptions.RouteOptions.Server, action
	}
	action = rule.DefaultOptions.Action
	if action == C.RuleActionTypeEvaluate {
		return rule.DefaultOptions.EvaluateOptions.Server, action
	}
	return rule.DefaultOptions.RouteOptions.Server, action
}

// reportDNSError records a whole-block drop on the parse-warning channel.
func reportDNSError(ctx context.Context, kind, tag, reason string) {
	fmt.Printf("[SingboxParser] %s\n", reason)
	parseWarningsFrom(ctx).addDrop("dns", kind, tag, reason)
}

// determineDNSCtx returns a context the DNS option decoders accept. The
// transport registry is only built when the caller's context has none (the parse
// paths pass libbox.BaseContext, which already carries it; CLI and test callers
// may pass a bare context).
func determineDNSCtx(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if service.FromContext[option.DNSTransportOptionsRegistry](ctx) != nil {
		return ctx
	}
	return include.Context(ctx)
}
