package config

import (
	"fmt"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// route_full_config.go — EnableFullConfig route semantics (FINDING 1.10).
//
// The switch used to widen only the inbound/leaf filter: BuildConfig copied
// input.Route into options.Route and setRoutingOptions then replaced the whole
// struct, so every route-level knob the profile author wrote (route.final,
// auto_detect_interface, default_domain_resolver, find_process, default_interface,
// …) was silently dropped.
//
// A full config is the user's own sing-box document, so its route block is
// honoured here — with the client's guarantees laid on top, never under:
//
//   - client rules come first, so sniff / hijack-dns / block-quic and the
//     profile-stack rules still win any conflict;
//   - the client's rule_sets stay first and keep their tags;
//   - route.final, default_domain_resolver and the geoip/geosite download
//     detours are honoured only when they still name a tag that exists AFTER the
//     build (the builder drops leaves for IPv6/disabled/parse reasons and the
//     engine replaces pathology/punnel parents with virtuals), otherwise they
//     are repaired to the client's value instead of leaving a dangling
//     reference that makes box.New refuse to start.
//
// Everything here is gated on hopts.EnableFullConfig by the caller.

// liveRouteTargets returns the outbound/endpoint tags that exist once the
// engine has run its own expansion passes. The builder must judge every
// user-supplied reference against this set, not against the raw outbound list:
// a pathology legend parent and a punnel services parent are deleted from the
// outbound manager at start (replaced by {parent}-{legend} / {parent}-{service}
// virtuals), so naming them is exactly as dangling as naming a dropped leaf.
func liveRouteTargets(options *option.Options) map[string]bool {
	if options == nil {
		return nil
	}
	live := make(map[string]bool, len(options.Outbounds)+len(options.Endpoints))
	outbounds := options.Outbounds
	// box.go expands pathology first, then punnel; mirror that order, and keep
	// whatever expansion succeeded so a partially broken profile still gets a
	// best-effort live set instead of an empty one.
	if expanded, err := option.ExpandPathologyOutbounds(outbounds); err == nil {
		outbounds = expanded
	}
	if expanded, err := option.ExpandPunnelOutbounds(outbounds); err == nil {
		outbounds = expanded
	}
	for _, outbound := range outbounds {
		if outbound.Tag != "" {
			live[outbound.Tag] = true
		}
	}
	for _, endpoint := range options.Endpoints {
		if endpoint.Tag != "" {
			live[endpoint.Tag] = true
		}
	}
	return live
}

// mergeFullConfigRoute appends the profile's own route policy (rule_sets and
// rules) after the client-generated ones. Client entries stay first so the
// client wins every conflict, exactly like the subscription overlay in
// MergeSubscriptionRoute; the difference is that a full config owns its route,
// so its entries are kept regardless of IgnoreSubscriptionRoute.
//
// Outbound targets cannot be validated here (the outbounds are not built yet),
// so pruneDeadFullConfigRules runs over the appended tail once they are.
func mergeFullConfigRoute(user *option.RouteOptions, rulesets *[]option.RuleSet, routeRules *[]option.Rule) {
	if user == nil {
		return
	}
	seen := make(map[string]struct{}, len(*rulesets))
	for _, ruleSet := range *rulesets {
		for _, tag := range ruleSet.Tag {
			if tag != "" {
				seen[tag] = struct{}{}
			}
		}
	}
	for _, ruleSet := range user.RuleSet {
		if len(ruleSet.Tag) == 0 {
			continue
		}
		duplicate := false
		for _, tag := range ruleSet.Tag {
			if tag == "" {
				continue
			}
			if _, ok := seen[tag]; ok {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		for _, tag := range ruleSet.Tag {
			if tag != "" {
				seen[tag] = struct{}{}
			}
		}
		*rulesets = append(*rulesets, ruleSet)
	}
	for _, rule := range user.Rules {
		if isClientL3Hook(rule) {
			// The client injects its own sniff / hijack-dns at L3; a bare hook
			// from the profile would only duplicate it.
			continue
		}
		*routeRules = append(*routeRules, NormalizeRouteRule(rule))
	}
}

// pruneDeadFullConfigRules drops the profile's own rules whose route action
// names an outbound that does not exist after the build — a leaf the builder
// filtered (IPv6 / disabled / parse) or a parent the engine expands away. Left
// in place they make box.New fail with "outbound not found", which would turn a
// mostly-valid full config into a profile that cannot start at all. Rules the
// client generated are never touched.
func pruneDeadFullConfigRules(rules []option.Rule, from int, live map[string]bool) []option.Rule {
	if from < 0 || from > len(rules) {
		return rules
	}
	dropped := 0
	kept := make([]option.Rule, 0, len(rules))
	kept = append(kept, rules[:from]...)
	for _, rule := range rules[from:] {
		if tag, dead := ruleDeadTarget(rule, live); dead {
			dropped++
			fmt.Printf("[SingboxParser] full config: skip route rule targeting outbound %q — it does not exist after build (dropped leaf, or a parent the engine expands away)\n", tag)
			continue
		}
		kept = append(kept, rule)
	}
	if dropped == 0 {
		return rules
	}
	return kept
}

// carryFullConfigRouteFields starts from the profile's route block — so every
// route-level field the client never sets survives (geoip, geosite,
// find_neighbor, dhcp_lease_files, override_android_vpn, default_mark,
// default_network_type, lx_idle_suspend, …) — and then re-lays the fields the
// client owns on top.
//
// clientOwnsFinal is true when the app's own routing policy is in play (an
// explicit routing-global-proxy choice or an enabled RoutingProfile). Then the
// generated final is authoritative, because it encodes that choice and the
// selector it points at is what the node picker drives. With no app policy the
// profile's `final` is exactly what a full config promises, so it wins — as
// long as it names a live outbound. Flip that by making clientOwnsFinal
// unconditional in setRoutingOptions.
//
// blockAutoDetect mirrors the client's own platform rule (and the engine's
// route/network.go validation): auto_detect_interface / default_interface are
// Linux/Windows/macOS only and are refused on Android/iOS.
func carryFullConfigRouteFields(user, client *option.RouteOptions, live map[string]bool, dns *option.DNSOptions, httpClients []option.HTTPClient, clientOwnsFinal, blockAutoDetect bool) *option.RouteOptions {
	if user == nil || client == nil {
		return client
	}
	route := *user

	// Lists are client-owned: the merged lists already carry the profile's own
	// entries behind the client's.
	route.Rules = client.Rules
	route.RuleSet = client.RuleSet

	route.Final = client.Final
	if final, ok := resolveFullConfigFinal(user.Final, live); ok && !clientOwnsFinal {
		route.Final = final
	} else if strings.TrimSpace(user.Final) != "" {
		switch {
		case clientOwnsFinal:
			fmt.Printf("[SingboxParser] full config: route.final %q not used — the client routing policy owns final; final is %q\n", user.Final, client.Final)
		default:
			fmt.Printf("[SingboxParser] full config: route.final %q does not name an outbound that exists after build; final is %q\n", user.Final, client.Final)
		}
	}

	// default_domain_resolver is honoured only when it names a DNS server that
	// exists in the built dns block — otherwise the engine fails resolution at
	// start with a dangling "dns_server" reference.
	route.DefaultDomainResolver = client.DefaultDomainResolver
	if user.DefaultDomainResolver != nil {
		if dnsServerTagExists(dns, user.DefaultDomainResolver.Server) {
			// Copy, so the built route never aliases the parsed input: the
			// same profile may be rebuilt (TestEngine) with another config.
			resolver := *user.DefaultDomainResolver
			route.DefaultDomainResolver = &resolver
		} else {
			fmt.Printf("[SingboxParser] full config: route.default_domain_resolver names unknown dns server %q; using the client resolver\n", user.DefaultDomainResolver.Server)
		}
	}

	route.FindProcess = client.FindProcess || user.FindProcess

	if blockAutoDetect {
		// The engine rejects auto_detect_interface on Android/iOS ("only
		// supported on Linux, Windows and macOS"), and on a device the OS binds
		// sockets to the network itself — auto-detect on the main TUN can bind
		// outbound traffic to our own tunnel. Same rule the client applies to its
		// own settings; the strategy goes with it because the engine requires
		// auto_detect_interface whenever default_network_strategy is set.
		if route.AutoDetectInterface || route.DefaultNetworkStrategy != nil {
			fmt.Printf("[SingboxParser] full config: auto_detect_interface / default_network_strategy are not honoured on this platform; dropped\n")
		}
		route.AutoDetectInterface = false
		route.DefaultNetworkStrategy = nil
		route.DefaultInterface = ""
	} else {
		// The engine rejects default_interface together with
		// default_network_strategy (route/network.go); the client sets the
		// strategy for non-default IPv6 modes, and that is the guarantee that
		// must survive, so the interface is dropped.
		if route.DefaultInterface != "" && (user.DefaultNetworkStrategy != nil || client.DefaultNetworkStrategy != nil) {
			fmt.Printf("[SingboxParser] full config: route.default_interface %q conflicts with default_network_strategy; dropped\n", route.DefaultInterface)
			route.DefaultInterface = ""
		}
		if route.DefaultNetworkStrategy == nil {
			route.DefaultNetworkStrategy = client.DefaultNetworkStrategy
		}

		route.AutoDetectInterface = user.AutoDetectInterface || client.AutoDetectInterface
		if route.DefaultNetworkStrategy != nil && !route.AutoDetectInterface {
			// "auto_detect_interface is required by default_network_strategy".
			route.AutoDetectInterface = true
		}
	}

	if !httpClientTagExists(httpClients, route.DefaultHTTPClient) {
		if route.DefaultHTTPClient != "" {
			fmt.Printf("[SingboxParser] full config: route.default_http_client names unknown client %q; dropped\n", route.DefaultHTTPClient)
		}
		route.DefaultHTTPClient = ""
	}

	// Copy before repairing: user is the parsed input and may be reused.
	if user.GeoIP != nil {
		geoIP := *user.GeoIP
		geoIP.DownloadDetour = repairFullConfigDetour(geoIP.DownloadDetour, live, "route.geoip.download_detour")
		route.GeoIP = &geoIP
	}
	if user.Geosite != nil {
		geosite := *user.Geosite
		geosite.DownloadDetour = repairFullConfigDetour(geosite.DownloadDetour, live, "route.geosite.download_detour")
		route.Geosite = &geosite
	}

	return &route
}

// resolveFullConfigFinal maps a profile spelling ("proxy"/"direct"/a real tag)
// onto a tag that exists after the build. Reject / missing targets report false
// so the caller keeps the client final.
func resolveFullConfigFinal(tag string, live map[string]bool) (string, bool) {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return "", false
	}
	mapped, reject := RemapLogicalOutbound(tag)
	if reject {
		return "", false
	}
	if live[mapped] {
		return mapped, true
	}
	return "", false
}

// repairFullConfigDetour clears a download detour that no longer resolves.
func repairFullConfigDetour(detour string, live map[string]bool, field string) string {
	detour = strings.TrimSpace(detour)
	if detour == "" {
		return ""
	}
	mapped, reject := RemapLogicalOutbound(detour)
	if reject || !live[mapped] {
		fmt.Printf("[SingboxParser] full config: %s %q does not name a live outbound after build; dropped\n", field, detour)
		return ""
	}
	return mapped
}

// ruleDeadTarget reports the outbound tag a rule routes to when that tag will
// not exist after the build. A route action with an empty outbound means "use
// route.final" and is never dangling.
func ruleDeadTarget(rule option.Rule, live map[string]bool) (string, bool) {
	switch rule.Type {
	case "", C.RuleTypeDefault:
		return actionDeadTarget(rule.DefaultOptions.RuleAction, live)
	case C.RuleTypeLogical:
		if tag, dead := actionDeadTarget(rule.LogicalOptions.RuleAction, live); dead {
			return tag, true
		}
		for _, child := range rule.LogicalOptions.Rules {
			if tag, dead := ruleDeadTarget(child, live); dead {
				return tag, true
			}
		}
	}
	return "", false
}

func actionDeadTarget(action option.RuleAction, live map[string]bool) (string, bool) {
	actionType := action.Action
	if actionType == "" {
		actionType = C.RuleActionTypeRoute
	}
	if actionType != C.RuleActionTypeRoute {
		return "", false
	}
	tag := action.RouteOptions.Outbound
	if tag == "" || live[tag] {
		return "", false
	}
	return tag, true
}

// dnsServerTagExists reports whether tag names a server in the built dns block.
func dnsServerTagExists(dns *option.DNSOptions, tag string) bool {
	if dns == nil || tag == "" {
		return false
	}
	for _, server := range dns.Servers {
		if server.Tag == tag {
			return true
		}
	}
	return false
}

// httpClientTagExists reports whether tag names a built http_client. An empty
// tag means "no explicit default" and is always fine.
func httpClientTagExists(clients []option.HTTPClient, tag string) bool {
	if tag == "" {
		return true
	}
	for _, client := range clients {
		if client.Tag == tag {
			return true
		}
	}
	return false
}
