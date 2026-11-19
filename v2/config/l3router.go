package config

import (
	"fmt"
	"net/netip"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// l3router overlay wiring (client side).
//
// The CP hands the client l3router endpoints in its subscription: one per
// address family, each carrying the client's own overlay address and the mesh
// prefix. They are a *network*, not a proxy leaf:
//
//   - the endpoint tag must never land in the balancer/selector pools — a pool
//     member is probed and picked as a proxy, and an l3router endpoint has no
//     server of its own to probe (its underlay is a separate outbound);
//   - the TUN owns the overlay prefix (own address kept, mesh prefix length),
//     so peers are on-link and intra-mesh traffic reaches the endpoint;
//   - a route rule sends the overlay subnet to the endpoint BEFORE the
//     BypassLAN rules — the overlay is RFC1918/ULA, so without it every mesh
//     packet is routed Direct and the mesh is silently unreachable;
//   - use_exit_node adds 0.0.0.0/0 + ::/0 AFTER BypassLAN/NTP: the user asked
//     the mesh to carry WAN traffic, but LAN and NTP keep the local uplink.
//
// Exception: a system spoke (the exit node) owns its own OS TUN and is
// mutually exclusive with the overlay TUN wiring above (SPEC 078). It keeps
// its underlay detour, but gets no TUN address and no route rule — its
// interface address installs the connected overlay route in the kernel and the
// endpoint forwards overlay → WAN itself.

// l3routerOption extracts the typed l3router options of an endpoint, nil when
// e is not an l3router endpoint.
func l3routerOption(e *option.Endpoint) *option.L3RouterEndpointOptions {
	if e == nil {
		return nil
	}
	opts, _ := e.Options.(*option.L3RouterEndpointOptions)
	return opts
}

// isL3RouterEndpoint reports whether e is an l3router endpoint (hub or spoke).
func isL3RouterEndpoint(e *option.Endpoint) bool {
	return l3routerOption(e) != nil
}

// l3routerIsSpoke reports whether e is an l3router *client* endpoint: it has a
// local overlay address and no hub peer table.
func l3routerIsSpoke(e *option.Endpoint) bool {
	o := l3routerOption(e)
	if o == nil {
		return false
	}
	return len(o.Peers) == 0 && o.Address.IsValid()
}

// l3routerIsUserspaceSpoke reports whether e is a spoke served by the box TUN
// and FlowOutbound. A system spoke (exit node) owns an OS TUN of its own and is
// mutually exclusive with overlay inbounds.tun → route → mesh (engine SPEC
// 078): assigning it TUN addresses or route rules would install a second owner
// of the overlay prefix and break its kernel forwarding.
func l3routerIsUserspaceSpoke(e *option.Endpoint) bool {
	o := l3routerOption(e)
	return o != nil && !o.System && l3routerIsSpoke(e)
}

// l3routerFamilyV6 reports the overlay address family of an l3router endpoint.
// known is false when the endpoint declares neither a subnet nor an address
// (a hub may derive both from its peer table).
func l3routerFamilyV6(e *option.Endpoint) (isV6 bool, known bool) {
	o := l3routerOption(e)
	if o == nil {
		return false, false
	}
	if o.Subnet.IsValid() {
		return !o.Subnet.Addr().Unmap().Is4(), true
	}
	if o.Address.IsValid() {
		return !o.Address.Unmap().Is4(), true
	}
	return false, false
}

// l3routerSpokePrefix is the overlay prefix this spoke lives in: the local
// address with the advertised mesh prefix length. Invalid for hubs.
func l3routerSpokePrefix(e *option.Endpoint) netip.Prefix {
	o := l3routerOption(e)
	if o == nil || len(o.Peers) > 0 {
		return netip.Prefix{}
	}
	addr := o.Address.Unmap()
	if !addr.IsValid() || !o.Subnet.IsValid() {
		return netip.Prefix{}
	}
	bits := o.Subnet.Bits()
	if bits < 0 || bits > addr.BitLen() {
		return netip.Prefix{}
	}
	// PrefixFrom keeps the host bits, which is exactly what a TUN interface
	// address needs (Prefix.Masked / Addr.Prefix would zero them).
	return netip.PrefixFrom(addr, bits)
}

// l3routerUnderlayTags returns the outbound tags l3router endpoints dial
// through. Those outbounds carry the mesh transport and never user traffic:
// they must stay out of the leaf/pool lists (a probe would dial the mesh
// transport as if it were a proxy).
func l3routerUnderlayTags(endpoints []option.Endpoint) map[string]struct{} {
	var tags map[string]struct{}
	for i := range endpoints {
		o := l3routerOption(&endpoints[i])
		if o == nil {
			continue
		}
		tag := strings.TrimSpace(o.Detour)
		if tag == "" {
			continue
		}
		if tags == nil {
			tags = make(map[string]struct{})
		}
		tags[tag] = struct{}{}
	}
	return tags
}

// isMeshUnderlayTag reports whether tag is a mesh transport dialed by an
// l3router endpoint rather than a proxy leaf.
func isMeshUnderlayTag(tags map[string]struct{}, tag string) bool {
	if len(tags) == 0 {
		return false
	}
	_, ok := tags[tag]
	return ok
}

// l3routerTunPrefixes lists the overlay prefixes the local TUN must own.
// Family gating mirrors tunAddressesForIPv6Mode: the v6 overlay needs a v6 TUN
// address, and the IPv4-only mode has none.
func l3routerTunPrefixes(endpoints []option.Endpoint, mode option.DomainStrategy, ipv6Supported bool) []netip.Prefix {
	var prefixes []netip.Prefix
	for i := range endpoints {
		ep := &endpoints[i]
		if !l3routerIsUserspaceSpoke(ep) {
			continue
		}
		prefix := l3routerSpokePrefix(ep)
		if !prefix.IsValid() {
			continue
		}
		isV6 := !prefix.Addr().Unmap().Is4()
		switch mode {
		case option.DomainStrategy(C.DomainStrategyIPv4Only):
			if isV6 {
				continue
			}
		case option.DomainStrategy(C.DomainStrategyIPv6Only):
			if !isV6 && ipv6Supported {
				continue
			}
			if isV6 && !ipv6Supported {
				continue
			}
		default:
			if isV6 && !ipv6Supported {
				continue
			}
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}

// applyL3RouterTunAddresses assigns the spoke overlay addresses to the TUN.
// Without them the OS never sources overlay traffic from the client's own
// overlay IP, and mesh packets delivered to this client have no local owner.
func applyL3RouterTunAddresses(options *option.Options, hopt *ClientOptions) {
	if options == nil || hopt == nil || !hopt.EnableTun {
		return
	}
	prefixes := l3routerTunPrefixes(options.Endpoints, hopt.IPv6Mode, isIPv6Supported())
	if len(prefixes) == 0 {
		return
	}
	for i := range options.Inbounds {
		inbound := &options.Inbounds[i]
		if inbound.Type != C.TypeTun {
			continue
		}
		tunOpts, ok := inbound.Options.(*option.TunInboundOptions)
		if !ok || tunOpts == nil {
			continue
		}
		seen := make(map[netip.Prefix]struct{}, len(tunOpts.Address))
		for _, prefix := range tunOpts.Address {
			seen[prefix] = struct{}{}
		}
		for _, prefix := range prefixes {
			if _, dup := seen[prefix]; dup {
				continue
			}
			seen[prefix] = struct{}{}
			tunOpts.Address = append(tunOpts.Address, prefix)
		}
	}
}

// l3routerOverlayRules routes the overlay subnets into their l3router
// endpoints. Must run before the BypassLAN rules: overlay space is private.
func l3routerOverlayRules(endpoints []option.Endpoint) []option.Rule {
	var rules []option.Rule
	for i := range endpoints {
		ep := &endpoints[i]
		if !l3routerIsUserspaceSpoke(ep) {
			continue
		}
		prefix := l3routerSpokePrefix(ep)
		if !prefix.IsValid() {
			continue
		}
		rules = append(rules, l3routerRouteRule([]netip.Prefix{prefix}, ep.Tag))
	}
	return rules
}

// l3routerExitRules routes WAN traffic through the mesh for
// use_exit_node spokes. Must run after BypassLAN and the NTP carve-out.
func l3routerExitRules(endpoints []option.Endpoint) []option.Rule {
	var rules []option.Rule
	for i := range endpoints {
		ep := &endpoints[i]
		o := l3routerOption(ep)
		if o == nil || !o.UseExitNode || !l3routerIsUserspaceSpoke(ep) {
			continue
		}
		isV6, known := l3routerFamilyV6(ep)
		if !known {
			continue
		}
		prefix := netip.PrefixFrom(netip.IPv4Unspecified(), 0)
		if isV6 {
			prefix = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
		}
		rules = append(rules, l3routerRouteRule([]netip.Prefix{prefix}, ep.Tag))
	}
	return rules
}

func l3routerRouteRule(prefixes []netip.Prefix, tag string) option.Rule {
	cidrs := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		cidrs = append(cidrs, prefix.String())
	}
	return option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{
				IPCIDR: prefixableCIDRs(cidrs),
			},
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.RouteActionOptions{
					Outbound: tag,
				},
			},
		},
	}
}

// dropL3RouterEndpointsWithDeadDetour removes l3router endpoints whose underlay
// outbound did not survive the build (IPv6 filter, disabled tag). Keeping them
// would fail the whole profile at box.New with "dependency[...] not found".
func dropL3RouterEndpointsWithDeadDetour(endpoints []option.Endpoint, outbounds []option.Outbound) []option.Endpoint {
	if len(endpoints) == 0 {
		return endpoints
	}
	live := make(map[string]struct{}, len(outbounds)+len(endpoints))
	for i := range outbounds {
		live[outbounds[i].Tag] = struct{}{}
	}
	for i := range endpoints {
		live[endpoints[i].Tag] = struct{}{}
	}
	kept := endpoints[:0]
	for _, ep := range endpoints {
		o := l3routerOption(&ep)
		if o == nil {
			kept = append(kept, ep)
			continue
		}
		detour := strings.TrimSpace(o.Detour)
		if detour == "" {
			kept = append(kept, ep)
			continue
		}
		if _, ok := live[detour]; !ok {
			fmt.Printf("[SingboxParser] l3router endpoint %q dropped: underlay outbound %q is not in this build\n", ep.Tag, detour)
			continue
		}
		kept = append(kept, ep)
	}
	return kept
}
