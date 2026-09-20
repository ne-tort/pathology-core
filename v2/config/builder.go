package config

import (
	context "context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	sync "sync"
	"time"

	"github.com/ne-tort/pathology-core/v2/hutils"
	mDNS "github.com/miekg/dns"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/json/badoption"
)

func normalizeBalancerStrategy(strategy string) string {
	switch strings.TrimSpace(strategy) {
	case "", "roundRobin":
		return "round-robin"
	case "lowestDelay":
		return "lowest-delay"
	case "leastLoad":
		return "least-load"
	case "stickySession":
		return "sticky-sessions"
	case "consistentHash":
		return "consistent-hashing"
	case "leastConnections":
		return "least-connections"
	case "sourceHash":
		return "source-hash"
	case "round-robin", "lowest-delay", "least-load", "sticky-sessions",
		"consistent-hashing", "least-connections", "source-hash":
		return strategy
	default:
		// Unknown → engine-safe default for the balance outbound (distinct from `lowest`).
		return "round-robin"
	}
}

const (
	DNSRemoteTag         = "dns-remote"
	DNSRemoteTagFallback = "dns-remote-fallback" // legacy unused
	DNSLocalTag          = "dns-local"
	DNSStaticTag         = "dns-static"
	DNSBootstrapTag      = "dns-bootstrap"
	DNSDirectTag         = DNSBootstrapTag // bootstrap resolves outbound server addresses
	DNSFakeTag           = "dns-fake"
	DNSTricksDirectTag   = "dns-trick-direct" // legacy unused
	DNSMultiDirectTag    = DNSBootstrapTag
	DNSMultiRemoteTag    = DNSRemoteTag

	OutboundDirectTag = "direct §hide§"
	OutboundBypassTag = "bypass §hide§"
	// OutboundBlockTag          = "block §hide§"
	OutboundSelectTag         = "select"
	OutboundURLTestTag        = "lowest"
	OutboundRoundRobinTag     = "balance"
	OutboundDNSTag            = "dns-out §hide§"
	OutboundDirectFragmentTag = "direct-fragment §hide§"

	InboundTUNTag    = "tun-in"
	InboundMixedTag  = "mixed-in"
	InboundTProxy    = "tproxy-in"
	InboundRedirect  = "redirect-in"
	InboundDirectTag = "dns-in"
)

var (
	OutboundMainDetour     = OutboundSelectTag
	PredefinedOutboundTags = []string{OutboundDirectTag, OutboundBypassTag, OutboundSelectTag, OutboundURLTestTag, OutboundDNSTag, OutboundDirectFragmentTag}
)

// BuildConfig merges layers:
//
//	L1 plane — outbounds/endpoints + selector (setOutbounds)
//	L2 dns — subscription dns as-is, or simple/advanced client template (setDns)
//	L3 client hooks — sniff; optional hijack-dns (setRoutingOptions)
//	L4 route policy — local RoutingProfile + subscription route merge (setRoutingOptions)
func BuildConfig(ctx context.Context, hopts *ClientOptions, inputOpt *ReadOptions) (*option.Options, error) {

	input, err := ReadSingOptions(ctx, inputOpt)
	if err != nil {
		return nil, err
	}

	var options option.Options
	if hopts.EnableFullConfig {
		options.Inbounds = input.Inbounds
		options.DNS = input.DNS
		options.Route = input.Route
	}

	setExperimental(&options, hopts)

	setLog(&options, hopts)
	setInbound(&options, hopts)
	staticIPs := make(map[string][]string)
	if err := setOutbounds(&options, input, hopts, &staticIPs); err != nil {
		return nil, err
	}

	useSubDNS := input.DNS != nil && len(input.DNS.Servers) > 0 && !hopts.IgnoreSubscriptionDNS
	if useSubDNS {
		options.DNS = input.DNS
	} else if err := setDns(&options, hopts, &staticIPs); err != nil {
		return nil, err
	}

	if err := setRoutingOptions(&options, input, hopts, useSubDNS); err != nil {
		return nil, err
	}

	return &options, nil
}

func setNTP(options *option.Options) {
	options.NTP = &option.NTPOptions{
		Enabled:       true,
		ServerOptions: option.ServerOptions{ServerPort: 123, Server: "time.apple.com"},
		Interval:      badoption.Duration(12 * time.Hour),
		DialerOptions: option.DialerOptions{
			Detour: OutboundDirectTag,
		},
	}
}

func getHostnameIfNotIP(inp string) (string, error) {
	if inp == "" {
		return "", fmt.Errorf("empty hostname: %s", inp)
	}
	if net.ParseIP(strings.Trim(inp, "[]")) == nil {
		inp2 := inp
		if !strings.Contains(inp, "://") {
			inp2 = "http://" + inp
		}
		u, err := url.Parse(inp2)
		if err != nil {
			return inp, nil
		}
		if net.ParseIP(strings.Trim(u.Host, "[]")) == nil {
			return u.Host, nil
		}
	}
	return "", fmt.Errorf("not a hostname: %s", inp)
}

func isOutboundDisabled(tag string, disabled []string) bool {
	return contains(disabled, tag)
}

func setOutbounds(options *option.Options, input *option.Options, opt *ClientOptions, staticIPs *map[string][]string) error {
	var outbounds []option.Outbound
	var endpoints []option.Endpoint
	var tags []string
	OutboundMainDetour = OutboundSelectTag
	detours := resolvedChainDetours(opt.Chain)
	knownExits := chainKnownExitSet(input)
	keepIPv6 := KeepIPv6Leaves(hasUsableGlobalIPv6(), opt.SubscriptionIPv6)
	// TestEngine must probe the same leaf set the UI shows; do not drop IPv6 leaves
	// based on the main core's SubscriptionIPv6 / OS probe.
	if opt.TestMode {
		keepIPv6 = true
	}
	for _, out := range input.Outbounds {

		if contains(PredefinedOutboundTags, out.Tag) {
			continue
		}
		if !keepIPv6 && IsIPv6Leaf(out.Tag, outboundServerHost(out)) {
			continue
		}
		outbound, err := patchOutbound(out, *opt, staticIPs)
		if err != nil {
			return err
		}
		out = *outbound
		if exit := chainExitFor(out.Tag, detours, knownExits); exit != "" {
			out = applyDetourToOutbound(out, exit)
		}

		switch out.Type {
		case C.TypeBlock, C.TypeDNS:
			continue
		case C.TypeSelector, C.TypeURLTest, C.TypeBalancer:
			continue
		case "custom": // LX-STUB: C.TypeCustom absent in sing-box-lx
			continue
		case "punnel": // reverse provider — keep outbound, never a dialable leaf
			// ExpandPunnel removes the parent tag; putting it in lowest/balance
			// would yield dependency[…punnel…] not found for outbound[lowest].
			//
			// Drop provider clones whose detour is an IPv6 leaf when IPv6 leaves
			// are filtered — otherwise start fails with dependency[…-ipv6] not
			// found (legacy subs that node-expanded punnel via detour {node:suffix}).
			if !keepIPv6 && dialerDetourIsIPv6Leaf(out.Options) {
				continue
			}
			outbounds = append(outbounds, out)
			continue
		default:

			if contains([]string{"direct", "bypass", "block"}, out.Tag) {
				continue
			}
			if !strings.Contains(out.Tag, "§hide§") && !isOutboundDisabled(out.Tag, opt.DisabledOutboundTags) {
				tags = append(tags, out.Tag)
			}
			outbounds = append(outbounds, out)
		}
	}

	for _, end := range input.Endpoints {
		if contains(PredefinedOutboundTags, end.Tag) {
			continue
		}
		if !keepIPv6 && IsIPv6Leaf(end.Tag, "") {
			continue
		}

		out, err := patchEndpoint(&end, *opt, staticIPs)
		if err != nil {
			return err
		}
		if exit := chainExitFor(out.Tag, detours, knownExits); exit != "" {
			applyDetourToEndpoint(out, exit)
		}

		if !strings.Contains(out.Tag, "§hide§") && !isOutboundDisabled(out.Tag, opt.DisabledOutboundTags) {
			tags = append(tags, out.Tag)
		}

		endpoints = append(endpoints, *out)
	}

	// WARP nodes live in a dedicated local profile (Flutter WarpAutoProfileSync).
	// Do not mix them into other profiles — multi-select merge covers composition.
	// Empty ConnectionTestUrls means latency checks are disabled — do not backfill
	// from ConnectionTestUrl (that singular is DNS/compat only).
	// urlTest := option.Outbound{
	// 	Type: C.TypeURLTest,
	// 	Tag:  OutboundURLTestTag,
	// 	Options: &option.URLTestOutboundOptions{
	// 		Outbounds: tags,
	// 		URL:       opt.ConnectionTestUrl,
	// 		URLs:      opt.ConnectionTestUrls,
	// 		Interval:  badoption.Duration(opt.URLTestInterval.Duration()),
	// 		// IdleTimeout: badoption.Duration(opt.URLTestIdleTimeout.Duration()),
	// 		Tolerance:                 1,
	// 		IdleTimeout:               badoption.Duration(opt.URLTestInterval.Duration().Nanoseconds() * 3),
	// 		InterruptExistConnections: true,
	// 	},
	// }
	// Preferred node from subscription marker (exact tag, not the marker alone).
	preferred := ""
	for _, tag := range tags {
		if strings.Contains(tag, "§default§") {
			preferred = tag
			break
		}
	}

	// TestMode (side TestEngine): omit balancers; select = leaves only.
	if opt.TestMode {
		selectTags := tags
		if slim := strings.TrimSpace(opt.TestOutboundTag); slim != "" {
			found := false
			for _, t := range tags {
				if t == slim {
					found = true
					break
				}
			}
			if found {
				selectTags = []string{slim}
			}
		}
		defaultSelect := ""
		if len(selectTags) > 0 {
			defaultSelect = selectTags[0]
		}
		if preferred != "" {
			for _, t := range selectTags {
				if t == preferred {
					defaultSelect = preferred
					break
				}
			}
		}
		if len(selectTags) == 0 {
			return fmt.Errorf("test mode: no probe outbounds (refusing Direct fallback)")
		}
		selector := option.Outbound{
			Type: C.TypeSelector,
			Tag:  OutboundSelectTag,
			Options: &option.SelectorOutboundOptions{
				Outbounds:                 selectTags,
				Default:                   defaultSelect,
				InterruptExistConnections: true,
			},
		}
		options.Endpoints = endpoints
		options.Outbounds = append(
			[]option.Outbound{selector},
			append(outbounds,
				option.Outbound{
					Tag:     OutboundDirectTag,
					Type:    C.TypeDirect,
					Options: &option.DirectOutboundOptions{},
				},
				option.Outbound{
					Tag:  OutboundDirectFragmentTag,
					Type: C.TypeDirect,
					Options: &option.DirectOutboundOptions{
						DialerOptions: option.DialerOptions{
							AbstractDialerOptions: option.AbstractDialerOptions{
								TCPFastOpen: false,
							},
						},
					},
				},
			)...,
		)
		return nil
	}

	// Two balancers as selectable modes under `select` (not route.final):
	//   lowest  — lowest-delay (latency)
	//   balance — user strategy (round-robin / least-load / sticky / …); SPEC 102
	// lx balancer.default: pin while Alive; Dead → strategy among the rest.
	lowestOpts := &option.BalancerOutboundOptions{
		Outbounds:                 tags,
		Default:                   preferred,
		Strategy:                  "lowest-delay",
		DelayAcceptableRatio:      2,
		Tolerance:                 1,
		InterruptExistConnections: true,
	}
	balanceOpts := &option.BalancerOutboundOptions{
		Outbounds:                 tags,
		Default:                   preferred,
		Strategy:                  normalizeBalancerStrategy(opt.BalancerStrategy),
		DelayAcceptableRatio:      2,
		Tolerance:                 1,
		InterruptExistConnections: true,
	}
	urlTest := option.Outbound{
		Type:    C.TypeBalancer,
		Tag:     OutboundURLTestTag,
		Options: lowestOpts,
	}
	balancer := option.Outbound{
		Type:    C.TypeBalancer,
		Tag:     OutboundRoundRobinTag,
		Options: balanceOpts,
	}

	// Traffic path: route.final → select → (balance|lowest|node) → nodes.
	// Keep final on select so UI/SelectOutbound can switch modes and nodes.
	if len(tags) == 0 {
		// Never silently turn a VPN profile into Direct. Only allow Direct-only
		// when the input itself had no proxy leaves (explicit Direct / empty stub).
		if n := countInputProxyLeaves(input); n > 0 {
			return fmt.Errorf("refusing Direct fallback: %d proxy leaf(ves) were dropped (IPv6 filter, disabled tags, or parse)", n)
		}
		selector := option.Outbound{
			Type: C.TypeSelector,
			Tag:  OutboundSelectTag,
			Options: &option.SelectorOutboundOptions{
				Outbounds:                 []string{OutboundDirectTag},
				Default:                   OutboundDirectTag,
				InterruptExistConnections: true,
			},
		}
		options.Endpoints = endpoints
		options.Outbounds = append(
			[]option.Outbound{selector},
			append(outbounds,
				option.Outbound{
					Tag:     OutboundDirectTag,
					Type:    C.TypeDirect,
					Options: &option.DirectOutboundOptions{},
				},
				option.Outbound{
					Tag:  OutboundDirectFragmentTag,
					Type: C.TypeDirect,
					Options: &option.DirectOutboundOptions{
						DialerOptions: option.DialerOptions{
							AbstractDialerOptions: option.AbstractDialerOptions{
								TCPFastOpen: false,
							},
						},
					},
				},
			)...,
		)
		return nil
	}

	defaultSelect := ""
	if len(tags) > 0 {
		defaultSelect = tags[0]
	}
	selectorTags := append([]string{}, tags...)
	if len(tags) > 1 {
		selectorTags = append([]string{urlTest.Tag, balancer.Tag}, selectorTags...)
		defaultSelect = balancer.Tag // auto load-balance until user picks otherwise
	}
	if preferred != "" {
		defaultSelect = preferred // explicit §default§ wins over auto balance
	}

	selector := option.Outbound{
		Type: C.TypeSelector,
		Tag:  OutboundSelectTag,
		Options: &option.SelectorOutboundOptions{
			Outbounds:                 selectorTags,
			Default:                   defaultSelect,
			InterruptExistConnections: true,
		},
	}
	outbounds = append([]option.Outbound{selector, urlTest, balancer}, outbounds...)
	options.Endpoints = endpoints
	options.Outbounds = append(
		outbounds,
		[]option.Outbound{
			{
				Tag:     OutboundDirectTag,
				Type:    C.TypeDirect,
				Options: &option.DirectOutboundOptions{},
			},
			{
				Tag:  OutboundDirectFragmentTag,
				Type: C.TypeDirect,
				Options: &option.DirectOutboundOptions{
					DialerOptions: option.DialerOptions{
						AbstractDialerOptions: option.AbstractDialerOptions{
							TCPFastOpen: false,
						},
					},
				},
			},
		}...,
	)

	return nil
}

// countInputProxyLeaves counts user proxy outbounds/endpoints in the profile pool
// before setOutbounds filtering (IPv6 / disabled / groups).
func countInputProxyLeaves(input *option.Options) int {
	if input == nil {
		return 0
	}
	n := 0
	for _, out := range input.Outbounds {
		switch out.Type {
		case C.TypeBlock, C.TypeDNS, C.TypeSelector, C.TypeURLTest, C.TypeBalancer:
			continue
		case C.TypeDirect:
			if contains([]string{"direct", "bypass", "block"}, out.Tag) || strings.Contains(out.Tag, "§hide§") {
				continue
			}
			n++
		default:
			if contains([]string{"direct", "bypass", "block"}, out.Tag) || strings.Contains(out.Tag, "§hide§") {
				continue
			}
			if contains(PredefinedOutboundTags, out.Tag) {
				continue
			}
			n++
		}
	}
	for _, end := range input.Endpoints {
		if contains(PredefinedOutboundTags, end.Tag) || strings.Contains(end.Tag, "§hide§") {
			continue
		}
		n++
	}
	return n
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func setExperimental(options *option.Options, hopt *ClientOptions) {
	cachePath := "data/clash.db"
	if p := strings.TrimSpace(hopt.CacheFilePath); p != "" {
		cachePath = p
	}
	enableCache := hopt.EnableCacheFile
	if hopt.TestMode {
		// Side TestEngine always needs its own cache file (separate path).
		enableCache = true
	}
	exp := &option.ExperimentalOptions{
		CacheFile: &option.CacheFileOptions{
			Enabled:     enableCache,
			Path:        cachePath,
			StoreFakeIP: enableCache && hopt.CacheFileStoreFakeIP,
			StoreDNS:    enableCache && hopt.CacheFileStoreDNS,
		},
		// LX-STUB: MonitoringOptions (URL-test monitor) absent in sing-box-lx ExperimentalOptions
	}
	// Clash API retired: builds omit with_clash_api; never emit experimental.clash_api.
	_ = hopt.EnableClashApi
	_ = hopt.ClashApiPort
	_ = hopt.ClashApiSecret
	options.Experimental = exp
}

func setLog(options *option.Options, opt *ClientOptions) {
	logOutput := opt.LogFile
	logDisabled := strings.TrimSpace(logOutput) == ""
	options.Log = &option.LogOptions{
		Level:        opt.LogLevel,
		Output:       logOutput,
		Disabled:     logDisabled,
		Timestamp:    false,
		DisableColor: true,
	}
}
// hasUsableGlobalIPv6 reports a non-loopback, non-link-local IPv6 on an UP iface.
// Used for IPv6 leaf filtering so UI and connect stay aligned (loopback alone is not enough).
// Excludes Teredo / 6to4 / ULA — same policy as Flutter OsIpv6 (Windows Teredo ≠ WAN IPv6).
func hasUsableGlobalIPv6() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		name := strings.ToLower(iface.Name)
		if strings.Contains(name, "teredo") ||
			strings.Contains(name, "6to4") ||
			strings.Contains(name, "isatap") {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if !isUsableGlobalIPv6Addr(ip) {
				continue
			}
			return true
		}
	}
	return false
}

func isUsableGlobalIPv6Addr(ip net.IP) bool {
	if ip == nil || ip.To4() != nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	// ULA fc00::/7 (Go IsPrivate covers IPv6 ULA).
	if ip.IsPrivate() {
		return false
	}
	return !isIPv6TransitionTunnel(ip)
}

// Teredo 2001:0::/32 and 6to4 2002::/16 are not real ISP IPv6.
func isIPv6TransitionTunnel(ip net.IP) bool {
	v6 := ip.To16()
	if v6 == nil {
		return false
	}
	// Teredo 2001:0000::/32
	if v6[0] == 0x20 && v6[1] == 0x01 && v6[2] == 0x00 && v6[3] == 0x00 {
		return true
	}
	// 6to4 2002::/16
	if v6[0] == 0x20 && v6[1] == 0x02 {
		return true
	}
	return false
}

func isIPv6Supported() bool {
	// Soft probe for TUN addressing: loopback bind OR usable global IPv6.
	c, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err == nil {
		_ = c.Close()
		return true
	}
	return hasUsableGlobalIPv6()
}

func tunAddressesForIPv6Mode(mode option.DomainStrategy, ipv6Supported bool) []netip.Prefix {
	v4Prefix := netip.MustParsePrefix("172.19.0.1/28")
	v6Prefix := netip.MustParsePrefix("fdfe:dcba:9876::1/126")

	switch mode {
	case option.DomainStrategy(C.DomainStrategyIPv4Only):
		return []netip.Prefix{v4Prefix}
	case option.DomainStrategy(C.DomainStrategyIPv6Only):
		if ipv6Supported {
			return []netip.Prefix{v6Prefix}
		}
		return []netip.Prefix{v4Prefix}
	default:
		addresses := []netip.Prefix{v4Prefix}
		if ipv6Supported {
			addresses = append(addresses, v6Prefix)
		}
		return addresses
	}
}

func defaultNetworkStrategyForIPv6Mode(mode option.DomainStrategy) *option.NetworkStrategy {
	switch mode {
	case option.DomainStrategy(C.DomainStrategyPreferIPv4),
		option.DomainStrategy(C.DomainStrategyIPv4Only),
		option.DomainStrategy(C.DomainStrategyPreferIPv6),
		option.DomainStrategy(C.DomainStrategyIPv6Only):
		strategy := option.NetworkStrategy(C.NetworkStrategyFallback)
		return &strategy
	default:
		return nil
	}
}

func setInbound(options *option.Options, hopt *ClientOptions) {
	ipv6Enable := isIPv6Supported()
	if hopt.EnableTun {

		opts := option.TunInboundOptions{
			Stack:         hopt.TUNStack,
			MTU:           hopt.MTU,
			AutoRoute:     true,
			StrictRoute:   hopt.StrictRoute,
			InterfaceName: hutils.TunInterfaceName,
			// Align with UI DNS hijack: lx default dns_mode is hijack; when UI hijack is off
			// keep TUN from silently hijacking :53 (route rule also omitted).
			DNSMode: map[bool]string{true: "hijack", false: "native"}[hopt.EnableDnsHijack],
			Address: tunAddressesForIPv6Mode(hopt.IPv6Mode, ipv6Enable),
		}
		tunInbound := option.Inbound{
			Type: C.TypeTun,
			Tag:  InboundTUNTag,

			Options: &opts,
		}

		options.Inbounds = append(options.Inbounds, tunInbound)

	}

	binds := []string{}

	if hopt.AllowConnectionFromLAN {
		if ipv6Enable {
			binds = append(binds, "::")
		} else {
			binds = append(binds, "0.0.0.0")
		}
	} else {
		if ipv6Enable {
			binds = append(binds, "::1")
		}
		binds = append(binds, "127.0.0.1")
	}

	for _, bind := range binds {
		addr := badoption.Addr(netip.MustParseAddr(bind))

		// Always expose mixed-port when configured: required for system-proxy, app IP
		// probes, and TUN-side localhost checks. Without it, configs had zero inbounds.
		// MixedPort == 0 with EnableMixedPort (TestMode): ListenPort 0 → kernel assign.
		if hopt.MixedPort > 0 || (hopt.EnableMixedPort && hopt.TestMode) {
			mixedOpts := &option.HTTPMixedInboundOptions{
				ListenOptions: option.ListenOptions{
					Listen:     &addr,
					ListenPort: hopt.MixedPort,
				},
				SetSystemProxy: hopt.SetSystemProxy,
			}
			if pw := strings.TrimSpace(hopt.LanSharingPassword); pw != "" && !hopt.SetSystemProxy {
				user := strings.TrimSpace(hopt.MixedProxyUsername)
				if user == "" {
					user = "pathology"
				}
				mixedOpts.Users = []auth.User{{
					Username: user,
					Password: pw,
				}}
			}
			options.Inbounds = append(
				options.Inbounds,
				option.Inbound{
					Type:    C.TypeMixed,
					Tag:     InboundMixedTag + bind,
					Options: mixedOpts,
				},
			)
		}
		if C.IsLinux && !C.IsAndroid && hopt.EnableTProxyPort && hopt.TProxyPort > 0 && hutils.IsAdmin() {
			options.Inbounds = append(
				options.Inbounds,
				option.Inbound{
					Type: C.TypeTProxy,
					Tag:  InboundTProxy + bind,
					Options: &option.TProxyInboundOptions{
						ListenOptions: option.ListenOptions{
							Listen:     &addr,
							ListenPort: hopt.TProxyPort,
						},
					},
				},
			)
		}
		if (C.IsLinux || C.IsDarwin) && !C.IsAndroid && hopt.EnableRedirectPort && hopt.RedirectPort > 0 {
			options.Inbounds = append(
				options.Inbounds,
				option.Inbound{
					Type: C.TypeRedirect,
					Tag:  InboundRedirect + bind,
					Options: &option.RedirectInboundOptions{
						ListenOptions: option.ListenOptions{
							Listen:     &addr,
							ListenPort: hopt.RedirectPort,
						},
					},
				},
			)
		}
		if hopt.EnableDirectPort && hopt.DirectPort > 0 {
			options.Inbounds = append(
				options.Inbounds,
				option.Inbound{
					Type: C.TypeDirect,
					Tag:  InboundDirectTag + bind,
					Options: &option.DirectInboundOptions{
						ListenOptions: option.ListenOptions{
							Listen:     &addr,
							ListenPort: hopt.DirectPort,
						},
					},
				},
			)
		}
	}
}

func setRoutingOptions(options *option.Options, input *option.Options, hopt *ClientOptions, useSubDNS bool) error {
	dnsRules := []option.DefaultDNSRule{}
	routeRules := []option.Rule{}
	rulesets := []option.RuleSet{}

	if !useSubDNS {
		forceDirectRules, err := addForceDirect(options, hopt)
		if err != nil {
			return err
		}
		dnsRules = append(dnsRules, forceDirectRules...)
	}

	// L3: sniff always; hijack-dns only when UI enables it (default off).
	routeRules = append(routeRules, option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeSniff,
			},
		},
	})
	if hopt.EnableDnsHijack {
		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					Protocol: []string{C.ProtocolDNS},
				},
				RuleAction: option.RuleAction{
					Action: C.RuleActionTypeHijackDNS,
				},
			},
		})
	}

	routeRules = append(routeRules, option.Rule{
		Type: C.RuleTypeDefault,

		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{
				IPCIDR: []string{
					"10.10.34.0/24",
					"2001:4188:2:600:10:10:34:0/120",
				},
			},
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.RouteActionOptions{
					Outbound: OutboundMainDetour,
				},
			},
		},
	})

	if hopt.BypassLAN {
		// Before profile: private RFC1918/ULA/link-local/loopback (sing IPIsPrivate).
		routeRules = append(
			routeRules,
			option.Rule{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					RawDefaultRule: option.RawDefaultRule{
						IPIsPrivate: true,
					},
					RuleAction: option.RuleAction{
						Action: C.RuleActionTypeRoute,
						RouteOptions: option.RouteActionOptions{
							Outbound: OutboundDirectTag,
						},
					},
				},
			},
			// CGNAT (RFC 6598) — not covered by Go netip.IsPrivate / IPIsPrivate.
			option.Rule{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					RawDefaultRule: option.RawDefaultRule{
						IPCIDR: []string{"100.64.0.0/10"},
					},
					RuleAction: option.RuleAction{
						Action: C.RuleActionTypeRoute,
						RouteOptions: option.RouteActionOptions{
							Outbound: OutboundDirectTag,
						},
					},
				},
			},
		)
	}

	forceDirectRoute := make([]string, 0)
	if options.NTP != nil && options.NTP.Enabled {
		forceDirectRoute = append(forceDirectRoute, options.NTP.Server)
	}

	if len(forceDirectRoute) > 0 {

		dnsRules = append(dnsRules, option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{
				Domain: forceDirectRoute,
			},
			DNSRuleAction: option.DNSRuleAction{
				Action:       C.RuleActionTypeRoute,
				RouteOptions: dnsRouteWithOptionalStrategy(DNSMultiDirectTag, hopt.DirectDnsDomainStrategy, hopt.EnableFakeDNS, &DEFAULT_DNS_TTL, false),
			},
		})
		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					Domain: forceDirectRoute,
				},
				RuleAction: option.RuleAction{
					Action: C.RuleActionTypeRoute,
					RouteOptions: option.RouteActionOptions{
						Outbound: OutboundDirectTag,
					},
				},
			},
		})
	}

	// L4: client-owned ads block (before profile buckets and subscription overlay).
	if hopt.BlockAds && hopt.AdsRuleSetPath != "" {
		appendAdsBlockRules(&rulesets, &routeRules, hopt.AdsRuleSetPath)
	}

	// L4: client-owned route — local profile stack first, then optional subscription overlay.
	var localRS []option.RuleSet
	var localRules []option.Rule
	profiles := hopt.RoutingProfiles
	if len(profiles) == 0 && hopt.RoutingProfile != nil {
		profiles = []*RoutingProfile{hopt.RoutingProfile}
	}
	for _, rp := range profiles {
		if rp == nil || !rp.Enabled {
			continue
		}
		rs, rules := CompileRoutingProfile(rp, hopt.GeoIPRuleSetURL, hopt.GeoSiteRuleSetURL)
		localRS = append(localRS, rs...)
		localRules = append(localRules, rules...)
	}
	for _, rs := range localRS {
		rulesets = append(rulesets, rs)
	}
	routeRules = append(routeRules, localRules...)

	// After profile: reject remaining QUIC so LAN / "No VPN" (direct) keep QUIC.
	if hopt.RouteOptions.BlockQuic {
		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					Protocol: []string{C.ProtocolQUIC},
				},
				RuleAction: option.RuleAction{
					Action: C.RuleActionTypeReject,
					RejectOptions: option.RejectActionOptions{
						Method: C.RuleActionRejectMethodDefault,
					},
				},
			},
		})
	}

	// Subscription route is raw merge at connect time only (never auto-imported into local profile).
	// Local rules are always evaluated first so the client wins conflicts.
	if input != nil && input.Route != nil && !hopt.IgnoreSubscriptionRoute {
		MergeSubscriptionRoute(input.Route, &rulesets, &routeRules)
	}

	sanitized, err := sanitizeRuleSetsLocalOnly(rulesets)
	if err != nil {
		return err
	}
	rulesets = sanitized

	final := OutboundMainDetour
	globalProxy := true
	if hopt.RoutingGlobalProxy != nil {
		globalProxy = *hopt.RoutingGlobalProxy
	} else if len(profiles) == 1 && profiles[0] != nil {
		globalProxy = profiles[0].GlobalProxy
	} else if hopt.RoutingProfile != nil {
		globalProxy = hopt.RoutingProfile.GlobalProxy
	}
	anyEnabled := false
	for _, rp := range profiles {
		if rp != nil && rp.Enabled {
			anyEnabled = true
			break
		}
	}
	if anyEnabled && !globalProxy {
		final = OutboundDirectTag
	}

	strategy := defaultNetworkStrategyForIPv6Mode(hopt.IPv6Mode)
	// sing-box requires auto_detect_interface whenever default_network_strategy is set.
	// Android/iOS normally skip this for main TUN (platform owns routing); TestMode side
	// box must enable it so ProtectFunc / auto_detect_interface_control runs under VPN.
	autoDetect := (!C.IsAndroid && !C.IsIos) && (hopt.EnableTun || hopt.EnableTunService || strategy != nil)
	if hopt.TestMode && (C.IsAndroid || C.IsIos) {
		autoDetect = true
	}

	findProcess := false
	for _, rp := range profiles {
		if ProfileNeedsFindProcess(rp) {
			findProcess = true
			break
		}
	}

	options.Route = &option.RouteOptions{
		Rules:                  routeRules,
		Final:                  final,
		AutoDetectInterface:    autoDetect,
		DefaultNetworkStrategy: strategy,
		RuleSet:                rulesets,
		FindProcess:            findProcess,
	}
	if useSubDNS {
		if options.DNS != nil {
			server := options.DNS.Final
			if server == "" && len(options.DNS.Servers) > 0 {
				server = options.DNS.Servers[0].Tag
			}
			if server != "" {
				options.Route.DefaultDomainResolver = &option.DomainResolveOptions{
					Server: server,
				}
			}
		}
	} else {
		options.Route.DefaultDomainResolver = &option.DomainResolveOptions{
			Server:   DNSBootstrapTag,
			Strategy: hopt.DirectDnsDomainStrategy,
		}
		if hopt.EnableFakeDNS {
			dnsRules = append(
				dnsRules,
				option.DefaultDNSRule{
					RawDefaultDNSRule: option.RawDefaultDNSRule{
						QueryType: badoption.Listable[option.DNSQueryType]{
							option.DNSQueryType(mDNS.StringToType["A"]),
							option.DNSQueryType(mDNS.StringToType["AAAA"]),
						},
					},
					DNSRuleAction: option.DNSRuleAction{
						Action:       C.RuleActionTypeRoute,
						// No Legacy strategy: incompatible with query_type in sing-box 1.14.
						RouteOptions: dnsRouteAction(DNSFakeTag, 0, &DEFAULT_DNS_TTL, true),
					},
				})
		}
		dnsRules = append(dnsRules, option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{},
			DNSRuleAction: option.DNSRuleAction{
				Action:       C.RuleActionTypeRoute,
				RouteOptions: dnsRouteWithOptionalStrategy(DNSRemoteTag, hopt.RemoteDnsDomainStrategy, hopt.EnableFakeDNS, &DEFAULT_DNS_TTL, false),
			},
		})
	}

	if !useSubDNS && options.DNS != nil {
		if hopt.EnableFakeDNS {
			// Move domain strategy off rule actions onto client-level dns.strategy.
			options.DNS.Strategy = hopt.RemoteDnsDomainStrategy
		}
		for _, dnsRule := range dnsRules {
			if dnsRule.IsValid() {
				options.DNS.Rules = append(
					options.DNS.Rules,
					option.DNSRule{
						Type:           C.RuleTypeDefault,
						DefaultOptions: dnsRule,
					},
				)
			}
		}
	}

	return nil
}


var (
	ipMaps      = map[string][]string{}
	ipMapsMutex sync.Mutex
)

func getIPs(domains ...string) []string {
	var wg sync.WaitGroup
	resChan := make(chan string, len(domains)*10) // Collect both IPv4 and IPv6
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	for _, d := range domains {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", domain)
			if err != nil {
				return
			}
			for _, ip := range ips {
				ipStr := ip.String()
				if !isBlockedIP(ipStr) {
					resChan <- ipStr
				}
			}
		}(d)
	}

	go func() {
		wg.Wait()
		close(resChan)
	}()

	var res []string
	for ip := range resChan {
		res = append(res, ip)
	}
	if len(res) == 0 && ipMaps[domains[0]] != nil {
		return ipMaps[domains[0]]
	}
	ipMapsMutex.Lock()
	ipMaps[domains[0]] = res
	ipMapsMutex.Unlock()

	return res
}

func isBlockedDomain(domain string) bool {
	if strings.HasPrefix("full:", domain) {
		return false
	}
	if strings.Contains(domain, "instagram") || strings.Contains(domain, "facebook") || strings.Contains(domain, "telegram") || strings.Contains(domain, "t.me") {
		return true
	}
	ips := getIPs(domain)
	if len(ips) == 0 {
		// fmt.Println(err)
		return true
	}

	// // Print the IP addresses associated with the domain
	// fmt.Printf("IP addresses for %s:\n", domain)
	// for _, ip := range ips {
	// 	if isBlockedIP(ip) {
	// 		return true
	// 	}
	// }
	return false
}

func isBlockedIP(ip string) bool {
	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "2001:4188:2:600:10") {
		return true
	}
	return false
}

func removeDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}
