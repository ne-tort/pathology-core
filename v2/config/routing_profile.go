package config

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// Default remote .srs templates (SagerNet rule-set branches).
const (
	DefaultGeoIPRuleSetURL   = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-{tag}.srs"
	DefaultGeoSiteRuleSetURL = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-{tag}.srs"
)

// RoutePriority is retained for JSON compat; Build always applies local profile
// before subscription route (client owns conflicts).
type RoutePriority string

const (
	RoutePriorityLocalFirst        RoutePriority = "local"
	RoutePrioritySubscriptionFirst RoutePriority = "subscription" // ignored; kept for older clients
)

// ProcessMatch is a desktop process owner matcher (name, path, and/or path regex).
// Mirrors Leadaxe singbox-launcher: route rules + find_process (not WFP/cgroup).
type ProcessMatch struct {
	Name      string `json:"name,omitempty"`
	Path      string `json:"path,omitempty"`
	PathRegex string `json:"path_regex,omitempty"`
}

// RoutingProfile is the Happ-like canonical routing model (client + optional panel).
type RoutingProfile struct {
	Name        string `json:"name,omitempty"`
	Enabled     bool   `json:"enabled,omitempty"`
	GlobalProxy bool   `json:"global_proxy,omitempty"` // final = proxy when true
	// RuleOrder: e.g. "block-direct-proxy" (default). Controls bucket emission order.
	RuleOrder string `json:"rule_order,omitempty"`

	DirectSites []string `json:"direct_sites,omitempty"`
	DirectIP    []string `json:"direct_ip,omitempty"`
	ProxySites  []string `json:"proxy_sites,omitempty"`
	ProxyIP     []string `json:"proxy_ip,omitempty"`
	BlockSites  []string `json:"block_sites,omitempty"`
	BlockIP     []string `json:"block_ip,omitempty"`

	// Android route-by-owner (package_name).
	DirectPackages []string `json:"direct_packages,omitempty"`
	ProxyPackages  []string `json:"proxy_packages,omitempty"`
	BlockPackages  []string `json:"block_packages,omitempty"`

	// Desktop route-by-owner (process_name / process_path).
	DirectProcesses []ProcessMatch `json:"direct_processes,omitempty"`
	ProxyProcesses  []ProcessMatch `json:"proxy_processes,omitempty"`
	BlockProcesses  []ProcessMatch `json:"block_processes,omitempty"`

	// Asset templates; `{tag}` replaced with country/category code (without geoip:/geosite: prefix).
	GeoIPURL   string `json:"geoip_url,omitempty"`
	GeoSiteURL string `json:"geosite_url,omitempty"`
}

// RoutingProfileOptions are client settings for profile merge.
type RoutingProfileOptions struct {
	IgnoreSubscriptionRoute bool             `json:"ignore-subscription-route,omitempty"`
	RoutePriority           RoutePriority    `json:"route-priority,omitempty"`
	Profile                 *RoutingProfile  `json:"routing-profile,omitempty"`
	GeoIPURL                string           `json:"geoip-ruleset-url,omitempty"`
	GeoSiteURL              string           `json:"geosite-ruleset-url,omitempty"`
}

// CompileRoutingProfile builds rule_sets + rules from an abstract profile.
func CompileRoutingProfile(p *RoutingProfile, geoIPURL, geoSiteURL string) (rulesets []option.RuleSet, rules []option.Rule) {
	if p == nil || !p.Enabled {
		return nil, nil
	}
	if geoIPURL == "" {
		geoIPURL = p.GeoIPURL
	}
	if geoSiteURL == "" {
		geoSiteURL = p.GeoSiteURL
	}
	if geoIPURL == "" {
		geoIPURL = DefaultGeoIPRuleSetURL
	}
	if geoSiteURL == "" {
		geoSiteURL = DefaultGeoSiteRuleSetURL
	}

	seen := map[string]struct{}{}
	addLocalRS := func(tag, path string) {
		if tag == "" || path == "" {
			return
		}
		if _, ok := seen[tag]; ok {
			return
		}
		seen[tag] = struct{}{}
		format := localRuleSetFormatByPath(path)
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeLocal,
			Tag:    ruleSetTags(tag),
			Format: format,
			LocalOptions: option.LocalRuleSet{
				Path: path,
			},
		})
	}
	addRS := func(tag, url string) {
		if tag == "" {
			return
		}
		if _, ok := seen[tag]; ok {
			return
		}
		url = strings.TrimSpace(url)
		if url != "" && !isRemoteRulesetURL(url) {
			addLocalRS(tag, normalizeLocalRulesetPath(strings.TrimPrefix(url, "file://")))
			return
		}
		seen[tag] = struct{}{}
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    ruleSetTags(tag),
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            url,
				UpdateInterval: badoption.Duration(24 * time.Hour),
				DownloadDetour: OutboundDirectTag,
			},
		})
	}

	var blockRS, directRS, proxyRS []string
	var blockDomain, directDomain, proxyDomain []string
	var blockCIDR, directCIDR, proxyCIDR []string

	consume := func(items []string, rs *[]string, domains *[]string, cidrs *[]string) {
		for _, raw := range items {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			lower := strings.ToLower(raw)
			switch {
			case strings.HasPrefix(lower, "geoip:"):
				code := strings.TrimPrefix(lower, "geoip:")
				tag := "geoip-" + code
				addRS(tag, strings.ReplaceAll(geoIPURL, "{tag}", code))
				*rs = append(*rs, tag)
			case strings.HasPrefix(lower, "geosite:"):
				code := strings.TrimPrefix(lower, "geosite:")
				tag := "geosite-" + code
				addRS(tag, strings.ReplaceAll(geoSiteURL, "{tag}", code))
				*rs = append(*rs, tag)
			case strings.HasPrefix(lower, "remote-srs:"):
				url := strings.TrimSpace(raw[len("remote-srs:"):])
				if url == "" {
					continue
				}
				tag := "custom-" + shortHash(url)
				addRS(tag, url)
				*rs = append(*rs, tag)
			case strings.HasPrefix(lower, "local-srs:"):
				path := normalizeLocalRulesetPath(strings.TrimSpace(raw[len("local-srs:"):]))
				if path == "" {
					continue
				}
				tag := "local-" + shortHash(path)
				addLocalRS(tag, path)
				*rs = append(*rs, tag)
			default:
				if isCIDR(raw) {
					*cidrs = append(*cidrs, raw)
				} else {
					*domains = append(*domains, raw)
				}
			}
		}
	}

	consume(p.BlockSites, &blockRS, &blockDomain, &blockCIDR)
	consume(p.BlockIP, &blockRS, &blockDomain, &blockCIDR)
	consume(p.DirectSites, &directRS, &directDomain, &directCIDR)
	consume(p.DirectIP, &directRS, &directDomain, &directCIDR)
	consume(p.ProxySites, &proxyRS, &proxyDomain, &proxyCIDR)
	consume(p.ProxyIP, &proxyRS, &proxyDomain, &proxyCIDR)

	appendMatchRules := func(rsTags, domains, cidrs []string, reject bool, outbound string) {
		if len(rsTags) > 0 {
			rules = append(rules, matchRule(rsTags, nil, nil, reject, outbound))
		}
		if len(domains) > 0 {
			rules = append(rules, matchRule(nil, domains, nil, reject, outbound))
		}
		if len(cidrs) > 0 {
			rules = append(rules, matchRule(nil, nil, cidrs, reject, outbound))
		}
	}

	appendOwnerRules := func(packages []string, processes []ProcessMatch, reject bool, outbound string) {
		pkgs := normalizeStringList(packages)
		if len(pkgs) > 0 {
			rules = append(rules, ownerRule(pkgs, nil, nil, nil, reject, outbound))
		}
		var names, paths, pathRegexes []string
		for _, proc := range processes {
			n := normalizeProcessToken(proc.Name)
			path := normalizeProcessToken(proc.Path)
			rx := normalizeProcessToken(proc.PathRegex)
			if rx != "" {
				pathRegexes = append(pathRegexes, rx)
				continue
			}
			if path != "" {
				if strings.Contains(path, "*") {
					if converted, err := simpleProcessPathPatternToRegex(path); err == nil {
						pathRegexes = append(pathRegexes, converted)
						continue
					}
				}
				paths = append(paths, path)
				continue
			}
			if n != "" {
				names = append(names, n)
			}
		}
		if len(names) > 0 {
			rules = append(rules, ownerRule(nil, names, nil, nil, reject, outbound))
		}
		if len(paths) > 0 {
			rules = append(rules, ownerRule(nil, nil, paths, nil, reject, outbound))
		}
		if len(pathRegexes) > 0 {
			rules = append(rules, ownerRule(nil, nil, nil, pathRegexes, reject, outbound))
		}
	}

	emitsOwner := map[string]func(){
		"block":  func() { appendOwnerRules(p.BlockPackages, p.BlockProcesses, true, "") },
		"direct": func() { appendOwnerRules(p.DirectPackages, p.DirectProcesses, false, OutboundDirectTag) },
		"proxy":  func() { appendOwnerRules(p.ProxyPackages, p.ProxyProcesses, false, OutboundSelectTag) },
	}
	emits := map[string]func(){
		"block":  func() { appendMatchRules(blockRS, blockDomain, blockCIDR, true, "") },
		"direct": func() { appendMatchRules(directRS, directDomain, directCIDR, false, OutboundDirectTag) },
		"proxy":  func() { appendMatchRules(proxyRS, proxyDomain, proxyCIDR, false, OutboundSelectTag) },
	}
	order := strings.Split(p.RuleOrder, "-")
	if len(order) != 3 {
		order = []string{"block", "direct", "proxy"}
	}
	// Owner (package/process) rules first — first-match wins over domain/IP buckets.
	seenOrder := map[string]struct{}{}
	for _, name := range order {
		name = strings.ToLower(strings.TrimSpace(name))
		fn, ok := emitsOwner[name]
		if !ok {
			continue
		}
		if _, dup := seenOrder[name]; dup {
			continue
		}
		seenOrder[name] = struct{}{}
		fn()
	}
	for _, name := range []string{"block", "direct", "proxy"} {
		if _, ok := seenOrder[name]; !ok {
			emitsOwner[name]()
		}
	}
	seenOrder = map[string]struct{}{}
	for _, name := range order {
		name = strings.ToLower(strings.TrimSpace(name))
		fn, ok := emits[name]
		if !ok {
			continue
		}
		if _, dup := seenOrder[name]; dup {
			continue
		}
		seenOrder[name] = struct{}{}
		fn()
	}
	for _, name := range []string{"block", "direct", "proxy"} {
		if _, ok := seenOrder[name]; !ok {
			emits[name]()
		}
	}

	return rulesets, rules
}

func normalizeStringList(items []string) []string {
	out := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, raw := range items {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		key := strings.ToLower(s)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, s)
	}
	return out
}

// normalizeProcessToken trims whitespace and strips matching quotes (`"..."` / `'...'`).
func normalizeProcessToken(raw string) string {
	s := strings.TrimSpace(raw)
	for len(s) >= 2 {
		a, b := s[0], s[len(s)-1]
		if (a == '"' && b == '"') || (a == '\'' && b == '\'') {
			s = strings.TrimSpace(s[1 : len(s)-1])
			continue
		}
		break
	}
	return s
}

func shortHash(s string) string {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return fmt.Sprintf("%08x", h)
}

func matchRule(rsTags, domains, cidrs []string, reject bool, outbound string) option.Rule {
	raw := option.RawDefaultRule{}
	if len(rsTags) > 0 {
		raw.RuleSet = rsTags
	}
	if len(domains) > 0 {
		raw.DomainSuffix = domains
	}
	if len(cidrs) > 0 {
		raw.IPCIDR = prefixableCIDRs(cidrs)
	}
	return ruleWithAction(raw, reject, outbound)
}

// prefixableCIDRs converts CIDR strings to the sing-box 1.5 shape
// (RawDefaultRule.IPCIDR changed []string → Listable[*Prefixable]).
// Bare IPs become host prefixes (mirrors Prefixable.UnmarshalJSON);
// unparsable entries are dropped — the engine rejects them at load anyway.
func prefixableCIDRs(cidrs []string) badoption.Listable[*badoption.Prefixable] {
	out := make(badoption.Listable[*badoption.Prefixable], 0, len(cidrs))
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if p, err := netip.ParsePrefix(c); err == nil {
			pp := badoption.Prefixable(p)
			out = append(out, &pp)
			continue
		}
		if a, err := netip.ParseAddr(c); err == nil {
			pp := badoption.Prefixable(netip.PrefixFrom(a, a.BitLen()))
			out = append(out, &pp)
		}
	}
	return out
}

func ownerRule(packages, processNames, processPaths, processPathRegexes []string, reject bool, outbound string) option.Rule {
	raw := option.RawDefaultRule{}
	if len(packages) > 0 {
		raw.PackageName = packages
	}
	if len(processNames) > 0 {
		raw.ProcessName = processNames
	}
	if len(processPaths) > 0 {
		raw.ProcessPath = processPaths
	}
	if len(processPathRegexes) > 0 {
		raw.ProcessPathRegex = processPathRegexes
	}
	return ruleWithAction(raw, reject, outbound)
}

// simpleProcessPathPatternToRegex ports Leadaxe singbox-launcher SimplePatternToRegex.
func simpleProcessPathPatternToRegex(pattern string) (string, error) {
	pattern = normalizeProcessToken(pattern)
	if pattern == "" {
		return "", fmt.Errorf("empty pattern")
	}
	var b strings.Builder
	for _, r := range pattern {
		switch {
		case r == '*':
			b.WriteString("(.*)")
		case strings.ContainsRune(`\.+?()[]{}^$|`, r):
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	s := b.String()
	if _, err := regexp.Compile(s); err != nil {
		return "", err
	}
	return s, nil
}

func ruleWithAction(raw option.RawDefaultRule, reject bool, outbound string) option.Rule {
	action := option.RuleAction{Action: C.RuleActionTypeRoute}
	if reject {
		action = option.RuleAction{
			Action: C.RuleActionTypeReject,
			RejectOptions: option.RejectActionOptions{
				Method: C.RuleActionRejectMethodDefault,
			},
		}
	} else {
		action.RouteOptions.Outbound = outbound
	}
	return option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: raw,
			RuleAction:     action,
		},
	}
}

// ProfileNeedsFindProcess reports whether compiled owner rules need process search.
func ProfileNeedsFindProcess(p *RoutingProfile) bool {
	if p == nil || !p.Enabled {
		return false
	}
	if len(p.DirectPackages) > 0 || len(p.ProxyPackages) > 0 || len(p.BlockPackages) > 0 {
		return true
	}
	hasProc := func(items []ProcessMatch) bool {
		for _, it := range items {
			if normalizeProcessToken(it.Name) != "" || normalizeProcessToken(it.Path) != "" || normalizeProcessToken(it.PathRegex) != "" {
				return true
			}
		}
		return false
	}
	return hasProc(p.DirectProcesses) || hasProc(p.ProxyProcesses) || hasProc(p.BlockProcesses)
}

func isCIDR(s string) bool {
	if strings.Contains(s, "/") {
		_, err := netip.ParsePrefix(s)
		return err == nil
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

func localRuleSetFormatByPath(path string) string {
	ext := strings.ToLower(filepath.Ext(strings.TrimSpace(path)))
	switch ext {
	case ".json":
		return C.RuleSetFormatSource
	default:
		return C.RuleSetFormatBinary
	}
}

// isWindowsDrivePath reports paths like C:\foo or C:/foo even when GOOS is not windows
// (filepath.IsAbs is false for these on Unix).
func isWindowsDrivePath(path string) bool {
	if len(path) < 3 || path[1] != ':' {
		return false
	}
	drive := path[0]
	if !((drive >= 'A' && drive <= 'Z') || (drive >= 'a' && drive <= 'z')) {
		return false
	}
	sep := path[2]
	return sep == '\\' || sep == '/'
}

// normalizeLocalRulesetPath converts legacy absolute Windows paths to base-relative refs.
// sing-box filemanager.BasePath only treats "/" as absolute, so "C:\..." gets joined again.
func normalizeLocalRulesetPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	raw := path
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) && !isWindowsDrivePath(raw) && !isWindowsDrivePath(path) {
		return path
	}
	// Force \ → / ourselves: filepath.ToSlash is a no-op for '\' when GOOS != windows.
	scan := strings.ReplaceAll(raw, `\`, `/`)
	lower := strings.ToLower(scan)
	for _, marker := range []string{"routing_profiles/", "rules/"} {
		idx := strings.Index(lower, marker)
		if idx >= 0 {
			return filepath.FromSlash(scan[idx:])
		}
	}
	return path
}

// ParseHappRoutingProfile imports Happ-compatible JSON fields into RoutingProfile.
func ParseHappRoutingProfile(m map[string]any) (*RoutingProfile, error) {
	if m == nil {
		return nil, fmt.Errorf("empty happ profile")
	}
	str := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := m[k]; ok {
				switch t := v.(type) {
				case string:
					return t
				}
			}
		}
		return ""
	}
	boolish := func(keys ...string) bool {
		for _, k := range keys {
			if v, ok := m[k]; ok {
				switch t := v.(type) {
				case bool:
					return t
				case string:
					return strings.EqualFold(t, "true") || t == "1"
				}
			}
		}
		return false
	}
	list := func(keys ...string) []string {
		for _, k := range keys {
			if v, ok := m[k]; ok {
				switch t := v.(type) {
				case []any:
					out := make([]string, 0, len(t))
					for _, e := range t {
						if s, ok := e.(string); ok && s != "" {
							out = append(out, s)
						}
					}
					return out
				case []string:
					return t
				}
			}
		}
		return nil
	}

	p := &RoutingProfile{
		Name:        str("Name", "name"),
		Enabled:     true,
		GlobalProxy: boolish("GlobalProxy", "global_proxy"),
		RuleOrder:   str("rule_order", "RuleOrder"),
		DirectSites: list("DirectSites", "direct_sites"),
		DirectIP:    list("DirectIp", "direct_ip"),
		ProxySites:  list("ProxySites", "proxy_sites"),
		ProxyIP:     list("ProxyIp", "proxy_ip"),
		BlockSites:  list("BlockSites", "block_sites"),
		BlockIP:     list("BlockIp", "block_ip"),
		GeoIPURL:    str("Geoipurl", "geoip_url"),
		GeoSiteURL:  str("Geositeurl", "geosite_url"),
	}
	// Happ Geoipurl points at .dat — ignore for sing-box remote .srs templates.
	if strings.Contains(strings.ToLower(p.GeoIPURL), ".dat") {
		p.GeoIPURL = ""
	}
	if strings.Contains(strings.ToLower(p.GeoSiteURL), ".dat") {
		p.GeoSiteURL = ""
	}
	return p, nil
}
