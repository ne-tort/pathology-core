package config

import (
	"reflect"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// RemapLogicalOutbound maps panel/Happ logical outbound tags to Hiddify sing-box tags.
// Returns (outboundTag, reject). If reject is true, the rule should use action reject.
func RemapLogicalOutbound(tag string) (outbound string, reject bool) {
	switch strings.ToLower(strings.TrimSpace(tag)) {
	case "", "proxy", "select", "lowest", "balance":
		return OutboundSelectTag, false
	case "direct", "bypass":
		return OutboundDirectTag, false
	case "block", "reject":
		return "", true
	default:
		// Already a concrete outbound tag from the subscription plane.
		if tag == OutboundDirectTag || tag == OutboundBypassTag {
			return tag, false
		}
		return tag, false
	}
}

// RemapDialerDetour maps logical dialer detour tags to concrete Hiddify outbound tags.
// Unlike route remapping, empty stays empty (no default to select), and reject/block clear.
func RemapDialerDetour(tag string) string {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return ""
	}
	out, reject := RemapLogicalOutbound(tag)
	if reject {
		return ""
	}
	return out
}

// ApplyDialerDetourRemap rewrites DialerOptions.Detour on outbounds/endpoints that expose it.
func ApplyDialerDetourRemap(opts any) {
	w, ok := opts.(option.DialerOptionsWrapper)
	if !ok {
		return
	}
	d := w.TakeDialerOptions()
	if d.Detour == "" {
		return
	}
	if remapped := RemapDialerDetour(d.Detour); remapped != d.Detour {
		d.Detour = remapped
		w.ReplaceDialerOptions(d)
	}
}

// NormalizeRouteRule remaps route/reject actions on a single rule.
func NormalizeRouteRule(rule option.Rule) option.Rule {
	switch rule.Type {
	case "", C.RuleTypeDefault:
		rule.Type = C.RuleTypeDefault
		rule.DefaultOptions = normalizeDefaultRule(rule.DefaultOptions)
	case C.RuleTypeLogical:
		// The logical rule's own action is the one the router resolves on match
		// (route/route.go:113), so normalize it before walking the children: a
		// panel spelling like "proxy"/"block" on the logical rule itself would
		// otherwise reach the outbound manager verbatim and fail as
		// "outbound not found". Doing it first also keeps the child loop below
		// untouched. Only rules that already carry an action are touched — an
		// action-less logical rule stays action-less (match-only) instead of
		// being turned into "route → select".
		if hasConfiguredRuleAction(rule.LogicalOptions.RuleAction) {
			rule.LogicalOptions.RuleAction = normalizeRuleAction(rule.LogicalOptions.RuleAction)
		}
		for i := range rule.LogicalOptions.Rules {
			rule.LogicalOptions.Rules[i] = NormalizeRouteRule(rule.LogicalOptions.Rules[i])
		}
	}
	return rule
}

// hasConfiguredRuleAction mirrors ruleHasConfiguredAction in the engine.
func hasConfiguredRuleAction(action option.RuleAction) bool {
	return !reflect.DeepEqual(action, option.RuleAction{})
}

func normalizeDefaultRule(r option.DefaultRule) option.DefaultRule {
	r.RuleAction = normalizeRuleAction(r.RuleAction)
	return r
}

// normalizeRuleAction remaps route/reject/bypass actions onto concrete client tags.
func normalizeRuleAction(action option.RuleAction) option.RuleAction {
	actionType := action.Action
	if actionType == "" {
		actionType = C.RuleActionTypeRoute
	}
	switch actionType {
	case C.RuleActionTypeRoute, "":
		out, reject := RemapLogicalOutbound(action.RouteOptions.Outbound)
		if reject {
			action.Action = C.RuleActionTypeReject
			action.RouteOptions = option.RouteActionOptions{}
			action.RejectOptions = option.RejectActionOptions{
				Method: C.RuleActionRejectMethodDefault,
			}
			return action
		}
		action.Action = C.RuleActionTypeRoute
		action.RouteOptions.Outbound = out
	case C.RuleActionTypeReject:
		// keep
	case C.RuleActionTypeBypass:
		action.Action = C.RuleActionTypeRoute
		action.RouteOptions.Outbound = OutboundDirectTag
		action.BypassOptions = option.RouteActionOptions{}
	}
	return action
}

// MergeSubscriptionRoute appends subscription rule_sets (dedup by tag) and
// normalized rules. Subscription route is never written into the local profile;
// it is only overlaid at connect time. Local rules must already be in routeRules
// so they win conflicts. Skips bare sniff/hijack that the client injects as L3.
func MergeSubscriptionRoute(
	sub *option.RouteOptions,
	rulesets *[]option.RuleSet,
	routeRules *[]option.Rule,
) {
	if !SubscriptionRouteHasPolicy(sub) {
		return
	}
	seen := make(map[string]struct{}, len(*rulesets))
	for _, rs := range *rulesets {
		for _, tag := range rs.Tag {
			if tag != "" {
				seen[tag] = struct{}{}
			}
		}
	}
	for _, rs := range sub.RuleSet {
		if len(rs.Tag) == 0 {
			continue
		}
		dup := false
		for _, tag := range rs.Tag {
			if tag == "" {
				continue
			}
			if _, ok := seen[tag]; ok {
				dup = true
				break
			}
		}
		if dup {
			continue
		}
		for _, tag := range rs.Tag {
			if tag != "" {
				seen[tag] = struct{}{}
			}
		}
		*rulesets = append(*rulesets, rs)
	}
	for _, rule := range sub.Rules {
		if isClientL3Hook(rule) {
			continue
		}
		*routeRules = append(*routeRules, NormalizeRouteRule(rule))
	}
}

// SubscriptionRouteHasPolicy is true when the subscription carries real route
// policy (rule_set or non-L3 rules), not only empty/sniff stubs.
func SubscriptionRouteHasPolicy(sub *option.RouteOptions) bool {
	if sub == nil {
		return false
	}
	if len(sub.RuleSet) > 0 {
		return true
	}
	for _, rule := range sub.Rules {
		if !isClientL3Hook(rule) {
			return true
		}
	}
	return false
}

func isClientL3Hook(rule option.Rule) bool {
	if rule.Type != "" && rule.Type != C.RuleTypeDefault {
		return false
	}
	r := rule.DefaultOptions
	switch r.Action {
	case C.RuleActionTypeSniff, C.RuleActionTypeHijackDNS:
		// Skip bare sniff / hijack without extra matchers — client owns L3.
		return !hasRouteMatchers(r)
	default:
		return false
	}
}

func hasRouteMatchers(r option.DefaultRule) bool {
	return len(r.RuleSet) > 0 ||
		len(r.Domain) > 0 ||
		len(r.DomainSuffix) > 0 ||
		len(r.DomainKeyword) > 0 ||
		len(r.DomainRegex) > 0 ||
		len(r.IPCIDR) > 0 ||
		len(r.SourceIPCIDR) > 0 ||
		len(r.Port) > 0 ||
		len(r.PortRange) > 0 ||
		len(r.ProcessName) > 0 ||
		len(r.PackageName) > 0 ||
		len(r.Protocol) > 0 ||
		r.IPIsPrivate ||
		r.SourceIPIsPrivate
}
