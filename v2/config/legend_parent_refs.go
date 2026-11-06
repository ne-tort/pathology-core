package config

import (
	"context"
	"fmt"

	"github.com/sagernet/sing-box/option"
)

// legend_parent_refs.go — a pathology legend parent exists only so the engine
// can expand it into {parent}-{legend} virtuals at box.New; the parent tag
// itself is deleted from the outbound manager (option.ExpandPathologyOutbounds:
// "Parent tag is omitted from the result when legends are set").
//
// Anything that still names the parent becomes a dangling reference and box.New
// fails dependency resolution:
//
//	dependency[...path-auto...] not found for outbound[fo]
//
// The engine proves that failure mode in test/pathology_legend_group_lx_test.go
// (TestPathologyLegendParentInGroupMemberList_LX), and it is reachable from an
// ordinary subscription: a profile that wraps a pathology legend set in a
// failover/scatter, or detours another outbound through it, hits it on every
// start. The builder is the only place that knows which parents survive — it
// drops the unusable ones and synthesizes the rotation group — so it owns the
// rewrite.

// legendRefPlan says what a reference to a legend parent must become: the
// virtual tags that replace it, or dropped=true when the parent was dropped
// whole and can never be referenced.
type legendRefPlan struct {
	virtuals []string
	dropped  bool
}

// expandLegendParentRefs rewrites group member lists that name a legend parent
// into the tags that will exist after expansion, and drops a group whose
// members all disappeared with the parent.
func expandLegendParentRefs(ctx context.Context, outbounds []option.Outbound, plans map[string]legendRefPlan) []option.Outbound {
	if len(plans) == 0 {
		return outbounds
	}
	kept := make([]option.Outbound, 0, len(outbounds))
	for _, ob := range outbounds {
		lists := groupRefLists(ob.Options)
		if len(lists) == 0 {
			kept = append(kept, ob)
			continue
		}
		touched := false
		for parent, plan := range plans {
			if !refListsContain(lists, parent) {
				continue
			}
			touched = true
			if plan.dropped {
				warnLegendParentNotEmitted(ctx, parent,
					fmt.Sprintf("dropped: group %q referenced it, so its members are removed from that group", ob.Tag))
				for i := range lists {
					*lists[i] = removeTag(*lists[i], parent)
				}
				continue
			}
			for i := range lists {
				*lists[i] = expandTag(*lists[i], parent, plan.virtuals)
			}
		}
		if !touched {
			kept = append(kept, ob)
			continue
		}
		if def := groupDefaultRef(ob.Options); def != nil {
			if plan, ok := plans[*def]; ok {
				*def = ""
				if len(plan.virtuals) > 0 {
					*def = plan.virtuals[0]
				}
			}
		}
		if allRefListsEmpty(lists) {
			// Every member was a dropped parent. An empty member list is itself
			// a start error ("missing tags"), and the group can never dial.
			fmt.Printf("[SingboxParser] skip outbound group type=%q tag=%q: every member was a pathology legend parent that could not be expanded\n", ob.Type, ob.Tag)
			continue
		}
		kept = append(kept, ob)
	}
	return kept
}

// expandLegendParentRefsInEndpoints rewrites an endpoint detour that names a
// legend parent. A detour is single-valued, so the first virtual is the
// faithful choice: the parent means "this legend set", and the rotation group
// is what actually picks a legend at dial time.
func expandLegendParentRefsInEndpoints(ctx context.Context, endpoints []option.Endpoint, plans map[string]legendRefPlan) []option.Endpoint {
	if len(plans) == 0 {
		return endpoints
	}
	for i := range endpoints {
		wrapper, ok := endpoints[i].Options.(option.DialerOptionsWrapper)
		if !ok {
			continue
		}
		dialer := wrapper.TakeDialerOptions()
		if dialer.Detour == "" {
			continue
		}
		plan, isParent := plans[dialer.Detour]
		if !isParent {
			continue
		}
		switch {
		case plan.dropped:
			warnLegendParentNotEmitted(ctx, dialer.Detour,
				fmt.Sprintf("dropped: endpoint %q detoured through it; the detour is cleared", endpoints[i].Tag))
			dialer.Detour = ""
		case len(plan.virtuals) > 0:
			dialer.Detour = plan.virtuals[0]
		default:
			continue
		}
		wrapper.ReplaceDialerOptions(dialer)
	}
	return endpoints
}

// groupRefLists returns the mutable member lists of a group outbound, or nil
// when the options are not a group. Each entry points into the option struct,
// so writing through it mutates the config in place.
func groupRefLists(opts any) []*[]string {
	switch o := opts.(type) {
	case *option.SelectorOutboundOptions:
		return []*[]string{&o.Outbounds}
	case *option.URLTestOutboundOptions:
		return []*[]string{&o.Outbounds}
	case *option.BalancerOutboundOptions:
		return []*[]string{&o.Outbounds}
	case *option.FailoverOutboundOptions:
		return []*[]string{&o.Outbounds}
	case *option.ScatterOutboundOptions:
		return []*[]string{&o.Paths, &o.UplinkPaths, &o.DownlinkPaths}
	default:
		return nil
	}
}

// groupDefaultRef returns the mutable `default` member of a group, if any.
func groupDefaultRef(opts any) *string {
	if o, ok := opts.(*option.SelectorOutboundOptions); ok {
		return &o.Default
	}
	return nil
}

func refListsContain(lists []*[]string, tag string) bool {
	for _, list := range lists {
		for _, item := range *list {
			if item == tag {
				return true
			}
		}
	}
	return false
}

func allRefListsEmpty(lists []*[]string) bool {
	if len(lists) == 0 {
		return false
	}
	for _, list := range lists {
		if len(*list) > 0 {
			return false
		}
	}
	return true
}

// removeTag drops every occurrence of tag, preserving order.
func removeTag(list []string, tag string) []string {
	out := make([]string, 0, len(list))
	for _, item := range list {
		if item == tag {
			continue
		}
		out = append(out, item)
	}
	return out
}

// expandTag replaces every occurrence of parent with the virtuals that stand in
// for it, preserving position and de-duplicating the result.
func expandTag(list []string, parent string, virtuals []string) []string {
	out := make([]string, 0, len(list)+len(virtuals))
	seen := make(map[string]bool, len(list)+len(virtuals))
	add := func(tag string) {
		if seen[tag] {
			return
		}
		seen[tag] = true
		out = append(out, tag)
	}
	for _, item := range list {
		if item == parent {
			for _, v := range virtuals {
				add(v)
			}
			continue
		}
		add(item)
	}
	return out
}
