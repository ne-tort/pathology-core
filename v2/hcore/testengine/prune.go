package testengine

import (
	"reflect"
	"sort"
	"strings"

	"github.com/ne-tort/pathology-core/v2/config"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// pruneToAllowlist narrows a TestMode config down to the UI allowlist.
//
// The pruned graph must be closed; TestMode's allowlist bounds *dialed leaves*,
// it must never break a group's member list. box.New resolves the whole
// dependency graph before it starts anything, so one missing tag
// ("dependency[...] not found for outbound[...]") takes the entire side box
// down — and with it every ping of the profile.
//
// That is why this is a reachability pass and not a tag/type guess:
//
//  1. seed the keep set with the allowlist, the predefined service tags and
//     every select/urltest/balancer/block/dns/direct outbound (a service tag
//     must survive even when it currently has no members);
//  2. transitively add every tag a kept outbound/endpoint references — group
//     members (selector/urltest/balancer), failover.outbounds, scatter paths,
//     detour, underlay_detour, l3router underlay/peer detours, and anything
//     else the engine marks reference:"outbound" — resolving {parent}-{legend}
//     pathology virtuals back to the parent outbound they are expanded from;
//  3. drop what is still unreachable — outbounds, and endpoints reached only
//     by a detour that nothing kept — then drop groups left without a single
//     usable member (and, transitively, whatever referenced them). A service
//     group is widened instead of dropped: it must exist, so emptying it would
//     fail NewSelector/NewURLTest/NewBalancer just as surely.
//
// Leaves that survive only because a kept node references them are reported on
// a prunedButReferenced line: the allowlist wanted them gone, the graph does
// not allow it.
func pruneToAllowlist(opts *option.Options, leaves []string) {
	if opts == nil {
		return
	}
	allow := make(map[string]struct{}, len(leaves))
	for _, tag := range leaves {
		if tag != "" {
			allow[tag] = struct{}{}
		}
	}

	graph := newPruneGraph(opts)
	keep := make(map[string]struct{}, len(opts.Outbounds)+len(leaves))
	// dead holds tags proven unusable (empty group dropped, provider excluded
	// in TestMode). Nothing re-adds a dead tag, which also bounds the fixed
	// point below.
	dead := make(map[string]struct{})

	// keepTag seeds the keep set through resolve, so an allowlist naming a
	// {parent}-{legend} virtual keeps the parent that expands into it, and a
	// tag the side box must not build (punnel provider) is never kept even if
	// the client lists it.
	keepTag := func(tag string) {
		target, ok := graph.resolve(tag)
		if !ok {
			return
		}
		if _, isDead := dead[target]; isDead {
			return
		}
		keep[target] = struct{}{}
	}
	for tag := range allow {
		keepTag(tag)
	}
	for _, tag := range config.PredefinedOutboundTags {
		keepTag(tag)
	}
	keepTag(config.OutboundRoundRobinTag)
	for _, ob := range opts.Outbounds {
		// Service tags: route.final and the UI reach them by name even when
		// they end up with no members of their own.
		if isServiceTag(ob.Tag, ob.Type) {
			keep[ob.Tag] = struct{}{}
		}
	}

	for {
		changed := graph.expand(keep, dead)
		if graph.dropEmptyGroups(keep, dead) {
			changed = true
		}
		if !changed {
			break
		}
	}

	prunedButReferencedOutbounds := make([]string, 0)
	keptOutbounds := make([]option.Outbound, 0, len(opts.Outbounds))
	for i := range opts.Outbounds {
		ob := opts.Outbounds[i]
		// Groups dropped by dropEmptyGroups are already out of keep.
		if _, kept := keep[ob.Tag]; !kept {
			continue
		}
		graph.narrowMembers(&ob, keep, dead)
		keptOutbounds = append(keptOutbounds, ob)
		if _, listed := allow[ob.Tag]; listed {
			continue
		}
		// Only plain leaves are interesting here: a group or a service tag is
		// kept by design, and counting it would bury the leaves this line is
		// meant to surface.
		if isServiceTag(ob.Tag, ob.Type) || graph.isGroup(ob.Tag) {
			continue
		}
		prunedButReferencedOutbounds = append(prunedButReferencedOutbounds, ob.Tag)
	}
	opts.Outbounds = keptOutbounds

	prunedButReferencedEndpoints := make([]string, 0)
	keptEndpoints := make([]option.Endpoint, 0, len(opts.Endpoints))
	for i := range opts.Endpoints {
		ep := opts.Endpoints[i]
		if _, kept := keep[ep.Tag]; !kept {
			continue
		}
		keptEndpoints = append(keptEndpoints, ep)
		if _, listed := allow[ep.Tag]; !listed {
			prunedButReferencedEndpoints = append(prunedButReferencedEndpoints, ep.Tag)
		}
	}
	opts.Endpoints = keptEndpoints

	if len(prunedButReferencedOutbounds) > 0 || len(prunedButReferencedEndpoints) > 0 {
		sort.Strings(prunedButReferencedOutbounds)
		sort.Strings(prunedButReferencedEndpoints)
		// The allowlist bounds dialed leaves, but a kept group still names
		// these: dropping them would break the graph instead of slimming it.
		elogf("prunedButReferenced: kept outbounds=%v endpoints=%v (outside the allowlist, still referenced)",
			prunedButReferencedOutbounds, prunedButReferencedEndpoints)
	}
}

// pruneGraph indexes one built (pre-prune) config so the reachability pass can
// look tags up without scanning slices per reference.
type pruneGraph struct {
	outboundIndex map[string]int
	endpointIndex map[string]int
	outbounds     []option.Outbound
	endpoints     []option.Endpoint
	// parents maps a virtual-expanding parent tag ({parent}-{id} virtuals) to
	// the ids that will actually exist after the engine's expand pass.
	parents map[string]map[string]struct{}
}

func newPruneGraph(opts *option.Options) *pruneGraph {
	g := &pruneGraph{
		outboundIndex: make(map[string]int, len(opts.Outbounds)),
		endpointIndex: make(map[string]int, len(opts.Endpoints)),
		outbounds:     opts.Outbounds,
		endpoints:     opts.Endpoints,
		parents:       make(map[string]map[string]struct{}),
	}
	for i, ob := range opts.Outbounds {
		if ob.Tag == "" {
			continue
		}
		g.outboundIndex[ob.Tag] = i
		if ids, ok := outboundVirtualIDs(ob); ok {
			g.parents[ob.Tag] = ids
		}
	}
	for i, ep := range opts.Endpoints {
		if ep.Tag == "" {
			continue
		}
		g.endpointIndex[ep.Tag] = i
	}
	return g
}

// outboundVirtualIDs reports the {tag}-{id} virtual tags box.New creates for a
// legend/services parent, i.e. the ids the engine's expand pass will install.
// Since ExpandPathologyOutbounds/ExpandPunnelOutbounds replace the parent with
// these, a group may legally name {parent}-{id} and still need {parent} kept.
func outboundVirtualIDs(ob option.Outbound) (map[string]struct{}, bool) {
	switch opts := ob.Options.(type) {
	case *option.PathologyOutboundOptions:
		if opts == nil || len(opts.Legends) == 0 {
			return nil, false
		}
		// box.ExpandPathologyOutbounds only builds a virtual for a legend that
		// has auth material; a legend without auth never becomes a tag.
		ids := make(map[string]struct{}, len(opts.Auth))
		for id := range opts.Legends {
			if _, hasAuth := opts.Auth[id]; hasAuth {
				ids[id] = struct{}{}
			}
		}
		return ids, true
	case *option.PunnelOutboundOptions:
		// Only a provider parent expands (option/punnel_expand.go gates on the
		// role), and only services with a local listen become virtuals.
		if opts == nil || len(opts.Services) == 0 || !strings.EqualFold(strings.TrimSpace(opts.Role), option.PunnelRoleProvider) {
			return nil, false
		}
		ids := make(map[string]struct{}, len(opts.Services))
		for id, entry := range opts.Services {
			if strings.TrimSpace(entry.Local) != "" {
				ids[id] = struct{}{}
			}
		}
		return ids, true
	}
	return nil, false
}

func (g *pruneGraph) exists(tag string) bool {
	if _, ok := g.outboundIndex[tag]; ok {
		return true
	}
	_, ok := g.endpointIndex[tag]
	return ok
}

func (g *pruneGraph) outbound(tag string) (option.Outbound, bool) {
	i, ok := g.outboundIndex[tag]
	if !ok {
		return option.Outbound{}, false
	}
	return g.outbounds[i], true
}

func (g *pruneGraph) endpoint(tag string) (option.Endpoint, bool) {
	i, ok := g.endpointIndex[tag]
	if !ok {
		return option.Endpoint{}, false
	}
	return g.endpoints[i], true
}

// isGroup reports whether tag names a group (member-list) outbound.
func (g *pruneGraph) isGroup(tag string) bool {
	ob, ok := g.outbound(tag)
	if !ok {
		return false
	}
	_, isGroup := groupMemberList(ob)
	return isGroup
}

// referencesOf returns every tag the kept outbound/endpoint named by tag points
// at. Endpoints are included: a wireguard/l3router endpoint referenced by a
// detour must survive for the same reason a member must.
func (g *pruneGraph) referencesOf(tag string) []string {
	if ob, ok := g.outbound(tag); ok {
		return outboundReferenceTags(ob)
	}
	if ep, ok := g.endpoint(tag); ok {
		return endpointReferenceTags(ep)
	}
	return nil
}

// expand adds every reachable reference of the current keep set. It reports
// whether the keep set grew; callers loop until the graph stops changing.
func (g *pruneGraph) expand(keep, dead map[string]struct{}) bool {
	changed := false
	for tag := range keep {
		if _, isDead := dead[tag]; isDead {
			continue
		}
		for _, ref := range g.referencesOf(tag) {
			target, ok := g.resolve(ref)
			if !ok {
				// Dangling (never existed) or excluded in TestMode; the
				// referencing group is emptied out by dropEmptyGroups.
				continue
			}
			if _, isDead := dead[target]; isDead {
				continue
			}
			if _, kept := keep[target]; kept {
				continue
			}
			keep[target] = struct{}{}
			changed = true
		}
	}
	return changed
}

// resolve maps a referenced tag to the tag that must be kept for it to exist
// after the engine's expand pass. ok=false means the reference cannot be
// satisfied.
func (g *pruneGraph) resolve(ref string) (string, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", false
	}
	if g.exists(ref) {
		if g.excludedInTestMode(ref) {
			return "", false
		}
		return ref, true
	}
	parent, ok := g.resolveVirtual(ref)
	if !ok || g.excludedInTestMode(parent) {
		return "", false
	}
	return parent, true
}

// resolveVirtual maps a {parent}-{id} virtual tag back to the parent outbound
// the engine expands it from. The longest matching parent wins: a legend id may
// itself contain a dash, and parents may be prefixes of other parents.
func (g *pruneGraph) resolveVirtual(tag string) (string, bool) {
	best := ""
	for parent, ids := range g.parents {
		prefix := parent + "-"
		if len(tag) <= len(prefix) || !strings.HasPrefix(tag, prefix) {
			continue
		}
		if _, ok := ids[tag[len(prefix):]]; !ok {
			continue
		}
		if len(parent) > len(best) {
			best = parent
		}
	}
	return best, best != ""
}

// excludedInTestMode reports tags the side box must not build. Punnel providers
// are excluded by setOutbounds (TestMode never runs a second provider — the hub
// keeps one session and replaces it on every auth), so nothing may resurrect
// them here.
func (g *pruneGraph) excludedInTestMode(tag string) bool {
	ob, ok := g.outbound(tag)
	return ok && ob.Type == C.TypePunnel
}

// usable reports whether ref will exist after pruning: it resolves, is not
// dead, and was kept.
func (g *pruneGraph) usable(ref string, keep, dead map[string]struct{}) bool {
	target, ok := g.resolve(ref)
	if !ok {
		return false
	}
	if _, isDead := dead[target]; isDead {
		return false
	}
	_, kept := keep[target]
	return kept
}

// dropEmptyGroups removes kept groups whose every member is gone. The gap this
// closes: a group can survive the allowlist and still be unbuildable — its only
// member was excluded, filtered upstream, or never existed — and box.New rejects
// an empty member list ("missing tags") just as hard as a missing one.
//
// Service groups (select/balance) cannot be removed: route.final and the UI
// address them by name. When one would be emptied they are widened back to
// whatever members the built config still has, which keeps the graph closed at
// the cost of a few extra leaves — the alternative is a side box that refuses
// to start.
func (g *pruneGraph) dropEmptyGroups(keep, dead map[string]struct{}) bool {
	changed := false
	for tag := range keep {
		if _, isDead := dead[tag]; isDead {
			continue
		}
		ob, ok := g.outbound(tag)
		if !ok {
			continue
		}
		members, isGroup := groupMemberList(ob)
		if !isGroup {
			continue
		}
		live := 0
		for _, member := range members {
			if g.usable(member, keep, dead) {
				live++
			}
		}
		if live > 0 {
			continue
		}
		if isServiceTag(tag, ob.Type) {
			// Widen instead of dropping: NewSelector/NewURLTest/NewBalancer
			// all reject "missing tags", and route.final points at select.
			widened := 0
			for _, member := range members {
				target, ok := g.resolve(member)
				if !ok {
					continue
				}
				if _, isDead := dead[target]; isDead {
					continue
				}
				if _, kept := keep[target]; kept {
					continue
				}
				keep[target] = struct{}{}
				widened++
			}
			if widened > 0 {
				elogf("prune: widening service group %s[%s] to %d member(s): the allowlist left it empty", ob.Type, tag, widened)
				changed = true
			}
			continue
		}
		delete(keep, tag)
		dead[tag] = struct{}{}
		elogf("prune: dropping %s[%s]: no usable members left after pruning", ob.Type, tag)
		changed = true
	}
	return changed
}

// narrowMembers rewrites a kept group's member lists to the members that will
// exist, so the group never names a pruned tag.
func (g *pruneGraph) narrowMembers(ob *option.Outbound, keep, dead map[string]struct{}) {
	live := func(tags []string) []string {
		if tags == nil {
			return nil
		}
		// Fresh slice: opts was built for this Ensure, but never alias the
		// array we were handed while filtering it.
		out := make([]string, 0, len(tags))
		for _, tag := range tags {
			if g.usable(tag, keep, dead) {
				out = append(out, tag)
			}
		}
		return out
	}
	switch opts := ob.Options.(type) {
	case *option.SelectorOutboundOptions:
		if opts == nil {
			return
		}
		opts.Outbounds = live(opts.Outbounds)
		// Only repoint an existing default: inventing one would change which
		// node the side box dials by default.
		if opts.Default != "" && !g.usable(opts.Default, keep, dead) {
			opts.Default = ""
			if len(opts.Outbounds) > 0 {
				opts.Default = opts.Outbounds[0]
			}
		}
		// NewSelector rejects "missing tags"; a default that survived on its
		// own has to become a member.
		if len(opts.Outbounds) == 0 && opts.Default != "" {
			opts.Outbounds = []string{opts.Default}
		}
	case *option.URLTestOutboundOptions:
		if opts == nil {
			return
		}
		opts.Outbounds = live(opts.Outbounds)
	case *option.BalancerOutboundOptions:
		if opts == nil {
			return
		}
		opts.Outbounds = live(opts.Outbounds)
		if opts.Default != "" && !g.usable(opts.Default, keep, dead) {
			opts.Default = ""
			if len(opts.Outbounds) > 0 {
				opts.Default = opts.Outbounds[0]
			}
		}
		if len(opts.Outbounds) == 0 && opts.Default != "" {
			opts.Outbounds = []string{opts.Default}
		}
	case *option.FailoverOutboundOptions:
		if opts == nil {
			return
		}
		opts.Outbounds = live(opts.Outbounds)
	case *option.ScatterOutboundOptions:
		if opts == nil {
			return
		}
		// path_weights is positional: filter it together with paths or the
		// group fails validation.
		if len(opts.PathWeights) == len(opts.Paths) && len(opts.Paths) > 0 {
			paths := make([]string, 0, len(opts.Paths))
			weights := make([]int, 0, len(opts.PathWeights))
			for i, path := range opts.Paths {
				if g.usable(path, keep, dead) {
					paths = append(paths, path)
					weights = append(weights, opts.PathWeights[i])
				}
			}
			opts.Paths, opts.PathWeights = paths, weights
		} else {
			opts.Paths = live(opts.Paths)
		}
		opts.UplinkPaths = live(opts.UplinkPaths)
		opts.DownlinkPaths = live(opts.DownlinkPaths)
	}
}

// groupMemberList returns the member tags of a group outbound and whether the
// outbound is a group at all.
func groupMemberList(ob option.Outbound) ([]string, bool) {
	switch opts := ob.Options.(type) {
	case *option.SelectorOutboundOptions:
		if opts == nil {
			return nil, true
		}
		return withDefaultMember(opts.Outbounds, opts.Default), true
	case *option.URLTestOutboundOptions:
		if opts == nil {
			return nil, true
		}
		return opts.Outbounds, true
	case *option.BalancerOutboundOptions:
		if opts == nil {
			return nil, true
		}
		return withDefaultMember(opts.Outbounds, opts.Default), true
	case *option.FailoverOutboundOptions:
		if opts == nil {
			return nil, true
		}
		return opts.Outbounds, true
	case *option.ScatterOutboundOptions:
		if opts == nil {
			return nil, true
		}
		return scatterMemberList(opts), true
	}
	return nil, false
}

func withDefaultMember(outbounds []string, defaultTag string) []string {
	if defaultTag == "" {
		return outbounds
	}
	return append(append(make([]string, 0, len(outbounds)+1), outbounds...), defaultTag)
}

func scatterMemberList(opts *option.ScatterOutboundOptions) []string {
	members := make([]string, 0, len(opts.Paths)+len(opts.UplinkPaths)+len(opts.DownlinkPaths))
	members = append(members, opts.Paths...)
	members = append(members, opts.UplinkPaths...)
	members = append(members, opts.DownlinkPaths...)
	return members
}

// outboundReferenceTags returns every tag an outbound references.
//
// The explicit cases cover the group types whose member lists carry no
// reference:"outbound" struct tag; taggedOutboundReferences then sweeps the
// engine's own reference metadata, so a type that grows a new reference field
// is picked up without touching this pass.
func outboundReferenceTags(ob option.Outbound) []string {
	var refs []string
	switch opts := ob.Options.(type) {
	case *option.SelectorOutboundOptions:
		if opts != nil {
			refs = append(refs, opts.Outbounds...)
			refs = append(refs, opts.Default)
		}
	case *option.URLTestOutboundOptions:
		if opts != nil {
			refs = append(refs, opts.Outbounds...)
		}
	case *option.BalancerOutboundOptions:
		if opts != nil {
			refs = append(refs, opts.Outbounds...)
			refs = append(refs, opts.Default)
		}
	case *option.FailoverOutboundOptions:
		if opts != nil {
			refs = append(refs, opts.Outbounds...)
		}
	case *option.ScatterOutboundOptions:
		if opts != nil {
			refs = append(refs, opts.Paths...)
			refs = append(refs, opts.UplinkPaths...)
			refs = append(refs, opts.DownlinkPaths...)
		}
	}
	return append(refs, taggedOutboundReferences(ob.Options)...)
}

// endpointReferenceTags returns every outbound tag an endpoint references
// (detour/underlay_detour/l3router underlay + peer detours).
func endpointReferenceTags(ep option.Endpoint) []string {
	var refs []string
	switch opts := ep.Options.(type) {
	case *option.L3RouterEndpointOptions:
		if opts != nil {
			refs = append(refs, opts.Detour)
			refs = append(refs, opts.Underlay.Outbounds...)
			for _, peer := range opts.Peers {
				refs = append(refs, peer.Detour)
			}
		}
	case *option.BBMeshEndpointOptions:
		if opts != nil {
			refs = append(refs, opts.UnderlayDetour)
		}
	}
	return append(refs, taggedOutboundReferences(ep.Options)...)
}

// taggedOutboundReferences collects the tags an options value references
// through the engine's own `reference:"outbound"` struct metadata — the same
// metadata the schema generator and the dependency linters read. Walking it
// keeps the pruning pass honest as the engine grows referencing types.
func taggedOutboundReferences(options any) (refs []string) {
	if options == nil {
		return nil
	}
	// Reflection over engine-owned option structs must never take the side box
	// down: anything unexpected is a missing reference, not a panic.
	defer func() { _ = recover() }()
	collectTaggedOutboundRefs(reflect.ValueOf(options), 0, &refs)
	return refs
}

func collectTaggedOutboundRefs(value reflect.Value, depth int, refs *[]string) {
	const maxDepth = 16 // options nest (underlay → tls → …); cycles are impossible
	if depth > maxDepth || !value.IsValid() {
		return
	}
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface:
		if value.IsNil() {
			return
		}
		collectTaggedOutboundRefs(value.Elem(), depth+1, refs)
	case reflect.Struct:
		valueType := value.Type()
		for i := 0; i < valueType.NumField(); i++ {
			field := valueType.Field(i)
			fieldValue := value.Field(i)
			if !fieldValue.CanInterface() {
				continue
			}
			if field.Tag.Get("reference") == "outbound" {
				appendStringRefs(fieldValue, refs)
				continue
			}
			collectTaggedOutboundRefs(fieldValue, depth+1, refs)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < value.Len(); i++ {
			collectTaggedOutboundRefs(value.Index(i), depth+1, refs)
		}
	case reflect.Map:
		iter := value.MapRange()
		for iter.Next() {
			collectTaggedOutboundRefs(iter.Value(), depth+1, refs)
		}
	}
}

func appendStringRefs(value reflect.Value, refs *[]string) {
	switch value.Kind() {
	case reflect.String:
		if tag := strings.TrimSpace(value.String()); tag != "" {
			*refs = append(*refs, tag)
		}
	case reflect.Slice:
		if value.Type().Elem().Kind() != reflect.String {
			return
		}
		for i := 0; i < value.Len(); i++ {
			if tag := strings.TrimSpace(value.Index(i).String()); tag != "" {
				*refs = append(*refs, tag)
			}
		}
	}
}

// isServiceTag reports whether tag is one the side box addresses by name, so it
// must survive pruning even with an empty member list: `select` is route.final
// and the UI's selector, `balance` is kept for the UI's mode switch, and the
// direct/block/dns exits are referenced by DNS/route fallbacks.
//
// It is deliberately narrower than "is a group": a *user* balancer — the
// synthesized {parent}-auto rotation group — is a TypeBalancer with a member
// list, so it can, and must, be dropped when its members are gone. Keeping it
// would leave a group nothing can build.
func isServiceTag(tag, outboundType string) bool {
	if tag == "" {
		return false
	}
	for _, service := range config.PredefinedOutboundTags {
		if tag == service {
			return true
		}
	}
	switch outboundType {
	case C.TypeBlock, C.TypeDNS, C.TypeDirect:
		return true
	}
	return tag == config.OutboundRoundRobinTag
}
