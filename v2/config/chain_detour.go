package config

import (
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func isWarpManagedTag(tag string) bool {
	return tag == WarpWGTag || tag == WarpMasqueTag
}

func isNonLeafOutboundType(typ string) bool {
	switch typ {
	case C.TypeSelector, C.TypeURLTest, C.TypeBalancer, C.TypeBlock, C.TypeDNS, C.TypeDirect, "custom",
		// Group wrappers (1.5): detour-on-wrapper is meaningless; they are
		// valid chain TARGETS (they live in the known-exit set), never members.
		C.TypeFailover, C.TypeScatter,
		// Reverse provider: side-channel, not user-traffic — the CP pins its
		// transport detour at compile time.
		C.TypePunnel:
		return true
	default:
		return false
	}
}

func isSkippedDetourTag(tag string) bool {
	if tag == "" || strings.Contains(tag, "§hide§") {
		return true
	}
	return contains([]string{"direct", "bypass", "block"}, tag)
}

// resolvedChainDetours prefers Detours map; otherwise expands legacy target+members.
func resolvedChainDetours(c ChainOptions) map[string]string {
	if len(c.Detours) > 0 {
		out := make(map[string]string, len(c.Detours))
		for member, exit := range c.Detours {
			m := strings.TrimSpace(member)
			e := strings.TrimSpace(exit)
			if m == "" || e == "" {
				continue
			}
			out[m] = e
		}
		return out
	}
	target := strings.TrimSpace(c.DetourTarget)
	if target == "" {
		return nil
	}
	out := make(map[string]string)
	for _, raw := range c.DetourMembers {
		m := strings.TrimSpace(raw)
		if m == "" || m == target {
			continue
		}
		out[m] = target
	}
	return out
}

func chainKnownExitSet(input *option.Options) map[string]struct{} {
	known := map[string]struct{}{
		OutboundSelectTag:     {},
		OutboundURLTestTag:    {},
		OutboundRoundRobinTag: {},
	}
	if input == nil {
		return known
	}
	for _, out := range input.Outbounds {
		if out.Tag != "" {
			known[out.Tag] = struct{}{}
		}
	}
	for _, end := range input.Endpoints {
		if end.Tag != "" {
			known[end.Tag] = struct{}{}
		}
	}
	return known
}

// chainExitFor returns the exit tag for member, or "" if the pair must be skipped.
func chainExitFor(member string, detours map[string]string, known map[string]struct{}) string {
	if member == "" || len(detours) == 0 {
		return ""
	}
	exit := strings.TrimSpace(detours[member])
	if exit == "" || exit == member || isSkippedDetourTag(member) || isSkippedDetourTag(exit) {
		return ""
	}
	if known != nil {
		if _, ok := known[exit]; !ok {
			return ""
		}
	}
	return exit
}

func applyDetourToOutbound(base option.Outbound, detour string) option.Outbound {
	if detour == "" || isSkippedDetourTag(base.Tag) || isNonLeafOutboundType(base.Type) {
		return base
	}
	if opts, ok := base.Options.(option.DialerOptionsWrapper); ok {
		dialer := opts.TakeDialerOptions()
		dialer.Detour = detour
		opts.ReplaceDialerOptions(dialer)
	}
	return base
}

func applyDetourToEndpoint(base *option.Endpoint, detour string) {
	if base == nil || detour == "" || isSkippedDetourTag(base.Tag) {
		return
	}
	if opts, ok := base.Options.(option.DialerOptionsWrapper); ok {
		dialer := opts.TakeDialerOptions()
		dialer.Detour = detour
		opts.ReplaceDialerOptions(dialer)
	}
}
