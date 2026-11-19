package config

import (
	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

type outboundMap map[string]interface{}

func patchOutboundMux(base option.Outbound, configOpt ClientOptions, obj outboundMap) outboundMap {
	if configOpt.Mux.Enable {
		multiplex := option.OutboundMultiplexOptions{
			Enabled:    true,
			Padding:    configOpt.Mux.Padding,
			MaxStreams: configOpt.Mux.MaxStreams,
			Protocol:   configOpt.Mux.Protocol,
		}
		obj["multiplex"] = multiplex
	}
	return obj
}

func patchOutboundTLSTricks(base option.Outbound, configOpt ClientOptions) option.Outbound {
	switch base.Type {
	case C.TypeSelector, C.TypeURLTest, C.TypeBlock, C.TypeDNS:
		return base
	// QUIC / non-TCP-TLS ClientHello paths — native tls.fragment does not apply.
	case C.TypeHysteria, C.TypeHysteria2, C.TypeTUIC, C.TypeShadowQUIC,
		C.TypeNaive, C.TypeSudoku, C.TypeTrustTunnel:
		return base
	}
	if isOutboundReality(base) {
		return base
	}
	return patchOutboundFragment(base, configOpt)
}

func tlsFragmentEnabled(tricks TLSTricks) bool {
	return tricks.EnableFragment || tricks.EnableRecordFragment
}

func parseFragmentFallbackDelay(raw string) badoption.Duration {
	s := strings.TrimSpace(raw)
	if s == "" {
		return badoption.Duration(C.TLSFragmentFallbackDelay)
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return badoption.Duration(C.TLSFragmentFallbackDelay)
	}
	return badoption.Duration(d)
}

func patchOutboundFragment(base option.Outbound, configOpt ClientOptions) option.Outbound {
	tricks := configOpt.TLSTricks
	if !tlsFragmentEnabled(tricks) {
		return base
	}

	// Apply native sing-box-lx TLS fragment knobs on TLS outbounds.
	if tlsopt, ok := base.Options.(option.OutboundTLSOptionsWrapper); ok {
		tls := tlsopt.TakeOutboundTLSOptions()
		if tls != nil && tls.Enabled {
			// A subscription may already carry an explicit shaping decision
			// (the CP "fragmenter" section or a hand-tuned profile). The two
			// fields are plain bools, so "unset" and "false" are the same, but
			// either true flag is an explicit request: never add the other one
			// (the engine rejects fragment+record_fragment) and never override
			// the fallback delay it shipped with.
			explicit := tls.Fragment || tls.RecordFragment
			if !explicit {
				// The engine rejects both flags together. When both global
				// switches are on, record fragmentation wins: it is the
				// cheaper, recommended mode.
				if tricks.EnableRecordFragment {
					tls.RecordFragment = true
				} else {
					tls.Fragment = true
				}
			}
			if tls.FragmentFallbackDelay == 0 {
				tls.FragmentFallbackDelay = parseFragmentFallbackDelay(tricks.FragmentFallbackDelay)
			}
			tlsopt.ReplaceOutboundTLSOptions(tls)
		}
	}

	// Fragment is incompatible with TCP Fast Open.
	if opts, ok := base.Options.(option.DialerOptionsWrapper); ok {
		dialer := opts.TakeDialerOptions()
		dialer.TCPFastOpen = false
		opts.ReplaceDialerOptions(dialer)
	}

	return base
}

func isOutboundReality(base option.Outbound) bool {
	// Reality + fragment is unreliable; skip (legacy Hiddify behavior for VLESS Reality).
	var tls *option.OutboundTLSOptions
	if tlsopt, ok := base.Options.(option.OutboundTLSOptionsWrapper); ok {
		tls = tlsopt.TakeOutboundTLSOptions()
	}
	if tls == nil || !tls.Enabled || tls.Reality == nil {
		return false
	}
	return tls.Reality.Enabled
}

func patchEndpoint(base *option.Endpoint, configOpt ClientOptions, staticIPs *map[string][]string) (*option.Endpoint, error) {
	_ = configOpt
	_ = staticIPs
	ApplyDialerDetourRemap(base.Options)
	return base, nil
}

func patchOutbound(base option.Outbound, configOpt ClientOptions, staticIPs *map[string][]string) (*option.Outbound, error) {
	base = patchOutboundTLSTricks(base, configOpt)
	ApplyDialerDetourRemap(base.Options)
	_ = staticIPs
	return &base, nil
}
