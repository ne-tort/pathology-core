package ray2sing

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"strconv"
	"strings"

	_ "github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// Share-link → typed option.Outbound / Endpoint.
// Unknown schemes fail here; unknown JSON `type` fails later in sing-box registry.
//
// Removed (Hiddify-only — not restored): psiphon://, dnstt://, warp://.
// lx: mieru / carrier / derp / shadowquic / sudoku / trusttunnel / anytls / shadowtls / snell;
// wireguard endpoint + Amnezia (wg://, awg://, vpn://, [Interface]) + pathology-wg://.
// inbound-only (no share parser): mixed, cloudflared.
var configTypes = map[string]ParserFunc{
	"vmess://":     VmessSingbox,
	"vless://":     VlessSingbox,
	"trojan://":    TrojanSingbox,
	"svmess://":    VmessSingbox,
	"svless://":    VlessSingbox,
	"strojan://":   TrojanSingbox,
	"ss://":        ShadowsocksSingbox,
	"tuic://":      TuicSingbox,
	"hysteria://":  HysteriaSingbox,
	"hysteria2://": Hysteria2Singbox,
	"hy2://":       Hysteria2Singbox,
	"ssh://":       SSHSingbox,
	"naive://":     NaiveSingbox,
	"mieru://":       MieruSingbox,
	"mierus://":      MieruSingbox,
	"carrier://":     CarrierSingbox,
	"derp://":        DerpSingbox,
	"shadowquic://":  ShadowQUICSingbox,
	"sudoku://":      SudokuSingbox,
	"trusttunnel://": TrustTunnelSingbox,
	"anytls://":      AnyTLSSingbox,
	"shadowtls://":   ShadowTLSSingbox,
	"snell://":       SnellSingbox,

	"ssconf://":  BeepassSingbox,
	"direct://":  DirectSingbox,
	"socks://":   SocksSingbox,
	"phttp://":   HttpSingbox,
	"phttps://":  HttpsSingbox,
	"http://":    HttpSingbox,
	"https://":   HttpsSingbox,
	"xvmess://":  VmessXray,
	"xvless://":  VlessXray,
	"xtrojan://": TrojanXray,
	"xdirect://": DirectXray,
}
var endpointParsers = map[string]EndpointParserFunc{
	"wg://":            WireguardEndpoint,
	"wireguard://":     WireguardEndpoint,
	"awg://":           AWGSingbox,
	"vpn://":           AmneziaVpnEndpoint,
	"pathologywg://":   PathologySingbox,
	"pathology-wg://":  PathologySingbox, // previous canonical scheme
	"pathology://":     PathologySingbox, // legacy share; app deep links use pathology:// without VPN host:port
	"patologiya://":    PathologySingbox,
	"[Interface]":      AWGSingboxTxt,
}
var xrayConfigTypes = map[string]ParserFunc{
	"vmess://":  VmessXray,
	"vless://":  VlessXray,
	"trojan://": TrojanXray,
	"direct://": DirectXray,
}

func decodeUrlBase64IfNeeded(config string) string {
	splt := strings.SplitN(config, "://", 2)
	if len(splt) < 2 {
		//return config
	}
	rest, _ := decodeBase64IfNeeded(splt[1])
	// fmt.Println(rest, err)
	return splt[0] + "://" + rest
}

type OutEnd struct {
	outbound  *T.Outbound
	outbounds []*T.Outbound // multi (e.g. mierus port/protocol pairs); outbound == first when set
	endpoint  *T.Endpoint
}

func processSingleConfig(config string, useXrayWhenPossible bool) (outend *OutEnd, err error) {
	defer func() {
		if r := recover(); r != nil {
			outend = nil
			stackTrace := make([]byte, 1024)
			s := runtime.Stack(stackTrace, false)
			stackStr := fmt.Sprint(string(stackTrace[:s]))
			err = E.New("Error in Parsing:", r, "Stack trace:", stackStr)
		}
	}()
	outend = &OutEnd{}
	if false && (useXrayWhenPossible || strings.Contains(config, "&core=xray")) {
		for k, v := range xrayConfigTypes {
			if strings.HasPrefix(config, k) {
				outend.outbound, err = v(config)
				break
			}
		}
	}
	if outend.outbound == nil && len(outend.outbounds) == 0 {
		if strings.HasPrefix(config, "mieru://") || strings.HasPrefix(config, "mierus://") {
			outs, e := MieruSingboxAll(config)
			err = e
			if err == nil && len(outs) > 0 {
				outend.outbounds = outs
				outend.outbound = outs[0]
			}
		} else {
			for k, v := range configTypes {
				if k == "mieru://" || k == "mierus://" {
					continue
				}
				if strings.HasPrefix(config, k) {
					outend.outbound, err = v(config)
					break
				}
			}
			for k, v := range endpointParsers {
				if strings.HasPrefix(config, k) {
					outend.endpoint, err = v(config)
					break
				}
			}
		}
	}

	if err != nil {
		return nil, err
	}
	if outend.endpoint == nil && outend.outbound == nil && len(outend.outbounds) == 0 {
		return nil, E.New("Not supported config type")
	}
	if len(outend.outbounds) == 0 && outend.outbound != nil {
		outend.outbounds = []*T.Outbound{outend.outbound}
	}
	for _, ob := range outend.outbounds {
		if ob.Tag == "" {
			ob.Tag = ob.Type
		}
	}
	if outend.endpoint != nil && outend.endpoint.Tag == "" {
		outend.endpoint.Tag = outend.endpoint.Type
	}

	return outend, nil
}

func GenerateConfigLite(input string, useXrayWhenPossible bool) (*option.Options, error) {

	configArray := expandDecodedConfig(input)

	var outbounds []T.Outbound
	var endpoints []T.Endpoint

	for _, config := range configArray {
		if len(config) < 5 || config[0] == '#' || config[0] == '/' {
			continue
		}
		detourTag := ""

		chains := strings.Split(normalizeDetourChain(config), " -> ")
		for i := len(chains) - 1; i >= 0; i-- {
			chain1 := chains[i]

			chain, _ := decodeBase64IfNeeded(chain1)
			outend, err := processSingleConfig(chain, useXrayWhenPossible)

			if err != nil {
				fmt.Fprintf(os.Stderr, "Error in %s \n %v\n", config, err)

				continue
			}

			if len(outend.outbounds) > 0 {
				for _, ob := range outend.outbounds {
					if dialerOpt, ok := ob.Options.(T.DialerOptionsWrapper); ok {
						d := dialerOpt.TakeDialerOptions()
						// Multi-hop chain overrides; keep ?detour=tag from getDialerOptions otherwise.
						if detourTag != "" {
							d.Detour = detourTag
							dialerOpt.ReplaceDialerOptions(d)
						}
					}
					detourTag = ob.Tag
					outbounds = append(outbounds, *ob)
				}
			} else if outend.endpoint != nil {
				if dialerOpt, ok := outend.endpoint.Options.(T.DialerOptionsWrapper); ok {
					d := dialerOpt.TakeDialerOptions()
					if detourTag != "" {
						d.Detour = detourTag
						dialerOpt.ReplaceDialerOptions(d)
					}
				}

				detourTag = outend.endpoint.Tag
				endpoints = append(endpoints, *outend.endpoint)
			}
		}

	}

	if len(outbounds) == 0 && len(endpoints) == 0 {
		return nil, E.New("No outbounds found")
	}

	uniquifyShareTags(outbounds, endpoints)
	resolveDetourTagRefs(outbounds, endpoints)

	fullConfig := T.Options{
		Outbounds: outbounds,
		Endpoints: endpoints,
	}

	return &fullConfig, nil
}

// uniquifyShareTags assigns deterministic tags: first keeps base name,
// duplicates become base-1, base-2, … (no " § N" suffixes).
func uniquifyShareTags(outbounds []T.Outbound, endpoints []T.Endpoint) {
	used := map[string]int{}
	allocate := func(tag string) string {
		base := strings.TrimSpace(tag)
		if base == "" {
			base = "proxy"
		}
		// Strip legacy " § N" if present.
		if i := strings.Index(base, "§"); i >= 0 {
			base = strings.TrimSpace(base[:i])
			if base == "" {
				base = "proxy"
			}
		}
		n := used[base]
		used[base] = n + 1
		if n == 0 {
			return base
		}
		return base + "-" + strconv.Itoa(n)
	}

	oldToNew := map[string]string{}
	for i := range outbounds {
		old := outbounds[i].Tag
		neu := allocate(old)
		outbounds[i].Tag = neu
		if old != "" {
			oldToNew[old] = neu
		}
	}
	for i := range endpoints {
		old := endpoints[i].Tag
		neu := allocate(old)
		endpoints[i].Tag = neu
		if old != "" {
			oldToNew[old] = neu
		}
	}
	// Rewrite in-chain detours that still point at pre-unique tags within this batch.
	for i := range outbounds {
		if dialerOpt, ok := outbounds[i].Options.(T.DialerOptionsWrapper); ok {
			d := dialerOpt.TakeDialerOptions()
			if d.Detour != "" {
				if neu, ok := oldToNew[d.Detour]; ok {
					d.Detour = neu
					dialerOpt.ReplaceDialerOptions(d)
				}
			}
		}
	}
	for i := range endpoints {
		if dialerOpt, ok := endpoints[i].Options.(T.DialerOptionsWrapper); ok {
			d := dialerOpt.TakeDialerOptions()
			if d.Detour != "" {
				if neu, ok := oldToNew[d.Detour]; ok {
					d.Detour = neu
					dialerOpt.ReplaceDialerOptions(d)
				}
			}
		}
	}
}

// normalizeDetourChain turns Hiddify `exit&&detour=entry` into `exit -> entry`
// so GenerateConfigLite can wire DialerOptions.Detour across hops.
func normalizeDetourChain(config string) string {
	if strings.Contains(config, " -> ") {
		return config
	}
	const marker = "&&detour="
	if !strings.Contains(config, marker) {
		return config
	}
	parts := strings.Split(config, marker)
	trimmed := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			trimmed = append(trimmed, p)
		}
	}
	if len(trimmed) < 2 {
		return config
	}
	return strings.Join(trimmed, " -> ")
}

func outboundTagBase(tag string) string {
	if i := strings.Index(tag, "§"); i >= 0 {
		return strings.TrimSpace(tag[:i])
	}
	return strings.TrimSpace(tag)
}

// resolveDetourTagRefs rewrites detour values that name a share-link base tag
// (before " § N") to the concrete renamed tag after numbering.
func resolveDetourTagRefs(outbounds []T.Outbound, endpoints []T.Endpoint) {
	byBase := make(map[string]string, len(outbounds)+len(endpoints))
	register := func(tag string) {
		if tag == "" {
			return
		}
		byBase[tag] = tag
		if base := outboundTagBase(tag); base != "" {
			byBase[base] = tag
		}
	}
	for _, ob := range outbounds {
		register(ob.Tag)
	}
	for _, ep := range endpoints {
		register(ep.Tag)
	}
	apply := func(opts any) {
		w, ok := opts.(T.DialerOptionsWrapper)
		if !ok {
			return
		}
		d := w.TakeDialerOptions()
		if d.Detour == "" {
			return
		}
		if full, ok := byBase[d.Detour]; ok {
			if full != d.Detour {
				d.Detour = full
				w.ReplaceDialerOptions(d)
			}
			return
		}
		if full, ok := byBase[outboundTagBase(d.Detour)]; ok && full != d.Detour {
			d.Detour = full
			w.ReplaceDialerOptions(d)
		}
	}
	for i := range outbounds {
		apply(outbounds[i].Options)
	}
	for i := range endpoints {
		apply(endpoints[i].Options)
	}
}

func Ray2Singbox(ctx context.Context, configs string, useXrayWhenPossible bool) (out []byte, err error) {
	convertedData, err := Ray2SingboxOptions(ctx, configs, useXrayWhenPossible)
	// err = libbox.CheckConfigOptions(convertedData)
	// if err != nil {
	// 	return nil, err
	// }
	return convertedData.MarshalJSONContext(ctx)
}
func Ray2SingboxOptions(ctx context.Context, configs string, useXrayWhenPossible bool) (out *option.Options, err error) {
	defer func() {
		if r := recover(); r != nil {
			out = nil
			stackTrace := make([]byte, 1024)
			s := runtime.Stack(stackTrace, false)
			stackStr := fmt.Sprint(string(stackTrace[:s]))
			err = E.New("Error in Parsing", configs, r, "Stack trace:", stackStr)

		}
	}()

	configs, _ = decodeBase64IfNeeded(configs)

	convertedData, err := GenerateConfigLite(configs, useXrayWhenPossible)
	return convertedData, err
}
