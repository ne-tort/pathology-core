package ray2sing

import (
	"encoding/json"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

// PathologySingbox maps pathologywg:// share links to a WireGuard endpoint with
// nested pathologywg{} (SPEC 084). Mutually exclusive with awg2/awg3.
//
// Compact form (preferred):
//
//	pathologywg://host:port/<base64url>#tag
//
// where base64url is JSON:
//
//	{
//	  "pk": "<private_key>",
//	  "peer_public_key": "<pub>",
//	  "local_address": "10.8.0.2/32",
//	  "allowed_ips": "0.0.0.0/0,::/0",
//	  "mtu": 1280,
//	  "keepalive": "25",
//	  "pathologywg": { "enabled": true, "key": "<psk>", "auto": true, ... }
//	}
//
// Query fallback:
//
//	pathologywg://host:port/?pk=…&peer_public_key=…&local_address=…&pathologywg_key=…&auto=1
//
// Aliases: pathology-wg:// (previous canonical), pathology:// (legacy share
// with host:port), patologiya://. Body key "pathology" is dual-read.
func PathologySingbox(rawURL string) (*T.Endpoint, error) {
	rawURL = strings.TrimSpace(rawURL)
	lower := strings.ToLower(rawURL)
	switch {
	case strings.HasPrefix(lower, "pathologywg://"):
		// ok (canonical)
	case strings.HasPrefix(lower, "pathology-wg://"):
		rawURL = "pathologywg://" + rawURL[len("pathology-wg://"):]
	case strings.HasPrefix(lower, "patologiya://"):
		rawURL = "pathologywg://" + rawURL[len("patologiya://"):]
	case strings.HasPrefix(lower, "pathology://"):
		// Legacy VPN share scheme (app deep links are pathology:///path without VPN host).
		rawURL = "pathologywg://" + rawURL[len("pathology://"):]
	default:
		return nil, E.New("pathologywg: unsupported scheme")
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, E.Cause(err, "pathology: url")
	}
	host := u.Hostname()
	if host == "" {
		return nil, E.New("pathology: address (host:port) required")
	}
	port := uint16(51820)
	if p := u.Port(); p != "" {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil || n == 0 {
			return nil, E.New("pathology: invalid port")
		}
		port = uint16(n)
	}
	name := u.Fragment

	pathPayload := strings.TrimPrefix(u.EscapedPath(), "/")
	pathPayload = strings.TrimSpace(pathPayload)

	// Query-only / query-after-slash fallback.
	if pathPayload == "" || strings.HasPrefix(pathPayload, "?") {
		params := map[string]string{}
		for k, vs := range u.Query() {
			params[normalizeStr(k)] = strings.Join(vs, ",")
		}
		return pathologyFromParams(host, port, name, params)
	}

	rawJSON, err := decodeBase64URLFlexible(pathPayload)
	if err != nil {
		return nil, E.Cause(err, "pathology: invalid base64")
	}
	var body pathologyShareBody
	if err := json.Unmarshal(rawJSON, &body); err != nil {
		return nil, E.Cause(err, "pathology: payload JSON")
	}

	pk := firstNonEmpty(body.PrivateKey, body.PK)
	peerPub := firstNonEmpty(body.PeerPublicKey, body.PeerPub, body.PublicKey)
	if pk == "" || peerPub == "" {
		return nil, E.New("pathology: pk and peer_public_key are required")
	}
	local := firstNonEmpty(body.LocalAddress, body.Address, "10.8.0.2/32")
	addrs, err := parseWGPrefixesCSV(local)
	if err != nil {
		return nil, E.Cause(err, "pathology local_address")
	}

	pathOpts := body.PathologyWG
	if !pathOpts.IsSet() && body.PathologyAlias.IsSet() {
		pathOpts = body.PathologyAlias
	}
	if pathOpts.Key == "" {
		pathOpts.Key = firstNonEmpty(body.PathologyWGKey, body.PathologyKey, body.Key)
	}
	if body.Auto != nil {
		pathOpts.Auto = *body.Auto
	}
	if pathOpts.Key == "" {
		return nil, E.New("pathologywg: pathologywg.key (or pathologywg_key) is required")
	}
	pathOpts.Enabled = true

	peer := T.WireGuardPeer{
		Address:                     host,
		Port:                        port,
		PublicKey:                   peerPub,
		PreSharedKey:                body.PreSharedKey,
		PersistentKeepaliveInterval: T.Uint32Range(body.Keepalive),
	}
	if body.AllowedIPs != "" {
		list, err := parseWGPrefixesCSV(body.AllowedIPs)
		if err != nil {
			return nil, E.Cause(err, "pathology allowed_ips")
		}
		peer.AllowedIPs = list
	} else {
		peer.AllowedIPs = badoption.Listable[netip.Prefix]{
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::/0"),
		}
	}
	if body.Reserved != "" {
		for _, p := range strings.Split(body.Reserved, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			v, err := strconv.ParseUint(p, 10, 8)
			if err != nil {
				return nil, E.Cause(err, "pathology reserved")
			}
			peer.Reserved = append(peer.Reserved, uint8(v))
		}
	}

	tag := name
	if tag == "" {
		tag = "PathologyWG"
	}
	opts := &T.WireGuardEndpointOptions{
		Address:     toPrefixableAddrs(addrs),
		PrivateKey:  pk,
		Peers:       []T.WireGuardPeer{peer},
		MTU:         body.MTU,
		Workers:     body.Workers,
		PathologyWG: pathOpts,
	}
	clampObfuscatedWGMTU(opts)
	return &T.Endpoint{
		Type:    C.TypeWireGuard,
		Tag:     tag,
		Options: opts,
	}, nil
}

type pathologyShareBody struct {
	PK             string               `json:"pk"`
	PrivateKey     string               `json:"private_key"`
	PeerPublicKey  string               `json:"peer_public_key"`
	PeerPub        string               `json:"peer_pub"`
	PublicKey      string               `json:"public_key"`
	LocalAddress   string               `json:"local_address"`
	Address        string               `json:"address"`
	AllowedIPs     string               `json:"allowed_ips"`
	PreSharedKey   string               `json:"pre_shared_key"`
	Reserved       string               `json:"reserved"`
	MTU            uint32               `json:"mtu"`
	Workers        int                  `json:"workers"`
	Keepalive      string               `json:"keepalive"`
	PathologyWGKey string               `json:"pathologywg_key"`
	PathologyKey   string               `json:"pathology_key"`
	Key            string               `json:"key"`
	Auto           *bool                `json:"auto"`
	PathologyWG    T.PathologyWGOptions `json:"pathologywg"`
	PathologyAlias T.PathologyWGOptions `json:"pathology"`
}

func pathologyFromParams(host string, port uint16, name string, params map[string]string) (*T.Endpoint, error) {
	pk := firstNonEmpty(params["pk"], params["private key"], params["privatekey"])
	peerPub := firstNonEmpty(params["peer public key"], params["peerpublickey"], params["public key"], params["pubkey"])
	if pk == "" || peerPub == "" {
		return nil, E.New("pathology: pk and peer_public_key are required")
	}
	local := firstNonEmpty(params["local address"], params["localaddress"], params["address"], "10.8.0.2/32")
	addrs, err := parseWGPrefixesCSV(local)
	if err != nil {
		return nil, err
	}
	pathKey := firstNonEmpty(params["pathologywg key"], params["pathologywgkey"], params["pathologywg_key"], params["pathology key"], params["pathologykey"], params["pathology_key"], params["key"])
	if pathKey == "" {
		return nil, E.New("pathologywg: pathologywg_key is required")
	}
	pathOpts := pathologyOptionsFromParams(params)
	pathOpts.Key = pathKey
	pathOpts.Enabled = true

	peer := T.WireGuardPeer{
		Address:                     host,
		Port:                        port,
		PublicKey:                   peerPub,
		PreSharedKey:                getOneOfN(params, "", "pre shared key", "presharedkey", "psk"),
		AllowedIPs:                  badoption.Listable[netip.Prefix]{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
		PersistentKeepaliveInterval: T.Uint32Range(getOneOfN(params, "", "keepalive", "persistent keepalive")),
	}
	if allowed := getOneOfN(params, "", "allowed ips", "allowedips"); allowed != "" {
		list, err := parseWGPrefixesCSV(allowed)
		if err != nil {
			return nil, err
		}
		peer.AllowedIPs = list
	}

	tag := name
	if tag == "" {
		tag = "PathologyWG"
	}
	opts := &T.WireGuardEndpointOptions{
		Address:     toPrefixableAddrs(addrs),
		PrivateKey:  pk,
		Peers:       []T.WireGuardPeer{peer},
		MTU:         uint32(toUInt16(params["mtu"], 0)),
		Workers:     int(toUInt16(params["workers"], 0)),
		PathologyWG: pathOpts,
	}
	clampObfuscatedWGMTU(opts)
	return &T.Endpoint{
		Type:    C.TypeWireGuard,
		Tag:     tag,
		Options: opts,
	}, nil
}

func pathologyOptionsFromParams(params map[string]string) T.PathologyWGOptions {
	o := T.PathologyWGOptions{
		Persona:     getOneOfN(params, "", "persona"),
		IdlePersona: getOneOfN(params, "", "idle persona", "idle_persona"),
		PadStrategy: getOneOfN(params, "", "pad strategy", "pad_strategy"),
		StartGapMs:  getOneOfN(params, "", "start gap ms", "start_gap_ms"),
		Frame:       getOneOfN(params, "", "frame"),
		StartDecoy:  getOneOfN(params, "", "start decoy", "start_decoy"),
		Cipher:      getOneOfN(params, "", "cipher"),
		Preset:      getOneOfN(params, "", "preset"),
		Mode:        getOneOfN(params, "", "mode"),
		Dialog:      getOneOfN(params, "", "dialog"),
		Auto:        params["auto"] == "1" || params["auto"] == "true",
		LowEntropy: params["low entropy"] == "1" || params["low entropy"] == "true" ||
			params["low_entropy"] == "1" || params["lowentropy"] == "1",
	}
	if v := getOneOfN(params, "", "pad budget", "pad_budget"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			o.PadBudget = &n
		}
	}
	if v := getOneOfN(params, "", "start cover", "start_cover"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			o.StartCover = &n
		}
	}
	if v := getOneOfN(params, "", "cover interval ms", "cover_interval_ms"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			o.CoverIntervalMs = &n
		}
	}
	if v := getOneOfN(params, "", "frame dcid len", "frame_dcid_len"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			o.FrameDCIDLen = &n
		}
	}
	if v := getOneOfN(params, "", "rotate sec", "rotate_sec"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			o.RotateSec = &n
		}
	}
	if v := getOneOfN(params, "", "intensity"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			o.Intensity = &n
		}
	}
	return o
}
