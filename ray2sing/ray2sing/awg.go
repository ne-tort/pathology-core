package ray2sing

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// parseWGPrefix accepts CIDR or a bare address (→ /32 or /128), as in many .conf exports.
func parseWGPrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, errors.New("empty address")
	}
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if addr.Is4() {
		return netip.ParsePrefix(addr.String() + "/32")
	}
	if addr.Is6() {
		return netip.ParsePrefix(addr.String() + "/128")
	}
	return netip.Prefix{}, fmt.Errorf("unsupported address: %v", addr)
}

func parseWGPrefixesCSV(raw string) (badoption.Listable[netip.Prefix], error) {
	var out []netip.Prefix
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		pfx, err := parseWGPrefix(part)
		if err != nil {
			return nil, err
		}
		out = append(out, pfx)
	}
	return badoption.Listable[netip.Prefix](out), nil
}

// toPrefixableAddrs adapts netip.Prefix list to WireGuardEndpointOptions.Address (SPEC 057).
func toPrefixableAddrs(list []netip.Prefix) badoption.Listable[badoption.Prefixable] {
	out := make(badoption.Listable[badoption.Prefixable], len(list))
	for i, p := range list {
		out[i] = badoption.Prefixable(p)
	}
	return out
}

func amneziaFromParams(params map[string]string) T.AmneziaWGOptions {
	return T.AmneziaWGOptions{
		Jc:                     uint32(toUInt16(params["jc"], 0)),
		Jmin:                   uint32(toUInt16(params["jmin"], 0)),
		Jmax:                   uint32(toUInt16(params["jmax"], 0)),
		S1:                     uint32(toUInt16(params["s1"], 0)),
		S2:                     uint32(toUInt16(params["s2"], 0)),
		S3:                     uint32(toUInt16(params["s3"], 0)),
		S4:                     uint32(toUInt16(params["s4"], 0)),
		H1:                     T.MagicHeader(getOneOfN(params, "", "h1")),
		H2:                     T.MagicHeader(getOneOfN(params, "", "h2")),
		H3:                     T.MagicHeader(getOneOfN(params, "", "h3")),
		H4:                     T.MagicHeader(getOneOfN(params, "", "h4")),
		I1:                     getOneOfN(params, "", "i1"),
		I2:                     getOneOfN(params, "", "i2"),
		I3:                     getOneOfN(params, "", "i3"),
		I4:                     getOneOfN(params, "", "i4"),
		I5:                     getOneOfN(params, "", "i5"),
		Id:                     getOneOfN(params, "", "id"),
		Ip:                     getOneOfN(params, "", "ip"),
		Ib:                     getOneOfN(params, "", "ib"),
		HeaderProtectionKey:    getOneOfN(params, "", "header protection key", "headerprotectionkey", "header_protection_key"),
		ContentPaddingAddition: T.Uint32Range(getOneOfN(params, "", "content padding addition", "contentpaddingaddition", "content_padding_addition")),
		RekeyAfterTime:         T.Uint32Range(getOneOfN(params, "", "rekey after time", "rekeyaftertime", "rekey_after_time")),
		RekeyTimeout:           T.Uint32Range(getOneOfN(params, "", "rekey timeout", "rekeytimeout", "rekey_timeout")),
		RejectAfterTime:        T.Uint32Range(getOneOfN(params, "", "reject after time", "rejectaftertime", "reject_after_time")),
		KeepaliveTimeout:       T.Uint32Range(getOneOfN(params, "", "keepalive timeout", "keepalivetimeout", "keepalive_timeout")),
		MaxHandshakeAttempts:   T.Uint32Range(getOneOfN(params, "", "max handshake attempts", "maxhandshakeattempts", "max_handshake_attempts")),
	}
}

func amneziaHasAWG3(awg T.AmneziaWGOptions) bool {
	return awg.HeaderProtectionKey != "" ||
		awg.ContentPaddingAddition != "" ||
		awg.RekeyAfterTime != "" ||
		awg.RekeyTimeout != "" ||
		awg.RejectAfterTime != "" ||
		awg.KeepaliveTimeout != "" ||
		awg.MaxHandshakeAttempts != ""
}

// applyAmneziaNested places Amnezia knobs under awg2 or awg3 (lx nested UX).
func applyAmneziaNested(opts *T.WireGuardEndpointOptions, awg T.AmneziaWGOptions) {
	if opts == nil || !awg.IsSet() {
		return
	}
	if amneziaHasAWG3(awg) {
		opts.AWG3 = awg
	} else {
		opts.AWG2 = awg
	}
	clampObfuscatedWGMTU(opts)
}

// clampObfuscatedWGMTU caps client MTU at 1280 when AWG/pathologywg is active
// (AmneziaWG / LxBox §097 recommendation). Plain WG is left untouched.
func clampObfuscatedWGMTU(opts *T.WireGuardEndpointOptions) {
	if opts == nil {
		return
	}
	if !opts.AWG2.IsSet() && !opts.AWG3.IsSet() && !opts.PathologyWG.IsSet() && !opts.PathologyWGAlias.IsSet() {
		return
	}
	if opts.MTU == 0 || opts.MTU > 1280 {
		opts.MTU = 1280
	}
}

// AWGSingboxTxt maps awg-quick / WireGuard .conf text ([Interface]/[Peer]) to an lx
// WireGuard endpoint with nested Amnezia blocks (awg2/awg3).
func AWGSingboxTxt(content string) (*T.Endpoint, error) {
	var (
		privateKey string
		addresses  []netip.Prefix
		mtu        uint32
		name       string
		awgFlat    = map[string]string{}
		peer       T.WireGuardPeer
	)

	section := ""
	lines := strings.Split(content, "\n")
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch section {
		case "interface":
			switch key {
			case "PrivateKey":
				privateKey = val
			case "Address":
				list, err := parseWGPrefixesCSV(val)
				if err != nil {
					return nil, fmt.Errorf("invalid Address: %w", err)
				}
				addresses = append(addresses, list...)
			case "MTU":
				if v, err := strconv.ParseUint(val, 10, 32); err == nil {
					mtu = uint32(v)
				}
			case "Name", "InterfaceName":
				name = val
			case "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4",
				"H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5",
				"Id", "Ip", "Ib",
				"HeaderProtectionKey", "ContentPaddingAddition",
				"RekeyAfterTime", "RekeyTimeout", "RejectAfterTime",
				"KeepaliveTimeout", "MaxHandshakeAttempts":
				awgFlat[strings.ToLower(key)] = val
			}
		case "peer":
			switch key {
			case "PublicKey":
				peer.PublicKey = val
			case "PresharedKey":
				peer.PreSharedKey = val
			case "AllowedIPs":
				list, err := parseWGPrefixesCSV(val)
				if err != nil {
					return nil, fmt.Errorf("invalid AllowedIPs: %w", err)
				}
				peer.AllowedIPs = list
			case "Endpoint":
				host, portStr, err := net.SplitHostPort(val)
				if err != nil {
					return nil, fmt.Errorf("invalid Endpoint: %w", err)
				}
				port, err := strconv.Atoi(portStr)
				if err != nil {
					return nil, fmt.Errorf("invalid Endpoint port: %w", err)
				}
				peer.Address = host
				peer.Port = uint16(port)
			case "PersistentKeepalive":
				peer.PersistentKeepaliveInterval = T.Uint32Range(val)
			}
		}
	}

	if privateKey == "" {
		return nil, errors.New("missing PrivateKey")
	}
	if peer.Address == "" || peer.Port == 0 {
		return nil, errors.New("missing peer Endpoint")
	}
	if len(peer.AllowedIPs) == 0 {
		peer.AllowedIPs = badoption.Listable[netip.Prefix]{
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::/0"),
		}
	}

	opts := &T.WireGuardEndpointOptions{
		PrivateKey: privateKey,
		Address:    toPrefixableAddrs(addresses),
		Peers:      []T.WireGuardPeer{peer},
	}
	applyAmneziaNested(opts, amneziaFromParams(awgFlat))
	if mtu != 0 {
		opts.MTU = mtu
	}
	if name != "" {
		opts.Name = name
	}

	tag := "wireguard"
	if opts.AWG2.IsSet() || opts.AWG3.IsSet() {
		tag = "awg"
	}
	return &T.Endpoint{
		Type:    C.TypeWireGuard,
		Tag:     tag,
		Options: opts,
	}, nil
}

// AWGSingbox maps awg:// (URL or base64 .conf) to a WireGuard endpoint with nested Amnezia blocks.
func AWGSingbox(raw string) (*T.Endpoint, error) {
	splt := strings.SplitN(raw, "://", 2)
	if len(splt) == 2 {
		d, _ := decodeBase64IfNeeded(splt[1])
		raw = splt[0] + "://" + d
	}

	// awg:// + base64 conf often decodes to "[Interface]\n..."
	if body := strings.TrimPrefix(raw, "awg://"); strings.HasPrefix(strings.TrimSpace(body), "[Interface]") {
		return AWGSingboxTxt(body)
	}
	if strings.HasPrefix(strings.TrimSpace(raw), "[Interface]") {
		return AWGSingboxTxt(raw)
	}

	u, err := ParseUrl(raw, 0)
	if err != nil || len(u.Params) == 0 {
		if end, err2 := AWGSingboxTxt(raw); err2 == nil {
			return end, nil
		}
		if err != nil {
			return nil, err
		}
		return nil, errors.New("awg: empty params")
	}

	// Prefer dedicated WireguardEndpoint query shape when present.
	if getOneOfN(u.Params, "", "pk", "private key", "privatekey") != "" &&
		getOneOfN(u.Params, "", "peer public key", "peerpublickey", "public key", "pubkey") != "" {
		return WireguardEndpoint(raw)
	}

	addresses, err := parseWGPrefixesCSV(getOneOfN(u.Params, "", "ip", "address", "local address", "localaddress"))
	if err != nil {
		return nil, err
	}
	allowedIPs, err := parseWGPrefixesCSV(getOneOfN(u.Params, "", "allowedips", "allowed ips"))
	if err != nil {
		return nil, err
	}
	if len(allowedIPs) == 0 {
		allowedIPs = badoption.Listable[netip.Prefix]{
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::/0"),
		}
	}

	pk := getOneOfN(u.Params, "", "privatekey", "pk", "private key")
	if pk == "" {
		pk = u.Username
	}
	pub := getOneOfN(u.Params, "", "peerpublickey", "publickey", "pub", "peerpub", "peer public key")
	if pk == "" {
		return nil, errors.New("missing private_key")
	}
	if pub == "" {
		return nil, errors.New("missing peer_public_key")
	}

	peer := T.WireGuardPeer{
		Address:                     u.Hostname,
		Port:                        u.Port,
		PublicKey:                   pub,
		PreSharedKey:                getOneOfN(u.Params, "", "presharedkey", "psk", "pre shared key"),
		AllowedIPs:                  allowedIPs,
		PersistentKeepaliveInterval: T.Uint32Range(getOneOfN(u.Params, "", "keepalive", "persistent keepalive", "persistentkeepalive")),
	}
	if reserved := getOneOfN(u.Params, "", "reserved"); reserved != "" {
		for _, part := range strings.Split(reserved, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			num, err := strconv.ParseUint(part, 10, 8)
			if err != nil {
				return nil, err
			}
			peer.Reserved = append(peer.Reserved, uint8(num))
		}
	}

	opts := &T.WireGuardEndpointOptions{
		PrivateKey: pk,
		Address:    toPrefixableAddrs(addresses),
		Peers:      []T.WireGuardPeer{peer},
		MTU:        uint32(toUInt16(getOneOfN(u.Params, "0", "mtu"), 0)),
		Workers:    int(toUInt16(u.Params["workers"], 0)),
	}
	applyAmneziaNested(opts, amneziaFromParams(u.Params))
	if name := getOneOfN(u.Params, "", "interface name", "name", "ifname"); name != "" {
		opts.Name = name
	}

	tag := u.Name
	if tag == "" {
		if opts.AWG2.IsSet() || opts.AWG3.IsSet() {
			tag = "AWG"
		} else {
			tag = "WG"
		}
	}
	return &T.Endpoint{
		Type:    C.TypeWireGuard,
		Tag:     tag,
		Options: opts,
	}, nil
}
