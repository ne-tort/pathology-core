package ray2sing

import (
	"strings"

	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

// TrustTunnelSingbox maps trusttunnel:// share links to TrustTunnelOutboundOptions.
//
//	trusttunnel://user:pass@host:443/?hostname=vpn.example.com&sni=vpn.example.com&protocol=http2&insecure=1
func TrustTunnelSingbox(rawURL string) (*T.Outbound, error) {
	u, err := ParseUrl(rawURL, 443)
	if err != nil {
		return nil, err
	}
	if u.Hostname == "" {
		return nil, E.New("trusttunnel: server is required")
	}
	decoded := u.Params
	username := firstNonEmpty(u.Username, decoded["username"], decoded["user"])
	password := firstNonEmpty(u.Password, decoded["password"], decoded["pass"])
	hostname := firstNonEmpty(decoded["hostname"], decoded["host"], decoded["sni"], u.Hostname)

	opts := &T.TrustTunnelOutboundOptions{
		DialerOptions: getDialerOptions(decoded),
		ServerOptions: u.GetServerOption(),
		Hostname:      hostname,
		Username:      username,
		Password:      password,
	}
	if username != "" || password != "" {
		opts.Auth = &T.TrustTunnelAuthOptions{Username: username, Password: password}
	}
	if addrs := getOneOfN(decoded, "", "addresses", "address"); addrs != "" {
		opts.Addresses = strings.Split(addrs, ",")
	}

	protocol := getOneOfN(decoded, "http2", "upstream protocol", "protocol")
	opts.Transport = &T.TrustTunnelTransportOptions{
		UpstreamProtocol: protocol,
		AntiDPI:          boolPtr(decoded["anti dpi"] == "1" || decoded["anti dpi"] == "true" || decoded["antidpi"] == "1"),
		ClientRandom:     getOneOfN(decoded, "", "client random"),
		ForceLegacyHTTP11Connect: boolPtr(
			decoded["force http1"] == "1" || decoded["force http1 connect"] == "1" || decoded["http1"] == "1",
		),
	}

	serverName := firstNonEmpty(decoded["sni"], decoded["server name"], hostname)
	insecure := decoded["insecure"] == "1" || decoded["insecure"] == "true" || decoded["allowinsecure"] == "1" || decoded["skip verification"] == "1"
	// 1.5: legacy tls.skip_verification / tls.remote_id are gone (SPEC 115) —
	// standard tls container (insecure) + root-level remote_id.
	opts.RemoteID = getOneOfN(decoded, "", "remote id")
	tlsOpts := &T.OutboundTLSOptions{
		Enabled:    true,
		ServerName: serverName,
		Insecure:   insecure,
	}
	if cert := getOneOfN(decoded, "", "certificate", "cert"); cert != "" {
		tlsOpts.Certificate = badoption.Listable[string]{cert}
	}
	opts.TLS = tlsOpts

	if platform := getOneOfN(decoded, "", "platform"); platform != "" || getOneOfN(decoded, "", "app name", "ua") != "" {
		opts.Headers = &T.TrustTunnelHeaderOptions{
			Platform:  platform,
			AppName:   getOneOfN(decoded, "", "app name"),
			UserAgent: getOneOfN(decoded, "", "user agent", "ua"),
			ExtraHost: getOneOfN(decoded, "", "host header"),
		}
	}

	if v := getOneOfN(decoded, "", "enable tcp", "tcp"); v != "" {
		opts.EnableTCP = boolPtr(v == "1" || v == "true")
	}
	if v := getOneOfN(decoded, "", "enable udp", "udp"); v != "" {
		opts.EnableUDP = boolPtr(v == "1" || v == "true")
	}
	if v := getOneOfN(decoded, "", "enable icmp", "icmp"); v != "" {
		opts.EnableICMP = boolPtr(v == "1" || v == "true")
	}

	return &T.Outbound{
		Tag:     u.Name,
		Type:    "trusttunnel",
		Options: opts,
	}, nil
}

func boolPtr(v bool) *bool { return &v }
