package ray2sing

import (
	"strings"

	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

// ShadowQUICSingbox maps shadowquic:// share links to ShadowQUICOutboundOptions.
//
//	shadowquic://user:pass@host:443/?sni=www.example.com&alpn=h3&zero_rtt_handshake=0&udp_over_stream=1
//
// Query may still use legacy zero_rtt / 0rtt; JSON emit uses zero_rtt_handshake (SPEC 099).
func ShadowQUICSingbox(rawURL string) (*T.Outbound, error) {
	u, err := ParseUrl(rawURL, 443)
	if err != nil {
		return nil, err
	}
	if u.Hostname == "" {
		return nil, E.New("shadowquic: server is required")
	}
	decoded := u.Params
	username := firstNonEmpty(u.Username, decoded["username"], decoded["user"])
	password := firstNonEmpty(u.Password, decoded["password"], decoded["pass"])
	if username == "" || password == "" {
		return nil, E.New("shadowquic: username and password are required")
	}
	serverName := firstNonEmpty(decoded["server name"], decoded["servername"], decoded["sni"], u.Hostname)
	zeroRTT := decoded["zero rtt handshake"] == "1" || decoded["zero rtt handshake"] == "true" ||
		decoded["zero rtt"] == "1" || decoded["zero rtt"] == "true" ||
		decoded["0rtt"] == "1" || decoded["0rtt"] == "true"
	opts := &T.ShadowQUICOutboundOptions{
		DialerOptions:     getDialerOptions(decoded),
		ServerOptions:     u.GetServerOption(),
		Username:          username,
		Password:          password,
		ServerName:        serverName,
		SNI:               getOneOfN(decoded, "", "sni"),
		UDPOverStream:     decoded["udp over stream"] == "1" || decoded["udp over stream"] == "true" || decoded["uot"] == "1",
		// 1.5: congestion_control / zero_rtt_handshake live on embedded QUICOptions (SSOT).
		QUICOptions: T.QUICOptions{
			ZeroRTTHandshake:  zeroRTT,
			CongestionControl: getOneOfN(decoded, "", "congestion control", "cc"),
		},
	}
	if alpn := getOneOfN(decoded, "", "alpn"); alpn != "" {
		opts.ALPN = badoption.Listable[string](strings.Split(alpn, ","))
	}
	return &T.Outbound{
		Tag:     u.Name,
		Type:    "shadowquic",
		Options: opts,
	}, nil
}
