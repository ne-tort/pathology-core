package config

import (
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

func TestPatchOutboundFragmentTLS(t *testing.T) {
	t.Parallel()
	opt := *DefaultClientOptions()
	opt.TLSTricks.EnableFragment = true
	opt.TLSTricks.EnableRecordFragment = true
	opt.TLSTricks.FragmentFallbackDelay = "300ms"

	base := option.Outbound{
		Type: C.TypeVLESS,
		Tag:  "proxy",
		Options: &option.VLESSOutboundOptions{
			ServerOptions: option.ServerOptions{Server: "1.2.3.4", ServerPort: 443},
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
				TLS: &option.OutboundTLSOptions{Enabled: true, ServerName: "example.com"},
			},
		},
	}
	out, err := patchOutbound(base, opt, nil)
	if err != nil {
		t.Fatal(err)
	}
	tls := out.Options.(*option.VLESSOutboundOptions).TLS
	// Both global switches on must still yield one valid mode: the engine
	// rejects fragment+record_fragment.
	if tls == nil || tls.Fragment || !tls.RecordFragment {
		t.Fatalf("tls=%#v", tls)
	}
	if time.Duration(tls.FragmentFallbackDelay) != 300*time.Millisecond {
		t.Fatalf("delay=%v", tls.FragmentFallbackDelay)
	}
	dialer := out.Options.(*option.VLESSOutboundOptions).DialerOptions
	if dialer.TCPFastOpen {
		t.Fatal("TCPFastOpen should be off")
	}
}

// A subscription (CP fragmenter) may ship its own shaping decision. That must
// win over the global switches: the default record fragment must not be added
// on top of an explicit packet fragment (the engine rejects both), and the
// shipped fallback delay must survive.
func TestPatchOutboundFragmentExplicitPacketWins(t *testing.T) {
	t.Parallel()
	opt := *DefaultClientOptions() // EnableRecordFragment defaults to true
	opt.TLSTricks.EnableFragment = true
	opt.TLSTricks.EnableRecordFragment = true
	opt.TLSTricks.FragmentFallbackDelay = "300ms"

	base := option.Outbound{
		Type: C.TypeVLESS,
		Tag:  "cp-shaped",
		Options: &option.VLESSOutboundOptions{
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
				TLS: &option.OutboundTLSOptions{
					Enabled:               true,
					Fragment:              true,
					FragmentFallbackDelay: badoption.Duration(450 * time.Millisecond),
				},
			},
		},
	}
	out, err := patchOutbound(base, opt, nil)
	if err != nil {
		t.Fatal(err)
	}
	tls := out.Options.(*option.VLESSOutboundOptions).TLS
	if !tls.Fragment || tls.RecordFragment {
		t.Fatalf("explicit packet mode overridden: %#v", tls)
	}
	if time.Duration(tls.FragmentFallbackDelay) != 450*time.Millisecond {
		t.Fatalf("explicit delay overridden: %v", tls.FragmentFallbackDelay)
	}
}

func TestPatchOutboundFragmentExplicitRecordWins(t *testing.T) {
	t.Parallel()
	opt := *DefaultClientOptions()
	opt.TLSTricks.EnableFragment = true
	opt.TLSTricks.EnableRecordFragment = false

	base := option.Outbound{
		Type: C.TypeTrojan,
		Tag:  "cp-shaped",
		Options: &option.TrojanOutboundOptions{
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
				TLS: &option.OutboundTLSOptions{Enabled: true, RecordFragment: true},
			},
		},
	}
	out, err := patchOutbound(base, opt, nil)
	if err != nil {
		t.Fatal(err)
	}
	tls := out.Options.(*option.TrojanOutboundOptions).TLS
	if tls.Fragment || !tls.RecordFragment {
		t.Fatalf("explicit record mode overridden: %#v", tls)
	}
}

func TestPatchOutboundFragmentSkipsReality(t *testing.T) {
	t.Parallel()
	opt := *DefaultClientOptions()
	opt.TLSTricks.EnableFragment = true
	opt.TLSTricks.EnableRecordFragment = true

	base := option.Outbound{
		Type: C.TypeVLESS,
		Tag:  "reality",
		Options: &option.VLESSOutboundOptions{
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
				TLS: &option.OutboundTLSOptions{
					Enabled: true,
					Reality: &option.OutboundRealityOptions{Enabled: true, PublicKey: "x"},
				},
			},
		},
	}
	out, err := patchOutbound(base, opt, nil)
	if err != nil {
		t.Fatal(err)
	}
	tls := out.Options.(*option.VLESSOutboundOptions).TLS
	if tls.Fragment || tls.RecordFragment {
		t.Fatalf("reality must not get fragment: %#v", tls)
	}
}

func TestPatchOutboundFragmentSkipsQUIC(t *testing.T) {
	t.Parallel()
	opt := *DefaultClientOptions()
	opt.TLSTricks.EnableFragment = true
	opt.TLSTricks.EnableRecordFragment = true

	base := option.Outbound{
		Type: C.TypeHysteria2,
		Tag:  "hy2",
		Options: &option.Hysteria2OutboundOptions{
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
				TLS: &option.OutboundTLSOptions{Enabled: true},
			},
		},
	}
	out, err := patchOutbound(base, opt, nil)
	if err != nil {
		t.Fatal(err)
	}
	tls := out.Options.(*option.Hysteria2OutboundOptions).TLS
	if tls.Fragment || tls.RecordFragment {
		t.Fatalf("quic outbound must not get fragment: %#v", tls)
	}
}

func TestParseFragmentFallbackDelay(t *testing.T) {
	t.Parallel()
	if d := parseFragmentFallbackDelay("250ms"); time.Duration(d) != 250*time.Millisecond {
		t.Fatal(d)
	}
	if d := parseFragmentFallbackDelay("bogus"); d != badoption.Duration(C.TLSFragmentFallbackDelay) {
		t.Fatal(d)
	}
}
