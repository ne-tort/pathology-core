package config

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestPunnelExcludedFromBalancerLeaves(t *testing.T) {
	opt := DefaultClientOptions()
	input := &option.Options{
		Outbounds: []option.Outbound{
			{
				Type: C.TypeVLESS,
				Tag:  "node-a",
				Options: &option.VLESSOutboundOptions{
					DialerOptions: option.DialerOptions{},
				},
			},
			{
				// Reverse provider — must stay in outbounds but never in lowest/balance.
				Type: "punnel",
				Tag:  "punnel-client",
				Options: &option.DirectOutboundOptions{
					DialerOptions: option.DialerOptions{Detour: "wg-client-ipv4"},
				},
			},
		},
	}
	var out option.Options
	if err := setOutbounds(&out, input, opt, &map[string][]string{}); err != nil {
		t.Fatal(err)
	}

	foundPunnel := false
	for _, o := range out.Outbounds {
		if o.Tag == "punnel-client" && o.Type == "punnel" {
			foundPunnel = true
		}
		if o.Tag != OutboundRoundRobinTag && o.Tag != OutboundURLTestTag {
			continue
		}
		opts, ok := o.Options.(*option.BalancerOutboundOptions)
		if !ok {
			t.Fatalf("%s: expected balancer options", o.Tag)
		}
		for _, tag := range opts.Outbounds {
			if tag == "punnel-client" {
				t.Fatalf("%s includes reverse-provider tag punnel-client", o.Tag)
			}
		}
		if len(opts.Outbounds) != 1 || opts.Outbounds[0] != "node-a" {
			t.Fatalf("%s outbounds=%v want [node-a]", o.Tag, opts.Outbounds)
		}
	}
	if !foundPunnel {
		t.Fatal("punnel-client outbound missing from built config")
	}
}

func TestPunnelIPv6DetourDroppedWhenIPv6Filtered(t *testing.T) {
	opt := DefaultClientOptions()
	opt.SubscriptionIPv6 = false
	input := &option.Options{
		Outbounds: []option.Outbound{
			{
				Type: C.TypeVLESS,
				Tag:  "node-a",
				Options: &option.VLESSOutboundOptions{
					DialerOptions: option.DialerOptions{},
				},
			},
			{
				Type: "punnel",
				Tag:  "punnel-client",
				Options: &option.DirectOutboundOptions{
					DialerOptions: option.DialerOptions{
						Detour: "profile · wg-client-ipv4",
					},
				},
			},
			{
				Type: "punnel",
				Tag:  "punnel-client § 2",
				Options: &option.DirectOutboundOptions{
					DialerOptions: option.DialerOptions{
						Detour: "profile · wg-client-ipv6",
					},
				},
			},
		},
	}
	var out option.Options
	if err := setOutbounds(&out, input, opt, &map[string][]string{}); err != nil {
		t.Fatal(err)
	}

	punnelTags := map[string]bool{}
	for _, o := range out.Outbounds {
		if o.Type == "punnel" {
			punnelTags[o.Tag] = true
		}
	}
	if !punnelTags["punnel-client"] {
		t.Fatal("expected IPv4-detour punnel kept")
	}
	if punnelTags["punnel-client § 2"] {
		t.Fatal("expected IPv6-detour punnel dropped when IPv6 leaves filtered")
	}
}
