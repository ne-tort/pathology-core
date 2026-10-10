package ray2sing_test

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
	T "github.com/sagernet/sing-box/option"
)

func TestPathologyCompactLink(t *testing.T) {
	body := map[string]any{
		"pk":              "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEE=",
		"peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
		"local_address":   "10.8.0.2/32",
		"mtu":             1280,
		"keepalive":       "25",
		"pathologywg": map[string]any{
			"enabled": true,
			"key":     "QV95nVY/gIU8UE//SIrwoyPILbfFJUpAWxizVg0zsmE=",
			"auto":    true,
		},
	}
	raw, _ := json.Marshal(body)
	b64 := base64.RawURLEncoding.EncodeToString(raw)
	link := "pathologywg://203.0.113.50:51820/" + b64 + "#path-1"
	ep, err := ray2sing.PathologySingbox(link)
	if err != nil {
		t.Fatal(err)
	}
	if ep.Type != "wireguard" {
		t.Fatalf("type=%s", ep.Type)
	}
	opts, ok := ep.Options.(*T.WireGuardEndpointOptions)
	if !ok {
		t.Fatalf("options type %T", ep.Options)
	}
	if !opts.PathologyWG.Enabled || opts.PathologyWG.Key == "" {
		t.Fatalf("pathologywg not set: %+v", opts.PathologyWG)
	}
	if opts.PathologyWG.Auto != true {
		t.Fatal("expected auto")
	}
}

func TestPathologyQueryLink(t *testing.T) {
	link := "pathologywg://203.0.113.50:51820/?pk=priv&peer_public_key=pub&local_address=10.8.0.2/32&pathologywg_key=psk&auto=1&persona=balanced#q"
	ep, err := ray2sing.PathologySingbox(link)
	if err != nil {
		t.Fatal(err)
	}
	opts := ep.Options.(*T.WireGuardEndpointOptions)
	if opts.PathologyWG.Key != "psk" || !opts.PathologyWG.Auto {
		t.Fatalf("%+v", opts.PathologyWG)
	}
}

func TestPathologyAliasPatologiya(t *testing.T) {
	link := "patologiya://203.0.113.50:51820/?pk=priv&peer_public_key=pub&pathology_key=k#a"
	if _, err := ray2sing.PathologySingbox(link); err != nil {
		t.Fatal(err)
	}
}

func TestCarrierCompactLink(t *testing.T) {
	body := map[string]any{
		"room":      "ROOM1",
		"password":  "P",
		"device_id": "dev1",
		"transport": "datachannel",
	}
	raw, _ := json.Marshal(body)
	b64 := base64.RawURLEncoding.EncodeToString(raw)
	link := "carrier://jitsi/" + b64 + "#c1"
	out, err := ray2sing.CarrierSingbox(link)
	if err != nil {
		t.Fatal(err)
	}
	if out.Type != "carrier" {
		t.Fatalf("type=%s", out.Type)
	}
}

func TestAmneziaVpnLink(t *testing.T) {
	ini := `[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEE=
Address = 10.0.0.2/32
Jc = 4
Jmin = 40
Jmax = 70

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = 203.0.113.50:51820
AllowedIPs = 0.0.0.0/0
`
	lastConfig, _ := json.Marshal(map[string]any{"config": ini, "mtu": "1280"})
	root := map[string]any{
		"dns1": "1.1.1.1",
		"dns2": "1.0.0.1",
		"containers": []any{
			map[string]any{
				"container": "amnezia-awg",
				"awg": map[string]any{
					"last_config": string(lastConfig),
				},
			},
		},
	}
	jsonBytes, _ := json.Marshal(root)
	var zbuf bytes.Buffer
	zw := zlib.NewWriter(&zbuf)
	_, _ = zw.Write(jsonBytes)
	_ = zw.Close()
	var payload bytes.Buffer
	_ = binary.Write(&payload, binary.BigEndian, uint32(len(jsonBytes)))
	payload.Write(zbuf.Bytes())
	link := "vpn://" + base64.RawURLEncoding.EncodeToString(payload.Bytes())

	inis, err := ray2sing.DecodeAmneziaVpnINIs(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(inis) != 1 {
		t.Fatalf("inis=%d", len(inis))
	}
	ep, err := ray2sing.AmneziaVpnEndpoint(link)
	if err != nil {
		t.Fatal(err)
	}
	opts := ep.Options.(*T.WireGuardEndpointOptions)
	if !opts.AWG2.IsSet() && !opts.AWG3.IsSet() {
		t.Fatal("expected nested awg from Jc fields")
	}

	full, err := ray2sing.Ray2SingboxOptions(t.Context(), link, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Endpoints) == 0 {
		t.Fatal("expected endpoint from vpn:// expand")
	}
}

func TestPathologyLegacySchemeAndBodyKey(t *testing.T) {
	body := map[string]any{
		"pk":              "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEE=",
		"peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
		"pathology": map[string]any{
			"enabled": true,
			"key":     "QV95nVY/gIU8UE//SIrwoyPILbfFJUpAWxizVg0zsmE=",
			"auto":    true,
		},
	}
	raw, _ := json.Marshal(body)
	b64 := base64.RawURLEncoding.EncodeToString(raw)
	for _, scheme := range []string{"pathology-wg://", "pathology://", "patologiya://"} {
		ep, err := ray2sing.PathologySingbox(scheme + "203.0.113.50:51820/" + b64 + "#legacy")
		if err != nil {
			t.Fatalf("%s: %v", scheme, err)
		}
		opts := ep.Options.(*T.WireGuardEndpointOptions)
		if !opts.PathologyWG.Enabled || opts.PathologyWG.Key == "" || !opts.PathologyWG.Auto {
			t.Fatalf("%s: legacy body key not dual-read: %+v", scheme, opts.PathologyWG)
		}
		if ep.Tag != "legacy" {
			t.Fatalf("%s: tag=%s", scheme, ep.Tag)
		}
	}
	// Default tag rename.
	ep, err := ray2sing.PathologySingbox("pathologywg://203.0.113.50:51820/?pk=priv&peer_public_key=pub&pathologywg_key=k")
	if err != nil {
		t.Fatal(err)
	}
	if ep.Tag != "PathologyWG" {
		t.Fatalf("default tag=%s", ep.Tag)
	}
}
