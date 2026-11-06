package config_test

import (
	"context"
	"testing"

	"github.com/ne-tort/pathology-core/v2/config"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
)

// Soft leaf filter UnmarshalJSONContext needs outbound registries from libbox.
// Plain context.Background (e.g. raw gRPC ctx) cannot decode any leaf; under
// 1.5 that surfaces as an explicit "missing outbound options registry" error
// instead of the old silent empty TestEngine pool. Every production entry
// point wraps with libbox.BaseContext (config_server, hcore, cmd/*).
func TestParseBuildConfigRequiresLibboxContext(t *testing.T) {
	raw := `{
  "outbounds": [
    {
      "type": "vless",
      "tag": "node-a",
      "server": "1.1.1.1",
      "server_port": 443,
      "uuid": "387c6b84-2e30-4b67-83c9-aa5692550e65"
    }
  ]
}`
	opt := config.DefaultClientOptions()
	opt.TestMode = true

	// Registry-less context: the soft filter must NOT silently return an empty
	// pool (that is what used to make TestEngine report "no nodes").
	if _, err := config.ParseBuildConfig(context.Background(), opt, &config.ReadOptions{Content: raw}); err == nil {
		t.Fatal("background ctx: expected a registry error, got a config")
	}

	good, err := config.ParseBuildConfig(libbox.BaseContext(nil), opt, &config.ReadOptions{Content: raw})
	if err != nil {
		t.Fatal(err)
	}
	if n := countProbeLeaves(good); n == 0 {
		t.Fatal("BaseContext: expected probe leaves, got empty pool")
	}
}

func countProbeLeaves(opts *option.Options) int {
	if opts == nil {
		return 0
	}
	n := 0
	for _, o := range opts.Outbounds {
		switch o.Type {
		case C.TypeSelector, C.TypeURLTest, C.TypeBalancer, C.TypeBlock, C.TypeDNS, C.TypeDirect:
			continue
		default:
			n++
		}
	}
	n += len(opts.Endpoints)
	return n
}
