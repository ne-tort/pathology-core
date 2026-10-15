package config

import (
	"context"

	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
)

// CheckConfigOptions validates an already-built option.Options the way
// libbox.CheckConfigOptions did in sing-box 1.4 (removed in 1.5): the options
// are marshalled to JSON and run through libbox.CheckConfig (strict decode +
// box.New/Close under a platform stub). box.New is by far the dominant cost,
// so the extra marshal round-trip is negligible here.
func CheckConfigOptions(ctx context.Context, options *option.Options) error {
	raw, err := options.MarshalJSONContext(ctx)
	if err != nil {
		return err
	}
	return libbox.CheckConfig(string(raw))
}
