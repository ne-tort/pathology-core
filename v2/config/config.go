package config

import (
	context "context"
	"path/filepath"
	"strings"

	"github.com/sagernet/sing-box/option"
)

type ReadOptions struct {
	Path    string
	Content string
	Options *option.Options
}

// IsScratchConfigPath reports validate-only / temporary profile paths that must not
// receive persistent .json or .src sidecars on disk.
func IsScratchConfigPath(configPath string) bool {
	if configPath == "" {
		return false
	}
	base := strings.ToLower(filepath.Base(configPath))
	if strings.Contains(base, ".tmp.") || strings.HasSuffix(base, ".tmp.json") {
		return true
	}
	normalized := filepath.ToSlash(configPath)
	return strings.Contains(normalized, "/tmp/") || strings.Contains(normalized, "\\tmp\\")
}

// ProfileSourcePath is the uncut import body next to the sliced profile JSON.
// Example: configs/<id>.json → configs/<id>.src
func ProfileSourcePath(configPath string) string {
	if configPath == "" {
		return ""
	}
	if strings.HasSuffix(strings.ToLower(configPath), ".json") {
		return configPath[:len(configPath)-len(".json")] + ".src"
	}
	return configPath + ".src"
}

// ResolveConfigReadPath returns the profile path Flutter/Start should build from.
// Historically this preferred a sidecar .src "uncut import"; that sidecar was
// frequently overwritten with Direct stubs while .json still held VLESS, so Start
// silently connected as Direct. Import bodies live under sources/ now — use .json.
func ResolveConfigReadPath(configPath string) string {
	return configPath
}

func ReadSingOptions(ctx context.Context, opt *ReadOptions) (*option.Options, error) {
	if opt.Options != nil {
		return opt.Options, nil
	}
	content, err := ReadContent(ctx, opt)
	if err != nil {
		return nil, err
	}
	var options option.Options
	err = options.UnmarshalJSONContext(ctx, content)
	return &options, err
}
func BuildConfigJson(ctx context.Context, configOpt *ClientOptions, input *ReadOptions) ([]byte, error) {
	options, err := BuildConfig(ctx, configOpt, input)
	if err != nil {
		return nil, err
	}
	if err := CheckConfigOptions(ctx, options); err != nil {
		return nil, err
	}

	return options.MarshalJSONContext(ctx)

}
func ParseBuildConfigBytes(ctx context.Context, hopts *ClientOptions, input *ReadOptions) ([]byte, error) {

	options, err := ParseBuildConfig(ctx, hopts, input)
	if err != nil {
		return nil, err
	}
	return options.MarshalJSONContext(ctx)
}
func ParseBuildConfig(ctx context.Context, hopts *ClientOptions, input *ReadOptions) (*option.Options, error) {
	options := input.Options
	if options == nil {
		var err error
		options, err = ParseConfig(ctx, input, false, hopts, false)
		if err != nil {
			return nil, err
		}

	}
	return BuildConfig(ctx, hopts, &ReadOptions{Options: options})
}
