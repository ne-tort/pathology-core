package config

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"

	"github.com/hiddify/ray2sing/ray2sing"
	"github.com/sagernet/sing-box/option"
	SJ "github.com/sagernet/sing/common/json"
	"github.com/xmdhs/clash2singbox/convert"
	clash2singmodel "github.com/xmdhs/clash2singbox/model"
	"github.com/xmdhs/clash2singbox/model/clash"
	"gopkg.in/yaml.v3"
)

//go:embed config.json.template
var configByte []byte

func ReadContent(ctx context.Context, opt *ReadOptions) ([]byte, error) {
	if opt.Content == "" {
		contentBytes, err := os.ReadFile(opt.Path)
		if err != nil {
			return nil, err
		}
		opt.Content = string(contentBytes)
	}
	return stripUTF8BOM([]byte(opt.Content)), nil
}

func stripUTF8BOM(b []byte) []byte {
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return b[3:]
	}
	return b
}

func ParseConfig(ctx context.Context, opt *ReadOptions, debug bool, configOpt *ClientOptions, fullConfig bool) (*option.Options, error) {
	content, err := ReadContent(ctx, opt)
	if err != nil {
		return nil, err
	}
	return parseConfigContent(ctx, content, debug, configOpt, fullConfig)
}

func ParseConfigBytes(ctx context.Context, opt *ReadOptions, debug bool, configOpt *ClientOptions, fullConfig bool) ([]byte, error) {
	options, err := ParseConfig(ctx, opt, debug, configOpt, fullConfig)
	if err != nil {
		return nil, err
	}

	// Empty profiles marshal to "{}" (omitempty), which then fails re-parse via the
	// single-outbound wrap path. Keep a stable empty shape for WARP-only / placeholder profiles.
	if len(options.Outbounds) == 0 && len(options.Endpoints) == 0 {
		return []byte("{\"outbounds\":[]}"), nil
	}

	return options.MarshalJSONContext(ctx)
}
func parseConfigContent(ctx context.Context, content []byte, debug bool, configOpt *ClientOptions, fullConfig bool) (*option.Options, error) {
	if configOpt == nil {
		configOpt = DefaultClientOptions()
	}
	content = stripUTF8BOM(content)

	var jsonObj map[string]interface{} = make(map[string]interface{})

	var tmpJsonResult any
	jsonDecoder := json.NewDecoder(SJ.NewCommentFilter(bytes.NewReader(content)))
	if err := jsonDecoder.Decode(&tmpJsonResult); err == nil {
		fmt.Printf("Convert using json\n")
		if tmpJsonObj, ok := tmpJsonResult.(map[string]interface{}); ok {
			if tmpJsonObj["outbounds"] == nil && tmpJsonObj["endpoints"] == nil {
				// Empty object → empty profile (WARP-only etc.). Non-empty object → single outbound wrap.
				if len(tmpJsonObj) == 0 {
					jsonObj["outbounds"] = []interface{}{}
				} else {
					jsonObj["outbounds"] = []interface{}{tmpJsonObj}
				}
			} else {
				if fullConfig || (configOpt != nil && configOpt.EnableFullConfig) {
					jsonObj = tmpJsonObj
				} else {
					if tmpJsonObj["outbounds"] != nil {
						jsonObj["outbounds"] = tmpJsonObj["outbounds"]
					}
					if tmpJsonObj["endpoints"] != nil {
						jsonObj["endpoints"] = tmpJsonObj["endpoints"]
					}
					// Retain dns/route for Build L2/L4 (do not strip on Parse).
					if tmpJsonObj["dns"] != nil {
						jsonObj["dns"] = tmpJsonObj["dns"]
					}
					if tmpJsonObj["route"] != nil {
						jsonObj["route"] = tmpJsonObj["route"]
					}
				}
			}
		} else if jsonArray, ok := tmpJsonResult.([]map[string]interface{}); ok {
			jsonObj["outbounds"] = jsonArray
		} else if jsonArray, ok := tmpJsonResult.([]interface{}); ok {
			jsonObj["outbounds"] = jsonArray
		} else {
			return nil, fmt.Errorf("[SingboxParser] Incorrect Json Format")
		}

		newContent, err := json.MarshalIndent(jsonObj, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("[SingboxParser] marshal error: %w", err)
		}

		return patchConfigStr(ctx, newContent, "SingboxParser", configOpt, fullConfig)
	}

	fmt.Printf("Convert using clash\n")
	clashObj := clash.Clash{}
	if err := yaml.Unmarshal(content, &clashObj); err == nil && clashObj.Proxies != nil {
		if len(clashObj.Proxies) == 0 {
			return nil, fmt.Errorf("[ClashParser] no outbounds found")
		}
		converted, endpoints, err := convert.Clash2sing(clashObj, clash2singmodel.SINGLATEST)
		if err != nil {
			return nil, fmt.Errorf("[ClashParser] converting clash to sing-box error: %w", err)
		}
		output := configByte
		output, err = convert.Patch(output, converted, endpoints, "", "", nil)
		if err != nil {
			return nil, fmt.Errorf("[ClashParser] patching clash config error: %w", err)
		}
		return patchConfigStr(ctx, output, "ClashParser", configOpt, fullConfig)
	}

	v2ray, err := ray2sing.Ray2SingboxOptions(ctx, string(content), false)
	if err == nil {
		// ray2sing emits 1.4-era keys (chrome_parrot, hy bandwidth, action direct,
		// …) that the 1.5 engine hard-rejects; run the same migration the JSON and
		// Clash paths get, instead of handing the raw conversion to the parser.
		if migrated, mErr := migrateOptionsJSON(ctx, v2ray); mErr != nil {
			return nil, fmt.Errorf("[V2rayParser] migrate 1.4→1.5: %w", mErr)
		} else if migrated != nil {
			v2ray = migrated
		}
		return patchConfigOptions(ctx, v2ray, "V2rayParser", configOpt, fullConfig)
	}

	return nil, fmt.Errorf("unable to determine config format")
}

// migrateOptionsJSON round-trips an already-converted option.Options through the
// legacy migrator. Returns nil (and no error) when the document does not decode
// to a JSON object, so the caller keeps the original value.
func migrateOptionsJSON(ctx context.Context, options *option.Options) (*option.Options, error) {
	if options == nil {
		return nil, nil
	}
	raw, err := options.MarshalJSONContext(ctx)
	if err != nil {
		return nil, err
	}
	var root map[string]interface{}
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, nil
	}
	if warnings := MigrateLegacyJSON(root); len(warnings) > 0 {
		warns := parseWarningsFrom(ctx)
		for _, w := range warnings {
			fmt.Printf("[SingboxParser] v2ray migrate 1.4→1.5: %s\n", w)
			warns.addMigration(w)
		}
	}
	migratedRaw, err := json.Marshal(root)
	if err != nil {
		return nil, err
	}
	migrated := &option.Options{}
	if err := migrated.UnmarshalJSONContext(ctx, migratedRaw); err != nil {
		return nil, err
	}
	return migrated, nil
}

func patchConfigStr(ctx context.Context, content []byte, name string, configOpt *ClientOptions, fullConfig bool) (*option.Options, error) {
	filterInbounds := fullConfig || (configOpt != nil && configOpt.EnableFullConfig)
	filtered, err := filterValidLeavesJSON(ctx, content, filterInbounds)
	if err != nil {
		return nil, fmt.Errorf("[%s] filter leaves: %w", name, err)
	}

	options := option.Options{}
	err = options.UnmarshalJSONContext(ctx, filtered)
	if err != nil {
		return nil, fmt.Errorf("[SingboxParser] unmarshal error: %w", err)
	}

	return patchConfigOptions(ctx, &options, name, configOpt, fullConfig)
}
func patchConfigOptions(ctx context.Context, options *option.Options, name string, configOpt *ClientOptions, fullConfig bool) (*option.Options, error) {
	_ = ctx
	_ = configOpt
	_ = fullConfig
	return validateResult(ctx, options, name)
}

func validateResult(ctx context.Context, options *option.Options, name string) (*option.Options, error) {
	err := CheckConfigOptions(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("[%s] invalid sing-box config: %w", name, err)
	}
	return options, nil
}
