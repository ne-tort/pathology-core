package hcore

import (
	"context"
	"encoding/json"

	"github.com/ne-tort/pathology-core/v2/config"
	"github.com/ne-tort/pathology-core/v2/db"
	hcommon "github.com/ne-tort/pathology-core/v2/hcommon"
	hutils "github.com/ne-tort/pathology-core/v2/hutils"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
)

func BuildConfigJson(ctx context.Context, in *StartRequest) (string, error) {
	Log(LogLevel_DEBUG, LogType_CORE, "Stating Service ")

	parsedContent, err := BuildConfig(ctx, in)
	if err != nil {
		return "", err
	}
	res, err := parsedContent.MarshalJSONContext(ctx)
	return string(res), err
}

func BuildConfig(ctx context.Context, in *StartRequest) (*option.Options, error) {
	Log(LogLevel_DEBUG, LogType_CORE, "Building Config...")

	if in.EnableRawConfig {
		return config.ReadSingOptions(ctx, &config.ReadOptions{Content: in.ConfigContent, Path: in.ConfigPath})
	}

	// Always build from the path Flutter passes (profile .json pool / _direct.json).
	// Never prefer a sidecar .src — that file was overwritten with Direct stubs by
	// Parse/empty compile and silently replaced working VLESS on reconnect/Start.
	return config.BuildConfig(ctx, static.ClientOptions, &config.ReadOptions{Content: in.ConfigContent, Path: in.ConfigPath})
}

func (s *CoreService) Parse(ctx context.Context, in *ParseRequest) (*ParseResponse, error) {
	return Parse(libbox.BaseContext(nil), in)
}

func Parse(ctx context.Context, in *ParseRequest) (*ParseResponse, error) {
	defer config.DeferPanicToError("parse", func(err error) {
		Log(LogLevel_FATAL, LogType_CONFIG, err.Error())
		StopAndAlert(MessageType_UNEXPECTED_ERROR, err.Error())
	})

  if static.ClientOptions == nil {
		static.ClientOptions = config.DefaultClientOptions()
	}

	// Client-side rule-set merge / DNS fragment actions.
	if in.Content != "" {
		var actionReq struct {
			HiddifyAction   string `json:"hiddify_action"`
			PathologyAction string `json:"pathology_action"`
		}
		if err := json.Unmarshal([]byte(in.Content), &actionReq); err == nil {
			action := actionReq.HiddifyAction
			if action == "" {
				action = actionReq.PathologyAction
			}
			if action != "" {
				switch action {
				case "merge_rulesets":
					var mergeReq struct {
						Inputs []string `json:"inputs"`
						Output string   `json:"output"`
					}
					if err := json.Unmarshal([]byte(in.Content), &mergeReq); err != nil {
						return &ParseResponse{ResponseCode: hcommon.ResponseCode_FAILED, Message: err.Error()}, nil
					}
					if err := config.MergeLocalRuleSets(mergeReq.Inputs, mergeReq.Output); err != nil {
						return &ParseResponse{ResponseCode: hcommon.ResponseCode_FAILED, Message: err.Error()}, nil
					}
					return &ParseResponse{ResponseCode: hcommon.ResponseCode_OK, Content: mergeReq.Output}, nil
				case "build_dns_fragment":
					var dnsReq struct {
						RemoteDetour string         `json:"remote_detour"`
						Options      map[string]any `json:"options"`
					}
					if err := json.Unmarshal([]byte(in.Content), &dnsReq); err != nil {
						return &ParseResponse{ResponseCode: hcommon.ResponseCode_FAILED, Message: err.Error()}, nil
					}
					rawOpts, _ := json.Marshal(dnsReq.Options)
					hopt := config.DefaultClientOptions()
					_ = json.Unmarshal(rawOpts, hopt)
					opts := option.Options{}
					if err := config.BuildDnsFragment(&opts, hopt, dnsReq.RemoteDetour); err != nil {
						return &ParseResponse{ResponseCode: hcommon.ResponseCode_FAILED, Message: err.Error()}, nil
					}
					out, err := json.Marshal(opts.DNS)
					if err != nil {
						return &ParseResponse{ResponseCode: hcommon.ResponseCode_FAILED, Message: err.Error()}, nil
					}
					return &ParseResponse{ResponseCode: hcommon.ResponseCode_OK, Content: string(out)}, nil
				default:
					return &ParseResponse{
						ResponseCode: hcommon.ResponseCode_FAILED,
						Message:      "unknown parse action: " + action,
					}, nil
				}
			}
		}
	}

	// Full config generation (debug/export): only config_path is set.
	// Apply current ClientOptions (incl. WARP inject) and do not rewrite the profile file.
	if in.TempPath == "" && in.Content == "" && in.ConfigPath != "" {
		built, err := config.ParseBuildConfigBytes(ctx, static.ClientOptions, &config.ReadOptions{Path: in.ConfigPath})
		if err != nil {
			return &ParseResponse{
				ResponseCode: hcommon.ResponseCode_FAILED,
				Message:      err.Error(),
			}, nil
		}
		return &ParseResponse{
			ResponseCode: hcommon.ResponseCode_OK,
			Content:      string(built),
		}, nil
	}

	path := in.TempPath
	if path == "" {
		path = in.ConfigPath
	}

	readOpt := &config.ReadOptions{Content: in.Content, Path: path}
	persistConfig := in.ConfigPath != "" && !config.IsScratchConfigPath(in.ConfigPath)
	// Do NOT write a .src sidecar from temp/raw. That path overwrote working VPN
	// pools with Direct stubs (empty compile / validate leftovers) while .json
	// still showed VLESS — Start then preferred .src and "connected" as Direct.

	parsed, err := config.ParseConfigBytes(ctx, readOpt, true, static.ClientOptions, false)
	if err != nil {
		return &ParseResponse{
			ResponseCode: hcommon.ResponseCode_FAILED,
			Message:      err.Error(),
		}, nil
	}
	if persistConfig {
		err = hutils.WriteFileAtomic(in.ConfigPath, parsed, 0o644)
		if err != nil {
			return &ParseResponse{
				ResponseCode: hcommon.ResponseCode_FAILED,
				Message:      err.Error(),
			}, nil
		}
	}
	return &ParseResponse{
		ResponseCode: hcommon.ResponseCode_OK,
		Content:      string(parsed),
		Message:      "",
	}, nil
}

func (s *CoreService) ChangeClientSettings(ctx context.Context, in *ChangeClientSettingsRequest) (*CoreInfoResponse, error) {
	return ChangeClientSettings(in, true)
}

func ChangeClientSettings(in *ChangeClientSettingsRequest, insert bool) (*CoreInfoResponse, error) {
	static.ClientOptions = config.DefaultClientOptions()
	defer func() {
		switch static.ClientOptions.LogLevel {
		case "debug":
			static.logLevel = LogLevel_DEBUG
		case "info":
			static.logLevel = LogLevel_INFO
		case "warn":
			static.logLevel = LogLevel_WARNING
		case "error":
			static.logLevel = LogLevel_ERROR
		case "fatal":
			static.logLevel = LogLevel_FATAL
		case "trace":
			static.logLevel = LogLevel_TRACE
		default:
			static.logLevel = LogLevel_INFO
		}
		static.debug = static.debug || static.logLevel <= LogLevel_DEBUG
	}()

	if in.ClientSettingsJson == "" {
		return &CoreInfoResponse{}, nil
	}
	if insert {
		settings := db.GetTable[hcommon.AppSettings]()
		settings.UpdateInsert(&hcommon.AppSettings{
			Id:    "ClientSettingsJson",
			Value: in.ClientSettingsJson,
		})
	}

	err := json.Unmarshal([]byte(in.ClientSettingsJson), static.ClientOptions)
	if err != nil {
		return nil, err
	}

	return &CoreInfoResponse{}, nil
}

func (s *CoreService) GenerateConfig(ctx context.Context, in *GenerateConfigRequest) (*GenerateConfigResponse, error) {
	return GenerateConfig(libbox.BaseContext(nil), in)
}

func GenerateConfig(ctx context.Context, in *GenerateConfigRequest) (*GenerateConfigResponse, error) {
	defer config.DeferPanicToError("generateConfig", func(err error) {
		Log(LogLevel_FATAL, LogType_CONFIG, err.Error())
		StopAndAlert(MessageType_UNEXPECTED_ERROR, err.Error())
	})
	if static.ClientOptions == nil {
		static.ClientOptions = config.DefaultClientOptions()
	}
	config, err := config.ParseBuildConfigBytes(ctx, static.ClientOptions, &config.ReadOptions{Path: in.Path})
	if err != nil {
		return nil, err
	}

	return &GenerateConfigResponse{
		ConfigContent: string(config),
	}, nil
}

func removeTunnelIfNeeded(options *option.Options) (tuninb *option.TunInboundOptions) {
	if hutils.TunAllowed() {
		return nil
	}

	// Create a new slice to hold the remaining inbounds
	newInbounds := make([]option.Inbound, 0, len(options.Inbounds))

	for _, inb := range options.Inbounds {
		if inb.Type == C.TypeTun {
			if d, ok := inb.Options.(option.TunInboundOptions); ok {
				tuninb = &d
			}

		} else {
			newInbounds = append(newInbounds, inb)
		}
	}

	options.Inbounds = newInbounds
	return tuninb
}
