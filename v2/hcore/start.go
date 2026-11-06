package hcore

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ne-tort/pathology-core/compat/monitoring"
	"github.com/ne-tort/pathology-core/v2/config"
	"github.com/ne-tort/pathology-core/v2/db"
	hcommon "github.com/ne-tort/pathology-core/v2/hcommon"
	"github.com/ne-tort/pathology-core/v2/hutils"
	service_manager "github.com/ne-tort/pathology-core/v2/service_manager"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
)

func (s *CoreService) Start(ctx context.Context, in *StartRequest) (*CoreInfoResponse, error) {
	return Start(static.baseContext(), in)
}

func Start(ctx context.Context, in *StartRequest) (*CoreInfoResponse, error) {
	return StartService(ctx, in)
}

func (s *CoreService) StartService(ctx context.Context, in *StartRequest) (*CoreInfoResponse, error) {
	return StartService(ctx, in)
}

func saveLastStartRequest(in *StartRequest) error {
	if in.ConfigContent == "" && in.ConfigPath == "" {
		return nil
	}
	settings := db.GetTable[hcommon.AppSettings]()
	return settings.UpdateInsert(
		&hcommon.AppSettings{
			Id:    "lastStartRequestPath",
			Value: in.ConfigPath,
		},
		&hcommon.AppSettings{
			Id:    "lastStartRequestContent",
			Value: in.ConfigContent,
		},
		&hcommon.AppSettings{
			Id:    "lastStartRequestName",
			Value: in.ConfigName,
		},
	)
}

func loadLastStartRequestIfNeeded(in *StartRequest) (*StartRequest, error) {
	if in != nil && (in.ConfigContent != "" || in.ConfigPath != "") {
		return in, nil
	}
	settings := db.GetTable[hcommon.AppSettings]()
	lastPath, err := settings.Get("lastStartRequestPath")
	if err != nil {
		return nil, err
	}
	lastContent, err := settings.Get("lastStartRequestContent")
	if err != nil {
		return nil, err
	}

	lastName, err := settings.Get("lastStartRequestName")
	if err != nil {
		return nil, err
	}
	return &StartRequest{
		ConfigPath:    lastPath.Value.(string),
		ConfigContent: lastContent.Value.(string),
		ConfigName:    lastName.Value.(string),
	}, nil
}

// buildStartOptions builds the config for a Start RPC on a context that carries
// a parse-warnings collector, and returns the collector's payload for
// CoreInfoResponse.parse_warnings ("" when nothing was dropped or migrated).
//
// Start re-parses/re-builds the profile, so drops and 1.4→1.5 migrations raised
// here are the same class the import path reports through ParseResponse.Message.
// Keep both channels on config.ParseWarningsCollector so the client renders them
// with one renderer.
func buildStartOptions(ctx context.Context, in *StartRequest) (*option.Options, string, error) {
	ctx, parseWarnings := config.WithParseWarnings(ctx)
	options, err := BuildConfig(ctx, in)
	if err != nil {
		return nil, "", err
	}
	return options, parseWarnings.MessageJSON(), nil
}

func StartService(ctx context.Context, in *StartRequest) (coreResponse *CoreInfoResponse, err error) {
	defer config.DeferPanicToError("startmobile", func(recovered_err error) {
		coreResponse, err = errorWrapper(MessageType_UNEXPECTED_ERROR, recovered_err)
	})
	static.lock.Lock()
	defer static.lock.Unlock()

	if static.CoreState != CoreStates_STOPPED {
		// return errorWrapper(MessageType_ALREADY_STARTED, fmt.Errorf("instance already started"))
		return &CoreInfoResponse{
			CoreState:   static.CoreState,
			MessageType: MessageType_ALREADY_STARTED,
			Message:     "instance already started",
		}, nil
	}
	SetCoreStatus(CoreStates_STARTING, MessageType_EMPTY, "")

	in, err = loadLastStartRequestIfNeeded(in)
	if err != nil {
		return errorWrapper(MessageType_ERROR_BUILDING_CONFIG, err)
	}

	static.previousStartRequest = in

	if static.ClientOptions == nil {
		return errorWrapper(
			MessageType_ERROR_BUILDING_CONFIG,
			errors.New("ClientOptions not initialized"),
		)
	}

	// The Start path RE-PARSES and RE-BUILDS the profile, so it raises the same
	// non-fatal warnings as import (soft-parse drops, 1.4→1.5 migrations). They
	// used to go to a nil collector: the app showed "connected" over a config
	// materially different from what the user saw at import time. They now ride
	// CoreInfoResponse.parse_warnings (see buildStartOptions).
	//
	// libbox.BaseContext REPLACES the context (it derives from the platform
	// context, not from ctx), so the collector is attached after it, inside
	// buildStartOptions — never on the caller's ctx.
	ctx = libbox.BaseContext(static.platform())
	options, parseWarnings, err := buildStartOptions(ctx, in)
	if err != nil {
		return errorWrapper(MessageType_ERROR_BUILDING_CONFIG, err)
	}
	saveLastStartRequest(in)

	Log(LogLevel_DEBUG, LogType_CORE, "Main Service pre start")
	if err := service_manager.OnMainServicePreStart(options); err != nil {
		return errorWrapper(MessageType_ERROR_EXTENSION, err)
	}
	currentBuildConfigPath := filepath.Join(sWorkingPath, "data/current-config.json")
	Log(LogLevel_DEBUG, LogType_CORE, "Saving config to ", currentBuildConfigPath)

	config.SaveCurrentConfig(ctx, currentBuildConfigPath, *options)
	if static.debug {
		pout, err := options.MarshalJSONContext(ctx)
		if err != nil {
			return errorWrapper(MessageType_ERROR_BUILDING_CONFIG, err)
		}
		Log(LogLevel_INFO, LogType_CORE, "Current Config is:\n", string(pout))
	}
	ctx = libbox.BaseContext(static.platform())
	Log(LogLevel_DEBUG, LogType_CORE, "Stating Service with delay ?", in.DelayStart)
	if in.DelayStart {
		<-time.After(1000 * time.Millisecond)
	}
	// LX memory limit: soft GOMEMLIMIT + OOM killer service (FreeOSMemory on pressure).
	configureMemoryLimit(in.DisableMemoryLimit)
	// Pre-start smoke: clear leftover Wintun/PathologyTunnel before create so the
	// first Connect after a crash does not pay a full adapter timeout.
	if hutils.StickyTunLikelyPresent() {
		Log(LogLevel_INFO, LogType_CORE, "sticky TUN present — HealStickyTunForce before NewService")
		hutils.HealStickyTunForce()
	}
	instance, err := NewService(ctx, *options)
	if err != nil && hutils.IsStickyTunStartError(err) {
		Log(LogLevel_INFO, LogType_CORE, "sticky TUN start error — heal + one silent NewService retry: ", err.Error())
		hutils.HealStickyTunForce()
		instance, err = NewService(ctx, *options)
	}
	if err != nil {
		hutils.HealStickyTunForce()
		return errorWrapper(MessageType_START_SERVICE, err)
	}
	static.StartedService = instance
	startWindowsMemoryScavenge()
	Log(LogLevel_INFO, LogType_CORE, fmt.Sprintf(
		"Start: after NewService goroutines=%d liveGVisorStacks=%d",
		runtime.NumGoroutine(), tun.LiveGVisorStackCount(),
	))
	if static.debug {
		logMemoryStats("after Start")
	}
	monitoring.Activate(static.Context(), static.Box(), static.UrlTestHistory(), func() []string {
		// Empty ConnectionTestUrls = latency checks disabled (do not fall back to ConnectionTestUrl).
		if static.ClientOptions == nil {
			return nil
		}
		return static.ClientOptions.ConnectionTestUrls
	}, func() string {
		if static.ClientOptions == nil {
			return "single"
		}
		s := strings.TrimSpace(static.ClientOptions.URLTestStrategy)
		if s == "" {
			return "single"
		}
		return s
	}, func() time.Duration {
		if static.ClientOptions == nil {
			return monitoring.DefaultProbeTimeout
		}
		ms := static.ClientOptions.URLTestProbeTimeoutMs
		if ms <= 0 {
			return monitoring.DefaultProbeTimeout
		}
		return time.Duration(ms) * time.Millisecond
	})
	if static.debug {
		dumpGoroutinesToFile(fmt.Sprint(sWorkingPath, "/data/goroutine-start.log"))
	}
	for inb := range options.Inbounds {
		if opts, ok := options.Inbounds[inb].Options.(option.SocksInboundOptions); ok {
			static.ListenPort = opts.ListenPort
		}
	}

	return SetCoreStatusWithParseWarnings(CoreStates_STARTED, MessageType_EMPTY, "", parseWarnings), nil
}
