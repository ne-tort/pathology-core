package hcore

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ne-tort/pathology-core/v2/config"
	"github.com/ne-tort/pathology-core/compat/monitoring"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/log"
)

type PathologyInstance struct {
	StartedService *daemon.StartedService
	ClientOptions *config.ClientOptions
	// activeConfigPath string
	CoreLogFactory            log.Factory
	coreInfoObserver          *monitoring.Broadcaster[*CoreInfoResponse]
	CoreState                 CoreStates
	logObserver               *monitoring.Broadcaster[*LogMessage]
	systemInfoObserver        *monitoring.Broadcaster[*SystemInfo]
	outboundsInfoObserver     *monitoring.Broadcaster[*OutboundGroupList]
	mainOutboundsInfoObserver *monitoring.Broadcaster[*OutboundGroupList]
	lock                      sync.Mutex
	// platformMu guards globalPlatformInterface/platformByMode/BaseContext.
	// Setup/Close rewrite them (under hcore mu) while TestEngine goroutines and
	// box starts read them concurrently — unsynchronized interface reads can
	// tear (itab/data pair) and crash the process.
	platformMu                sync.RWMutex
	globalPlatformInterface   libbox.PlatformInterface
	// platformByMode keeps the platform each gRPC mode was set up with so the
	// shared interface can be re-resolved when a mode closes (Android: bg mode 4
	// owns the TUN-capable VPNService wrapper; fg mode 3 only the wrapper).
	platformByMode            map[SetupMode]libbox.PlatformInterface
	previousStartRequest      *StartRequest
	debug                     bool
	ListenPort                uint16
	BaseContext               context.Context
	endPauseTimer             *time.Timer // only for ios
	// startedAtMs is the Unix-millis moment CoreState entered STARTED (true
	// tunnel/service start). It lives in the core process (bg service on
	// Android, Host on desktop), so the UI can show real uptime across its own
	// restarts. Atomic: written by SetCoreStatus, read by readStatus each tick.
	startedAtMs atomic.Int64

	logLevel LogLevel
}

// setPlatformForMode registers a non-nil platform for the mode and re-resolves
// the shared interface. Never downgrades to nil (v4.3.9 netlink-ban fix).
func (h *PathologyInstance) setPlatformForMode(mode SetupMode, p libbox.PlatformInterface) {
	h.platformMu.Lock()
	defer h.platformMu.Unlock()
	if p != nil {
		if h.platformByMode == nil {
			h.platformByMode = make(map[SetupMode]libbox.PlatformInterface)
		}
		h.platformByMode[mode] = p
	}
	h.globalPlatformInterface = h.resolvePlatformLocked(h.globalPlatformInterface)
}

// dropPlatformForMode removes a closed mode's platform and re-resolves the
// shared interface (falls back to the best remaining mode, else keeps the
// current value — never nil).
func (h *PathologyInstance) dropPlatformForMode(mode SetupMode) {
	h.platformMu.Lock()
	defer h.platformMu.Unlock()
	delete(h.platformByMode, mode)
	h.globalPlatformInterface = h.resolvePlatformLocked(h.globalPlatformInterface)
}

// resolvePlatformLocked picks the best registered platform. Background (VPN
// service) modes own the TUN-capable platform and MUST win while registered:
// an fg re-Setup (app resume) used to overwrite VPNService with the
// ForegroundPlatform whose openTun always fails ("invalid argument"), so every
// later bg box rebuild died at start.
func (h *PathologyInstance) resolvePlatformLocked(fallback libbox.PlatformInterface) libbox.PlatformInterface {
	for _, m := range []SetupMode{
		SetupMode_GRPC_BACKGROUND_INSECURE,
		SetupMode_GRPC_BACKGROUND,
		SetupMode_GRPC_NORMAL_INSECURE,
		SetupMode_GRPC_NORMAL,
	} {
		if p, ok := h.platformByMode[m]; ok && p != nil {
			return p
		}
	}
	return fallback
}

func (h *PathologyInstance) platform() libbox.PlatformInterface {
	h.platformMu.RLock()
	defer h.platformMu.RUnlock()
	return h.globalPlatformInterface
}

func (h *PathologyInstance) setBaseContext(ctx context.Context) {
	h.platformMu.Lock()
	defer h.platformMu.Unlock()
	h.BaseContext = ctx
}

func (h *PathologyInstance) baseContext() context.Context {
	h.platformMu.RLock()
	defer h.platformMu.RUnlock()
	return h.BaseContext
}

var static = &PathologyInstance{
	CoreState:                 CoreStates_STOPPED,
	coreInfoObserver:          monitoring.NewBroadcaster[*CoreInfoResponse](context.Background()),
	logObserver:               monitoring.NewBroadcaster[*LogMessage](context.Background()),
	systemInfoObserver:        monitoring.NewBroadcaster[*SystemInfo](context.Background()),
	outboundsInfoObserver:     monitoring.NewBroadcaster[*OutboundGroupList](context.Background()),
	mainOutboundsInfoObserver: monitoring.NewBroadcaster[*OutboundGroupList](context.Background()),
}
