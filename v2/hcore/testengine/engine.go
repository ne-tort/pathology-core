// Package testengine runs a side sing-box instance for profile outbound latency probes.
// It must not call monitoring.Activate (that would clobber the main UrlTest history).
package testengine

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ne-tort/pathology-core/compat/monitoring"
	"github.com/ne-tort/pathology-core/v2/config"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/batch"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	IdleTimeout     = 60 * time.Second
	DefaultStrategy = "single"
	samplesSingle   = 1
	samplesAverage  = 3
	samplesStress   = 10
	maxStartTries    = 2
	// closeWaitBudget: cancel probes first, then wait for in-flight Ping to exit
	// before CloseService (stress wall ≈ ProbeTimeout*10 + margin).
	closeWaitBudget = 45 * time.Second
)

// SideStarter starts a side box from built options.
type SideStarter func(ctx context.Context, options option.Options) (*daemon.StartedService, error)

// Engine is the process-wide TestEngine slot (one profile at a time).
type Engine struct {
	mu sync.Mutex

	// opMu serializes side-box lifecycle operations (Ensure/Stop). Without it
	// two concurrent Ensure calls could build two boxes and race for the slot
	// ("test engine slot taken"), and a Stop could tear the box down mid-build.
	// Ping does NOT take it: probes are fenced by pingsInFlight and must stay
	// parallel (profile-wide test fans out 3+ concurrent RPCs).
	opMu sync.Mutex

	deps Deps

	profileID   string
	configPath  string
	configStamp string
	allowlistKey string
	mixedPort   uint16
	lastActive  time.Time
	service     *daemon.StartedService
	leafTags    []string

	pingsInFlight sync.WaitGroup

	idleCancel context.CancelFunc

	// probeCtx is cancelled on Stop / idle teardown so in-flight Ping dials abort.
	probeCtx    context.Context
	probeCancel context.CancelFunc
}

// Deps wires Engine to the main PathologyInstance without importing hcore (cycle).
// Installed atomically via Configure (Setup only); Ensure/Ping snapshot a copy.
//
// BaseContext/Platform are GETTERS: Android re-resolves the shared platform and
// BaseContext on every Setup/Close (bg VPNService wrapper vs fg wrapper), so
// captured values go stale — a side box built after the VPN service died used
// to keep dialing JNI methods on a destroyed Kotlin service.
type Deps struct {
	BaseContext  func() context.Context
	Platform     func() libbox.PlatformInterface
	WorkingDir   string
	CloneOptions func() (*config.ClientOptions, error)
	StartSide    SideStarter
	// Log routes engine diagnostics into the core log (visible on Android via
	// the LogListener stream / stderr files). std log.Printf on Android goes to
	// /dev/null — the engine was effectively silent in device artifacts.
	Log func(msg string)
}

var global = &Engine{}

// logFn is the Configure-installed core logger (atomic: read from probe
// goroutines without holding e.mu).
var logFn atomic.Pointer[func(string)]

func elogf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if p := logFn.Load(); p != nil {
		(*p)(msg)
		return
	}
	log.Printf("testengine: %s", msg)
}

// Configure installs process-wide dependencies (Setup only — not per Ensure).
func Configure(d Deps) {
	global.mu.Lock()
	defer global.mu.Unlock()
	global.deps = d
	if d.Log != nil {
		logFn.Store(&d.Log)
	}
}

func (e *Engine) snapshotDeps() Deps {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.deps
}

// Global returns the process singleton.
func Global() *Engine { return global }

// EnsureResponse is returned after a successful side-box start (or reuse).
type EnsureResponse struct {
	ProfileID string
	MixedPort uint16
	LeafTags  []string
}

// PingResult is one leaf probe aggregate.
type PingResult struct {
	Tag          string
	DelayMs      int32
	Failed       bool
	FailRate     float64
	Samples      int32
	SamplesOK    int32
	ErrorMessage string
}

// Ensure starts or reuses the side instance for profileID.
// allowlist is the Dart UI membership set (IPv6 + disabled filters); required.
func (e *Engine) Ensure(ctx context.Context, profileID, configPath string, allowlist []string) (*EnsureResponse, error) {
	profileID = strings.TrimSpace(profileID)
	configPath = strings.TrimSpace(configPath)
	if profileID == "" {
		return nil, status.Error(codes.InvalidArgument, "profile_id required")
	}
	if configPath == "" {
		return nil, status.Error(codes.InvalidArgument, "profile_config_path required")
	}
	allowlist = normalizeAllowlist(allowlist)
	if len(allowlist) == 0 {
		return nil, status.Error(codes.InvalidArgument, "outbound_tags required")
	}
	stamp := configStamp(configPath)
	deps := e.snapshotDeps()
	allowKey := strings.Join(allowlist, "\x1f")

	// Serialize side-box lifecycle: two concurrent Ensures must not both build
	// (slot-taken abort) and an Ensure must not overlap a Stop teardown.
	e.opMu.Lock()
	defer e.opMu.Unlock()

	e.mu.Lock()
	// Reuse when the running box already covers the request: same profile/config
	// AND (identical allowlist OR every requested tag is already a built leaf).
	// The subset rule removes the swap-on-every-ping behavior — a single ping
	// after a profile ping (or after another single ping when the client sends
	// the full leaf set) no longer tears the side box down under in-flight work.
	if e.canReuseLocked(profileID, configPath, stamp) &&
		(e.allowlistKey == allowKey || e.allowlistCoveredLocked(allowlist)) {
		e.touchLocked()
		resp := &EnsureResponse{
			ProfileID: e.profileID,
			MixedPort: e.mixedPort,
			LeafTags:  append([]string{}, e.leafTags...),
		}
		e.mu.Unlock()
		return resp, nil
	}
	old := e.takeServiceLocked()
	e.mu.Unlock()

	if err := closeSideService(old, &e.pingsInFlight, closeWaitBudget); err != nil {
		elogf("stop previous side box: %v", err)
		return nil, status.Errorf(codes.Aborted, "stop previous: %v", err)
	}

	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}

	opts, err := cloneMainOptions(deps)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "clone options: %v", err)
	}
	applyTestOverrides(opts, profileID, deps.WorkingDir)
	// Kernel-assign mixed port (ListenPort 0); read back after start.
	opts.InboundOptions.MixedPort = 0
	opts.InboundOptions.EnableMixedPort = true

	parseCtx := serviceContext(deps)
	built, builtLeaves, berr := buildTestConfig(parseCtx, opts, configPath)
	if berr != nil {
		return nil, berr
	}
	leaves := intersectAllowlist(allowlist, builtLeaves)
	if len(leaves) == 0 {
		return nil, status.Errorf(
			codes.FailedPrecondition,
			"empty leaf set after allowlist (path=%s built=%d allow=%d outbounds=%d endpoints=%d)",
			configPath,
			len(builtLeaves),
			len(allowlist),
			countBuiltOutbounds(built),
			countBuiltEndpoints(built),
		)
	}
	narrowSelectOutbounds(built, leaves)
	pruneToAllowlist(built, leaves)

	var lastErr error
	for try := 0; try < maxStartTries; try++ {
		if err := ctx.Err(); err != nil {
			return nil, status.FromContextError(err).Err()
		}
		startCtx := serviceContext(deps)
		svc, serr := sideStart(deps, startCtx, *built)
		if serr != nil {
			lastErr = serr
			if isBindError(serr) {
				continue
			}
			return nil, status.Errorf(codes.Unavailable, "start side box: %v", serr)
		}
		port, perr := readMixedListenPort(svc)
		if perr != nil {
			if cerr := closeSideService(svc, nil, closeWaitBudget); cerr != nil {
				elogf("close after mixed-port read fail: %v", cerr)
			}
			lastErr = perr
			continue
		}

		e.mu.Lock()
		if e.service != nil {
			e.mu.Unlock()
			if cerr := closeSideService(svc, nil, closeWaitBudget); cerr != nil {
				elogf("close raced side box: %v", cerr)
			}
			e.mu.Lock()
			if e.canReuseLocked(profileID, configPath, stamp) &&
				(e.allowlistKey == allowKey || e.allowlistCoveredLocked(allowlist)) {
				resp := &EnsureResponse{
					ProfileID: e.profileID,
					MixedPort: e.mixedPort,
					LeafTags:  append([]string{}, e.leafTags...),
				}
				e.mu.Unlock()
				return resp, nil
			}
			e.mu.Unlock()
			return nil, status.Error(codes.Aborted, "test engine slot taken")
		}
		e.resetProbeCtxLocked()
		e.service = svc
		e.profileID = profileID
		e.configPath = configPath
		e.configStamp = stamp
		e.allowlistKey = allowKey
		e.mixedPort = port
		e.leafTags = leaves
		e.touchLocked()
		resp := &EnsureResponse{
			ProfileID: profileID,
			MixedPort: port,
			LeafTags:  append([]string{}, leaves...),
		}
		e.mu.Unlock()
		return resp, nil
	}
	return nil, status.Errorf(codes.ResourceExhausted, "start side box: %v", lastErr)
}

// Stop closes the side instance if running.
func (e *Engine) Stop(ctx context.Context) error {
	_ = ctx
	e.opMu.Lock()
	defer e.opMu.Unlock()
	e.mu.Lock()
	old := e.takeServiceLocked()
	e.mu.Unlock()
	err := closeSideService(old, &e.pingsInFlight, closeWaitBudget)
	if err != nil {
		elogf("Stop CloseService: %v", err)
	} else if old != nil {
		elogf("side stop done")
	}
	return err
}

// Ping runs a strategy probe for one outbound tag (outboundTag required).
func (e *Engine) Ping(ctx context.Context, profileID, outboundTag, strategy, testURL string) ([]PingResult, error) {
	profileID = strings.TrimSpace(profileID)
	testURL = strings.TrimSpace(testURL)
	if profileID == "" {
		return nil, status.Error(codes.InvalidArgument, "profile_id required")
	}
	if testURL == "" {
		return nil, status.Error(codes.InvalidArgument, "test_url required")
	}

	e.mu.Lock()
	if e.service == nil || e.profileID == "" {
		e.mu.Unlock()
		return nil, status.Error(codes.FailedPrecondition, "test engine not running; call Ensure first")
	}
	if profileID != e.profileID {
		e.mu.Unlock()
		return nil, status.Errorf(codes.FailedPrecondition, "profile mismatch: engine=%s request=%s", e.profileID, profileID)
	}
	svc := e.service
	leaves := append([]string{}, e.leafTags...)
	probeCtx := e.probeCtx
	e.pingsInFlight.Add(1)
	e.touchLocked()
	e.mu.Unlock()
	defer e.pingsInFlight.Done()

	strategy = normalizeStrategy(strategy)
	samples, concurrency := strategyParams(strategy)

	// Client must pass an explicit tag. Empty outboundTag used to mean "all Ensure
	// leaves", which can include IPv6 nodes the Flutter UI hides via filterIpv6Leaves.
	t := strings.TrimSpace(outboundTag)
	if t == "" {
		return nil, status.Error(codes.InvalidArgument, "outbound_tag required")
	}
	if !containsString(leaves, t) {
		return nil, status.Errorf(codes.FailedPrecondition, "outbound not enabled for test: %s", t)
	}
	tags := []string{t}

	boxInst := svc.Instance()
	if boxInst == nil || boxInst.Box() == nil {
		return nil, status.Error(codes.Aborted, "side box closed")
	}
	b := boxInst.Box()

	// Honour gRPC cancel and engine Stop (probeCtx). Hard wall still bounds dials.
	wall := probeWallClock(len(tags), samples, concurrency)
	parent, cancel := pingContext(ctx, probeCtx, wall)
	defer cancel()

	results := make([]PingResult, len(tags))
	bch, _ := batch.New(parent, batch.WithConcurrencyNum[any](concurrency))
	for i, tag := range tags {
		i, tag := i, tag
		bch.Go(fmt.Sprintf("%d:%s", i, tag), func() (any, error) {
			// Probe containment: sing's batch runs closures on bare goroutines —
			// an unrecovered panic in dialer/urltest code (protocol plugins,
			// JNI-backed platform calls on Android) would abort the whole
			// in-process app. A dead probe is a failed result, not a dead client.
			defer func() {
				if r := recover(); r != nil {
					elogf("probe panic tag=%s: %v\n%s", tag, r, debug.Stack())
					results[i] = PingResult{
						Tag:          tag,
						Samples:      int32(samples),
						Failed:       true,
						FailRate:     1,
						ErrorMessage: fmt.Sprintf("probe panic: %v", r),
					}
				}
			}()
			results[i] = probeTagBounded(parent, b, tag, testURL, samples)
			return nil, nil
		})
	}
	_ = bch.Wait()

	e.mu.Lock()
	if e.service == svc {
		e.touchLocked()
	}
	e.mu.Unlock()
	return results, nil
}

func probeWallClock(tagCount, samples, concurrency int) time.Duration {
	if tagCount < 1 {
		tagCount = 1
	}
	if samples < 1 {
		samples = 1
	}
	if concurrency < 1 {
		concurrency = 1
	}
	rounds := (tagCount + concurrency - 1) / concurrency
	perLeaf := probeMaxWait(samples)
	return time.Duration(rounds)*perLeaf + 5*time.Second
}

func probeMaxWait(samples int) time.Duration {
	if samples < 1 {
		samples = 1
	}
	// Full sample budget (dead leaves exit early via fail-fast).
	return monitoring.ProbeTimeout*time.Duration(samples) + time.Second
}

func (e *Engine) canReuseLocked(profileID, configPath, stamp string) bool {
	return e.service != nil &&
		e.profileID == profileID &&
		e.configPath == configPath &&
		e.configStamp == stamp
}

// allowlistCoveredLocked reports whether every requested tag is already a built
// leaf of the running side box — then no rebuild is needed even though the
// allowlist key differs (single-tag ping against a full-profile box).
func (e *Engine) allowlistCoveredLocked(allowlist []string) bool {
	if e.service == nil || len(e.leafTags) == 0 {
		return false
	}
	for _, t := range allowlist {
		if !containsString(e.leafTags, t) {
			return false
		}
	}
	return true
}

// resetProbeCtxLocked installs a fresh probe cancel scope for the new side box.
// Caller must hold e.mu.
func (e *Engine) resetProbeCtxLocked() {
	if e.probeCancel != nil {
		e.probeCancel()
		e.probeCancel = nil
	}
	e.probeCtx, e.probeCancel = context.WithCancel(context.Background())
}

// takeServiceLocked detaches the running service and clears the slot. Caller must hold e.mu.
// Cancels idle watch and in-flight probes before returning the service for Close.
func (e *Engine) takeServiceLocked() *daemon.StartedService {
	if e.idleCancel != nil {
		e.idleCancel()
		e.idleCancel = nil
	}
	if e.probeCancel != nil {
		e.probeCancel()
		e.probeCancel = nil
	}
	e.probeCtx = nil
	svc := e.service
	e.service = nil
	e.profileID = ""
	e.configPath = ""
	e.configStamp = ""
	e.allowlistKey = ""
	e.mixedPort = 0
	e.leafTags = nil
	return svc
}

// pingContext bounds a Ping by wall clock and cancels when gRPC ctx or probeCtx ends.
func pingContext(grpcCtx, probeCtx context.Context, wall time.Duration) (context.Context, context.CancelFunc) {
	if grpcCtx == nil {
		grpcCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(grpcCtx, wall)
	if probeCtx == nil {
		return ctx, cancel
	}
	go func() {
		select {
		case <-probeCtx.Done():
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

func closeSideService(svc *daemon.StartedService, pings *sync.WaitGroup, wait time.Duration) error {
	if svc == nil {
		return nil
	}
	if pings != nil {
		if wait <= 0 {
			wait = closeWaitBudget
		}
		done := make(chan struct{})
		go func() {
			pings.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(wait):
			elogf("wait for in-flight probes timed out after %v", wait)
		}
	}
	// Contained close: CloseService tears down gvisor/mixed inbound/protocol
	// clients — a panic there (e.g. use-after-close racing a stuck probe) must
	// surface as an error, not abort the in-process app.
	err := func() (cerr error) {
		defer func() {
			if r := recover(); r != nil {
				elogf("CloseService panic: %v\n%s", r, debug.Stack())
				cerr = fmt.Errorf("CloseService panic: %v", r)
			}
		}()
		return svc.CloseService()
	}()
	if err == nil || errors.Is(err, os.ErrInvalid) {
		return nil
	}
	// Already-closed / wrong-state races after idle Stop.
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "invalid") || strings.Contains(msg, "not started") {
		return nil
	}
	return err
}

// buildTestConfig mirrors Core.Start path preference (.src when present) but
// falls back to the Dart-resolved path when the preferred file yields no leaves.
func buildTestConfig(ctx context.Context, opts *config.ClientOptions, configPath string) (*option.Options, []string, error) {
	candidates := make([]string, 0, 2)
	if alt := config.ResolveConfigReadPath(configPath); alt != "" && alt != configPath {
		candidates = append(candidates, alt)
	}
	candidates = append(candidates, configPath)

	var (
		best       *option.Options
		bestLeaves []string
		lastErr    error
		tried      []string
	)
	for _, path := range candidates {
		if path == "" {
			continue
		}
		tried = append(tried, path)
		built, err := config.ParseBuildConfig(ctx, opts, &config.ReadOptions{Path: path})
		if err != nil {
			lastErr = err
			continue
		}
		leaves := collectTestLeaves(built)
		if len(leaves) > len(bestLeaves) {
			best = built
			bestLeaves = leaves
		}
		// Prefer first successful non-empty (Start order: .src first).
		if len(leaves) > 0 {
			return built, leaves, nil
		}
		best = built
	}
	if best != nil {
		return best, bestLeaves, nil
	}
	if lastErr != nil {
		return nil, nil, status.Errorf(codes.FailedPrecondition, "build config (tried %v): %v", tried, lastErr)
	}
	return nil, nil, status.Errorf(codes.FailedPrecondition, "build config failed (tried %v)", tried)
}

func countBuiltOutbounds(opts *option.Options) int {
	if opts == nil {
		return 0
	}
	return len(opts.Outbounds)
}

func countBuiltEndpoints(opts *option.Options) int {
	if opts == nil {
		return 0
	}
	return len(opts.Endpoints)
}

func cloneMainOptions(deps Deps) (*config.ClientOptions, error) {
	if deps.CloneOptions != nil {
		return deps.CloneOptions()
	}
	return config.DefaultClientOptions(), nil
}

func sideStart(deps Deps, ctx context.Context, options option.Options) (*daemon.StartedService, error) {
	if deps.StartSide != nil {
		return deps.StartSide(ctx, options)
	}
	return nil, fmt.Errorf("side starter not configured")
}

func serviceContext(deps Deps) context.Context {
	var ctx context.Context
	if deps.BaseContext != nil {
		ctx = deps.BaseContext()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var platform libbox.PlatformInterface
	if deps.Platform != nil {
		platform = deps.Platform()
	}
	// Always refresh filemanager (paths + uid), same as Core.StartService.
	// Stale BaseContext from before Setup enables chown on Windows and fails.
	return libbox.FromContext(ctx, platform)
}

func normalizeAllowlist(tags []string) []string {
	out := make([]string, 0, len(tags))
	seen := map[string]struct{}{}
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}

func intersectAllowlist(allowlist, built []string) []string {
	if len(allowlist) == 0 || len(built) == 0 {
		return nil
	}
	ok := make(map[string]struct{}, len(built))
	for _, t := range built {
		ok[t] = struct{}{}
	}
	var out []string
	for _, t := range allowlist {
		if _, hit := ok[t]; hit {
			out = append(out, t)
		}
	}
	return out
}

func narrowSelectOutbounds(opts *option.Options, leaves []string) {
	if opts == nil || len(leaves) == 0 {
		return
	}
	for i := range opts.Outbounds {
		ob := &opts.Outbounds[i]
		if ob.Tag != config.OutboundSelectTag {
			continue
		}
		sel, ok := ob.Options.(*option.SelectorOutboundOptions)
		if !ok || sel == nil {
			continue
		}
		sel.Outbounds = append([]string{}, leaves...)
		if sel.Default == "" || !containsString(leaves, sel.Default) {
			sel.Default = leaves[0]
		}
		return
	}
}

// pruneToAllowlist drops leaf outbounds/endpoints not in the Ensure allowlist so
// side-box start does not spin up N Reality/XHTTP clients before the first probe.
// Keeps select/group/direct and other predefined service tags.
func pruneToAllowlist(opts *option.Options, leaves []string) {
	if opts == nil {
		return
	}
	keep := make(map[string]struct{}, len(leaves)+len(config.PredefinedOutboundTags)+1)
	for _, t := range leaves {
		keep[t] = struct{}{}
	}
	for _, t := range config.PredefinedOutboundTags {
		keep[t] = struct{}{}
	}
	keep[config.OutboundRoundRobinTag] = struct{}{}

	keptOb := opts.Outbounds[:0]
	for _, ob := range opts.Outbounds {
		if _, ok := keep[ob.Tag]; ok {
			keptOb = append(keptOb, ob)
			continue
		}
		switch ob.Type {
		case C.TypeSelector, C.TypeURLTest, C.TypeBalancer, C.TypeBlock, C.TypeDNS, C.TypeDirect:
			keptOb = append(keptOb, ob)
		}
	}
	opts.Outbounds = keptOb

	keptEp := opts.Endpoints[:0]
	for _, ep := range opts.Endpoints {
		if _, ok := keep[ep.Tag]; ok {
			keptEp = append(keptEp, ep)
		}
	}
	opts.Endpoints = keptEp
}

func readMixedListenPort(svc *daemon.StartedService) (uint16, error) {
	if svc == nil {
		return 0, fmt.Errorf("nil service")
	}
	inst := svc.Instance()
	if inst == nil || inst.Box() == nil {
		return 0, fmt.Errorf("side box not running")
	}
	b := inst.Box()
	inbounds := b.Inbound().Inbounds()
	for _, in := range inbounds {
		if in == nil || in.Type() != C.TypeMixed {
			continue
		}
		type porter interface{ ListenPort() uint16 }
		if p, ok := in.(porter); ok {
			if port := p.ListenPort(); port != 0 {
				return port, nil
			}
		}
	}
	return 0, fmt.Errorf("mixed inbound listen port not available")
}

func (e *Engine) touchLocked() {
	e.lastActive = time.Now()
	e.startIdleWatchLocked()
}

func (e *Engine) startIdleWatchLocked() {
	if e.idleCancel != nil {
		e.idleCancel()
		e.idleCancel = nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.idleCancel = cancel
	deadline := e.lastActive.Add(IdleTimeout)
	go func() {
		// Containment: this goroutine closes the side box on a timer — a panic
		// here (teardown races) would abort the in-process app with no RPC to
		// blame it on.
		defer func() {
			if r := recover(); r != nil {
				elogf("idle watch panic: %v\n%s", r, debug.Stack())
			}
		}()
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			e.mu.Lock()
			if e.service == nil {
				e.mu.Unlock()
				return
			}
			if time.Since(e.lastActive) < IdleTimeout {
				e.startIdleWatchLocked()
				e.mu.Unlock()
				return
			}
			old := e.takeServiceLocked()
			e.mu.Unlock()
			if err := closeSideService(old, &e.pingsInFlight, closeWaitBudget); err != nil {
				elogf("idle CloseService: %v", err)
			} else if old != nil {
				elogf("side idle stop done")
			}
		}
	}()
}

func applyTestOverrides(opts *config.ClientOptions, profileID, workingDir string) {
	opts.TestMode = true
	opts.TestOutboundTag = ""
	opts.EnableClashApi = false
	opts.AllowConnectionFromLAN = false
	opts.LanSharingPassword = ""
	// Leaf enablement comes from the profile config path (Dart resolveStartTarget /
	// merge). Do not inherit the main core's disabled-tag list for another profile.
	opts.DisabledOutboundTags = nil
	opts.InboundOptions.EnableTun = false
	opts.InboundOptions.EnableTunService = false
	opts.InboundOptions.SetSystemProxy = false
	opts.InboundOptions.EnableTProxyPort = false
	opts.InboundOptions.EnableRedirectPort = false
	opts.InboundOptions.EnableDirectPort = false
	opts.InboundOptions.TProxyPort = 0
	opts.InboundOptions.RedirectPort = 0
	opts.InboundOptions.DirectPort = 0
	opts.InboundOptions.EnableMixedPort = true
	opts.InboundOptions.MixedPort = 0 // kernel assign; read back after sideStart
	safe := sanitizeProfileID(profileID)
	rel := filepath.Join("data", "test-engine", safe)
	opts.CacheFilePath = filepath.ToSlash(filepath.Join(rel, "clash.db"))
	dir := rel
	if workingDir != "" {
		dir = filepath.Join(workingDir, rel)
	}
	_ = os.MkdirAll(dir, 0o755)
}

func sanitizeProfileID(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	s := b.String()
	if s == "" {
		return "profile"
	}
	return s
}

func collectSelectLeaves(opts *option.Options) []string {
	if opts == nil {
		return nil
	}
	for _, ob := range opts.Outbounds {
		if ob.Tag != config.OutboundSelectTag {
			continue
		}
		sel, ok := ob.Options.(*option.SelectorOutboundOptions)
		if !ok || sel == nil {
			continue
		}
		var out []string
		for _, t := range sel.Outbounds {
			if isSkippedTestLeafTag(t) {
				continue
			}
			out = append(out, t)
		}
		return out
	}
	return nil
}

// collectTestLeaves prefers select members; falls back to scanning built leaves
// when select only contains direct/hide placeholders.
func collectTestLeaves(opts *option.Options) []string {
	if leaves := collectSelectLeaves(opts); len(leaves) > 0 {
		return leaves
	}
	return collectAllProbeLeaves(opts)
}

func collectAllProbeLeaves(opts *option.Options) []string {
	if opts == nil {
		return nil
	}
	var out []string
	seen := map[string]struct{}{}
	add := func(tag string) {
		if tag == "" || isSkippedTestLeafTag(tag) {
			return
		}
		if _, ok := seen[tag]; ok {
			return
		}
		seen[tag] = struct{}{}
		out = append(out, tag)
	}
  for _, ob := range opts.Outbounds {
		switch ob.Type {
		case C.TypeSelector, C.TypeURLTest, C.TypeBalancer, C.TypeBlock, C.TypeDNS, C.TypeDirect:
			continue
		case "punnel": // reverse provider — not a probe leaf
			continue
		default:
			add(ob.Tag)
		}
	}
	for _, ep := range opts.Endpoints {
		add(ep.Tag)
	}
	return out
}

func isSkippedTestLeafTag(tag string) bool {
	if tag == "" || tag == config.OutboundDirectTag || strings.Contains(tag, "§hide§") {
		return true
	}
	if tag == config.OutboundURLTestTag || tag == config.OutboundRoundRobinTag || tag == config.OutboundSelectTag {
		return true
	}
	return false
}

func configStamp(configPath string) string {
	// Prefer stamp of the file Build actually reads (.src when present).
	paths := make([]string, 0, 2)
	if alt := config.ResolveConfigReadPath(configPath); alt != "" && alt != configPath {
		paths = append(paths, alt)
	}
	paths = append(paths, configPath)
	var b strings.Builder
	for i, p := range paths {
		if i > 0 {
			b.WriteByte(';')
		}
		st, err := os.Stat(p)
		if err != nil {
			b.WriteString(p)
			b.WriteString("|missing")
			continue
		}
		b.WriteString(fmt.Sprintf("%s|%d|%d", p, st.Size(), st.ModTime().UnixNano()))
	}
	return b.String()
}

func normalizeStrategy(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "fastaverage", "fast_average", "fast-average":
		return "fastAverage"
	case "stress":
		return "stress"
	default:
		return "single"
	}
}

func strategyParams(strategy string) (samples, concurrency int) {
	switch strategy {
	case "fastAverage":
		return samplesAverage, 8
	case "stress":
		return samplesStress, 4
	default:
		return samplesSingle, 8
	}
}

func failFastLimit(samples int) int {
	// One failed sample with zero successes is enough to mark a leaf dead.
	// Remaining samples only run after at least one success (average/stress).
	_ = samples
	return 1
}

func probeTagBounded(parent context.Context, b *box.Box, tag, testURL string, samples int) PingResult {
	// Prefer cancelable timeout over a racing goroutine: returning early while
	// urltest still holds *box.Box races with CloseService (use-after-close).
	maxWait := probeMaxWait(samples)
	ctx, cancel := context.WithTimeout(parent, maxWait)
	defer cancel()
	return probeTag(ctx, b, tag, testURL, samples)
}

func probeTag(parent context.Context, b *box.Box, tag, testURL string, samples int) PingResult {
	res := PingResult{Tag: tag, Samples: int32(samples), Failed: true}
	dialer, err := resolveDialer(b, tag)
	if err != nil {
		res.ErrorMessage = err.Error()
		return res
	}

	urls := splitProbeURLs(testURL)
	if len(urls) == 0 {
		res.ErrorMessage = "test_url required"
		return res
	}

	var sum int64
	var okCount int
	var lastErr error
	failStreak := 0
	limit := failFastLimit(samples)
	attempted := 0
	for i := 0; i < samples; i++ {
		if parent.Err() != nil {
			lastErr = parent.Err()
			break
		}
		attempted++
		delay, perr := raceProbeURLs(parent, dialer, urls)
		if perr != nil || delay > monitoring.MaxSuccessDelay || delay == 0 {
			lastErr = perr
			if lastErr == nil {
				lastErr = E.New("probe failed")
			}
			failStreak++
			// Dead leaf: stop wasting samples once we have enough consecutive failures
			// and no successes yet.
			if okCount == 0 && failStreak >= limit {
				break
			}
			continue
		}
		failStreak = 0
		okCount++
		sum += int64(delay)
	}
	if attempted > 0 {
		res.Samples = int32(attempted)
	}
	res.SamplesOK = int32(okCount)
	if attempted > 0 {
		res.FailRate = float64(attempted-okCount) / float64(attempted)
	} else if samples > 0 {
		res.FailRate = 1
	}
	if okCount == 0 {
		res.Failed = true
		if lastErr != nil {
			res.ErrorMessage = lastErr.Error()
		} else {
			res.ErrorMessage = "all samples failed"
		}
		return res
	}
	avg := int32(sum / int64(okCount))
	if avg == 0 {
		avg = 1
	}
	res.DelayMs = avg
	res.Failed = false
	return res
}

func splitProbeURLs(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == '\r'
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return []string{raw}
	}
	return out
}

func raceProbeURLs(parent context.Context, dialer N.Dialer, urls []string) (uint16, error) {
	if len(urls) == 1 {
		testCtx, cancel := context.WithTimeout(parent, monitoring.ProbeTimeout)
		defer cancel()
		return urltest.URLTest(testCtx, urls[0], dialer)
	}
	type result struct {
		delay uint16
		err   error
	}
	ch := make(chan result, len(urls))
	raceCtx, cancel := context.WithTimeout(parent, monitoring.ProbeTimeout)
	defer cancel()
	for _, u := range urls {
		link := u
		go func() {
			// Contained: URLTest dials run protocol-plugin code (reality/mux/…)
			// and JNI-backed platform hooks on Android; a panic on this bare
			// goroutine would abort the whole in-process app.
			defer func() {
				if r := recover(); r != nil {
					elogf("probe race panic url=%s: %v\n%s", link, r, debug.Stack())
					ch <- result{err: fmt.Errorf("probe panic: %v", r)}
				}
			}()
			d, err := urltest.URLTest(raceCtx, link, dialer)
			ch <- result{delay: d, err: err}
		}()
	}
	var lastErr error
	remaining := len(urls)
	for remaining > 0 {
		select {
		case <-raceCtx.Done():
			if lastErr == nil {
				lastErr = raceCtx.Err()
			}
			return 0, lastErr
		case r := <-ch:
			remaining--
			if r.err == nil && r.delay > 0 && r.delay <= monitoring.MaxSuccessDelay {
				cancel()
				return r.delay, nil
			}
			if r.err != nil {
				lastErr = r.err
			}
		}
	}
	return 0, lastErr
}

func resolveDialer(b *box.Box, tag string) (N.Dialer, error) {
	if ob, ok := b.Outbound().Outbound(tag); ok {
		if _, isGroup := ob.(adapter.OutboundGroup); isGroup {
			return nil, E.New("tag is a group, not a leaf: ", tag)
		}
		return ob, nil
	}
	if ep, ok := b.Endpoint().Get(tag); ok {
		return ep, nil
	}
	// Do not SelectOutbound: concurrent probes must not mutate shared selector state.
	return nil, E.New("outbound not found: ", tag)
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func isBindError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "address already in use") ||
		strings.Contains(msg, "only one usage of each socket address") ||
		strings.Contains(msg, "bind: ") ||
		(strings.Contains(msg, "listen tcp") && strings.Contains(msg, "bind"))
}
