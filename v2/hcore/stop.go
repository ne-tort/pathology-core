package hcore

import (
	"context"
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/ne-tort/pathology-core/compat/monitoring"
	"github.com/ne-tort/pathology-core/v2/config"
	hcommon "github.com/ne-tort/pathology-core/v2/hcommon"
	hutils "github.com/ne-tort/pathology-core/v2/hutils"
	"github.com/sagernet/sing-tun"
)

func (s *CoreService) Stop(ctx context.Context, empty *hcommon.Empty) (*CoreInfoResponse, error) {
	return Stop()
}

func Stop() (coreResponse *CoreInfoResponse, err error) {
	defer config.DeferPanicToError("stop", func(recovered_err error) {
		coreResponse, err = errorWrapper(MessageType_UNEXPECTED_ERROR, recovered_err)
	})

	// if static.CoreState != CoreStates_STARTED {
	// 	return errorWrapper(MessageType_INSTANCE_NOT_STARTED, fmt.Errorf("instance not started"))
	// }
	// if static.Box == nil {
	// 	return errorWrapper(MessageType_INSTANCE_NOT_FOUND, fmt.Errorf("instance not found"))
	// }
	static.lock.Lock()
	defer static.lock.Unlock()

	SetCoreStatus(CoreStates_STOPPING, MessageType_EMPTY, "")
	stopWindowsMemoryScavenge()
	ss := static.StartedService
	if ss == nil {
		monitoring.Deactivate()
		closeDbIfIdle()
		return SetCoreStatus(CoreStates_STOPPED, MessageType_ALREADY_STOPPED, ""), nil
	}

	goroutinesBefore := runtime.NumGoroutine()
	liveStacksBefore := tun.LiveGVisorStackCount()
	Log(LogLevel_INFO, LogType_CORE, fmt.Sprintf(
		"Stop: before CloseService goroutines=%d liveGVisorStacks=%d",
		goroutinesBefore, liveStacksBefore,
	))

	monitoring.Deactivate()
	if err := ss.CloseService(); err != nil {
		static.StartedService = nil
		configureMemoryLimit(true) // drop soft GOMEMLIMIT after failed stop
		closeDbIfIdle()
		dumpGoroutinesToFile(fmt.Sprint(sWorkingPath, "/data/goroutine-stop.log"))
		hutils.HealStickyTun()
		return errorWrapper(MessageType_UNEXPECTED_ERROR, err)
	}
	// err = common.Close(static.StartedService)
	static.StartedService = nil
	configureMemoryLimit(true) // clear soft limit while VPN is down
	closeDbIfIdle()

	goroutinesAfter := runtime.NumGoroutine()
	liveStacksAfter := tun.LiveGVisorStackCount()
	Log(LogLevel_INFO, LogType_CORE, fmt.Sprintf(
		"Stop: after CloseService goroutines=%d liveGVisorStacks=%d",
		goroutinesAfter, liveStacksAfter,
	))
	// Residual live stacks or a large goroutine floor after teardown → leak dump.
	if liveStacksAfter > 0 || goroutinesAfter > 1500 {
		_ = dumpGoroutinesToFile(fmt.Sprint(sWorkingPath, "/data/goroutine-stop-leak.log"))
		Log(LogLevel_WARNING, LogType_CORE, fmt.Sprintf(
			"Stop: residual after teardown liveGVisorStacks=%d goroutines=%d (dumped goroutine-stop-leak.log)",
			liveStacksAfter, goroutinesAfter,
		))
	}
	debug.FreeOSMemory()
	logMemoryStats("after Stop FreeOSMemory")

	hutils.HealStickyTun()
	return SetCoreStatus(CoreStates_STOPPED, MessageType_EMPTY, ""), nil
}
