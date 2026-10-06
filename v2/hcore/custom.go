package hcore

import (
	"github.com/ne-tort/pathology-core/compat/monitoring"
	"github.com/ne-tort/pathology-core/v2/config"
	"github.com/ne-tort/pathology-core/v2/db"
	"github.com/sagernet/sing-box/log"
)

func errorWrapper(state MessageType, err error) (*CoreInfoResponse, error) {
	Log(LogLevel_FATAL, LogType_CORE, err.Error())
	StopAndAlert(MessageType_UNEXPECTED_ERROR, err.Error())
	return SetCoreStatus(CoreStates_STOPPED, state, err.Error()), err
}

// closeDbIfIdle closes the shared LevelDB only when no gRPC mode can still
// serve RPCs on it. Android hosts the fg and bg modes in ONE process, so an
// unconditional db.CloseAll (service stop from the notification) leaves the
// live mode's next RPC touching a closed database — a process-killing panic.
func closeDbIfIdle() {
	if anyGrpcServerAlive() {
		return
	}
	_ = db.CloseAll()
}

func StopAndAlert(msgType MessageType, message string) {
	SetCoreStatus(CoreStates_STOPPED, msgType, message)

	monitoring.Deactivate()
	if ss := static.StartedService; ss != nil {
		ss.CloseService()
		static.StartedService = nil
	}
	closeDbIfIdle()
}

func Close(mode SetupMode) error {
	defer config.DeferPanicToError("close", func(err error) {
		Log(LogLevel_FATAL, LogType_CORE, err.Error())
		StopAndAlert(MessageType_UNEXPECTED_ERROR, err.Error())
	})
	log.Debug("[Service] Closing")

	_, err := Stop()
	CloseGrpcServer(mode)
	closeDbIfIdle()

	return err
}

// func (s *CoreService) Status(ctx context.Context, empty *hcommon.Empty) (*CoreInfoResponse, error) {
// 	return Status()
// }
