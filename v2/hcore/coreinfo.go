package hcore

import (
	"fmt"
	"time"

	hcommon "github.com/ne-tort/pathology-core/v2/hcommon"
	"google.golang.org/grpc"
)

func SetCoreStatus(state CoreStates, msgType MessageType, message string) *CoreInfoResponse {
	return setCoreStatus(state, msgType, message, "")
}

// SetCoreStatusWithParseWarnings is [SetCoreStatus] plus the non-fatal
// parse/build warnings of the call that produced this state (Start path: the
// core re-parses the profile, so leaves can be dropped or 1.4→1.5 keys
// migrated between import and connect). The payload is
// config.ParseWarningsCollector.MessageJSON(), i.e. the same
// {"parseWarnings": {...}} blob ParseResponse.Message carries, so the client
// feeds both channels through one renderer.
//
// A single constructor for both keeps the message handed to subscribers
// identical to the one returned to the caller — mutating the returned response
// after Publish would be a data race against the core-info listener.
func SetCoreStatusWithParseWarnings(state CoreStates, msgType MessageType, message string, parseWarnings string) *CoreInfoResponse {
	return setCoreStatus(state, msgType, message, parseWarnings)
}

func setCoreStatus(state CoreStates, msgType MessageType, message string, parseWarnings string) *CoreInfoResponse {
	msg := fmt.Sprintf("%s: %s %s", state.String(), msgType.String(), message)
	if msgType == MessageType_EMPTY {
		msg = fmt.Sprintf("%s: %s", state.String(), message)
	}
	Log(LogLevel_INFO, LogType_CORE, msg)
	// Tunnel uptime source for the UI: stamp the STARTED transition once (a
	// repeated STARTED, e.g. ALREADY_STARTED re-announce, must not reset the
	// clock) and clear it on STOPPED. Lives in the core process so the uptime
	// survives UI restarts on both desktop (Host) and Android (bg service).
	switch state {
	case CoreStates_STARTED:
		if static.CoreState != CoreStates_STARTED {
			static.startedAtMs.Store(time.Now().UnixMilli())
		}
	case CoreStates_STOPPED:
		static.startedAtMs.Store(0)
	}
	static.CoreState = state
	info := CoreInfoResponse{
		CoreState:     state,
		MessageType:   msgType,
		Message:       message,
		ParseWarnings: parseWarnings,
	}
	static.coreInfoObserver.Publish(&info)

	notifyTrayConnectionSync()

	return &info
}

// CurrentCoreState returns the in-process core state (Host tray status poll).
func CurrentCoreState() CoreStates {
	return static.CoreState
}

func (s *CoreService) CoreInfoListener(req *hcommon.Empty, stream grpc.ServerStreamingServer[CoreInfoResponse]) error {
	coreSub := static.coreInfoObserver.Subscribe(1)
	defer static.coreInfoObserver.Unsubscribe(coreSub)
	stream.Send(&CoreInfoResponse{
		CoreState:   static.CoreState,
		MessageType: MessageType_EMPTY,
		Message:     "",
	})
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case info := <-coreSub:
			stream.Send(info)
			// case <-time.After(500 * time.Millisecond):
			// 	// 	info := SetCoreStatus(CoreStates_STOPPED, MessageType_EMPTY, "")
			// 	stream.Send(&CoreInfoResponse{
			// 		CoreState:   static.CoreState,
			// 		MessageType: MessageType_EMPTY,
			// 		Message:     "",
			// 	})
		}
	}
}
