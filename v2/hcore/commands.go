package hcore

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/ne-tort/pathology-core/v2/config"
	"github.com/ne-tort/pathology-core/v2/db"
	hcommon "github.com/ne-tort/pathology-core/v2/hcommon"
	"github.com/sagernet/sing-box/adapter"
	// "github.com/sagernet/sing-box/common/conntrack"
	"github.com/sagernet/sing-box/protocol/group"

	"github.com/ne-tort/pathology-core/compat/monitoring"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/memory"
	"google.golang.org/grpc"
)

func (h *PathologyInstance) readStatus(prev *SystemInfo) *SystemInfo {
	var message SystemInfo
	message.Memory = int64(memory.Inuse())
	message.Goroutines = int32(runtime.NumGoroutine())
	message.StartedAtMs = h.startedAtMs.Load()
	// message.ConnectionsOut = int32(conntrack.Count())

	if ss := h.StartedService; ss != nil {
		status := ss.ReadStatus()
		message.DownlinkTotal = status.DownlinkTotal
		message.UplinkTotal = status.UplinkTotal
		message.ConnectionsIn = status.ConnectionsIn
		message.ConnectionsOut = status.ConnectionsOut

		if prev != nil {
			message.Uplink = message.UplinkTotal - prev.UplinkTotal
			message.Downlink = message.DownlinkTotal - prev.DownlinkTotal
		}
		if box := h.Box(); box != nil {
			current := ""
			if currentOutBound, ok := box.Outbound().Outbound(config.OutboundSelectTag); ok {
				if selectOutBound, ok := currentOutBound.(*group.Selector); ok {
					current = selectOutBound.Now()
					message.CurrentOutbound = TrimTagName(current)
				}
			}
			// if message.CurrentOutbound == config.OutboundURLTestTag {
			if currentOutBound, ok := box.Outbound().Outbound(current); ok {
				leaf := currentOutBound
				if g, ok := currentOutBound.(adapter.OutboundGroup); ok {
					if now := g.Now(); now != "" {
						message.CurrentOutbound = fmt.Sprint(message.CurrentOutbound, "→", TrimTagName(now))
						if next, ok := box.Outbound().Outbound(now); ok {
							leaf = next
						}
					}
				}
				// Protocol type of the FINAL leaf (e.g. "hysteria2") — the
				// Android notification shows it instead of tags/profile.
				message.CurrentOutboundType = leaf.Type()
			}
			// }
		}

		if prev == nil || prev.CurrentProfile == "" || message.UplinkTotal < 1000000 {
			settings := db.GetTable[hcommon.AppSettings]()
			lastName, err := settings.Get("lastStartRequestName")
			if err == nil {
				message.CurrentProfile = lastName.Value.(string)
			}
		} else {
			message.CurrentProfile = prev.CurrentProfile
		}
	}

	return &message
}

func (s *CoreService) GetSystemInfo(ctx context.Context, req *hcommon.Empty) (*SystemInfo, error) {
	return static.readStatus(nil), nil

}
func (s *CoreService) GetSystemInfoStream(req *hcommon.Empty, stream grpc.ServerStreamingServer[SystemInfo]) error {
	return static.GetSystemInfo(stream)

}
func (h *PathologyInstance) MakeSureContextIsNew(streamContext context.Context) {
	for range 10 {
		if ctx := h.Context(); ctx != nil {
			select {
			case <-ctx.Done(): //if old context is done waiting for new context
			default:
				return
			}
		}
		select {
		case <-streamContext.Done():
			return
		case <-time.After(time.Millisecond * 500):
		}
	}
}
func (h *PathologyInstance) GetSystemInfo(stream grpc.ServerStreamingServer[SystemInfo]) error {
	// return fmt.Errorf("not implemented yet")
	h.MakeSureContextIsNew(stream.Context())

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()

	ctx := h.Context()
	if ctx == nil {
		return E.New("service not ready")
	}
	current_status := h.readStatus(nil)
	if err := stream.Send(current_status); err != nil {
		Log(LogLevel_ERROR, LogType_CORE, "send System Info failed", err)
	}
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			current_status = h.readStatus(current_status)
			if err := stream.Send(current_status); err != nil {
				// return err
				Log(LogLevel_ERROR, LogType_CORE, "send System Info failed", err)
			}
		}
	}

}

// func (s *CoreService) OutboundsInfo(req *hcommon.Empty, stream grpc.ServerStreamingServer[OutboundGroupList]) error {
// 	if groupClient == nil {
// 		groupClient = libbox.NewCommandClient(
// 			&CommandClientHandler{
// 				command: libbox.CommandGroup,
// 				// port:   s.port,
// 			},
// 			&libbox.CommandClientOptions{
// 				Command:        libbox.CommandGroup,
// 				StatusInterval: 500000000, // 500ms debounce
// 			},
// 		)

// 		defer func() {
// 			groupClient.Disconnect()
// 			groupClient = nil
// 		}()

// 		groupClient.Connect()
// 	}

// 	sub, done, _ := outboundsInfoObserver.Subscribe()

// 	for {
// 		select {
// 		case <-stream.Context().Done():
// 			return nil
// 		case <-done:
// 			return nil
// 		case info := <-sub:
// 			stream.Send(info)
// 			// case <-time.After(500 * time.Millisecond):
// 		}
// 	}
// }

// func (s *CoreService) MainOutboundsInfo(req *hcommon.Empty, stream grpc.ServerStreamingServer[OutboundGroupList]) error {
// 	if groupInfoOnlyClient == nil {
// 		groupInfoOnlyClient = libbox.NewCommandClient(
// 			&CommandClientHandler{
// 				command: libbox.CommandGroupInfoOnly,
// 				// port:   s.port,
// 			},
// 			&libbox.CommandClientOptions{
// 				Command:        libbox.CommandGroupInfoOnly,
// 				StatusInterval: 500000000, // 500ms debounce
// 			},
// 		)

// 		defer func() {
// 			groupInfoOnlyClient.Disconnect()
// 			groupInfoOnlyClient = nil
// 		}()
// 		groupInfoOnlyClient.Connect()
// 	}

// 	sub, stopch, _ := mainOutboundsInfoObserver.Subscribe()

// 	for {
// 		select {
// 		case <-stream.Context().Done():
// 			return nil
// 		case <-stopch:
// 			return nil
// 		case info := <-sub:
// 			stream.Send(info)
// 			// case <-time.After(500 * time.Millisecond):
// 		}
// 	}
// }

func (s *CoreService) SelectOutbound(ctx context.Context, in *SelectOutboundRequest) (*hcommon.Response, error) {
	return static.SelectOutbound(in)
}

func (h *PathologyInstance) SelectOutbound(in *SelectOutboundRequest) (*hcommon.Response, error) {
	// err := libbox.NewStandaloneCommandClient().SelectOutbound(in.GroupTag, in.OutboundTag)
	// if err != nil {
	// 	return &hcommon.Response{
	// 		Code:    hcommon.ResponseCode_FAILED,
	// 		Message: err.Error(),
	// 	}, err
	// }

	// return &hcommon.Response{
	// 	Code:    hcommon.ResponseCode_OK,
	// 	Message: "",
	// }, nil
	Log(LogLevel_DEBUG, LogType_CORE, "select outbound: ", in.GroupTag, " -> ", in.OutboundTag)
	if box := h.Box(); box != nil {
		outboundGroup, isLoaded := box.Outbound().Outbound(in.GroupTag)
		if !isLoaded {
			return &hcommon.Response{
				Code:    hcommon.ResponseCode_FAILED,
				Message: E.New("selector not found: ", in.GroupTag).Error(),
			}, E.New("selector not found: ", in.GroupTag)
		}
		selector, isSelector := outboundGroup.(*group.Selector)
		if !isSelector {
			return &hcommon.Response{
				Code:    hcommon.ResponseCode_FAILED,
				Message: E.New("outbound is not a selector: ", in.GroupTag).Error(),
			}, E.New("outbound is not a selector: ", in.GroupTag)
		}
		if !selector.SelectOutbound(in.OutboundTag) {
			return &hcommon.Response{
				Code:    hcommon.ResponseCode_FAILED,
				Message: E.New("outbound not found in selector:: ", in.GroupTag).Error(),
			}, E.New("outbound not found in selector: ", in.GroupTag)
		}
		Log(LogLevel_DEBUG, LogType_CORE, "Trying to ping outbound: ", in.OutboundTag)

		// if urltesHistory := h.UrlTestHistory(); urltesHistory != nil {
		// 	urltesHistory.Observer().Emit(2)
		// }
	}
	return &hcommon.Response{
		Code:    hcommon.ResponseCode_OK,
		Message: "",
	}, nil
}

func (s *CoreService) UrlTest(ctx context.Context, in *UrlTestRequest) (*hcommon.Response, error) {
	return static.UrlTest(ctx, in)
}

func (s *CoreService) UrlTestActive(ctx context.Context, in *hcommon.Empty) (*hcommon.Response, error) {
	return static.UrlTestActive(ctx)
}

func (h *PathologyInstance) UrlTestActive(ctx context.Context) (*hcommon.Response, error) {
	if box := h.Box(); box != nil {
		outboundGroup, isLoaded := box.Outbound().Outbound(config.OutboundSelectTag)
		if !isLoaded {
			return &hcommon.Response{
				Code:    hcommon.ResponseCode_FAILED,
				Message: E.New("selector not found: ", config.OutboundSelectTag).Error(),
			}, E.New("selector not found: ", config.OutboundSelectTag)
		}
		selector, isSelector := outboundGroup.(adapter.OutboundGroup)
		if !isSelector {
			return &hcommon.Response{
				Code:    hcommon.ResponseCode_FAILED,
				Message: E.New("outbound is not a selector: ", config.OutboundSelectTag).Error(),
			}, E.New("outbound is not a selector: ", config.OutboundSelectTag)
		}
		now := selector.Now()
		if now == "" {
			return &hcommon.Response{
				Code:    hcommon.ResponseCode_FAILED,
				Message: E.New("outbound not found in selector: ", config.OutboundSelectTag).Error(),
			}, E.New("outbound not found in selector: ", config.OutboundSelectTag)
		}
		// Walk nested groups (select → balance/lowest → leaf) until a concrete outbound.
		seen := map[string]struct{}{now: {}}
		for {
			ob, ok := box.Outbound().Outbound(now)
			if !ok {
				break
			}
			grp, isgrp := ob.(adapter.OutboundGroup)
			if !isgrp {
				break
			}
			n2 := grp.Now()
			if n2 == "" || n2 == now {
				break
			}
			if _, loop := seen[n2]; loop {
				break
			}
			seen[n2] = struct{}{}
			now = n2
		}
		return h.UrlTest(ctx, &UrlTestRequest{
			Tag: now,
		})

	}
	return &hcommon.Response{
		Code:    hcommon.ResponseCode_OK,
		Message: "",
	}, nil
}

func (h *PathologyInstance) UrlTest(ctx context.Context, in *UrlTestRequest) (*hcommon.Response, error) {
	if in.Tag == "" {
		return h.UrlTestActive(ctx)
	}
	box := h.Box()
	if box == nil {
		return nil, E.New("service not ready")
	}
	// Honour gRPC cancel; Deactivate cancels monitor ctx on Stop.
	_ = monitoring.Get(h.Context()).TestNowContext(ctx, in.Tag)

	return &hcommon.Response{
		Code:    hcommon.ResponseCode_OK,
		Message: "",
	}, nil
}
