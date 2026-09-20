package hcore

import (
	"strings"
	"time"

	hcommon "github.com/ne-tort/pathology-core/v2/hcommon"
	"github.com/sagernet/sing-box/adapter"
	"github.com/ne-tort/pathology-core/compat/monitoring"
	G "github.com/sagernet/sing-box/protocol/group"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"
	"google.golang.org/grpc"

	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

func (h *PathologyInstance) historyForDetour(hismap map[string]*adapter.URLTestHistory, detour adapter.Outbound) *adapter.URLTestHistory {
	if hismap == nil || detour == nil {
		return nil
	}
	pickAlive := func(tag string) *adapter.URLTestHistory {
		h := hismap[tag]
		if h == nil || h.Delay == 0 || h.Delay >= monitoring.FailDelay {
			return nil
		}
		return h
	}
	if h := pickAlive(detour.Tag()); h != nil {
		return h
	}
	// Balancer/selector tags usually have no own history — use the selected leaf.
	tag := monitoring.RealTag(detour)
	if tag != "" && tag != detour.Tag() {
		if h := pickAlive(tag); h != nil {
			return h
		}
	}
	if group, ok := detour.(adapter.OutboundGroup); ok {
		var best *adapter.URLTestHistory
		for _, itemTag := range group.All() {
			h := pickAlive(itemTag)
			if h == nil {
				continue
			}
			if best == nil || h.Delay < best.Delay {
				best = h
			}
		}
		if best != nil {
			return best
		}
		// Fall back to raw selected history (including fail) so UI can show timeout.
		if tag != "" {
			return hismap[tag]
		}
	}
	return hismap[detour.Tag()]
}

func (h *PathologyInstance) GetProxyInfo(url_test_history *adapter.URLTestHistory, detour adapter.Outbound) *OutboundInfo {
	// historyStorage := h.UrlTestHistory()
	// if historyStorage == nil {
	// 	return nil
	// }

	out := &OutboundInfo{}
	// realTag := ""

	out.Tag = detour.Tag()
	// LX-STUB: adapter.Outbound.DisplayType() was fork-only; lx has Type() only.
	out.Type = detour.Type()
	if group, isGroup := detour.(adapter.OutboundGroup); isGroup {
		out.IsGroup = true
		gnow := group.Now()
		out.GroupSelectedTag = &gnow
	}
	out.TagDisplay = TrimTagName(out.Tag)

	if tag := monitoring.RealTag(detour); tag != "" {
		dtag := TrimTagName(tag)
		out.GroupSelectedTagDisplay = &dtag
	}

	// Outbound-scoped counters are hiddify-sing-box specific; lx exposes totals only.
	_ = h.TrafficManager()
	if url_test_history != nil {
		out.UrlTestTime = timestamppb.New(url_test_history.Time)
		out.UrlTestDelay = int32(url_test_history.Delay)
		// LX-STUB: IsFromCache / IpInfo fields absent on lx adapter.URLTestHistory.
	}
	if deps := detour.Dependencies(); len(deps) == 1 {
		out.Detour = deps[0]
	}
	return out
}

func (h *PathologyInstance) GetAllProxiesInfo(hismap map[string]*adapter.URLTestHistory, onlyGroupitems bool) *OutboundGroupList {
	ctx, box := h.Context(), h.Box()
	if ctx == nil || box == nil {
		return nil
	}
	cacheFile := service.FromContext[adapter.CacheFile](ctx)

	outbounds_converted := make(map[string]*OutboundInfo, 0)
	var iGroups []adapter.OutboundGroup
	for _, it := range box.Endpoint().Endpoints() {
		outbounds_converted[it.Tag()] = h.GetProxyInfo(h.historyForDetour(hismap, it), it)
	}
	for _, it := range box.Outbound().Outbounds() {
		outbounds_converted[it.Tag()] = h.GetProxyInfo(h.historyForDetour(hismap, it), it)
	}
	for _, it := range outbounds_converted {
		if it.Detour == "" {
			continue
		}
		if det, ok := outbounds_converted[it.Detour]; ok {
			it.TagDisplay += " → " + det.TagDisplay
			it.Type += " → " + det.Type
		}
	}
	for _, it := range box.Outbound().Outbounds() {
		if group, isGroup := it.(adapter.OutboundGroup); isGroup {
			iGroups = append(iGroups, group)

			// up := 0
			// down := 0
			// for _, itemTag := range group.All() {
			// 	if pinfo, ok := outbounds_converted[itemTag]; ok {
			// 		up += int(pinfo.Upload)
			// 		down += int(pinfo.Download)
			// 	}
			// }
			// outbounds_converted[it.Tag()].Upload += int64(up)
			// outbounds_converted[it.Tag()].Download += int64(down)
		}
	}

	var groups OutboundGroupList
	for _, iGroup := range iGroups {
		var group OutboundGroup
		group.Tag = iGroup.Tag()
		group.Type = iGroup.Type()
		_, group.Selectable = iGroup.(*G.Selector)
		selectedTag := iGroup.Now()
		group.Selected = selectedTag

		// outbounds_converted[iGroup.Tag()].GroupSelectedOutbound = &group.Selected
		if cacheFile != nil {
			if isExpand, loaded := cacheFile.LoadGroupExpand(group.Tag); loaded {
				group.IsExpand = isExpand
			}
		}

		for _, itemTag := range iGroup.All() {
			if onlyGroupitems && itemTag != selectedTag {
				continue
			}
			pinfo := outbounds_converted[itemTag]
			pinfo.IsSelected = itemTag == selectedTag
			if onlyGroupitems && pinfo.GroupSelectedTagDisplay != nil && pinfo.TagDisplay != *pinfo.GroupSelectedTagDisplay {
				pinfo.TagDisplay = pinfo.TagDisplay + " → " + *pinfo.GroupSelectedTagDisplay
			}
			group.Items = append(group.Items, pinfo)
			pinfo.IsVisible = !strings.Contains(itemTag, "§hide§") &&
				!strings.EqualFold(pinfo.Type, "punnel")

		}
		if len(group.Items) == 0 {
			continue
		}

		groups.Items = append(groups.Items, &group)


	}

	return &groups
}

func TrimTagName(tag string) string {
	return strings.Trim(strings.Split(tag, "§")[0], " ")
}

func (s *CoreService) OutboundsInfo(req *hcommon.Empty, stream grpc.ServerStreamingServer[OutboundGroupList]) error {
	return static.AllProxiesInfoStream(stream, false)
}

func (s *CoreService) MainOutboundsInfo(req *hcommon.Empty, stream grpc.ServerStreamingServer[OutboundGroupList]) error {
	return static.AllProxiesInfoStream(stream, true)
}

func (h *PathologyInstance) AllProxiesInfoStream(stream grpc.ServerStreamingServer[OutboundGroupList], onlyMain bool) error {
	// stream.Send(&OutboundGroupList{})
	h.MakeSureContextIsNew(stream.Context())

	if ctx, urlTestHistory := h.Context(), h.UrlTestHistory(); ctx != nil && urlTestHistory != nil {
		monitor := monitoring.Get(ctx)

		stream.Send(h.GetAllProxiesInfo(monitor.OutboundsHistory(""), onlyMain))

		urltestch, err := monitor.SubscribeGroup("")
		if err != nil {
			Log(LogLevel_ERROR, LogType_CORE, "failed to send outbounds info: ", err)
			// return err
		}
		defer monitor.UnsubscribeGroup("", urltestch)

		// timer2 := time.NewTicker(10 * time.Second)
		// defer timer2.Stop()
		debounceWindow := 1000 * time.Millisecond
		var (
			timer   *time.Timer
			timerCh <-chan time.Time
		)
		defer func() {
			if timer != nil {
				timer.Stop()
			}
		}()
		for {
			select {
			case <-stream.Context().Done():
				return nil
			case <-ctx.Done():
				return nil
			case _, ok := <-urltestch:
				if !ok {
					return nil
				}
				if timer == nil {
					timer = time.NewTimer(debounceWindow)
					timerCh = timer.C
				}
			case <-timerCh:
				if err := stream.Send(h.GetAllProxiesInfo(monitor.OutboundsHistory(""), onlyMain)); err != nil {
					Log(LogLevel_ERROR, LogType_CORE, "failed to send outbounds info: ", err)
					// return err
				}
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer = nil
				timerCh = nil
			}
		}
	}

	return E.New("hiddify service not found")
}
