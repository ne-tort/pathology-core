package hcore

import (
	"context"

	box "github.com/sagernet/sing-box"

	"github.com/ne-tort/pathology-core/v2/config"
	"github.com/ne-tort/pathology-core/v2/service_manager"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

func NewService(ctx context.Context, options option.Options) (*daemon.StartedService, error) {
	return newService(ctx, options, true)
}

// NewSideService starts a secondary sing-box instance (TestEngine) without
// invoking main-service extension lifecycle hooks or writing static.StartedService.
func NewSideService(ctx context.Context, options option.Options) (*daemon.StartedService, error) {
	return newService(ctx, options, false)
}

func newService(ctx context.Context, options option.Options, invokeMainHooks bool) (*daemon.StartedService, error) {
	logInterface := LogInterface{}
	bopts := daemon.ServiceOptions{
		Context:           ctx,
		Debug:             static.debug,
		LogMaxLines:       100,
		Handler:           &logInterface,
		OOMKillerEnabled:  oomKillerEnabled,
		OOMKillerDisabled: oomKillerDisabled,
		OOMMemoryLimit:    oomMemoryLimit,
	}
	err := config.CheckConfigOptions(ctx, &options)
	if err != nil {
		return nil, err
	}
	instance := daemon.NewStartedService(bopts)

	configJSON, err := json.Marshal(options)
	if err != nil {
		return nil, err
	}
	if err := instance.StartOrReloadService(ctx, string(configJSON), nil); err != nil {
		_ = instance.CloseService()
		return nil, err
	}
	if invokeMainHooks {
		// ExtraServices/AddService is hiddify-sing-box-specific; invoke lifecycle hooks directly.
		_ = service_manager.OnMainServiceStart()
	}

	return instance, nil
}

func (h *PathologyInstance) UrlTestHistory() *urltest.HistoryStorage {
	ins := h.Instance()
	if ins == nil {
		return nil
	}
	return ins.UrlTestHistory()
}

func (h *PathologyInstance) Box() *box.Box {
	ins := h.Instance()
	if ins == nil {
		return nil
	}
	return ins.Box()
}

func (h *PathologyInstance) Instance() *daemon.Instance {
	ss := h.StartedService
	if ss == nil {
		return nil
	}
	return ss.Instance()
}

func (h *PathologyInstance) Context() context.Context {
	ins := h.Instance()
	if ins == nil {
		return nil
	}
	return ins.Context()
}

func (h *PathologyInstance) TrafficManager() *trafficcontrol.Manager {
	if ins := h.Instance(); ins != nil {
		return ins.TrafficManager()
	}
	return nil
}
