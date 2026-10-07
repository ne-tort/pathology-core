package hcore

import (
	"context"

	"github.com/ne-tort/pathology-core/v2/config"
	"github.com/ne-tort/pathology-core/v2/hcore/testengine"
	"github.com/sagernet/sing-box/experimental/libbox"
)

func configureTestEngine() {
	testengine.Configure(testengine.Deps{
		// Getters, not values: Android re-resolves the shared platform/BaseContext
		// on every Setup/Close (bg VPNService wrapper vs fg wrapper). Captured
		// values went stale — e.g. after the VPN service died, side boxes kept
		// dialing JNI methods on a destroyed Kotlin service.
		BaseContext: func() context.Context { return static.baseContext() },
		Platform:    func() libbox.PlatformInterface { return static.platform() },
		WorkingDir:  sWorkingPath,
		CloneOptions: func() (*config.ClientOptions, error) {
			return config.CloneClientOptions(static.ClientOptions)
		},
		StartSide: NewSideService,
		Log: func(msg string) {
			Log(LogLevel_INFO, LogType_CORE, "testengine: "+msg)
		},
	})
}
