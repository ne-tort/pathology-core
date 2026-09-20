//go:build windows || darwin || linux

package tray

import (
	"context"
	"sync"
	"time"

	hcore "github.com/ne-tort/pathology-core/v2/hcore"

	"fyne.io/systray"
)

var (
	trayCtx           context.Context
	transitionWatchMu sync.Mutex
	transitionWatching bool
)

// transitionPollCeiling bounds how long watchCoreTransitions will poll STARTING/
// STOPPING before giving up. Without a ceiling, a stuck core state (Start that
// never reaches STARTED/STOPPED) keeps refreshing the tray forever from a
// non-UI goroutine, racing with WndProc menu mutations.
const transitionPollCeiling = 10 * time.Second

// transitionPollInterval is the cadence while STARTING/STOPPING.
const transitionPollInterval = 300 * time.Millisecond

func applyTrayIcon(state hcore.CoreStates, darkTheme bool) {
	var icon []byte
	switch state {
	case hcore.CoreStates_STARTED:
		icon = trayIconConnected
	case hcore.CoreStates_STARTING, hcore.CoreStates_STOPPING:
		icon = trayIconConnecting
	default:
		if darkTheme {
			icon = trayIconDark
		} else {
			icon = trayIconDisconnected
		}
	}
	if len(icon) > 0 {
		systray.SetIcon(icon)
	}
}

// refreshConnectionUI mutates the icon and toggle label. It must be safe to
// call from any goroutine; the actual mutation is serialized on the tray UI
// goroutine to avoid racing WndProc menu handling and concurrent rebuilds.
func refreshConnectionUI(state hcore.CoreStates) {
	dispatch(func() { refreshConnectionUISync(state) })
}

// refreshConnectionUISync performs the mutation in-place. Call only from the
// tray UI goroutine (i.e. inside dispatch) to avoid races.
func refreshConnectionUISync(state hcore.CoreStates) {
	refreshConnectionMenu(state)
	applyTrayIcon(state, darkMenu)
}

// watchCoreTransitions polls briefly only while STARTING/STOPPING (icon + toggle
// label). Bounded by transitionPollCeiling so a stuck state can't poll forever.
func watchCoreTransitions(ctx context.Context) {
	transitionWatchMu.Lock()
	if transitionWatching {
		transitionWatchMu.Unlock()
		return
	}
	transitionWatching = true
	transitionWatchMu.Unlock()

	go func() {
		defer func() {
			transitionWatchMu.Lock()
			transitionWatching = false
			transitionWatchMu.Unlock()
		}()
		deadline := time.Now().Add(transitionPollCeiling)
		for {
			state := hcore.CurrentCoreState()
			refreshConnectionUI(state)
			if state != hcore.CoreStates_STARTING && state != hcore.CoreStates_STOPPING {
				return
			}
			if time.Now().After(deadline) {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(transitionPollInterval):
			}
		}
	}()
}
