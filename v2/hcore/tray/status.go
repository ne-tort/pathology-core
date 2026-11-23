//go:build windows || darwin || linux

package tray

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	hcore "github.com/ne-tort/pathology-core/v2/hcore"

	"fyne.io/systray"
)

var (
	trayCtx            context.Context
	transitionWatchMu  sync.Mutex
	transitionWatching bool
)

// trayErrorState marks the last session action as failed. While set, the tray
// shows the error tooltip; it clears on the next error-free action or any
// STARTED transition. Atomic: written from menu goroutines, read on the tray
// UI goroutine.
var trayErrorState atomic.Bool

func setTrayError(hasError bool) { trayErrorState.Store(hasError) }

// transitionPollCeiling bounds how long watchCoreTransitions will poll STARTING/
// STOPPING before giving up. Without a ceiling, a stuck core state (Start that
// never reaches STARTED/STOPPED) keeps refreshing the tray forever from a
// non-UI goroutine, racing with WndProc menu mutations.
const transitionPollCeiling = 10 * time.Second

// transitionPollInterval is the cadence while STARTING/STOPPING.
const transitionPollInterval = 300 * time.Millisecond

// applyTrayIcon shows the single full-color logo for every state: the icon
// no longer encodes connection state, theme or errors (those surface via the
// toggle label and the error tooltip).
func applyTrayIcon(state hcore.CoreStates) {
	if state == hcore.CoreStates_STARTED {
		trayErrorState.Store(false)
	}
	systray.SetIcon(trayIcon)
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
	applyTrayIcon(state)
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
