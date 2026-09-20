//go:build windows || darwin || linux

package tray

// trayCmd is a unit of work that must run on the tray UI goroutine.
//
// All systray mutations (icon/tooltip/menu rebuilds, label updates, profile
// submenu diffing) are funneled through cmdCh. The dispatcher executes them
// sequentially on a single goroutine, so:
//
//   - concurrent refreshTrayDisplay / refreshConnectionUI / rebuildProfileSubmenuIfNeeded
//     calls (from gRPC worker pool, prefs watcher, watchCoreTransitions) can
//     no longer race with each other on systray's shared map state and
//     MenuItem.ClickedCh;
//   - without serialization, rebuildProfileSubmenuIfNeeded's item.Remove()
//     (which closes ClickedCh) can race with systrayMenuItemSelected writing
//     to that channel from WndProc → "send on closed channel" panic inside
//     the message loop → tray menu dies, icon lingers, clicks dead.
var cmdCh = make(chan func(), 64)

// dispatch schedules fn on the tray UI goroutine. Non-blocking drop when the
// queue is saturated or the tray is shutting down; a stale refresh after
// onExit is harmless (systray ops are guarded by isReady).
func dispatch(fn func()) {
	select {
	case cmdCh <- fn:
	default:
	}
}

// runDispatcher consumes cmdCh until ctxDone. It serializes all tray mutations
// on one goroutine, eliminating races between concurrent refresh requests.
func runDispatcher(ctxDone <-chan struct{}) {
	for {
		select {
		case <-ctxDone:
			return
		case fn, ok := <-cmdCh:
			if !ok {
				return
			}
			fn()
		}
	}
}
