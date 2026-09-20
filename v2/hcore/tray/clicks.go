//go:build windows || darwin || linux

package tray

import "fyne.io/systray"

// setupClickHandlers binds the tray primary click to show/spawn the UI.
//
// A single left-click (or several quick clicks) always brings the UI to the
// foreground or launches it; the tray never closes the UI. Closing the UI is
// the job of the "Quit" menu item or the window close button, never a click.
//
// The native context menu stays on right-click (systray default).
func setupClickHandlers(onClick func()) {
	systray.SetOnTapped(func() {
		onClick()
	})
}
