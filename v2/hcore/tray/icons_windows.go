//go:build windows

package tray

import _ "embed"

//go:embed icons/tray_icon.ico
var trayIconDisconnected []byte

//go:embed icons/tray_icon_connected.ico
var trayIconConnected []byte

//go:embed icons/tray_icon_disconnected.ico
var trayIconConnecting []byte

//go:embed icons/tray_icon_dark.ico
var trayIconDark []byte

// trayIconSet returns (disconnected, connecting, connected).
//
// Windows has no light/dark icon split: the .ico carries its own multi-size
// artwork and the taskbar does not tint notification icons, so the flag is
// ignored here.
func trayIconSet(_ bool) (disconnected, connecting, connected []byte) {
	return trayIconDisconnected, trayIconConnecting, trayIconConnected
}
