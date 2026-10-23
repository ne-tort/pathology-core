//go:build darwin || linux

package tray

import _ "embed"

//go:embed icons/tray_icon.png
var trayIconDisconnected []byte

//go:embed icons/tray_icon_connected.png
var trayIconConnected []byte

//go:embed icons/tray_icon_disconnected.png
var trayIconConnecting []byte

//go:embed icons/tray_icon_dark.png
var trayIconDark []byte

// Light variants: the same silhouettes drawn in white, for dark panels.
//
// The `.ico` sources of tray_icon / tray_icon_connected / tray_icon_dark are
// byte-identical, so "dark" really meant "the same dark glyph". On Ubuntu's
// #131313 top bar that glyph disappears and only a thin white interior is left,
// which is why the tray looked empty. See icons/gen_png_from_ico.py.
//
//go:embed icons/tray_icon_light.png
var trayIconDisconnectedLight []byte

//go:embed icons/tray_icon_connected_light.png
var trayIconConnectedLight []byte

//go:embed icons/tray_icon_disconnected_light.png
var trayIconConnectingLight []byte

// trayIconSet returns (disconnected, connecting, connected) for the panel.
func trayIconSet(light bool) (disconnected, connecting, connected []byte) {
	if light {
		return trayIconDisconnectedLight, trayIconConnectingLight, trayIconConnectedLight
	}
	return trayIconDisconnected, trayIconConnecting, trayIconConnected
}
