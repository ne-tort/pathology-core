//go:build windows

package tray

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

func setHideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}

func initTheme(themeMode string) {
	applyThemeMode(themeMode)
}

func applyThemeMode(themeMode string) {
	allowDarkModeForApp(true)
	switch stringsToLower(themeMode) {
	case "dark", "black":
		setPreferredAppMode(1)
	case "system":
		if osPrefersDarkMenu() {
			setPreferredAppMode(1)
		} else {
			setPreferredAppMode(0)
		}
	default:
		setPreferredAppMode(0)
	}
	refreshImmersiveColorPolicyState()
}

func stringsToLower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

func allowDarkModeForApp(allow bool) {
	uxtheme := windows.NewLazySystemDLL("uxtheme.dll")
	proc := uxtheme.NewProc("AllowDarkModeForApp")
	if proc.Find() != nil {
		return
	}
	var v uintptr
	if allow {
		v = 1
	}
	_, _, _ = proc.Call(v)
}

// applyDarkContextMenu aligns the native Win32 popup menu chrome with the app
// theme before the menu is (re)created. Called from onReady so the immersive
// dark/light mode is flushed before TrackPopupMenuEx first runs.
func applyDarkContextMenu() {
	allowDarkModeForApp(true)
	if darkMenu {
		setPreferredAppMode(1)
	} else {
		setPreferredAppMode(0)
	}
	refreshImmersiveColorPolicyState()
}

func setPreferredAppMode(mode int32) bool {
	uxtheme := windows.NewLazySystemDLL("uxtheme.dll")
	proc := uxtheme.NewProc("SetPreferredAppMode")
	if proc.Find() != nil {
		return false
	}
	r, _, _ := proc.Call(uintptr(mode))
	return r != 0
}

// refreshImmersiveColorPolicyState tells uxtheme to re-read the preferred app
// mode so the next menu/metrics repaint honours dark or light.
func refreshImmersiveColorPolicyState() {
	uxtheme := windows.NewLazySystemDLL("uxtheme.dll")
	proc := uxtheme.NewProc("RefreshImmersiveColorPolicyState")
	if proc.Find() != nil {
		return
	}
	_, _, _ = proc.Call()
}