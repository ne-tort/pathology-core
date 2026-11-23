//go:build darwin || linux

package tray

import (
	"os/exec"
	"runtime"
	"strings"
)

func setHideWindow(cmd *exec.Cmd) {}

func initTheme(themeMode string) {
	_ = themeMode
}

func applyThemeMode(themeMode string) {
	_ = themeMode
}

// applyDarkContextMenu is a no-op outside Windows; macOS/Linux menus use the
// desktop toolkit's own theming and do not need a Win32 immersive mode flip.
func applyDarkContextMenu() {}

func stringsToLower(s string) string {
	return strings.ToLower(s)
}

// osPrefersDarkMenu reports OS dark chrome when app theme is "system".
func osPrefersDarkMenu() bool {
	switch runtime.GOOS {
	case "darwin":
		return darwinPrefersDarkMenu()
	case "linux":
		return linuxPrefersDarkMenu()
	default:
		return false
	}
}

func darwinPrefersDarkMenu() bool {
	out, err := exec.Command("defaults", "read", "-g", "AppleInterfaceStyle").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "Dark"
}

func linuxPrefersDarkMenu() bool {
	if out, err := exec.Command("gsettings", "get", "org.gnome.desktop.interface", "color-scheme").Output(); err == nil {
		if prefersDarkSetting(string(out)) {
			return true
		}
	}
	if out, err := exec.Command("gsettings", "get", "org.gnome.desktop.interface", "gtk-theme").Output(); err == nil {
		return prefersDarkSetting(string(out))
	}
	return false
}

func prefersDarkSetting(raw string) bool {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.Trim(s, "'\"")
	return strings.Contains(s, "dark") && !strings.Contains(s, "light")
}
