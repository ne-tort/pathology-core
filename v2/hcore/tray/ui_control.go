//go:build windows || darwin || linux

package tray

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	hcore "github.com/ne-tort/pathology-core/v2/hcore"
)

const uiControlFile = "ui_control.request"

func uiControlPath() string {
	return filepath.Join(basePath, uiControlFile)
}

func signalUiControl(action string) {
	if basePath == "" {
		return
	}
	path := uiControlPath()
	payload := fmt.Sprintf(`{"action":"%s","ts":%d}`, action, time.Now().UnixNano())
	_ = os.WriteFile(path, []byte(payload), 0o644)
}

func logUiControl(action string, pid int, alive bool) {
	hcore.Log(hcore.LogLevel_DEBUG, hcore.LogType_CORE,
		fmt.Sprintf("tray ui_control action=%s ui_pid=%d alive=%v lifecycle=%d", action, pid, alive, uiLifecycle))
}

func requestUiShowOrSpawn() {
	pid, alive := resolveUiPid()
	logUiControl("show_or_spawn", pid, alive)
	if alive {
		signalUiControl("show")
		return
	}
	spawnUiReconnect()
}

// ShowOrSpawnUiOnTrayClickDetached brings an already-running UI process to the
// foreground, or launches a fresh one if none is alive. It never closes the UI.
//
// Detached lifecycle (PathologyCli host serve --tray): the UI is a separate
// process, so bringing it forward means signalling it via ui_control.request.
func ShowOrSpawnUiOnTrayClickDetached() {
	pid, alive := resolveUiPid()
	logUiControl("click_detached", pid, alive)
	if alive {
		signalUiControl("show")
		return
	}
	spawnUiReconnect()
}

// ShowOrSpawnUiOnTrayClickEmbedded shows the in-process window via a file signal.
//
// Embedded lifecycle (in-process DLL tray): UI and core share one process, so
// we only ever show the window (never kill the process on a click).
func ShowOrSpawnUiOnTrayClickEmbedded() {
	pid, alive := resolveUiPid()
	logUiControl("click_embedded", pid, alive)
	signalUiControl("show")
}

func onTrayClick() {
	switch uiLifecycle {
	case UiLifecycleEmbedded:
		ShowOrSpawnUiOnTrayClickEmbedded()
	default:
		ShowOrSpawnUiOnTrayClickDetached()
	}
}

func spawnUiReconnect() {
	pid, alive := resolveUiPid()
	if alive {
		logUiControl("spawn_skipped_alive", pid, true)
		signalUiControl("show")
		return
	}

	exe := uiExe
	if exe == "" {
		exe = defaultUIExePath()
	}
	if exe == "" {
		return
	}
	logUiControl("spawn", pid, false)
	cmd := exec.Command(exe, "--reconnect-host")
	_ = cmd.Start()
}

func requestUiQuit(pid int) {
	logUiControl("quit", pid, pid > 0 && processAliveFn(pid))
	signalUiControl("quit")
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if pid <= 0 || !processAliveFn(pid) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if pid > 0 && processAliveFn(pid) {
		_ = killProcess(pid)
		time.Sleep(100 * time.Millisecond)
	}
	if pid <= 0 || !processAliveFn(pid) {
		_ = hcore.SessionClearUiPidIf(int32(pid))
	}
}