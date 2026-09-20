//go:build windows || darwin || linux

package tray

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ne-tort/pathology-core/v2/hcore/session"
)

func TestShowOrSpawnUiOnTrayClickDetachedShowsWhenAlive(t *testing.T) {
	dir := t.TempDir()
	basePath = dir
	uiLifecycle = UiLifecycleDetached
	t.Cleanup(resetUiControlHooks)

	setUiControlHooks(
		func() session.State { return session.State{UiPid: 1234} },
		func(pid int) bool { return pid == 1234 },
	)

	ShowOrSpawnUiOnTrayClickDetached()
	raw, err := os.ReadFile(filepath.Join(dir, uiControlFile))
	if err != nil {
		t.Fatalf("expected show signal file: %v", err)
	}
	if !strings.Contains(string(raw), `"action":"show"`) {
		t.Fatalf("alive UI should be shown, got %s", string(raw))
	}
}

func TestShowOrSpawnUiOnTrayClickDetachedDoesNotQuitWhenAlive(t *testing.T) {
	dir := t.TempDir()
	basePath = dir
	uiLifecycle = UiLifecycleDetached
	t.Cleanup(resetUiControlHooks)

	setUiControlHooks(
		func() session.State { return session.State{UiPid: 1234} },
		func(pid int) bool { return pid == 1234 },
	)

	ShowOrSpawnUiOnTrayClickDetached()
	raw, _ := os.ReadFile(filepath.Join(dir, uiControlFile))
	if strings.Contains(string(raw), `"action":"quit"`) {
		t.Fatalf("tray click must never quit a live UI, got %s", string(raw))
	}
}

func TestShowOrSpawnUiOnTrayClickEmbeddedAlwaysShows(t *testing.T) {
	dir := t.TempDir()
	basePath = dir
	uiLifecycle = UiLifecycleEmbedded
	t.Cleanup(resetUiControlHooks)

	setUiControlHooks(
		func() session.State { return session.State{UiPid: 999} },
		func(pid int) bool { return pid == 999 },
	)

	ShowOrSpawnUiOnTrayClickEmbedded()
	raw, err := os.ReadFile(filepath.Join(dir, uiControlFile))
	if err != nil {
		t.Fatalf("expected show signal file: %v", err)
	}
	if !strings.Contains(string(raw), `"action":"show"`) {
		t.Fatalf("embedded click should only show, got %s", string(raw))
	}
	if strings.Contains(string(raw), `"action":"toggle"`) {
		t.Fatalf("embedded click must never toggle (close) UI, got %s", string(raw))
	}
}

func TestSpawnUiReconnectSkipsWhenPidAlive(t *testing.T) {
	dir := t.TempDir()
	basePath = dir
	t.Cleanup(resetUiControlHooks)

	setUiControlHooks(
		func() session.State { return session.State{UiPid: 42} },
		func(pid int) bool { return pid == 42 },
	)

	spawnUiReconnect()
	raw, err := os.ReadFile(filepath.Join(dir, uiControlFile))
	if err != nil {
		t.Fatalf("expected show file: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("expected show signal")
	}
}

func TestOnTrayClickRoutesByLifecycle(t *testing.T) {
	dir := t.TempDir()
	basePath = dir
	t.Cleanup(resetUiControlHooks)

	setUiControlHooks(
		func() session.State { return session.State{UiPid: 1} },
		func(pid int) bool { return pid == 1 },
	)

	uiLifecycle = UiLifecycleEmbedded
	onTrayClick()
	raw, err := os.ReadFile(filepath.Join(dir, uiControlFile))
	if err != nil {
		t.Fatalf("embedded click should write a signal: %v", err)
	}
	if !strings.Contains(string(raw), `"action":"show"`) {
		t.Fatalf("embedded click should show, got %s", string(raw))
	}

	os.Remove(filepath.Join(dir, uiControlFile))
	uiLifecycle = UiLifecycleDetached
	onTrayClick()
	raw, err = os.ReadFile(filepath.Join(dir, uiControlFile))
	if err != nil || len(raw) == 0 {
		t.Fatal("detached click should write a signal")
	}
	if !strings.Contains(string(raw), `"action":"show"`) {
		t.Fatalf("detached click with alive UI should show, got %s", string(raw))
	}
}