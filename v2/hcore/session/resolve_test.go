package session

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveStartTarget_DirectMissing(t *testing.T) {
	dir := t.TempDir()
	st := State{DirectMode: true}
	_, err := ResolveStartTarget(st, dir)
	require.Error(t, err)
	require.Contains(t, err.Error(), "direct config missing")
}

func TestResolveStartTarget_SingleProfile(t *testing.T) {
	dir := t.TempDir()
	configs := filepath.Join(dir, "configs")
	require.NoError(t, os.MkdirAll(configs, 0o755))
	id := "abc123"
	require.NoError(t, os.WriteFile(filepath.Join(configs, id+".json"), []byte("{}"), 0o644))

	st := State{
		ActiveProfileIDs: []string{id},
		Profiles:         []ProfileMeta{{ID: id, Name: "My VPN", Active: true}},
	}
	target, err := ResolveStartTarget(st, dir)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(configs, id+".json"), target.Path)
	require.Equal(t, "My VPN", target.Name)
}

func TestResolveStartTarget_NoProfiles(t *testing.T) {
	dir := t.TempDir()
	_, err := ResolveStartTarget(State{}, dir)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no active profile")
}

func TestResolveStartTarget_CachedStartTarget(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cached.json")
	require.NoError(t, os.WriteFile(p, []byte("{}"), 0o644))
	st := State{DirectMode: true, StartTarget: &StartTarget{Path: p, Name: "Cached"}}
	target, err := ResolveStartTarget(st, dir)
	require.NoError(t, err)
	require.Equal(t, p, target.Path)
	require.Equal(t, "Cached", target.Name)
}

// A stale cache (past direct session or since-disabled profile) must NOT be
// honored when the session is no longer connectable — otherwise the QS tile
// connects «No VPN» on a phone with zero enabled profiles.
func TestResolveStartTarget_StaleCacheIgnored(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cached.json")
	require.NoError(t, os.WriteFile(p, []byte("{}"), 0o644))
	st := State{StartTarget: &StartTarget{Path: p, Name: "Cached"}}
	_, err := ResolveStartTarget(st, dir)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no active profile")
}
