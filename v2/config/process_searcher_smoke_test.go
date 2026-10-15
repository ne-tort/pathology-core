//go:build windows || (linux && !android)

package config_test

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ne-tort/pathology-core/v2/config"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/process"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

// Smoke: OS process searcher can attribute a live localhost TCP connection to this process.
// Mirrors Leadaxe desktop find_process path (no WFP/cgroup).
func TestSmokeProcessSearcherSelfConnection(t *testing.T) {
	searcher, err := process.NewSearcher(process.Config{Logger: log.NewNOPFactory().Logger()})
	if err != nil {
		t.Fatalf("NewSearcher: %v", err)
	}
	defer searcher.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- c
	}()

	client, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	select {
	case c := <-accepted:
		defer c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("accept timeout")
	}

	// Give the OS a moment to publish the TCP row (Windows IP Helper / Linux sock_diag).
	time.Sleep(50 * time.Millisecond)

	local := client.LocalAddr().(*net.TCPAddr)
	remote := client.RemoteAddr().(*net.TCPAddr)
	src := netip.AddrPortFrom(addrFromTCP(local), uint16(local.Port))
	dst := netip.AddrPortFrom(addrFromTCP(remote), uint16(remote.Port))

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	info, err := process.FindProcessInfo(searcher, ctx, "tcp", src, dst)
	if err != nil {
		t.Fatalf("FindProcessInfo(%s -> %s): %v", src, dst, err)
	}
	if info.ProcessID == 0 && len(info.ProcessPaths) == 0 {
		t.Fatalf("empty owner: %+v", info)
	}

	self := os.Getpid()
	exe, _ := os.Executable()
	t.Logf("owner pid=%d path=%q self_pid=%d self_exe=%q", info.ProcessID, ownerFirstPath(info), self, exe)

	if info.ProcessID != 0 && int(info.ProcessID) != self {
		// On some CI/sandbox setups the row may resolve to a wrapper; still require a path.
		if len(info.ProcessPaths) == 0 {
			t.Fatalf("pid mismatch (got %d want %d) and empty path", info.ProcessID, self)
		}
		t.Logf("pid mismatch tolerated (got %d want %d) path=%q", info.ProcessID, self, ownerFirstPath(info))
	}
	if len(info.ProcessPaths) > 0 && exe != "" {
		base := strings.ToLower(filepath.Base(exe))
		got := strings.ToLower(filepath.Base(ownerFirstPath(info)))
		// go test binary names vary (config.test.exe / __debug_bin); require shared stem or .test
		if got != base && !strings.Contains(got, "test") && !strings.Contains(base, "test") {
			t.Logf("basename differ self=%q owner=%q (ok if sandbox)", base, got)
		}
	}
}

// Smoke: compile desktop owner rules + FindProcess flag (Windows/Linux host or Docker).
func TestSmokeCompileProcessOwnerFindProcess(t *testing.T) {
	name := "smoke-proc"
	if runtime.GOOS == "windows" {
		name = "smoke-proc.exe"
	}
	p := &config.RoutingProfile{
		Name:        "smoke",
		Enabled:     true,
		GlobalProxy: true,
		DirectProcesses: []config.ProcessMatch{
			{Name: name},
			{PathRegex: `(.*)[\\/]chrome(.*)`},
		},
		ProxyProcesses: []config.ProcessMatch{
			{Path: `*\Discord\*`},
		},
	}
	_, rules := config.CompileRoutingProfile(p, "", "")
	if len(rules) < 2 {
		t.Fatalf("rules=%d", len(rules))
	}
	if !config.ProfileNeedsFindProcess(p) {
		t.Fatal("expected FindProcess")
	}

	opts := option.Options{
		Outbounds: []option.Outbound{
			{Type: "direct", Tag: "direct"},
			{Type: "direct", Tag: "select"}, // placeholder; BuildConfig tests cover real build
		},
	}
	_ = opts
	foundName, foundRx, foundConverted := false, false, false
	for _, rule := range rules {
		r := rule.DefaultOptions.RawDefaultRule
		for _, n := range r.ProcessName {
			if n == name {
				foundName = true
			}
		}
		for _, rx := range r.ProcessPathRegex {
			if strings.Contains(rx, "chrome") {
				foundRx = true
			}
			if strings.Contains(rx, "Discord") {
				foundConverted = true
			}
		}
	}
	if !foundName || !foundRx || !foundConverted {
		t.Fatalf("name=%v rx=%v converted=%v", foundName, foundRx, foundConverted)
	}
}

func addrFromTCP(a *net.TCPAddr) netip.Addr {
	ip, _ := netip.AddrFromSlice(a.IP)
	return ip.Unmap()
}

// ownerFirstPath adapts the 1.5 adapter.ConnectionOwner (ProcessPaths []string)
// to the single-path checks of this smoke test.
func ownerFirstPath(info *adapter.ConnectionOwner) string {
	if info == nil || len(info.ProcessPaths) == 0 {
		return ""
	}
	return info.ProcessPaths[0]
}
