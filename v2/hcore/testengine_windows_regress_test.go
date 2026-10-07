package hcore_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/ne-tort/pathology-core/v2/config"
	"github.com/ne-tort/pathology-core/v2/hcore"
	"github.com/ne-tort/pathology-core/v2/hcore/testengine"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing/service/filemanager"
)

// End-to-end: Setup → BaseContext → TestEngine Ensure (cache-file + leaves) on Windows.
func TestTestEngineEnsureStartsSideBoxOnWindows(t *testing.T) {
	origWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// Avoid t.TempDir: libbox keeps CrashReport-*.log open under WorkingPath.
	work := filepath.Join(origWD, "testdata", "te_win_ensure")
	_ = os.RemoveAll(work)
	tmp := filepath.Join(work, "tmp")
	if err := os.MkdirAll(filepath.Join(work, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(tmp, 0o755)

	if err := libbox.Setup(&libbox.SetupOptions{
		BasePath:    work,
		WorkingPath: work,
		TempPath:    tmp,
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(work); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = testengine.Global().Stop(context.Background())
		_ = os.Chdir(origWD)
		time.Sleep(50 * time.Millisecond)
		_ = os.RemoveAll(work)
	})

	base := libbox.BaseContext(nil)
	probe := filepath.Join(work, "data", "chown-probe")
	_ = os.WriteFile(probe, []byte("x"), 0o644)
	if err := filemanager.Chown(base, probe); err != nil {
		t.Fatalf("post-Setup BaseContext must not chown-fail on %s: %v", runtime.GOOS, err)
	}

	cfgPath := filepath.Join(work, "profile.json")
	raw := `{
  "outbounds": [
    {
      "type": "vless",
      "tag": "node-a",
      "server": "1.1.1.1",
      "server_port": 443,
      "uuid": "387c6b84-2e30-4b67-83c9-aa5692550e65"
    }
  ]
}`
	if err := os.WriteFile(cfgPath, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}

	opt := config.DefaultClientOptions()
	testengine.Configure(testengine.Deps{
		BaseContext: func() context.Context { return base },
		WorkingDir:  work,
		CloneOptions: func() (*config.ClientOptions, error) {
			return config.CloneClientOptions(opt)
		},
		StartSide: hcore.NewSideService,
	})

	eng := testengine.Global()

	// gRPC-like plain ctx (no registries) — Ensure must use serviceContext internally.
	res, err := eng.Ensure(context.Background(), "prof-win", cfgPath, []string{"node-a"})
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if res.MixedPort == 0 {
		t.Fatal("expected mixed port")
	}
	if len(res.LeafTags) != 1 || res.LeafTags[0] != "node-a" {
		t.Fatalf("leaf tags=%v", res.LeafTags)
	}

	cache := filepath.Join(work, "data", "test-engine", "prof-win", "clash.db")
	if st, err := os.Stat(cache); err != nil || st.Size() == 0 {
		t.Fatalf("expected test-engine clash.db, err=%v", err)
	}

	results, err := eng.Ping(context.Background(), "prof-win", "node-a", "single", "http://1.1.1.1")
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if len(results) != 1 || results[0].Tag != "node-a" {
		t.Fatalf("results=%+v", results)
	}
}
