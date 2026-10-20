package db

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/syndtr/goleveldb/leveldb/opt"
	tmdb "github.com/tendermint/tm-db"
)

// A broken CURRENT pointer (power loss / disk full mid-write) makes every
// plain open fail. openGoLevelDB must recover the store via
// leveldb.RecoverFile instead of returning an error to every caller forever.
func TestOpenRecoversCorruptedCurrent(t *testing.T) {
	dir := t.TempDir()
	SetDataDir(dir)
	t.Cleanup(func() {
		_ = CloseAll()
		SetDataDir("")
	})

	// Seed a healthy DB.
	raw, err := tmdb.NewGoLevelDBWithOpts("testRow", dir, &opt.Options{})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := SerializeKey("k")
	val, _ := Serialize(&testRow{Id: "k", Value: "v"})
	if err := raw.Set(key, val); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	// Point CURRENT at a manifest that does not exist.
	dbDir := filepath.Join(dir, "testRow.db")
	if err := os.WriteFile(filepath.Join(dbDir, "CURRENT"), []byte("MANIFEST-999999\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Sanity: plain open must now fail, so the recovery path is what saves us.
	if probe, err := tmdb.NewGoLevelDBWithOpts("testRow", dir, &opt.Options{}); err == nil {
		_ = probe.Close()
		t.Fatal("plain open unexpectedly succeeded on broken CURRENT")
	}

	table := GetTable[testRow]()
	if err := table.UpdateInsert(&testRow{Id: "k2", Value: "v2"}); err != nil {
		t.Fatalf("open after corruption failed (no recovery?): %v", err)
	}
	got, err := table.Get("k2")
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != "v2" {
		t.Fatalf("value=%q", got.Value)
	}
	// Pre-corruption data should survive journal/table recovery too.
	if got, err := table.Get("k"); err != nil || got.Value != "v" {
		t.Fatalf("old value lost: got=%q err=%v", got.Value, err)
	}
}
