//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEngineCleanupRequiresSameFile(t *testing.T) {
	root := t.TempDir()
	own := filepath.Join(root, "runtime", "evasion.exe")
	game := gameEngineLayout(layout{Base: root, Engine: own}).Engine
	if want := filepath.Join(root, "game-runtime", "evasion.exe"); game != want {
		t.Fatalf("game engine = %q, want %q", game, want)
	}
	other := filepath.Join(root, "other", "Evasion.exe")
	for _, p := range []string{own, game, other} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("same-content"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if !sameEngineImage(own, own) {
		t.Fatal("own image rejected")
	}
	if sameEngineImage(other, own) {
		t.Fatal("unrelated process with same name accepted")
	}
	if !sameEngineImage(game, game) || sameEngineImage(game, own) || sameEngineImage(own, game) || sameEngineImage(other, game) {
		t.Fatal("game cleanup did not distinguish game, main and unrelated engines")
	}
	if sameEngineImage(root, root) || sameEngineImage(filepath.Join(root, "missing"), own) {
		t.Fatal("invalid image accepted")
	}
}
