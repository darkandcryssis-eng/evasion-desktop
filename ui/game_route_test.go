package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGameRouteMetadataNeedsBothFilesAndBoundedNodes(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, gameRouteFile)
	if gameRouteView(base).Configured {
		t.Fatal("missing route configured")
	}
	os.WriteFile(path, []byte("sealed"), 0600)
	for _, data := range []string{`{"nodes":0}`, `{"nodes":99999}`, `{"nodes":-1}`, `invalid`} {
		os.WriteFile(path+".info.json", []byte(data), 0600)
		if gameRouteView(base).Configured {
			t.Fatal("bad metadata accepted")
		}
	}
	os.WriteFile(path+".info.json", []byte(`{"nodes":4}`), 0600)
	v := gameRouteView(base)
	if !v.Configured || v.Nodes != 4 {
		t.Fatal(v)
	}
}
