package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckCustomIPs(t *testing.T) {
	n, err := checkCustomIPs("# сервер\n203.0.113.7\n198.51.100.0/24, 203.0.113.7\n2001:db8::/32\n")
	if err != nil || n != 3 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	for _, bad := range []string{"example.com", "192.168.0.1", "0.0.0.0/0", "8.0.0.0/7", "::/0", "127.0.0.1", "1.2.3.4/40"} {
		if _, err := checkCustomIPs(bad); err == nil {
			t.Errorf("%q принято", bad)
		}
	}
}

func TestCustomIPArgs(t *testing.T) {
	base := t.TempDir()
	if args := customIPArgs(base); args != nil {
		t.Fatalf("нет файла: %v", args)
	}
	path := filepath.Join(base, customIPsFile)
	for text, want := range map[string]int{"# пусто\n": 0, "не адрес\n": 0, "203.0.113.7\n": 2} {
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		if args := customIPArgs(base); len(args) != want {
			t.Errorf("%q: %v", text, args)
		}
	}
}
