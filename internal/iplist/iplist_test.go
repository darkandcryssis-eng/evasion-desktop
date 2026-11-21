package iplist

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestParseAndContains(t *testing.T) {
	s, err := Parse("# мои серверы\n203.0.113.7\n198.51.100.0/24, 203.0.113.7 ; 2001:db8::/32\r\n::ffff:192.0.2.1\n192.0.2.77/24 # хвост\n")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"203.0.113.7", "198.51.100.0/24", "2001:db8::/32", "192.0.2.1", "192.0.2.0/24"}
	if got := s.Entries(); !reflect.DeepEqual(got, want) {
		t.Fatalf("entries = %v, want %v", got, want)
	}
	for ip, in := range map[string]bool{"203.0.113.7": true, "203.0.113.8": false, "198.51.100.200": true, "::ffff:198.51.100.1": true, "2001:db8:1::5": true, "2001:db9::1": false, "192.0.2.200": true} {
		if got := s.Contains(netip.MustParseAddr(ip)); got != in {
			t.Errorf("Contains(%s) = %v, want %v", ip, got, in)
		}
	}
}

func TestParseRejects(t *testing.T) {
	for _, in := range []string{"example.com", "192.168.1.1", "10.0.0.0/8", "127.0.0.1", "0.0.0.0/0", "8.0.0.0/7", "::/0", "fe80::1", "1.2.3.4/33", "1.2.3", "224.0.0.1"} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) accepted", in)
		}
	}
}

func TestEmptyAndNil(t *testing.T) {
	s, err := Parse("\n# только комментарий\n")
	if err != nil || s.Len() != 0 {
		t.Fatalf("len=%d err=%v", s.Len(), err)
	}
	var n *Set
	if n.Contains(netip.MustParseAddr("1.1.1.1")) || n.Len() != 0 || len(n.Entries()) != 0 {
		t.Fatal("nil set must be empty")
	}
	if s, err = Load(t.TempDir() + "/missing.txt"); err != nil || s.Len() != 0 {
		t.Fatalf("missing file: len=%d err=%v", s.Len(), err)
	}
}
