package quic

import "testing"

func TestBuildClientInitialIsParseable(t *testing.T) {
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	datagram, ok := BuildClientInitial("vk.com", dcid)
	if !ok || len(datagram) != 1200 {
		t.Fatalf("ok=%v len=%d", ok, len(datagram))
	}
	if sni, ok := ExtractSNI(datagram); !ok || sni != "vk.com" {
		t.Fatalf("ExtractSNI = %q, %v", sni, ok)
	}
	if sni, ok := PeekSNI(datagram); !ok || sni != "vk.com" {
		t.Fatalf("PeekSNI = %q, %v", sni, ok)
	}
	if _, ok := BuildClientInitial("vk.com", []byte{1, 2, 3}); ok {
		t.Fatal("короткий DCID должен быть отвергнут")
	}
}
