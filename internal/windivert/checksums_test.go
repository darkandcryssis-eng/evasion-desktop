package windivert

import "testing"

func TestFinalTCPChecksumsPreserveCapturedAddress(t *testing.T) {
	for value := 0; value < 256; value++ {
		var address Address
		for i := range address {
			address[i] = byte(i * 3)
		}
		address[flagsOffset] = byte(value)
		before := address
		final, ok := address.WithFinalTCPChecksums().(Address)
		if !ok {
			t.Fatal("address type lost")
		}
		want := before
		want[flagsOffset] |= (1 << 5) | (1 << 6)
		if final != want || address != before {
			t.Fatalf("address altered beyond checksum flags: %02x", value)
		}
	}
}
