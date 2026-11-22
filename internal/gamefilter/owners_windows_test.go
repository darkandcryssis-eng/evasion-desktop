//go:build windows

package gamefilter

import (
	"net"
	"os"
	"testing"
)

func TestNativeOwnershipUsesActualSocketPID(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	o := Default()
	o.Mode = "balanced"
	o.Executables = []string{self}
	owners := NewOwners(o)
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			address := "127.0.0.1:0"
			if network == "udp6" {
				address = "[::1]:0"
			}
			conn, err := net.ListenPacket(network, address)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			port := uint16(conn.LocalAddr().(*net.UDPAddr).Port)
			owners.last = owners.last.Add(-1000000000)
			if !owners.Owns("udp", port) {
				targets, reason := owners.Status()
				t.Fatalf("self socket not owned: %v %s", targets, reason)
			}
			if NewOwners(Default()).Owns("udp", port) {
				t.Fatal("unselected process was owned")
			}
		})
	}
}
