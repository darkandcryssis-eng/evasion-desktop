package main

import (
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestGameRelayProcessHelper(t *testing.T) {
	TestGameTLSProcessHelper(t)
	for _, host := range []string{"example.com.", "www.cloudflare.com."} {
		name, _ := dnsmessage.NewName(host)
		query := dnsmessage.Message{Header: dnsmessage.Header{ID: 0xe7a5, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
		data, err := query.Pack()
		if err != nil {
			t.Fatal(err)
		}
		c, err := net.Dial("udp", "1.1.1.1:53")
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		_, err = c.Write(data)
		if err != nil {
			c.Close()
			t.Fatal(err)
		}
		buf := make([]byte, 4096)
		n, err := c.Read(buf)
		c.Close()
		if err != nil {
			t.Fatal("UDP response missing", err)
		}
		var response dnsmessage.Message
		if response.Unpack(buf[:n]) != nil || response.ID != query.ID || !response.Response || response.RCode != dnsmessage.RCodeSuccess || len(response.Answers) == 0 {
			t.Fatal("invalid DNS response through UDP channel")
		}
	}
}
