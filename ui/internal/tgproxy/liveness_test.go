package tgproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestPayloadKeepsConnectionAliveWhenRelayDoesNotPong(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		// No reader: this relay does not process/respond to Ping.
		for range 20 {
			if c.WriteMessage(websocket.BinaryMessage, []byte("data")) != nil {
				return
			}
			time.Sleep(15 * time.Millisecond)
		}
	}))
	defer server.Close()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	p := newWSPeerWithTiming(c, 100*time.Millisecond, 30*time.Millisecond)
	defer p.Close()
	data, _ := io.ReadAll(p)
	if len(data) != 80 {
		t.Fatalf("active connection was cut off: %d/80 bytes", len(data))
	}
}
