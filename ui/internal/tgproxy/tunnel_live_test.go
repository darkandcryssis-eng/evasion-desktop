package tgproxy

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestLiveTelegramSOCKS(t *testing.T) {
	endpoint := os.Getenv("EVASION_TELEGRAM_SOCKS")
	dial := SOCKSDialer(endpoint)
	if connect := os.Getenv("EVASION_TELEGRAM_CONNECT"); connect != "" {
		endpoint = connect
		dial = CONNECTDialer(endpoint)
	}
	if endpoint == "" {
		t.Skip("set EVASION_TELEGRAM_SOCKS or EVASION_TELEGRAM_CONNECT for a public Telegram tunnel check")
	}
	for _, dc := range []int{2, 4} {
		candidate := tunnelRoute(dc, false)
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		started := time.Now()
		conn, err := dial(ctx, candidate)
		if err == nil {
			err = probePeer(ctx, conn, candidate)
			_ = conn.Close()
		}
		cancel()
		if err != nil {
			t.Fatalf("DC%d: %v", dc, err)
		}
		t.Logf("Verified Telegram resPQ through configured tunnel to DC%d in %v", dc, time.Since(started).Round(time.Millisecond))
	}
}
