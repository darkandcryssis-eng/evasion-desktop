package config

import "testing"

func TestOptionalYouTubeQUICDoesNotChangeGlobalMode(t *testing.T) {
	for _, mode := range []string{"off", "desync", "block"} {
		c, err := parse([]byte(`{"quic_mode":"desync","youtube_quic_mode":"` + mode + `"}`))
		if err != nil || c.YouTubeQUICMode == nil || string(*c.YouTubeQUICMode) != mode || c.QUICMode != QUICDesync {
			t.Fatalf("%s: %+v %v", mode, c, err)
		}
	}
	c, err := parse([]byte(`{"quic_mode":"block"}`))
	if err != nil || c.YouTubeQUICMode != nil || c.QUICMode != QUICBlock {
		t.Fatal("legacy mode changed")
	}
	if _, err := parse([]byte(`{"youtube_quic_mode":"invalid"}`)); err == nil {
		t.Fatal("invalid mode accepted")
	}
}
