package windivert

import "testing"

func TestScopeFilter(t *testing.T) {
	t.Cleanup(func() { SetExcludedInterface(0) })
	if got := scopeFilter("outbound and tcp"); got != "outbound and tcp" {
		t.Fatalf("без исключения фильтр изменён: %q", got)
	}
	SetExcludedInterface(30)
	if got := scopeFilter("outbound and tcp or udp"); got != "(outbound and tcp or udp) and ifIdx != 30" {
		t.Fatalf("фильтр с исключением: %q", got)
	}
	if got := scopeFilter("false"); got != "false" {
		t.Fatalf("фильтр-заглушка изменён: %q", got)
	}
}
