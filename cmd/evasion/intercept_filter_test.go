package main

import (
	"strings"
	"testing"
)

func TestInterceptFilterSkipsPureACKs(t *testing.T) {
	if !strings.Contains(interceptFilter, interceptSegments) {
		t.Fatalf("interceptFilter must only lift segments with payload or lifecycle flags: %q", interceptFilter)
	}
	for _, flag := range []string{"tcp.PayloadLength > 0", "tcp.Syn", "tcp.Fin", "tcp.Rst"} {
		if !strings.Contains(interceptSegments, flag) {
			t.Fatalf("interceptSegments lacks %q", flag)
		}
	}
	if !strings.HasSuffix(interceptFilter, "and not impostor") {
		t.Fatalf("interceptFilter must exclude own injections: %q", interceptFilter)
	}
}

func TestInterceptFilterRedirectKeepsEveryOutboundSegment(t *testing.T) {
	if strings.Contains(interceptFilterRedirect, interceptSegments) {
		t.Fatalf("rtc redirect rewrites every outbound segment; ACKs must stay in the filter: %q", interceptFilterRedirect)
	}
	if !strings.Contains(interceptFilterRedirect, "inbound and tcp and tcp.SrcPort == 8443") {
		t.Fatalf("redirect filter lost inbound restore: %q", interceptFilterRedirect)
	}
}
