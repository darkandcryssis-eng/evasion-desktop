package main

import (
	"slices"
	"testing"
	"time"
)

func TestCurlArgsPinsLocalPort(t *testing.T) {
	args := curlArgs("youtube.com", 40007, 8*time.Second)

	// Закрепление порта — главное, чем проба песочницы отличается от обычной.
	i := slices.Index(args, "--local-port")
	if i < 0 || i+1 >= len(args) {
		t.Fatalf("нет --local-port в аргументах: %v", args)
	}
	if args[i+1] != "40007" {
		t.Fatalf("локальный порт не закреплён верно: %q", args[i+1])
	}
	// Цель — последним аргументом, по https.
	if got := args[len(args)-1]; got != "https://youtube.com" {
		t.Fatalf("цель собрана неверно: %q", got)
	}
	// Таймаут передан в секундах.
	ti := slices.Index(args, "--max-time")
	if ti < 0 || args[ti+1] != "8" {
		t.Fatalf("таймаут не передан верно: %v", args)
	}
}

func TestCurlArgsTimeoutFloorsToOneSecond(t *testing.T) {
	// Таймаут меньше секунды округляется до 1: curl --max-time в секундах, и 0
	// означал бы «без ограничения».
	args := curlArgs("example.com", 40000, 100*time.Millisecond)
	ti := slices.Index(args, "--max-time")
	if ti < 0 || args[ti+1] != "1" {
		t.Fatalf("дробный таймаут не округлён до 1 секунды: %v", args)
	}
}

func TestSandboxCoveragePerGroup(t *testing.T) {
	groups := map[string][]string{
		"video":   {"youtube.com", "googlevideo.com", "ytimg.com"},
		"discord": {"discord.com", "discord.gg", "discordapp.com"},
	}
	radius := []string{"youtube.com", "googlevideo.com", "ytimg.com", "discord.com", "discord.gg", "discordapp.com"}
	probes := []string{"www.youtube.com", "discord.com"}

	reps, coverage := sandboxCoverage(groups, radius, probes)

	if len(reps) != 2 {
		t.Fatalf("представителей %d, ожидалось 2: %v", len(reps), reps)
	}
	// Представитель video — youtube.com (в него попадает www.youtube.com).
	vid, ok := coverage["youtube.com"]
	if !ok || len(vid) != 3 {
		t.Fatalf("покрытие youtube.com = %v, ожидались 3 домена группы video", vid)
	}
	dis, ok := coverage["discord.com"]
	if !ok || len(dis) != 3 {
		t.Fatalf("покрытие discord.com = %v, ожидались 3 домена группы discord", dis)
	}
}

func TestSandboxCoverageSkipsGroupWithoutProbe(t *testing.T) {
	groups := map[string][]string{
		"video": {"youtube.com", "googlevideo.com"},
		"misc":  {"example.org"}, // probe_target в неё не попадает
	}
	radius := []string{"youtube.com", "googlevideo.com", "example.org"}
	probes := []string{"www.youtube.com"}

	reps, coverage := sandboxCoverage(groups, radius, probes)

	if len(reps) != 1 || reps[0] != "youtube.com" {
		t.Fatalf("ожидался один представитель youtube.com, получено %v", reps)
	}
	if _, ok := coverage["example.org"]; ok {
		t.Fatal("группа без probe_target не должна покрываться: её нечем проверить")
	}
}
