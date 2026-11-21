package main

import (
	"io"
	"log/slog"
	"testing"
	"time"
)

// newTestChurn — детектор с управляемыми часами и тихим логом для тестов.
func newTestChurn(now *time.Time) *voiceChurn {
	c := newVoiceChurn(slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.now = func() time.Time { return *now }
	return c
}

const voiceSNI = "c-arn08-da88e905.discord.media"

// TestChurnBlocksAfterThreshold — порог переподключений к одному голосовому
// серверу за окно помечает его обходимым.
func TestChurnBlocksAfterThreshold(t *testing.T) {
	now := time.Unix(0, 0)
	c := newTestChurn(&now)

	// До порога — не обходим.
	for i := 0; i < voiceChurnThreshold-1; i++ {
		c.Observe(voiceSNI)
		now = now.Add(time.Second)
	}
	if c.Contains(voiceSNI) {
		t.Fatalf("до порога (%d) сервер не должен обходиться", voiceChurnThreshold)
	}
	// Порог достигнут — обходим.
	c.Observe(voiceSNI)
	if !c.Contains(voiceSNI) {
		t.Fatal("на пороге переподключений сервер должен стать обходимым")
	}
}

// TestChurnNonVoiceNeverBlocked — не-голосовые имена (CDN/gateway) не
// обходятся НИКОГДА, сколько бы ClientHello ни пришло. Это защита радиуса:
// пропуск CDN сырьём означал бы утечку SNI и обрыв картинок.
func TestChurnNonVoiceNeverBlocked(t *testing.T) {
	now := time.Unix(0, 0)
	c := newTestChurn(&now)

	for _, name := range []string{"cdn.discordapp.com", "media.discordapp.net", "gateway.discord.gg"} {
		for i := 0; i < voiceChurnThreshold+5; i++ {
			c.Observe(name)
			now = now.Add(time.Second)
		}
		if c.Contains(name) {
			t.Fatalf("не-голосовое имя %q не должно обходиться ни при каком числе ClientHello", name)
		}
	}
}

// TestChurnWindowExpiry — редкие переподключения (реже порога за окно) не
// копятся: вышедшие за окно наблюдения отбрасываются.
func TestChurnWindowExpiry(t *testing.T) {
	now := time.Unix(0, 0)
	c := newTestChurn(&now)

	// По одному ClientHello раз в полокна: в окне всегда < threshold.
	step := voiceChurnWindow/2 + time.Second
	for i := 0; i < 5; i++ {
		c.Observe(voiceSNI)
		if c.Contains(voiceSNI) {
			t.Fatalf("на шаге %d редкие переподключения не должны давать обход", i)
		}
		now = now.Add(step)
	}
}

// TestChurnTTLExpires — после срабатывания обход держится TTL и затем снимается
// сам (сервер получает честную попытку заново, не вечный бан).
func TestChurnTTLExpires(t *testing.T) {
	now := time.Unix(0, 0)
	c := newTestChurn(&now)

	for i := 0; i < voiceChurnThreshold; i++ {
		c.Observe(voiceSNI)
		now = now.Add(time.Second)
	}
	if !c.Contains(voiceSNI) {
		t.Fatal("после порога ожидался обход")
	}
	// Перематываем за TTL — обход снимается.
	now = now.Add(voiceChurnTTL + time.Second)
	if c.Contains(voiceSNI) {
		t.Fatal("после истечения TTL обход должен сниматься")
	}
}

// TestAnyBlocklistUnion — объединение блок-листов: SNI заблокирован, если его
// блокирует любой источник; nil-источники безопасны.
func TestAnyBlocklistUnion(t *testing.T) {
	now := time.Unix(0, 0)
	c := newTestChurn(&now)
	for i := 0; i < voiceChurnThreshold; i++ {
		c.Observe(voiceSNI)
	}
	rtc := &rtcBlocklist{}
	union := anyBlocklist{nil, rtc, c}

	if !union.Contains(voiceSNI) {
		t.Fatal("union должен блокировать SNI, помеченный churn-детектором")
	}
	if union.Contains("example.com") {
		t.Fatal("union не должен блокировать то, что не блокирует ни один источник")
	}
}

// TestChurnParallelStreamsNotBlocked — голос, своя демонстрация экрана и два
// просматриваемых стрима идут на один сервер отдельными соединениями; это не
// цикл переподключений.
func TestChurnParallelStreamsNotBlocked(t *testing.T) {
	now := time.Unix(0, 0)
	c := newTestChurn(&now)
	for i := 0; i < 4; i++ {
		c.Observe(voiceSNI)
		now = now.Add(5 * time.Second)
	}
	if c.Contains(voiceSNI) {
		t.Fatal("параллельные соединения голоса и демонстрации не должны давать обход")
	}
}

// TestChurnBlockNotExtendedByRetries — попытки во время обхода срок не
// продлевают, а после него счёт идёт с нуля.
func TestChurnBlockNotExtendedByRetries(t *testing.T) {
	now := time.Unix(0, 0)
	c := newTestChurn(&now)
	for i := 0; i < voiceChurnThreshold; i++ {
		c.Observe(voiceSNI)
	}
	for i := 0; i < 20; i++ {
		now = now.Add(voiceChurnTTL / 20)
		c.Observe(voiceSNI)
	}
	now = now.Add(time.Second)
	if c.Contains(voiceSNI) {
		t.Fatal("повторные попытки не должны продлевать обход")
	}
	c.Observe(voiceSNI)
	if c.Contains(voiceSNI) {
		t.Fatal("после обхода первая попытка должна идти с десинком")
	}
}
