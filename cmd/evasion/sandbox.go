package main

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/sandbox"
)

// Пробер песочницы: как мерить кандидата живым соединением. Тонкий и
// проверяемый без сети — оркестровка (кого и когда мерить) живёт выше.

// curlProber — живой пробер песочницы: внешний curl с закреплённым локальным
// портом. Реализует sandbox.Prober.
//
// Внешним процессом, а не рукопожатием внутри процесса движка: измерено, что
// внутрипроцессная проба не получает десинк так, как внешнее соединение (см.
// probeOnce). Закрепление порта (--local-port) и есть то, чем проба песочницы
// отличается от обычной: по этому порту контур перехвата песочницы выбирает
// проверяемого кандидата (5.2).
type curlProber struct {
	timeout time.Duration
}

// sandboxProbeTimeout — таймаут пробы песочницы. Короче, чем у blockcheck (8 с):
// успешное рукопожатие даже с десинком укладывается в секунду-две, а провалы и
// заблокированная базовая линия висят ровно до таймаута и съедают время
// прогрева. Укорачивание ускоряет набор порога (5.5), не задевая успехи.
// Выводить его из измеренного базового RTT (5.3) — отдельное уточнение.
const sandboxProbeTimeout = 5 * time.Second

// Probe делает одну пробу к target с локального порта localPort и переводит
// результат curl в градуированный исход (5.3, быстрый уровень).
//
// Различаем три состояния, а не два: код есть и не "000" — рукопожатие прошло
// (ok); код "000" — curl отработал, но соединение сорвано (fail); вывода нет —
// пробу не удалось снять вовсе (inconclusive, вес 0), и наказывать за это
// стратегию нельзя (тот же принцип, что у «не измерили» в blockcheck).
func (c curlProber) Probe(ctx context.Context, target string, localPort uint16) core.Outcome {
	// Небольшой запас сверх curl --max-time, чтобы контекст не убивал curl
	// раньше его собственного таймаута.
	cctx, cancel := context.WithTimeout(ctx, c.timeout+2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cctx, "curl", curlArgs(target, localPort, c.timeout)...)
	// На сбросе соединения curl печатает "000" в stdout и завершается ненулевым
	// кодом: ошибку игнорируем, решает именно напечатанный код.
	out, _ := cmd.Output()

	switch code := strings.TrimSpace(string(out)); {
	case code == "":
		return core.OutcomeInconclusive
	case code == "000":
		return core.OutcomeFail
	default:
		return core.OutcomeOK
	}
}

// curlArgs собирает аргументы curl для пробы. Вынесено отдельной функцией, чтобы
// проверить состав команды (в частности закрепление порта) без запуска curl.
func curlArgs(target string, localPort uint16, timeout time.Duration) []string {
	secs := int(timeout.Seconds())
	if secs < 1 {
		secs = 1
	}
	return []string{
		"-s", "-o", os.DevNull, "-w", "%{http_code}",
		"--max-time", strconv.Itoa(secs),
		// --local-port закрепляет исходный порт: по нему контур перехвата
		// песочницы находит проверяемого кандидата. curl с одним числом берёт
		// ровно этот порт.
		"--local-port", strconv.Itoa(int(localPort)),
		"https://" + target,
	}
}

// статическая проверка соответствия интерфейсу пробера пакета sandbox.
var _ sandbox.Prober = curlProber{}
