// Общий запуск библиотеки прогонов.
//
// Запускает каждый прогон как отдельный процесс и собирает итоги. Отдельными
// процессами, а не вызовами функций, намеренно: прогон правит исходники,
// поднимает движок, останавливает службы — такой код не должен делить
// состояние с соседом. Упавший прогон при этом не уносит с собой остальные.
//
// Порядок прогонов задан списком, а не обходом каталога: обход отдал бы их в
// алфавитном порядке, а длинные прогоны разумнее держать в конце — быстрый
// отказ полезнее аккуратного алфавита.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

// runs — прогоны в порядке запуска. Имя совпадает с именем папки.
var runs = []string{
	// Сначала то, что ничего не требует от сети: дефект в самом движке
	// выгоднее найти до измерений.
	"tests-can-fail-under-mutation",
	// Затем сквозные прогоны: им нужен настоящий трафик.
	"proxy-applies-strategy-end-to-end",
	"archive-persists-observations",
	"probes-earn-evidence-without-user-traffic",
	// Проверка инструмента измерения и само измерение — в конце: они зависят
	// от средств перехвата и от того, что на машине вообще происходит.
	"interception-tools-stopped-and-restored",
	"targets-measured-without-interference",
}

func main() {
	fmt.Println("=== библиотека прогонов Evasion ===")
	fmt.Printf("прогонов: %d\n\n", len(runs))

	type outcome struct {
		name string
		ok   bool
		took time.Duration
	}
	var results []outcome

	for _, name := range runs {
		fmt.Printf("--- %s ---\n", name)
		start := time.Now()

		cmd := exec.Command("go", "run", "./tests/"+name)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err := cmd.Run()

		took := time.Since(start)
		results = append(results, outcome{name: name, ok: err == nil, took: took})
		fmt.Println()
	}

	fmt.Println("=== итог ===")
	failed := 0
	for _, r := range results {
		mark := "пройден"
		if !r.ok {
			mark = "НЕ ПРОЙДЕН"
			failed++
		}
		fmt.Printf("  %-42s %s (%v)\n", r.name, mark, r.took.Round(time.Millisecond))
	}

	if failed > 0 {
		fmt.Printf("\nне пройдено прогонов: %d из %d\n", failed, len(results))
		os.Exit(1)
	}
	var total time.Duration
	for _, r := range results {
		total += r.took
	}
	fmt.Printf("\nвсе прогоны пройдены: %d за %v\n", len(results), total.Round(time.Millisecond))
}
