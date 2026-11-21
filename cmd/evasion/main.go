// Команда evasion — консольная поверхность управления движком (2.3).
//
// Это единственный способ работы с движком на этапе 0: машинно-читаемый вывод по
// флагу --json служит контрактом для будущего интерфейса (2.2), который движок
// не содержит. Человекочитаемый вывод — отдельная ветка форматирования и на
// структуры --json не влияет.
//
// Команды добавляются вместе с пакетами, которые их обслуживают: заглушка,
// возвращающая пустоту, нарушила бы критерий готовности (8.4). Поэтому здесь
// пока только то, что уже работает на этапе 0.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// usage — краткая справка по доступным командам. Выводится при запуске без
// команды или с неизвестной командой.
const usage = `Evasion — движок обхода DPI (этап 0, режим прокси)

Использование:
  evasion run [флаги]        запустить контур управления режима прокси
  evasion status [флаги]     состояние работающего движка
  evasion portfolio [флаги]  стратегии портфеля с их ступенями
  evasion doctor [флаги]     проверка окружения: почему не работает (5.9)
  evasion cleanup [флаги]    откат всех системных изменений (hosts, firewall)
  evasion events [флаги]     поток событий жизненного цикла (events.jsonl)
  evasion blockcheck <host>  перебор портфеля стратегий по одной цели (2.3)
  evasion search [флаги]     генетический поиск стратегий в песочнице (5.6)
  evasion hosts <sub>        управление hosts: apply|clean|status (транспорт A)
  evasion warp <sub>         регистрация в Cloudflare WARP (Phase 2 туннеля)
  evasion tunnel <sub>       WireGuard-туннель к WARP (Phase 2.2): ping
  evasion discord-proxy     локальный резервный HTTPS-прокси только для Discord
  evasion youtube-proxy     локальный HTTPS-прокси YouTube с direct/VLESS-маршрутом

Для справки по команде: evasion <команда> -h
`

// main разбирает имя команды и передаёт управление её обработчику. Код возврата
// ненулевой при ошибке, чтобы запускающий скрипт мог её заметить.
func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	// Контекст отменяется по SIGINT/SIGTERM: даёт командам (прежде всего run)
	// корректно завершиться, закрыв соединения, а не обрываться на полуслове.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "game-profile":
		err = gameProfileCommand(ctx, args)
	case "youtube-probe":
		err = youtubeProbeCommand(ctx, args)
	case "youtube-tune":
		err = youtubeTuneCommand(ctx, args)
	case "youtube-profile":
		err = youtubeProfileCommand(ctx, args)
	case "run":
		err = runCommand(ctx, args)
	case "status":
		err = statusCommand(ctx, args)
	case "portfolio":
		err = portfolioCommand(ctx, args)
	case "doctor":
		err = doctorCommand(ctx, args)
	case "cleanup":
		err = cleanupCommand(ctx, args)
	case "events":
		err = eventsCommand(ctx, args)
	case "blockcheck":
		err = blockcheckCommand(ctx, args)
	case "search":
		err = searchCommand(ctx, args)
	case "hosts":
		err = hostsCommand(ctx, args)
	case "warp":
		err = warpCommand(ctx, args)
	case "tunnel":
		err = tunnelCommand(ctx, args)
	case "discord-proxy":
		err = discordProxyCommand(ctx, args)
	case "youtube-proxy":
		err = youtubeProxyCommand(ctx, args)
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "неизвестная команда %q\n\n%s", cmd, usage)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "evasion %s: %v\n", cmd, err)
		os.Exit(1)
	}
}
