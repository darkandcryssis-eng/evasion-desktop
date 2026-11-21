package proxy

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/fitting-1c/evasion/internal/socketexec"
)

// DialFunc устанавливает соединение с сервером назначения. Вынесен в конфиг,
// чтобы в тестах подставить соединение в памяти и проверять прокси без сети.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Значения по умолчанию для параметров, не заданных в конфиге.
const (
	defaultHelloLimit   = 16 << 10 // предел буфера ClientHello
	defaultHelloTimeout = 10 * time.Second
)

// Config задаёт параметры прокси.
//
// Эти параметры требуют перезапуска (адрес прослушивания, диалер) и потому
// отделены от параметров автопилота, перечитываемых на ходу (10.5).
type Config struct {
	// Provider выбирает стратегию для соединения. Обязателен.
	Provider StrategyProvider
	// Observe включает режим наблюдения: стратегии не применяются, трафик
	// только перекладывается (1.6). Безопасный режим по умолчанию для отладки.
	Observe bool
	// Dial устанавливает соединения с серверами; nil означает обычный
	// сетевой диалер.
	Dial DialFunc
	// Logger — структурированный журнал; nil означает slog.Default.
	Logger *slog.Logger
	// HelloLimit — предел буфера при чтении ClientHello; 0 — значение по
	// умолчанию.
	HelloLimit int
	// HelloTimeout — таймаут на вычленение ClientHello; 0 — значение по
	// умолчанию.
	HelloTimeout time.Duration
	// Outcomes принимает исходы соединений; nil означает, что исходы никому не
	// нужны.
	//
	// nil — законная настройка, а не недосмотр: прокси обязан работать и без
	// контура управления (так он работал весь этап 0 до M6). Но без приёмника
	// автопилот не учится на живом трафике, и это надо помнить.
	Outcomes OutcomeSink
}

// Server — SOCKS5-сервер режима прокси.
type Server struct {
	cfg  Config
	exec socketexec.Executor
	log  *slog.Logger
	dial DialFunc
	wg   sync.WaitGroup
}

// NewServer создаёт сервер по конфигу. Провайдер стратегий обязателен.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Provider == nil {
		return nil, errNoProvider
	}
	if cfg.HelloLimit <= 0 {
		cfg.HelloLimit = defaultHelloLimit
	}
	if cfg.HelloTimeout <= 0 {
		cfg.HelloTimeout = defaultHelloTimeout
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	dial := cfg.Dial
	if dial == nil {
		var d net.Dialer
		dial = d.DialContext
	}
	return &Server{
		cfg:  cfg,
		exec: socketexec.New(),
		log:  logger,
		dial: dial,
	}, nil
}

// Serve принимает соединения на слушателе до отмены контекста.
//
// Слушатель передаётся снаружи, а не создаётся здесь: так вызывающий (CLI или
// тест) контролирует адрес и может узнать фактический порт при привязке к :0.
// По отмене контекста слушатель закрывается, и Serve дожидается завершения уже
// принятых соединений.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	// Закрываем слушатель при отмене, чтобы разблокировать Accept.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			// После отмены Accept вернёт ошибку закрытого слушателя — это
			// штатное завершение, а не сбой.
			if ctx.Err() != nil {
				s.wg.Wait()
				return ctx.Err()
			}
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(ctx, conn)
		}()
	}
}
