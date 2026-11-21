package proxy

import (
	"errors"
	"net"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/tlsparse"
)

// helloResult — что удалось вычленить из начала клиентского потока.
type helloResult struct {
	// buf — все прочитанные из клиента байты. Их в любом случае нужно
	// переслать серверу: либо через стратегию (часть buf), либо как есть.
	buf []byte
	// helloLen — длина записи ClientHello в начале buf. Ноль, если ClientHello
	// не распознан (не TLS, фрагментирован по записям или битый).
	helloLen int
	// sni — имя сервера из ClientHello; пусто, если его нет.
	sni string
	// isHello — распознан ли пригодный ClientHello.
	isHello bool
	// cuts — структурные точки разреза записи. Вычисляются здесь, потому что
	// здесь уже есть разобранное сообщение: повторный разбор в desync стоил бы
	// времени на горячем пути и потребовал бы знания TLS там, где его быть не
	// должно (4.1).
	cuts []core.CutPoint
}

// hello возвращает срез байт записи ClientHello.
func (r helloResult) hello() []byte { return r.buf[:r.helloLen] }

// rest возвращает прочитанные байты за записью ClientHello (начало следующих
// записей, если клиент прислал их тем же куском).
func (r helloResult) rest() []byte { return r.buf[r.helloLen:] }

// readClientHello читает начало клиентского потока, пока не распознает
// ClientHello или не убедится, что это не он.
//
// Различение «данных мало» и «это не ClientHello» — ключевое: в первом случае
// надо дочитать, во втором — прекратить и переслать как есть. Если ClientHello
// не укладывается в предел буфера, он тоже считается нераспознанным (пересылаем
// как есть): это защита от клиента, который шлёт бесконечно, не завершая запись.
//
// Чтение ограничивается дедлайном вызывающего (SetReadDeadline на соединении):
// сам метод таймаут не ставит, чтобы не навязывать политику.
func readClientHello(c net.Conn, limit int) (helloResult, error) {
	var res helloResult
	buf := make([]byte, 0, 1024)
	chunk := make([]byte, 4096)

	for {
		n, err := c.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)

			ch, perr := tlsparse.ParseClientHello(buf)
			switch {
			case perr == nil:
				// Полный ClientHello распознан.
				res.buf = buf
				res.helloLen = ch.Record.End()
				sni, ok := ch.SNI(buf)
				if ok {
					res.sni = string(sni)
				}
				// Ёмкость с запасом на все виды точек, чтобы append не
				// перевыделял: сейчас их шесть.
				res.cuts = ch.CutPointsWithSNI(make([]core.CutPoint, 0, 8), sni)
				res.isHello = true
				return res, nil
			case errors.Is(perr, tlsparse.ErrIncomplete):
				// Структура пока корректна, не хватает байт — дочитываем, если
				// не упёрлись в предел.
				if len(buf) >= limit {
					res.buf = buf
					return res, nil
				}
			default:
				// Не ClientHello (не TLS, фрагментирован по записям, битый):
				// пересылаем прочитанное как есть, стратегию не применяем.
				res.buf = buf
				return res, nil
			}
		}
		if err != nil {
			// Чтение прервано (в том числе EOF). Отдаём, что успели прочитать:
			// вызывающий решит, пересылать ли и как закрыть соединение.
			res.buf = buf
			return res, err
		}
	}
}
