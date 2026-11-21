package intercept

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/fitting-1c/evasion/internal/tlsparse"
)

func TestDetectorPreservesRecordsCoalescedWithClientHello(t *testing.T) {
	full, _ := buildFullHello(t, "www.youtube.com", 20)
	for _, tail := range [][]byte{{20, 3, 3, 0, 1, 1}, {23, 3, 3, 0, 3, 1, 2, 3}} {
		input := append(append([]byte{}, full...), tail...)
		got, complete, isTLS := TLSHelloDetector(input)
		if !complete || !isTLS || !bytes.Equal(got, input) {
			t.Fatal("trailing TLS record dropped")
		}
	}
}

// buildHello собирает минимальный ClientHello с заданным именем сервера поверх
// записи TLS. extraLen > 0 раздувает объявленные длины записи и сообщения
// рукопожатия, НЕ добавляя байт: так получается точная модель первого сегмента
// многосегментного ClientHello — заголовки обещают больше, чем пришло, а
// server_name уже целиком на месте.
func buildHello(t testing.TB, name string, extraLen int) []byte {
	t.Helper()

	// Расширение server_name.
	entry := []byte{0 /*host_name*/}
	entry = binary.BigEndian.AppendUint16(entry, uint16(len(name)))
	entry = append(entry, name...)
	sniData := binary.BigEndian.AppendUint16(nil, uint16(len(entry)))
	sniData = append(sniData, entry...)
	ext := binary.BigEndian.AppendUint16(nil, 0 /*extServerName*/)
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(sniData)))
	ext = append(ext, sniData...)

	// Тело ClientHello.
	body := binary.BigEndian.AppendUint16(nil, 0x0303) // legacy_version
	body = append(body, make([]byte, 32)...)           // random
	body = append(body, 0)                             // session_id: пусто
	body = binary.BigEndian.AppendUint16(body, 2)      // cipher_suites len
	body = append(body, 0x13, 0x01)
	body = append(body, 1, 0) // compression_methods
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)

	// Заголовок сообщения рукопожатия (тип + 3 байта длины).
	msgLen := len(body) + extraLen
	hs := []byte{1 /*client_hello*/, byte(msgLen >> 16), byte(msgLen >> 8), byte(msgLen)}
	hs = append(hs, body...)

	// Заголовок записи TLS (тип + версия + 2 байта длины).
	recLen := len(hs) + extraLen
	rec := []byte{22 /*handshake*/, 0x03, 0x01, byte(recLen >> 8), byte(recLen)}
	rec = append(rec, hs...)
	return rec
}

// TestDetectorCompleteHello — целый ClientHello распознаётся как завершённый.
func TestDetectorCompleteHello(t *testing.T) {
	pkt := buildHello(t, "example.com", 0)
	hello, complete, isTLS := TLSHelloDetector(pkt)
	if !isTLS || !complete {
		t.Fatalf("целый ClientHello: isTLS=%v complete=%v", isTLS, complete)
	}
	if len(hello) == 0 {
		t.Fatal("ожидались байты hello")
	}
}

// TestDetectorFirstSegmentWithSNI — первый сегмент большого ClientHello, где
// server_name уже целиком, теперь считается применимым (complete=true): это и
// есть починка многосегментного случая.
func TestDetectorFirstSegmentWithSNI(t *testing.T) {
	pkt := buildHello(t, "video.googlevideo.example", 2000)
	hello, complete, isTLS := TLSHelloDetector(pkt)
	if !isTLS {
		t.Fatal("первый сегмент ClientHello должен распознаваться как TLS")
	}
	if !complete {
		t.Fatal("первый сегмент с целым server_name должен быть применим для десинка")
	}
	if len(hello) != len(pkt) {
		t.Fatalf("hello должен быть всем сегментом: получено %d из %d", len(hello), len(pkt))
	}

	sni, cuts, ok := TLSHelloParser(hello)
	if !ok {
		t.Fatal("разбор первого сегмента не удался")
	}
	if sni != "video.googlevideo.example" {
		t.Fatalf("SNI = %q", sni)
	}
	if len(cuts) == 0 {
		t.Fatal("ожидались точки разреза")
	}
}

// TestDetectorFirstSegmentBeforeSNI — если сегмент обрезан до server_name,
// имени не видно: десинк не применяется (complete=false), но это всё ещё TLS.
func TestDetectorFirstSegmentBeforeSNI(t *testing.T) {
	full := buildHello(t, "example.com", 2000)
	// Обрезаем так, чтобы server_name заведомо не поместился: оставляем только
	// заголовок записи и начало тела рукопожатия.
	seg := full[:10]
	_, complete, isTLS := TLSHelloDetector(seg)
	if !isTLS {
		t.Fatal("обрывок рукопожатия должен распознаваться как TLS")
	}
	if complete {
		t.Fatal("без видимого server_name десинк применять нельзя")
	}
}

// TestDetectorNotTLS — не-TLS нагрузка отвергается.
func TestDetectorNotTLS(t *testing.T) {
	_, _, isTLS := TLSHelloDetector([]byte("GET / HTTP/1.1\r\n\r\n"))
	if isTLS {
		t.Fatal("HTTP-запрос не должен считаться TLS")
	}
}

// tlsRecord оборачивает payload в заголовок записи TLS handshake.
func tlsRecord(payload []byte) []byte {
	r := []byte{22 /*handshake*/, 0x03, 0x01, byte(len(payload) >> 8), byte(len(payload))}
	return append(r, payload...)
}

// buildFragmentedHello собирает ClientHello, РУКОПОЖАТИЕ которого растянуто на
// две записи TLS (как крупный post-quantum ClientHello Chrome). server_name
// кладётся первым расширением (→ целиком в первой записи), следом — padding,
// по которому и проходит граница записей. Это точная модель полевого случая
// `не_tls`: строгий разбор вернёт ErrFragmentedHandshake, а server_name уже
// виден нестрого.
func buildFragmentedHello(t testing.TB, name string, pad int) []byte {
	t.Helper()

	// server_name.
	entry := []byte{0 /*host_name*/}
	entry = binary.BigEndian.AppendUint16(entry, uint16(len(name)))
	entry = append(entry, name...)
	sniData := binary.BigEndian.AppendUint16(nil, uint16(len(entry)))
	sniData = append(sniData, entry...)
	sniExt := binary.BigEndian.AppendUint16(nil, 0 /*server_name*/)
	sniExt = binary.BigEndian.AppendUint16(sniExt, uint16(len(sniData)))
	sniExt = append(sniExt, sniData...)

	// padding (type 21) — хвост после имени; по нему пройдёт граница записей.
	padExt := binary.BigEndian.AppendUint16(nil, 21 /*padding*/)
	padExt = binary.BigEndian.AppendUint16(padExt, uint16(pad))
	padExt = append(padExt, make([]byte, pad)...)

	exts := append(append([]byte{}, sniExt...), padExt...)

	body := binary.BigEndian.AppendUint16(nil, 0x0303)
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // session_id: пусто
	body = binary.BigEndian.AppendUint16(body, 2)
	body = append(body, 0x13, 0x01) // cipher_suites
	body = append(body, 1, 0)       // compression_methods
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)

	hs := []byte{1 /*client_hello*/, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	// Режем поток рукопожатия на две записи где-то в середине padding: имя уже
	// позади, объявленная msgLen (всё тело) больше первой записи → строгий
	// разбор увидит ErrFragmentedHandshake.
	split := len(hs) - pad/2
	return append(tlsRecord(hs[:split]), tlsRecord(hs[split:])...)
}

// buildHelloBadLaterExt собирает ClientHello, у которого server_name — первое
// расширение (видно нестрого), а СЛЕДУЮЩЕЕ расширение объявляет длину больше,
// чем есть данных. Строгий разбор доходит до плохого расширения и отдаёт
// ErrMalformed (жёсткая ошибка, НЕ неполнота), а нестрогий успевает вернуть
// SNI раньше. Модель редкого/нестандартного расширения после имени.
func buildHelloBadLaterExt(t testing.TB, name string) []byte {
	t.Helper()

	entry := []byte{0 /*host_name*/}
	entry = binary.BigEndian.AppendUint16(entry, uint16(len(name)))
	entry = append(entry, name...)
	sniData := binary.BigEndian.AppendUint16(nil, uint16(len(entry)))
	sniData = append(sniData, entry...)
	sniExt := binary.BigEndian.AppendUint16(nil, 0 /*server_name*/)
	sniExt = binary.BigEndian.AppendUint16(sniExt, uint16(len(sniData)))
	sniExt = append(sniExt, sniData...)

	// Плохое расширение после имени: объявленная длина много больше данных.
	badExt := binary.BigEndian.AppendUint16(nil, 0x0017)
	badExt = binary.BigEndian.AppendUint16(badExt, 0xFFFF)
	badExt = append(badExt, 0x00, 0x00)

	exts := append(append([]byte{}, sniExt...), badExt...)

	body := binary.BigEndian.AppendUint16(nil, 0x0303)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = binary.BigEndian.AppendUint16(body, 2)
	body = append(body, 0x13, 0x01)
	body = append(body, 1, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)

	hs := []byte{1 /*client_hello*/, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{22 /*handshake*/, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

// TestDetectorStrictFailsAfterSNIStillApplies — строгий разбор спотыкается на
// поле ПОСЛЕ server_name (жёсткая ошибка, не неполнота), но имя уже видно
// нестрого → десинк обязан примениться, а не уронить поток в «не TLS». Это и
// добивает остаток пропусков `не_tls` на крупных/нестандартных ClientHello.
func TestDetectorStrictFailsAfterSNIStillApplies(t *testing.T) {
	const name = "cdn.discordapp.example"
	pkt := buildHelloBadLaterExt(t, name)

	_, err := tlsparse.ParseClientHello(pkt)
	if err == nil || errors.Is(err, tlsparse.ErrIncomplete) || errors.Is(err, tlsparse.ErrFragmentedHandshake) {
		t.Fatalf("ожидалась жёсткая ошибка строгого разбора (не неполнота), получено %v", err)
	}

	hello, complete, isTLS := TLSHelloDetector(pkt)
	if !isTLS || !complete {
		t.Fatalf("имя видно нестрого → сегмент должен быть применим: isTLS=%v complete=%v", isTLS, complete)
	}
	sni, cuts, ok := TLSHelloParser(hello)
	if !ok || sni != name {
		t.Fatalf("SNI из hello с плохим поздним расширением: ok=%v sni=%q", ok, sni)
	}
	if len(cuts) == 0 {
		t.Fatal("ожидались точки разреза внутри имени")
	}
}

// TestDetectorGarbageStillNotTLS — мусор, в котором нет корректной структуры
// server_name, нестрогий разбор НЕ принимает: детектор по-прежнему честно
// отвечает «не TLS» (обобщение на любую ошибку не даёт ложных десинков).
func TestDetectorGarbageStillNotTLS(t *testing.T) {
	// Запись TLS handshake по заголовку, но тело — мусор без ClientHello.
	junk := []byte{22, 0x03, 0x01, 0x00, 0x06, 0x02, 0x00, 0x00, 0x02, 0xaa, 0xbb}
	_, complete, isTLS := TLSHelloDetector(junk)
	if isTLS || complete {
		t.Fatalf("мусор без server_name не должен применяться: isTLS=%v complete=%v", isTLS, complete)
	}
}

// TestDetectorFragmentedHandshakeAppliesViaSNI — регрессия на пропуски `не_tls`
// в поле. ClientHello с рукопожатием на две записи строгий разбор отвергает
// (ErrFragmentedHandshake), но server_name виден в первой записи, поэтому
// детектор обязан признать сегмент применимым (complete=true), а не уронить
// сборку в «не TLS». До правки такой hello уходил сырым → утечка SNI → RST
// картинок cdn.discordapp.com.
func TestDetectorFragmentedHandshakeAppliesViaSNI(t *testing.T) {
	const name = "cdn.discordapp.example"
	frag := buildFragmentedHello(t, name, 200)

	// Документируем механизм: строгий разбор именно фрагментирован.
	if _, err := tlsparse.ParseClientHello(frag); !errors.Is(err, tlsparse.ErrFragmentedHandshake) {
		t.Fatalf("ожидалась ErrFragmentedHandshake, получено %v", err)
	}

	hello, complete, isTLS := TLSHelloDetector(frag)
	if !isTLS || !complete {
		t.Fatalf("фрагментированное рукопожатие с видимым SNI должно быть применимо: isTLS=%v complete=%v", isTLS, complete)
	}
	sni, cuts, ok := TLSHelloParser(hello)
	if !ok || sni != name {
		t.Fatalf("SNI из фрагментированного hello: ok=%v sni=%q", ok, sni)
	}
	if len(cuts) == 0 {
		t.Fatal("ожидались точки разреза внутри имени")
	}
}
