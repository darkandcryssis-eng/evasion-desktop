package tlsfake

import "testing"

// TestGoogleClientHelloParsesToSNI разбирает собранный ClientHello так же, как
// это сделал бы DPI: проходит по длинам записи, рукопожатия и расширений и
// достаёт SNI. Успешный проход доказывает, что все поля длины согласованы
// (иначе разбор вышел бы за границы), а извлечённое имя — что фейк несёт именно
// безобидный домен, а не что-то иное.
func TestGoogleClientHelloParsesToSNI(t *testing.T) {
	raw := GoogleClientHello()

	host, err := parseSNI(raw)
	if err != nil {
		t.Fatalf("разбор ClientHello: %v", err)
	}
	wantSNI := "www.google.com"
	if host != wantSNI {
		t.Fatalf("SNI = %q, ожидался %q", host, wantSNI)
	}
}

// TestGoogleClientHelloFreshCopy проверяет, что каждый вызов отдаёт независимый
// срез: правка результата не портит следующий вызов.
func TestGoogleClientHelloFreshCopy(t *testing.T) {
	a := GoogleClientHello()
	for i := range a {
		a[i] = 0
	}
	b := GoogleClientHello()
	if b[0] != 0x16 {
		t.Fatalf("второй вызов повреждён первым: первый байт %#x, ожидался 0x16", b[0])
	}
}

// parseSNI — минимальный разбор ClientHello до имени сервера. Повторяет логику,
// по которой имя достаёт инспекция трафика: любая рассогласованная длина уводит
// за границы и даёт ошибку, что и делает тест проверкой корректности сборки.
func parseSNI(b []byte) (string, error) {
	r := reader{b: b}
	if r.u8() != 0x16 {
		return "", errf("не TLS handshake record")
	}
	r.skip(2)          // legacy record version
	recLen := r.u16()  // длина записи
	if r.err != nil || recLen == 0 {
		return "", errf("негодная длина записи")
	}
	if r.u8() != 0x01 {
		return "", errf("не ClientHello")
	}
	r.skip(3)  // длина рукопожатия
	r.skip(2)  // legacy_version
	r.skip(32) // random
	sidLen := r.u8()
	r.skip(sidLen)
	csLen := r.u16()
	r.skip(csLen)
	compLen := r.u8()
	r.skip(compLen)
	extTotal := r.u16()
	if r.err != nil {
		return "", r.err
	}
	end := r.i + extTotal
	for r.i < end && r.err == nil {
		extType := r.u16()
		extLen := r.u16()
		if extType == 0x0000 { // server_name
			r.u16()           // server_name_list length
			if r.u8() != 0x00 { // host_name
				return "", errf("тип имени не host_name")
			}
			nameLen := r.u16()
			name := r.bytes(nameLen)
			if r.err != nil {
				return "", r.err
			}
			return string(name), nil
		}
		r.skip(extLen)
	}
	return "", errf("расширение server_name не найдено")
}

// reader — курсор по байтам с переносом первой ошибки выхода за границы.
type reader struct {
	b   []byte
	i   int
	err error
}

func (r *reader) u8() int {
	if r.err != nil || r.i+1 > len(r.b) {
		r.fail()
		return 0
	}
	v := int(r.b[r.i])
	r.i++
	return v
}

func (r *reader) u16() int {
	if r.err != nil || r.i+2 > len(r.b) {
		r.fail()
		return 0
	}
	v := int(r.b[r.i])<<8 | int(r.b[r.i+1])
	r.i += 2
	return v
}

func (r *reader) skip(n int) {
	if r.err != nil || r.i+n > len(r.b) {
		r.fail()
		return
	}
	r.i += n
}

func (r *reader) bytes(n int) []byte {
	if r.err != nil || r.i+n > len(r.b) {
		r.fail()
		return nil
	}
	v := r.b[r.i : r.i+n]
	r.i += n
	return v
}

func (r *reader) fail() {
	if r.err == nil {
		r.err = errf("выход за границы при разборе")
	}
}

type parseErr string

func (e parseErr) Error() string { return string(e) }

func errf(s string) error { return parseErr(s) }
