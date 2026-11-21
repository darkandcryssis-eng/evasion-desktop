package packet

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// md5PacketV4 собирает валидный IPv4/TCP-пакет с 20-байтным заголовком TCP
// (без опций) и заданной нагрузкой. Суммы пересчитывает.
func md5PacketV4(t *testing.T, payload []byte) []byte {
	t.Helper()
	buf := make([]byte, 20+20+len(payload))
	buf[0] = 0x45
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))
	buf[8] = 64
	buf[9] = 6 // TCP
	copy(buf[12:16], net.ParseIP("10.0.0.1").To4())
	copy(buf[16:20], net.ParseIP("93.184.216.34").To4())
	binary.BigEndian.PutUint16(buf[20:22], 50000)
	binary.BigEndian.PutUint16(buf[22:24], 443)
	binary.BigEndian.PutUint32(buf[24:28], 1000)
	buf[32] = 0x50 // смещение данных 5 слов (20 байт)
	buf[33] = 0x18 // PSH|ACK
	binary.BigEndian.PutUint16(buf[34:36], 65535)
	copy(buf[40:], payload)
	d, err := Dissect(buf)
	if err != nil {
		t.Fatalf("разбор тестового пакета: %v", err)
	}
	if !d.RecomputeChecksums(buf) {
		t.Fatalf("пересчёт сумм тестового пакета не удался")
	}
	return buf
}

func TestMD5SignatureOption(t *testing.T) {
	var digest [16]byte
	for i := range digest {
		digest[i] = byte(i)
	}
	opt := MD5SignatureOption(digest)
	if len(opt) != 18 {
		t.Fatalf("длина опции %d, ожидалось 18", len(opt))
	}
	if opt[0] != TCPOptMD5 {
		t.Errorf("вид опции 0x%02x, ожидался 19", opt[0])
	}
	if opt[1] != 18 {
		t.Errorf("длина в опции %d, ожидалось 18", opt[1])
	}
	if !bytes.Equal(opt[2:], digest[:]) {
		t.Errorf("дайджест в опции %x, ожидался %x", opt[2:], digest[:])
	}
}

func TestInsertTCPOptionMD5V4(t *testing.T) {
	payload := []byte{0x16, 0x03, 0x01, 0xAA, 0xBB, 0xCC, 0xDD}
	buf := md5PacketV4(t, payload)
	orig := append([]byte(nil), buf...)

	d, err := Dissect(buf)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}

	var digest [16]byte
	for i := range digest {
		digest[i] = 0xA5
	}
	out, d2, err := d.InsertTCPOption(buf, MD5SignatureOption(digest))
	if err != nil {
		t.Fatalf("InsertTCPOption: %v", err)
	}

	// Исходный буфер не изменён.
	if !bytes.Equal(buf, orig) {
		t.Errorf("исходный буфер изменён вставкой")
	}

	// 18 байт опции + 2 NOP выравнивания = +20.
	if len(out) != len(buf)+20 {
		t.Fatalf("длина пакета %d, ожидалось %d", len(out), len(buf)+20)
	}

	th, ok := d2.TCP(out)
	if !ok {
		t.Fatal("собранный пакет не TCP")
	}
	// Заголовок TCP вырос с 20 до 40 байт (смещение данных 10 слов).
	if th.HeaderLen() != 40 {
		t.Errorf("длина заголовка TCP %d, ожидалось 40", th.HeaderLen())
	}
	// Общая длина IPv4 обновлена.
	ih, ok := d2.IPv4(out)
	if !ok || int(ih.TotalLen()) != len(out) {
		t.Errorf("total len %d, ожидалось %d", ih.TotalLen(), len(out))
	}
	// Нагрузка не тронута и не сдвинута по содержимому.
	p2, ok := d2.Payload(out)
	if !ok || !bytes.Equal(p2, payload) {
		t.Errorf("нагрузка после вставки %x, ожидалось %x", p2, payload)
	}
	// Опция MD5 присутствует и парсится: вид 19, значение ровно дайджест.
	var found bool
	for o := range th.Options() {
		if o.Kind == TCPOptMD5 {
			found = true
			if len(o.Value) != 16 || !bytes.Equal(o.Value, digest[:]) {
				t.Errorf("значение опции %x, ожидался дайджест %x", o.Value, digest[:])
			}
		}
	}
	if !found {
		t.Error("опция MD5 не найдена в собранном пакете")
	}
	// Область опций валидна и суммы сходятся.
	if err := th.ValidateOptions(); err != nil {
		t.Errorf("опции невалидны: %v", err)
	}
	if !d2.RecomputeChecksums(out) {
		t.Fatal("пересчёт сумм не удался")
	}
	if !d2.VerifyChecksums(out) {
		t.Error("суммы собранного пакета неверны")
	}
}

func TestInsertTCPOptionMD5V6(t *testing.T) {
	payload := []byte{0x16, 0x03, 0x01, 0x11, 0x22}
	// IPv6/TCP вручную: 40 байт заголовка IPv6 + 20 TCP + нагрузка.
	buf := make([]byte, 40+20+len(payload))
	buf[0] = 0x60 // версия 6
	binary.BigEndian.PutUint16(buf[4:6], uint16(20+len(payload)))
	buf[6] = 6  // next header = TCP
	buf[7] = 64 // hop limit
	copy(buf[8:24], net.ParseIP("2001:db8::1").To16())
	copy(buf[24:40], net.ParseIP("2001:db8::2").To16())
	binary.BigEndian.PutUint16(buf[40:42], 50000)
	binary.BigEndian.PutUint16(buf[42:44], 443)
	binary.BigEndian.PutUint32(buf[44:48], 1000)
	buf[52] = 0x50
	buf[53] = 0x18
	binary.BigEndian.PutUint16(buf[54:56], 65535)
	copy(buf[60:], payload)

	d, err := Dissect(buf)
	if err != nil {
		t.Fatalf("разбор IPv6: %v", err)
	}
	if !d.RecomputeChecksums(buf) {
		t.Fatalf("пересчёт сумм IPv6 не удался")
	}

	var digest [16]byte
	out, d2, err := d.InsertTCPOption(buf, MD5SignatureOption(digest))
	if err != nil {
		t.Fatalf("InsertTCPOption v6: %v", err)
	}
	if len(out) != len(buf)+20 {
		t.Fatalf("длина пакета %d, ожидалось %d", len(out), len(buf)+20)
	}
	// Длина нагрузки IPv6 обновлена: всё после 40-байтного заголовка.
	ih, ok := d2.IPv6(out)
	if !ok || int(ih.PayloadLen()) != len(out)-40 {
		t.Errorf("payload len %d, ожидалось %d", ih.PayloadLen(), len(out)-40)
	}
	p2, ok := d2.Payload(out)
	if !ok || !bytes.Equal(p2, payload) {
		t.Errorf("нагрузка v6 %x, ожидалось %x", p2, payload)
	}
	if !d2.RecomputeChecksums(out) || !d2.VerifyChecksums(out) {
		t.Error("суммы IPv6-пакета неверны")
	}
}

func TestInsertTCPOptionExceedsHeaderLimit(t *testing.T) {
	buf := md5PacketV4(t, []byte{0x16, 0x03})
	d, _ := Dissect(buf)
	// 44 байта опции + заголовок 20 = 64 > 60 (предел смещения данных).
	big := make([]byte, 44)
	big[0], big[1] = TCPOptMD5, 44
	if _, _, err := d.InsertTCPOption(buf, big); err == nil {
		t.Error("ожидалась ошибка превышения предела смещения данных")
	}
}

func TestInsertTCPOptionNonTCP(t *testing.T) {
	// UDP-пакет: вставка опции TCP неприменима.
	buf := make([]byte, 20+8+4)
	buf[0] = 0x45
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))
	buf[8] = 64
	buf[9] = 17 // UDP
	copy(buf[12:16], net.ParseIP("10.0.0.1").To4())
	copy(buf[16:20], net.ParseIP("10.0.0.2").To4())
	binary.BigEndian.PutUint16(buf[24:26], uint16(8+4)) // длина UDP
	d, err := Dissect(buf)
	if err != nil {
		t.Fatalf("разбор UDP: %v", err)
	}
	if _, _, err := d.InsertTCPOption(buf, MD5SignatureOption([16]byte{})); err == nil {
		t.Error("ожидалась ошибка: вставка опции TCP не в TCP-пакет")
	}
}
