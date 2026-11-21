package warp

import (
	"encoding/json"
	"fmt"
	"net/netip"
)

// Account — зарегистрированное у Cloudflare WARP устройство.
//
// Это всё, что движку нужно, чтобы поднять WireGuard-туннель и обновлять
// учётку при необходимости. Структура — наш формат (не прямой зеркало ответа
// API): лишние поля из ответа Cloudflare не сохраняются, иначе при изменении
// их схемы наш файл состояния пришлось бы мигрировать.
type Account struct {
	// Keypair — пара ключей WireGuard, которую мы сгенерировали при
	// регистрации. Приватный лежит здесь же; файл состояния обязан быть с
	// правами 0600 (это забота вызывающего при записи).
	Keypair Keypair `json:"keypair"`

	// DeviceID — идентификатор устройства в WARP (возвращается API). Нужен
	// для последующих API-вызовов (апгрейд, перегенерация ключей).
	DeviceID string `json:"device_id"`
	// Token — bearer-токен для авторизации тех же вызовов. Хранится здесь.
	Token string `json:"token"`

	// IPv4, IPv6 — адреса, выданные нам Cloudflare в WARP-сети. Используются
	// как InterfaceAddresses в WireGuard-конфиге.
	IPv4 netip.Addr `json:"ipv4"`
	IPv6 netip.Addr `json:"ipv6"`

	// PeerPublicKey — публичный ключ Cloudflare WARP, с которым peer-ится
	// наш туннель. Константа на уровне Cloudflare, но получаем из ответа API,
	// а не захардкоживаем — ключ в теории может ротироваться.
	PeerPublicKey string `json:"peer_public_key"`
	// PeerEndpoint — хост:порт endpoint-а WARP (`engage.cloudflareclient.com:2408`
	// или прямой IP с портом). Берём из ответа API, у Cloudflare может
	// отличаться по регионам.
	PeerEndpoint string `json:"peer_endpoint"`
}

// Validate проверяет, что все обязательные поля на месте. Нужен при загрузке
// из файла: битый или обрезанный файл состояния не должен молча порождать
// туннель, который «не поднимается по непонятной причине».
func (a *Account) Validate() error {
	if a == nil {
		return fmt.Errorf("warp: account == nil")
	}
	if _, err := ParseKeypair(a.Keypair.Private, a.Keypair.Public); err != nil {
		return err
	}
	if a.DeviceID == "" {
		return fmt.Errorf("warp: device_id пуст")
	}
	if a.Token == "" {
		return fmt.Errorf("warp: token пуст")
	}
	if !a.IPv4.IsValid() {
		return fmt.Errorf("warp: ipv4 не разобран")
	}
	if !a.IPv6.IsValid() {
		return fmt.Errorf("warp: ipv6 не разобран")
	}
	if _, err := decodeKey(a.PeerPublicKey); err != nil {
		return fmt.Errorf("warp: peer_public_key: %w", err)
	}
	if a.PeerEndpoint == "" {
		return fmt.Errorf("warp: peer_endpoint пуст")
	}
	return nil
}

// Marshal сериализует account в JSON. Отдельная функция, чтобы вызывающий
// (команда CLI) не задумывался о форматировании и об экранировании.
func (a *Account) Marshal() ([]byte, error) {
	return json.MarshalIndent(a, "", "  ")
}

// UnmarshalAccount разбирает account из JSON. Строгий — неизвестные поля
// отвергаются, иначе опечатка в сохранённом файле (или ручная правка) молча
// превратится в «ключа нет».
func UnmarshalAccount(data []byte) (*Account, error) {
	var a Account
	dec := json.NewDecoder(newBytesReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return nil, fmt.Errorf("warp: разбор account: %w", err)
	}
	if err := a.Validate(); err != nil {
		return nil, err
	}
	return &a, nil
}

// newBytesReader — микрообёртка над bytes.NewReader с явной типизацией; выделена,
// чтобы в UnmarshalAccount не тащить bytes в сигнатуре. Пустая строка — не
// валидный JSON, Decode отдаст ясную ошибку.
func newBytesReader(b []byte) *bytesReader {
	return &bytesReader{b: b}
}

type bytesReader struct {
	b   []byte
	pos int
}

func (r *bytesReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.b) {
		return 0, errEOF
	}
	n := copy(p, r.b[r.pos:])
	r.pos += n
	return n, nil
}

// errEOF — io.EOF без импорта io. Пакет и так небольшой, минимизируем
// зависимости в самом файле ради читаемости.
var errEOF = fmt.Errorf("EOF")

// Это сработает: json.NewDecoder принимает io.Reader, errEOF отдаёт пустое
// чтение; стандартный Decode при пустом вводе отдаст json.UnmarshalEOF — это
// именно то, что мы хотим.
