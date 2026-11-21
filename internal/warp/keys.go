package warp

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// Keypair — пара ключей WireGuard (Curve25519 / X25519).
//
// Приватный ключ владеет клиент (мы), публичный ключ отдаётся серверу WARP при
// регистрации. Сервер при каждом хендшейке проверяет, что клиент владеет
// соответствующим приватным. Для Cloudflare WARP ключи те же, что у обычного
// WireGuard: 32 байта каждый.
type Keypair struct {
	// Private — приватный ключ, base64 (стандартный WireGuard-формат).
	Private string
	// Public — публичный ключ, base64.
	Public string
}

// GenerateKeypair создаёт новую пару ключей.
//
// Используется стандартный пакет `crypto/ecdh`: он даёт X25519 без внешних
// зависимостей. Это сознательно — у проекта правило «внешние зависимости по
// минимуму, без CGO» (3.1), и `golang.org/x/crypto/curve25519` можно обойти.
//
// Ключи сразу кодируются в base64 — так они и попадают в WireGuard-конфиг и
// в API Cloudflare, других форматов нам не нужно. Хранить сырые байты смысла
// нет: при любой операции они снова кодируются.
func GenerateKeypair() (*Keypair, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("warp: генерация X25519-ключа: %w", err)
	}
	return &Keypair{
		Private: base64.StdEncoding.EncodeToString(priv.Bytes()),
		Public:  base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()),
	}, nil
}

// ParseKeypair разбирает ключи из их base64-формы.
//
// Нужен, когда account загружается из файла и мы восстанавливаем состояние.
// Валидация жёсткая: длина 32 байта, base64 стандартный (не URL-safe —
// WireGuard требует именно его). Негодный ключ — явная ошибка, а не молчаливое
// принятие: туннель с битым ключом даст непонятное «peer не отвечает» вместо
// внятного «ключ сломан» на старте.
func ParseKeypair(privB64, pubB64 string) (*Keypair, error) {
	if _, err := decodeKey(privB64); err != nil {
		return nil, fmt.Errorf("warp: приватный ключ: %w", err)
	}
	if _, err := decodeKey(pubB64); err != nil {
		return nil, fmt.Errorf("warp: публичный ключ: %w", err)
	}
	return &Keypair{Private: privB64, Public: pubB64}, nil
}

// keyLen — длина ключа WireGuard в байтах. Это Curve25519-константа, не наша
// настройка.
const keyLen = 32

// decodeKey разбирает base64 и проверяет длину ключа.
func decodeKey(b64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("негодный base64: %w", err)
	}
	if len(raw) != keyLen {
		return nil, fmt.Errorf("длина %d байт, ожидалось %d", len(raw), keyLen)
	}
	return raw, nil
}
