// Package tgproxy implements Telegram's obfuscated MTProto transport over WSS.
// Interoperability reference: Telegram MTProto transports and Flowseal/tg-ws-proxy.
package tgproxy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

const maxPacket = 16 << 20

type handshake struct {
	dc       int
	media    bool
	protocol byte
	decrypt  cipher.Stream
	encrypt  cipher.Stream
}

func ctr(key, iv []byte) cipher.Stream {
	block, _ := aes.NewCipher(key)
	return cipher.NewCTR(block, iv)
}

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}

func readHandshake(r io.Reader, secret []byte) (handshake, error) {
	var h handshake
	if len(secret) != 16 {
		return h, errors.New("secret must be 16 bytes")
	}
	init := make([]byte, 64)
	if _, err := io.ReadFull(r, init); err != nil {
		return h, err
	}
	key := sha256.Sum256(append(append([]byte(nil), init[8:40]...), secret...))
	h.decrypt = ctr(key[:], init[40:56])
	plain := make([]byte, 64)
	h.decrypt.XORKeyStream(plain, init)
	h.protocol = plain[56]
	if h.protocol != 0xef && h.protocol != 0xee && h.protocol != 0xdd {
		return h, errors.New("invalid MTProto secret or protocol")
	}
	for _, b := range plain[56:60] {
		if b != h.protocol {
			return h, errors.New("invalid MTProto protocol")
		}
	}
	dc := int(int16(binary.LittleEndian.Uint16(plain[60:62])))
	h.media = dc < 0
	if dc < 0 {
		dc = -dc
	}
	if _, ok := dcIPs[dc]; !ok {
		return h, errors.New("unsupported Telegram data center")
	}
	h.dc = dc
	reversed := reverse(init[8:56])
	key = sha256.Sum256(append(append([]byte(nil), reversed[:32]...), secret...))
	h.encrypt = ctr(key[:], reversed[32:])
	return h, nil
}

func relayHandshake(h handshake) ([]byte, cipher.Stream, cipher.Stream, error) {
	return relayHandshakeFrom(h, rand.Reader)
}

func relayHandshakeFrom(h handshake, source io.Reader) ([]byte, cipher.Stream, cipher.Stream, error) {
	init := make([]byte, 64)
	for {
		if _, err := io.ReadFull(source, init); err != nil {
			return nil, nil, nil, err
		}
		prefix := string(init[:4])
		if init[0] == 0xef || prefix == "HEAD" || prefix == "POST" || prefix == "GET " || prefix == "OPTI" || prefix == "\xee\xee\xee\xee" || prefix == "\xdd\xdd\xdd\xdd" || prefix == "\x16\x03\x01\x02" || binary.LittleEndian.Uint32(init[4:8]) == 0 {
			continue
		}
		break
	}
	for i := 56; i < 60; i++ {
		init[i] = h.protocol
	}
	dc := h.dc
	if h.media {
		dc = -dc
	}
	binary.LittleEndian.PutUint16(init[60:62], uint16(int16(dc)))
	if _, err := io.ReadFull(source, init[62:64]); err != nil {
		return nil, nil, nil, err
	}
	enc := ctr(init[8:40], init[40:56])
	reversed := reverse(init[8:56])
	dec := ctr(reversed[:32], reversed[32:])
	encrypted := make([]byte, 64)
	enc.XORKeyStream(encrypted, init)
	copy(init[56:], encrypted[56:])
	return init, enc, dec, nil
}

func readPacketHeader(r io.Reader, protocol byte) ([]byte, int64, error) {
	header := make([]byte, 4)
	n := 4
	var size uint32
	if protocol == 0xef {
		if _, err := io.ReadFull(r, header[:1]); err != nil {
			return nil, 0, err
		}
		if header[0]&0x7f == 0x7f {
			if _, err := io.ReadFull(r, header[1:]); err != nil {
				return nil, 0, err
			}
			size = uint32(header[1]) | uint32(header[2])<<8 | uint32(header[3])<<16
		} else {
			size = uint32(header[0] & 0x7f)
			n = 1
		}
		size *= 4
	} else if protocol == 0xee || protocol == 0xdd {
		if _, err := io.ReadFull(r, header); err != nil {
			return nil, 0, err
		}
		size = binary.LittleEndian.Uint32(header) & 0x7fffffff
	} else {
		return nil, 0, errors.New("unsupported MTProto framing")
	}
	if size == 0 || size > maxPacket {
		return nil, 0, errors.New("invalid MTProto packet size")
	}
	return header[:n], int64(size), nil
}
