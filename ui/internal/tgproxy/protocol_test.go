package tgproxy

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"
)

type vector struct {
	Protocol     byte
	Secret       string
	ClientInit   string `json:"client_init"`
	Plain        string
	ClientCipher string `json:"client_cipher"`
	ClientReply  string `json:"client_reply"`
	RelayInit    string `json:"relay_init"`
	RelayCipher  string `json:"relay_cipher"`
	RelayReply   string `json:"relay_reply"`
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func vectors(t *testing.T) []vector {
	t.Helper()
	b, err := os.ReadFile("testdata/protocol.json")
	if err != nil {
		t.Fatal(err)
	}
	var v []vector
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

type deterministicReader struct{}

func (deterministicReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = byte(i + 1)
	}
	return len(b), nil
}

func TestPythonInteroperabilityVectors(t *testing.T) {
	for _, v := range vectors(t) {
		t.Run(hex.EncodeToString([]byte{v.Protocol}), func(t *testing.T) {
			h, err := readHandshake(bytes.NewReader(unhex(t, v.ClientInit)), unhex(t, v.Secret))
			if err != nil {
				t.Fatal(err)
			}
			if h.dc != 2 || !h.media || h.protocol != v.Protocol {
				t.Fatal("incorrect authenticated DC or protocol")
			}
			plain := unhex(t, v.Plain)
			decoded := make([]byte, len(plain))
			h.decrypt.XORKeyStream(decoded, unhex(t, v.ClientCipher))
			if !bytes.Equal(decoded, plain) {
				t.Fatal("client cipher stream offset differs from Python")
			}
			encoded := make([]byte, len(plain))
			h.encrypt.XORKeyStream(encoded, plain)
			if !bytes.Equal(encoded, unhex(t, v.ClientReply)) {
				t.Fatal("client reply cipher differs from Python")
			}
			init, enc, dec, err := relayHandshakeFrom(h, deterministicReader{})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(init, unhex(t, v.RelayInit)) {
				t.Fatal("relay handshake differs from Python")
			}
			enc.XORKeyStream(encoded, plain)
			if !bytes.Equal(encoded, unhex(t, v.RelayCipher)) {
				t.Fatal("relay stream offset differs from Python")
			}
			dec.XORKeyStream(decoded, unhex(t, v.RelayReply))
			if !bytes.Equal(decoded, plain) {
				t.Fatal("relay reply decrypt differs from Python")
			}
		})
	}
}

func TestFramingQuickAckAndLimits(t *testing.T) {
	for _, v := range vectors(t) {
		frame := unhex(t, v.Plain)
		frame[0] |= 0x80
		if v.Protocol != 0xef {
			binary.LittleEndian.PutUint32(frame, 16|0x80000000)
		}
		header, size, err := readPacketHeader(bytes.NewReader(frame), v.Protocol)
		if err != nil || size != 16 || int(size)+len(header) != len(frame) {
			t.Fatalf("quick ack frame: %v %d", err, size)
		}
	}
	for _, test := range []struct {
		protocol byte
		data     []byte
	}{{0xef, []byte{0}}, {0xee, []byte{0, 0, 0, 0}}, {0xdd, []byte{0xff, 0xff, 0xff, 0x7f}}, {0xee, []byte{1, 2}}, {0xef, []byte{0x7f, 1}}} {
		if _, _, err := readPacketHeader(bytes.NewReader(test.data), test.protocol); err == nil {
			t.Fatal("accepted malformed or oversized packet")
		}
	}
}

func TestHandshakeRejectsWrongSecretAndShortInput(t *testing.T) {
	v := vectors(t)[0]
	bad := make([]byte, 16)
	if _, err := readHandshake(bytes.NewReader(unhex(t, v.ClientInit)), bad); err == nil {
		t.Fatal("wrong secret accepted")
	}
	if _, err := readHandshake(bytes.NewReader([]byte{1, 2}), unhex(t, v.Secret)); err != io.ErrUnexpectedEOF {
		t.Fatalf("short init: %v", err)
	}
	if _, err := readHandshake(bytes.NewReader(unhex(t, v.ClientInit)), bad[:1]); err == nil {
		t.Fatal("short secret accepted")
	}
}
