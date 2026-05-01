package internal

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// KeySize размер ключа ChaCha20-Poly1305 (32 байта).
	KeySize = chacha20poly1305.KeySize
	// NonceSize размер nonce ChaCha20-Poly1305 (12 байт).
	NonceSize = chacha20poly1305.NonceSize
	// AEADOverhead размер дополнительных данных AEAD (nonce + tag).
	AEADOverhead = NonceSize + 16
)

// Crypto обеспечивает AEAD-шифрование пакетов с помощью ChaCha20-Poly1305.
type Crypto struct {
	aead cipher.AEAD
}

// NewCrypto создаёт Crypto с заданным 32-байтным ключом.
func NewCrypto(key []byte) (*Crypto, error) {
	if len(key) != KeySize {
		return nil, errors.New("invalid key size")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &Crypto{aead: aead}, nil
}

// Encrypt шифрует plaintext и возвращает буфер вида nonce|ciphertext|tag.
func (c *Crypto) Encrypt(plaintext []byte) ([]byte, error) {
	dst := make([]byte, NonceSize, NonceSize+len(plaintext)+c.aead.Overhead())
	if _, err := io.ReadFull(rand.Reader, dst); err != nil {
		return nil, err
	}
	return c.aead.Seal(dst, dst[:NonceSize], plaintext, nil), nil
}

// Decrypt расшифровывает буфер вида nonce|ciphertext|tag и возвращает plaintext.
func (c *Crypto) Decrypt(packet []byte) ([]byte, error) {
	if len(packet) < AEADOverhead {
		return nil, errors.New("ciphertext too short")
	}
	return c.aead.Open(nil, packet[:NonceSize], packet[NonceSize:], nil)
}
