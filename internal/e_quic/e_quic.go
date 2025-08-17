package e_quic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"golang.org/x/crypto/sha3"
)

const (
	// Use HMAC-SHA256 for integrity.
	hmacSize = 32
	// Use AES-GCM, which requires a nonce.
	nonceSize = 12
)

var (
	ErrInvalidPacket = errors.New("invalid e-quic packet: authentication failed")
	ErrShortPacket   = errors.New("e-quic packet is too short")
)

// Pack encapsulates a QUIC payload into an E-QUIC packet with post-quantum security.
// The key should be 32 bytes for AES-256.
// Packet format: [Kyber Ciphertext][HMAC (32 bytes)][Nonce (12 bytes)][Encrypted Payload]
func Pack(payload []byte, key []byte) ([]byte, error) {
	// Derive 64-byte seed from key using Shake256
	seed := make([]byte, 64) // Hardcode to match KeySeedSize = 64
	h := sha3.NewShake256()
	h.Write(key)
	h.Read(seed)
	pk, _ := kyber768.NewKeyFromSeed(seed)

	// Encapsulate shared secret
	ct := make([]byte, kyber768.CiphertextSize)
	sharedSecret := make([]byte, kyber768.SharedKeySize)
	pk.EncapsulateTo(ct, sharedSecret, nil)
	ciphertext := ct

	// Derive AES key from shared secret and preshared key
	derivedKey := deriveKey(sharedSecret, key)

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 1. Create nonce
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// 2. Encrypt payload
	encryptedPayload := gcm.Seal(nil, nonce, payload, nil)

	// 3. Create packet (Nonce + Encrypted Payload)
	packet := append(nonce, encryptedPayload...)

	// 4. Calculate HMAC for the packet
	mac := hmac.New(sha256.New, key)
	mac.Write(ciphertext)
	mac.Write(packet)
	hmacTag := mac.Sum(nil)
	// HMAC generated successfully

	// 5. Prepend HMAC to the final packet
	// Prepend Kyber ciphertext and HMAC to the final packet
	packetWithHmac := append(hmacTag, packet...)
	finalPacket := append(ciphertext, packetWithHmac...)

	return finalPacket, nil
}

// Unpack extracts the QUIC payload from an E-QUIC packet with post-quantum security.
func Unpack(packet []byte, key []byte) ([]byte, error) {
	// Validate packet length

	// Derive 64-byte seed from key using Shake256
	seed := make([]byte, 64) // Hardcode to match KeySeedSize = 64
	h := sha3.NewShake256()
	h.Write(key)
	h.Read(seed)
	_, sk := kyber768.NewKeyFromSeed(seed)

	kyberSize := kyber768.CiphertextSize
	if len(packet) < kyberSize + hmacSize + nonceSize {
		return nil, ErrShortPacket
	}

	// Extract Kyber ciphertext
	ciphertext := packet[:kyberSize]
	data := packet[kyberSize:]

	// Extract HMAC tag
	hmacTag := data[:hmacSize]
	packetData := data[hmacSize:]

	// Extract packet components

	// Verify HMAC
	mac := hmac.New(sha256.New, key)
	mac.Write(ciphertext)
	mac.Write(packetData)
	expectedHMAC := mac.Sum(nil)
	if !hmac.Equal(expectedHMAC, hmacTag) {
		// HMAC verification failed
		return nil, ErrInvalidPacket
	}

	// Decapsulate shared secret
	sharedSecret := make([]byte, kyber768.SharedKeySize)
	sk.DecapsulateTo(sharedSecret, ciphertext)

	// Derive AES key from shared secret and preshared key
	derivedKey := deriveKey(sharedSecret, key)

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := packetData[:nonceSize]
	encryptedPayload := packetData[nonceSize:]

	payload, err := gcm.Open(nil, nonce, encryptedPayload, nil)
	if err != nil {
		return nil, err // Decryption failed
	}

	return payload, nil
}

// deriveKey derives a key from shared secret and preshared key using HKDF.
func deriveKey(sharedSecret, presharedKey []byte) []byte {
	hkdf := hmac.New(sha256.New, presharedKey)
	hkdf.Write(sharedSecret)
	return hkdf.Sum(nil)[:32] // AES-256 key
}
