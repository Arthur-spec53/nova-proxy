package e_quic

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

// TestPackUnpackBasic tests basic Pack/Unpack functionality
func TestPackUnpackBasic(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{"Empty Payload", []byte{}},
		{"Small Payload", []byte("Hello, World!")},
		{"Medium Payload", make([]byte, 1024)},
		{"Large Payload", make([]byte, 4096)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate random key
			key := make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				t.Fatal(err)
			}

			// Fill payload with random data if it's not empty
			if len(tt.payload) > 0 {
				if _, err := rand.Read(tt.payload); err != nil {
					t.Fatal(err)
				}
			}

			// Pack the payload
			packed, err := Pack(tt.payload, key)
			if err != nil {
				t.Fatalf("Pack failed: %v", err)
			}

			// Verify packed data structure
			expectedMinSize := kyber768.CiphertextSize + hmacSize + nonceSize
			if len(packed) < expectedMinSize {
				t.Errorf("Packed data too small: got %d, expected at least %d", len(packed), expectedMinSize)
			}

			// Unpack the payload
			unpacked, err := Unpack(packed, key)
			if err != nil {
				t.Fatalf("Unpack failed: %v", err)
			}

			// Verify unpacked data matches original
			if !bytes.Equal(tt.payload, unpacked) {
				t.Errorf("Unpacked data does not match original payload")
				t.Errorf("Original: %x", tt.payload)
				t.Errorf("Unpacked: %x", unpacked)
			}
		})
	}
}

// TestPackUnpackWithWrongKey tests authentication failure
func TestPackUnpackWithWrongKey(t *testing.T) {
	payload := []byte("test payload")
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	// Pack with key1
	packed, err := Pack(payload, key1)
	if err != nil {
		t.Fatalf("Pack failed: %v", err)
	}

	// Try to unpack with key2 (should fail)
	_, err = Unpack(packed, key2)
	if err == nil {
		t.Error("Expected authentication failure but got none")
	}
	if err != ErrInvalidPacket {
		t.Errorf("Expected ErrInvalidPacket, got %v", err)
	}
}

// TestPackUnpackShortPacket tests handling of short packets
func TestPackUnpackShortPacket(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	// Test various short packet sizes
	shortPackets := [][]byte{
		{}, // Empty
		make([]byte, 10),  // Too short
		make([]byte, 100), // Still too short
		make([]byte, kyber768.CiphertextSize), // Missing HMAC and nonce
		make([]byte, kyber768.CiphertextSize+hmacSize), // Missing nonce
	}

	for i, shortPacket := range shortPackets {
		_, err := Unpack(shortPacket, key)
		if err != ErrShortPacket {
			t.Errorf("Test %d: Expected ErrShortPacket, got %v", i, err)
		}
	}
}

// TestPacketStructure tests the exact packet structure
func TestPacketStructure(t *testing.T) {
	payload := []byte("test payload")
	key := make([]byte, 32)
	rand.Read(key)

	packed, err := Pack(payload, key)
	if err != nil {
		t.Fatalf("Pack failed: %v", err)
	}

	// Verify packet structure: [Kyber Ciphertext][HMAC][Nonce][Encrypted Payload]
	kyberSize := kyber768.CiphertextSize
	if len(packed) < kyberSize+hmacSize+nonceSize {
		t.Fatalf("Packet too short: %d", len(packed))
	}

	// Extract components
	ciphertext := packed[:kyberSize]
	hmacTag := packed[kyberSize : kyberSize+hmacSize]
	nonce := packed[kyberSize+hmacSize : kyberSize+hmacSize+nonceSize]
	encryptedPayload := packed[kyberSize+hmacSize+nonceSize:]

	// Verify component sizes
	if len(ciphertext) != kyberSize {
		t.Errorf("Ciphertext size mismatch: got %d, expected %d", len(ciphertext), kyberSize)
	}
	if len(hmacTag) != hmacSize {
		t.Errorf("HMAC size mismatch: got %d, expected %d", len(hmacTag), hmacSize)
	}
	if len(nonce) != nonceSize {
		t.Errorf("Nonce size mismatch: got %d, expected %d", len(nonce), nonceSize)
	}

	// Verify encrypted payload is not empty and different from original
	if len(encryptedPayload) == 0 {
		t.Error("Encrypted payload is empty")
	}
	if bytes.Equal(payload, encryptedPayload) {
		t.Error("Encrypted payload should not match original payload")
	}

	t.Logf("Packet structure verified:")
	t.Logf("  Total size: %d bytes", len(packed))
	t.Logf("  Kyber ciphertext: %d bytes", len(ciphertext))
	t.Logf("  HMAC: %d bytes", len(hmacTag))
	t.Logf("  Nonce: %d bytes", len(nonce))
	t.Logf("  Encrypted payload: %d bytes", len(encryptedPayload))
}

// TestRandomnessAndUniqueness tests that each Pack operation produces unique output
func TestRandomnessAndUniqueness(t *testing.T) {
	payload := []byte("same payload")
	key := make([]byte, 32)
	rand.Read(key)

	numTests := 10
	packedResults := make([][]byte, numTests)

	// Pack the same payload multiple times
	for i := 0; i < numTests; i++ {
		packed, err := Pack(payload, key)
		if err != nil {
			t.Fatalf("Pack %d failed: %v", i, err)
		}
		packedResults[i] = packed
	}

	// Verify all results are different (due to random nonce)
	for i := 0; i < numTests; i++ {
		for j := i + 1; j < numTests; j++ {
			if bytes.Equal(packedResults[i], packedResults[j]) {
				t.Errorf("Pack results %d and %d are identical (should be different due to random nonce)", i, j)
			}
		}
	}

	// Verify all can be unpacked correctly
	for i, packed := range packedResults {
		unpacked, err := Unpack(packed, key)
		if err != nil {
			t.Errorf("Unpack %d failed: %v", i, err)
			continue
		}
		if !bytes.Equal(payload, unpacked) {
			t.Errorf("Unpack %d result does not match original", i)
		}
	}
}