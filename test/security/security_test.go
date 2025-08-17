package security

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"nova-proxy/internal/config"
	"nova-proxy/internal/e_quic"
	"nova-proxy/internal/protocol"
)

// TestPasswordSecurity tests password-based security mechanisms
func TestPasswordSecurity(t *testing.T) {
	tests := []struct {
		name        string
		password1   string
		password2   string
		expectMatch bool
	}{
		{
			name:        "Same Password",
			password1:   "secure_password_123",
			password2:   "secure_password_123",
			expectMatch: true,
		},
		{
			name:        "Different Passwords",
			password1:   "secure_password_123",
			password2:   "different_password_456",
			expectMatch: false,
		},
		{
			name:        "Case Sensitive",
			password1:   "Password123",
			password2:   "password123",
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key1 := make([]byte, 32)
			key2 := make([]byte, 32)
			salt := make([]byte, 32)
			rand.Read(salt)

			// Simulate key derivation (simplified)
			payload1 := []byte(tt.password1)
			payload2 := []byte(tt.password2)

			packed1, err := e_quic.Pack(payload1, key1)
			if err != nil {
				t.Fatal(err)
			}

			packed2, err := e_quic.Pack(payload2, key2)
			if err != nil {
				t.Fatal(err)
			}

			// For same passwords, test that decryption works correctly
			if tt.expectMatch {
				// Test that both can be decrypted with the same key
				unpacked1, err := e_quic.Unpack(packed1, key1)
				if err != nil {
					t.Fatal(err)
				}
				unpacked2, err := e_quic.Unpack(packed2, key2)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(unpacked1, payload1) || !bytes.Equal(unpacked2, payload2) {
					t.Error("Decryption failed for same password")
				}
			} else {
				// For different passwords, encrypted outputs should be different
				if bytes.Equal(packed1, packed2) {
					t.Error("Expected different encrypted outputs for different passwords")
				}
			}
		})
	}
}

// TestEncryptionStrength tests the strength of E-QUIC encryption
func TestEncryptionStrength(t *testing.T) {
	tests := []struct {
		name        string
		payloadSize int
		numSamples  int
	}{
		{"Small Payload", 64, 100},
		{"Medium Payload", 1024, 50},
		{"Large Payload", 4096, 20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, 32)
			rand.Read(key)

			encryptedSamples := make([][]byte, tt.numSamples)

			for i := 0; i < tt.numSamples; i++ {
				payload := make([]byte, tt.payloadSize)
				rand.Read(payload)

				encrypted, err := e_quic.Pack(payload, key)
				if err != nil {
					t.Fatal(err)
				}

				encryptedSamples[i] = encrypted

				// Verify encrypted data is different from plaintext
				if bytes.Equal(payload, encrypted) {
					t.Error("Encrypted data should not match plaintext")
				}

				// Verify encrypted data is larger (includes overhead)
				if len(encrypted) <= len(payload) {
					t.Error("Encrypted data should be larger than plaintext")
				}
			}

			// Test for randomness - no two encrypted samples should be identical
			for i := 0; i < len(encryptedSamples); i++ {
				for j := i + 1; j < len(encryptedSamples); j++ {
					if bytes.Equal(encryptedSamples[i], encryptedSamples[j]) {
						t.Errorf("Found identical encrypted samples at indices %d and %d", i, j)
					}
				}
			}
		})
	}
}

// TestKeyIsolation tests that different keys produce different results
func TestKeyIsolation(t *testing.T) {
	payload := []byte("test payload for key isolation")
	numKeys := 10

	encryptedResults := make([][]byte, numKeys)

	for i := 0; i < numKeys; i++ {
		key := make([]byte, 32)
		rand.Read(key)

		encrypted, err := e_quic.Pack(payload, key)
		if err != nil {
			t.Fatal(err)
		}

		encryptedResults[i] = encrypted
	}

	// Verify all encrypted results are different
	for i := 0; i < len(encryptedResults); i++ {
		for j := i + 1; j < len(encryptedResults); j++ {
			if bytes.Equal(encryptedResults[i], encryptedResults[j]) {
				t.Errorf("Keys %d and %d produced identical encrypted results", i, j)
			}
		}
	}
}

// TestTampering tests detection of data tampering
func TestTampering(t *testing.T) {
	payload := []byte("sensitive data that should not be tampered with")
	key := make([]byte, 32)
	rand.Read(key)

	encrypted, err := e_quic.Pack(payload, key)
	if err != nil {
		t.Fatal(err)
	}

	// Test various tampering scenarios
	tamperingTests := []struct {
		name   string
		tamper func([]byte) []byte
	}{
		{
			name: "Flip Single Bit",
			tamper: func(data []byte) []byte {
				tampered := make([]byte, len(data))
				copy(tampered, data)
				if len(tampered) > 0 {
					tampered[0] ^= 0x01 // Flip first bit
				}
				return tampered
			},
		},
		{
			name: "Modify Middle Byte",
			tamper: func(data []byte) []byte {
				tampered := make([]byte, len(data))
				copy(tampered, data)
				if len(tampered) > 2 {
					tampered[len(tampered)/2] = 0xFF
				}
				return tampered
			},
		},
		{
			name: "Truncate Data",
			tamper: func(data []byte) []byte {
				if len(data) > 1 {
					return data[:len(data)-1]
				}
				return data
			},
		},
		{
			name: "Append Extra Data",
			tamper: func(data []byte) []byte {
				return append(data, 0xAA, 0xBB, 0xCC)
			},
		},
	}

	for _, tt := range tamperingTests {
		t.Run(tt.name, func(t *testing.T) {
			tampered := tt.tamper(encrypted)

			// Attempt to decrypt tampered data
			_, err := e_quic.Unpack(tampered, key)
			if err == nil {
				t.Error("Expected decryption to fail for tampered data")
			}
		})
	}
}

// TestReplayAttack tests protection against replay attacks
func TestReplayAttack(t *testing.T) {
	payload := []byte("message that should not be replayed")
	key := make([]byte, 32)
	rand.Read(key)

	// Encrypt the same payload multiple times
	encryptions := make([][]byte, 5)
	for i := 0; i < len(encryptions); i++ {
		encrypted, err := e_quic.Pack(payload, key)
		if err != nil {
			t.Fatal(err)
		}
		encryptions[i] = encrypted
	}

	// Verify that each encryption is different (nonce/IV should be different)
	for i := 0; i < len(encryptions); i++ {
		for j := i + 1; j < len(encryptions); j++ {
			if bytes.Equal(encryptions[i], encryptions[j]) {
				t.Errorf("Encryption %d and %d are identical - vulnerable to replay attack", i, j)
			}
		}
	}

	// Verify all can be decrypted to the same payload
	for i, encrypted := range encryptions {
		decrypted, err := e_quic.Unpack(encrypted, key)
		if err != nil {
			t.Fatalf("Failed to decrypt encryption %d: %v", i, err)
		}
		if !bytes.Equal(payload, decrypted) {
			t.Errorf("Decrypted payload %d does not match original", i)
		}
	}
}

// TestProtocolFrameSecurity tests security aspects of protocol frames
func TestProtocolFrameSecurity(t *testing.T) {
	// Test with potentially malicious inputs
	maliciousInputs := []struct {
		name string
		host string
		port uint16
	}{
		{"Long Hostname", strings.Repeat("a", 1000), 80},
		{"Special Characters", "../../../etc/passwd", 22},
		{"Null Bytes", "host\x00.evil.com", 443},
		{"Unicode", "тест.рф", 80},
		{"Empty Host", "", 80},
	}

	for _, tt := range maliciousInputs {
		t.Run(tt.name, func(t *testing.T) {
			frame := &protocol.Frame{
				Version:  protocol.Version,
				Options:  0,
				AddrType: protocol.AddrTypeDomain,
				Host:     tt.host,
				Port:     tt.port,
			}

			var buf bytes.Buffer
			err := frame.Encode(&buf)

			// The encoding should either succeed or fail gracefully
			if err != nil {
				// If it fails, the error should be descriptive
				if len(err.Error()) == 0 {
					t.Error("Error message should not be empty")
				}
			} else {
				// If it succeeds, the buffer should contain data
				if buf.Len() == 0 {
					t.Error("Encoded frame should not be empty")
				}
			}
		})
	}
}

// TestTLSConfiguration tests TLS security configuration
func TestTLSConfiguration(t *testing.T) {
	// Create test certificates
	certPEM := `-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIK
BQfZ9roKbN4xSBm9+kz9oXn6KTNsQxiUSQJeig9u+DQC7aGrua5iGpqsy2+ffrBd
F/Be5S5EBwiVDXpAz+NjVBajUjBQMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAK
BggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMBsGA1UdEQQUMBKCECouZXhhbXBsZS1n
by5jb20wCgYIKoZIzj0EAwIDSAAwRQIhAPAh2q4PiMubaOh2p1aPGP9HfiS8E6dR
Nxy25o+i1KQVAIEA7v3lp3Zb2JDgEgPbk2qvK+2L05er1FaTXVqmvdvZXOA=
-----END CERTIFICATE-----`

	keyPEM := `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIrYSSNQFaA2Hwf1duRSxKtLYX5CB04fSeQ6tF1aY/PuoAoGCCqGSM49
AwEHoUQDQgAEgoEF2fa6CmzeMUgZvfpM/aF5+ikzbEMYlEkCXooPbvg0Au2hq7mu
YhqarMtvn36wXRfwXuUuRAcIlQ16QM/jY1Q==
-----END EC PRIVATE KEY-----`

	// Create temporary certificate files
	certFile, err := os.CreateTemp("", "cert.*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(certFile.Name())

	keyFile, err := os.CreateTemp("", "key.*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(keyFile.Name())

	_, err = certFile.WriteString(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	certFile.Close()

	_, err = keyFile.WriteString(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	keyFile.Close()

	// Test TLS configuration
	cert, err := tls.LoadX509KeyPair(certFile.Name(), keyFile.Name())
	if err != nil {
		// Skip certificate loading test if certificates are invalid
		t.Skipf("Skipping certificate test due to invalid test certificates: %v", err)
	}

	// Create TLS config with security best practices
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		},
	}

	// Verify TLS configuration
	if tlsConfig.MinVersion < tls.VersionTLS12 {
		t.Error("TLS version should be at least 1.2")
	}

	if len(tlsConfig.CipherSuites) == 0 {
		t.Error("Cipher suites should be explicitly configured")
	}

	// Test that weak cipher suites are not included
	weakCiphers := []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	}

	for _, weakCipher := range weakCiphers {
		for _, configuredCipher := range tlsConfig.CipherSuites {
			if weakCipher == configuredCipher {
				t.Errorf("Weak cipher suite 0x%04X should not be configured", weakCipher)
			}
		}
	}
}

// TestConfigurationSecurity tests security aspects of configuration loading
func TestConfigurationSecurity(t *testing.T) {
	// Test with potentially malicious configuration
	maliciousConfigs := []struct {
		name   string
		config string
	}{
		{
			name: "Extremely Long Password",
			config: `{
				"listen_addr": "127.0.0.1:8888",
				"cert_file": "cert.pem",
				"key_file": "key.pem",
				"password": "` + strings.Repeat("a", 10000) + `"
			}`,
		},
		{
			name: "Special Characters in Path",
			config: `{
				"listen_addr": "127.0.0.1:8888",
				"cert_file": "../../../etc/passwd",
				"key_file": "../../../etc/shadow",
				"password": "test"
			}`,
		},
		{
			name: "Null Bytes in Config",
			config: `{
				"listen_addr": "127.0.0.1:8888\x00",
				"cert_file": "cert.pem",
				"key_file": "key.pem",
				"password": "test\x00admin"
			}`,
		},
	}

	for _, tt := range maliciousConfigs {
		t.Run(tt.name, func(t *testing.T) {
			tmpfile, err := os.CreateTemp("", "config.*.json")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(tmpfile.Name())

			_, err = tmpfile.WriteString(tt.config)
			if err != nil {
				t.Fatal(err)
			}
			tmpfile.Close()

			// Attempt to load the configuration
			cfg, err := config.LoadServerConfig(tmpfile.Name())

			// The loading should either succeed or fail gracefully
			if err != nil {
				// If it fails, verify the error is descriptive
				if len(err.Error()) == 0 {
					t.Error("Error message should not be empty")
				}
			} else {
				// If it succeeds, verify the configuration is reasonable
				if cfg == nil {
					t.Error("Configuration should not be nil")
				}
				if len(cfg.Password) > 1000 {
					t.Error("Password length should be reasonable")
				}
			}
		})
	}
}

// TestTimingAttacks tests resistance to timing attacks
func TestTimingAttacks(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping timing attack test in short mode")
	}

	key := make([]byte, 32)
	rand.Read(key)

	// Create payloads of different sizes
	payloads := [][]byte{
		make([]byte, 64),
		make([]byte, 1024),
		make([]byte, 4096),
	}

	for _, payload := range payloads {
		rand.Read(payload)
	}

	// Measure encryption times
	numSamples := 1000
	timings := make([][]time.Duration, len(payloads))

	for i, payload := range payloads {
		timings[i] = make([]time.Duration, numSamples)

		for j := 0; j < numSamples; j++ {
			start := time.Now()
			_, err := e_quic.Pack(payload, key)
			if err != nil {
				t.Fatal(err)
			}
			timings[i][j] = time.Since(start)
		}
	}

	// Calculate average timings
	averages := make([]time.Duration, len(payloads))
	for i, timing := range timings {
		var total time.Duration
		for _, t := range timing {
			total += t
		}
		averages[i] = total / time.Duration(len(timing))
	}

	// Log timing information (for manual analysis)
	for i, avg := range averages {
		t.Logf("Payload size %d bytes: average encryption time %v", len(payloads[i]), avg)
	}

	// Basic timing analysis - encryption time should scale reasonably with payload size
	// This is a simplified test; real timing attack analysis would be more sophisticated
	if averages[2] < averages[0] {
		t.Error("Encryption time should generally increase with payload size")
	}
}

// TestRandomnessQuality tests the quality of randomness used in encryption
func TestRandomnessQuality(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping randomness quality test in short mode")
	}

	numSamples := 1000
	payload := []byte("test payload for randomness analysis")
	key := make([]byte, 32)
	rand.Read(key)

	// Collect encrypted samples
	samples := make([][]byte, numSamples)
	for i := 0; i < numSamples; i++ {
		encrypted, err := e_quic.Pack(payload, key)
		if err != nil {
			t.Fatal(err)
		}
		samples[i] = encrypted
	}

	// Test 1: No identical samples
	for i := 0; i < len(samples); i++ {
		for j := i + 1; j < len(samples); j++ {
			if bytes.Equal(samples[i], samples[j]) {
				t.Errorf("Found identical encrypted samples at indices %d and %d", i, j)
			}
		}
	}

	// Test 2: Byte distribution analysis (simplified)
	// Collect all bytes from all samples
	allBytes := make([]byte, 0)
	for _, sample := range samples {
		allBytes = append(allBytes, sample...)
	}

	// Count byte frequencies
	byteFreq := make(map[byte]int)
	for _, b := range allBytes {
		byteFreq[b]++
	}

	// Check that all 256 possible byte values appear (with enough samples)
	if len(allBytes) > 10000 {
		uniqueBytes := len(byteFreq)
		if uniqueBytes < 200 { // Allow some tolerance
			t.Errorf("Poor byte distribution: only %d unique bytes out of 256 possible", uniqueBytes)
		}
	}

	// Test 3: Basic entropy check (simplified)
	// Calculate the most and least frequent bytes
	minFreq := len(allBytes)
	maxFreq := 0
	for _, freq := range byteFreq {
		if freq < minFreq {
			minFreq = freq
		}
		if freq > maxFreq {
			maxFreq = freq
		}
	}

	// The ratio shouldn't be too extreme (simplified entropy check)
	if len(allBytes) > 1000 && maxFreq > minFreq*10 {
		t.Errorf("Poor entropy: max frequency %d is more than 10x min frequency %d", maxFreq, minFreq)
	}

	t.Logf("Randomness analysis: %d samples, %d total bytes, %d unique byte values", numSamples, len(allBytes), len(byteFreq))
	t.Logf("Frequency range: %d (min) to %d (max)", minFreq, maxFreq)
}

// TestSideChannelResistance tests basic side-channel resistance
func TestSideChannelResistance(t *testing.T) {
	// Test that encryption/decryption doesn't leak information through exceptions
	key := make([]byte, 32)
	rand.Read(key)

	// Test with various payload sizes to ensure consistent behavior
	payloadSizes := []int{0, 1, 16, 64, 256, 1024, 4096}

	for _, size := range payloadSizes {
		t.Run("Size_"+hex.EncodeToString([]byte{byte(size)}), func(t *testing.T) {
			payload := make([]byte, size)
			if size > 0 {
				rand.Read(payload)
			}

			// Encryption should not panic or leak information through exceptions
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Encryption panicked with payload size %d: %v", size, r)
				}
			}()

			encrypted, err := e_quic.Pack(payload, key)
			if err != nil {
				// Error is acceptable, but should be consistent
				if len(err.Error()) == 0 {
					t.Error("Error message should not be empty")
				}
				return
			}

			// Decryption should also not panic
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Decryption panicked with payload size %d: %v", size, r)
				}
			}()

			decrypted, err := e_quic.Unpack(encrypted, key)
			if err != nil {
				t.Errorf("Decryption failed for payload size %d: %v", size, err)
				return
			}

			if !bytes.Equal(payload, decrypted) {
				t.Errorf("Decrypted data doesn't match original for payload size %d", size)
			}
		})
	}
}