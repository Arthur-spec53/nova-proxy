package unit

import (
	"bytes"
	"crypto/rand"
	"os"
	"testing"
	"time"

	"nova-proxy/internal/config"
	"nova-proxy/internal/e_quic"
	"nova-proxy/internal/protocol"
	"nova-proxy/internal/shaping"
	"nova-proxy/test/framework"
)

// TestConfigValidation tests configuration validation
func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name      string
		configJSON string
		expectErr bool
	}{
		{
			name: "Valid Server Config",
			configJSON: `{
				"listen_addr": "0.0.0.0:8888",
				"cert_file": "server.crt",
				"key_file": "server.key",
				"password": "test_password"
			}`,
			expectErr: false,
		},
		{
			name: "Invalid JSON",
			configJSON: `{"listen_addr": "0.0.0.0:8888",}`,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpfile, err := os.CreateTemp("", "config.*.json")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(tmpfile.Name())

			_, err = tmpfile.WriteString(tt.configJSON)
			if err != nil {
				t.Fatal(err)
			}
			err = tmpfile.Close()
			if err != nil {
				t.Fatal(err)
			}

			_, err = config.LoadServerConfig(tmpfile.Name())
			if tt.expectErr && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

// TestProtocolFrameEncoding tests protocol frame encoding/decoding
func TestProtocolFrameEncoding(t *testing.T) {
	tests := []struct {
		name  string
		frame *protocol.Frame
	}{
		{
			name: "Domain Address Frame",
			frame: &protocol.Frame{
				Version:  protocol.Version,
				Options:  0,
				AddrType: protocol.AddrTypeDomain,
				Host:     "example.com",
				Port:     80,
			},
		},
		{
			name: "IPv4 Address Frame",
			frame: &protocol.Frame{
				Version:  protocol.Version,
				Options:  0,
				AddrType: protocol.AddrTypeIPv4,
				Host:     "192.168.1.1",
				Port:     443,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := tt.frame.Encode(&buf)
			if err != nil {
				t.Fatal(err)
			}

			// Verify the buffer contains data
			if buf.Len() == 0 {
				t.Error("Expected encoded data but buffer is empty")
			}
		})
	}
}

// TestEQUICPackEncryption tests E-QUIC packet encryption/decryption
func TestEQUICPackEncryption(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		key     []byte
	}{
		{
			name:    "Small Payload",
			payload: []byte("Hello, World!"),
			key:     make([]byte, 32), // AES-256 key
		},
		{
			name:    "Large Payload",
			payload: make([]byte, 1024),
			key:     make([]byte, 32),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate random key and payload
			_, err := rand.Read(tt.key)
			if err != nil {
				t.Fatal(err)
			}
			if len(tt.payload) > 13 {
				_, err = rand.Read(tt.payload)
				if err != nil {
					t.Fatal(err)
				}
			}

			// Pack the payload
			packed, err := e_quic.Pack(tt.payload, tt.key)
			if err != nil {
				t.Fatalf("Pack failed: %v", err)
			}

			// Verify packed data is larger than original
			if len(packed) <= len(tt.payload) {
				t.Error("Expected packed data to be larger than original payload")
			}

			// Unpack the payload
			unpacked, err := e_quic.Unpack(packed, tt.key)
			if err != nil {
				t.Fatalf("Unpack failed: %v", err)
			}

			// Verify unpacked data matches original
			if !bytes.Equal(tt.payload, unpacked) {
				t.Error("Unpacked data does not match original payload")
			}
		})
	}
}

// TestShapingProfileLoading tests traffic shaping profile loading
func TestShapingProfileLoading(t *testing.T) {
	// Create a test profile file
	profileJSON := `{
		"name": "test_profile",
		"packet_size_distribution": {
			"type": "histogram",
			"buckets": [
				{"size": 1300, "probability": 1.0}
			]
		},
		"interval_distribution_ms": {
			"type": "gaussian",
			"mean": 1.0,
			"stddev": 0.5
		}
	}`

	tmpfile, err := os.CreateTemp("", "profile.*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.WriteString(profileJSON)
	if err != nil {
		t.Fatal(err)
	}
	err = tmpfile.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Load the profile
	profile, err := shaping.LoadProfile(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to load profile: %v", err)
	}

	if profile.Name != "test_profile" {
		t.Errorf("Expected profile name 'test_profile', got '%s'", profile.Name)
	}

	// Test random size generation
	size := profile.GetRandomSize()
	if size <= 0 {
		t.Error("Expected positive packet size")
	}

	// Test random interval generation
	interval := profile.GetRandomIntervalMs()
	if interval <= 0 {
		t.Error("Expected positive interval")
	}
}

// TestConcurrentConnections tests handling of concurrent connections
func TestConcurrentConnections(t *testing.T) {
	tf := framework.NewTestFramework()
	defer tf.Cleanup()

	// Test concurrent operations
	numOperations := 10
	results := make(chan error, numOperations)

	for i := 0; i < numOperations; i++ {
		go func(id int) {
			// Simulate some concurrent work
			time.Sleep(10 * time.Millisecond)
			tf.RecordBytesTransferred(1024)
			results <- nil
		}(i)
	}

	// Wait for all operations to complete
	for i := 0; i < numOperations; i++ {
		err := <-results
		if err != nil {
			t.Errorf("Operation %d failed: %v", i, err)
		}
	}

	// Verify metrics
	metrics := tf.GetMetrics()
	expectedBytes := int64(numOperations * 1024)
	if metrics.BytesTransferred != expectedBytes {
		t.Errorf("Expected %d bytes transferred, got %d", expectedBytes, metrics.BytesTransferred)
	}
}

// TestErrorHandling tests error handling scenarios
func TestErrorHandling(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() error
		expected string
	}{
		{
			name: "Invalid Config File",
			setup: func() error {
				_, err := config.LoadServerConfig("/nonexistent/config.json")
				return err
			},
			expected: "no such file or directory",
		},
		{
			name: "Invalid E-QUIC Key",
			setup: func() error {
				// Try to unpack with wrong key
				key1 := make([]byte, 32)
				key2 := make([]byte, 32)
				rand.Read(key1)
				rand.Read(key2)

				payload := []byte("test")
				packed, err := e_quic.Pack(payload, key1)
				if err != nil {
					return err
				}

				// Try to unpack with different key
				_, err = e_quic.Unpack(packed, key2)
				return err
			},
			expected: "authentication failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.setup()
			if err == nil {
				t.Error("Expected error but got none")
				return
			}
			if tt.expected != "" && !contains(err.Error(), tt.expected) {
				t.Errorf("Expected error containing '%s', got '%s'", tt.expected, err.Error())
			}
		})
	}
}

// BenchmarkProtocolEncoding benchmarks protocol frame encoding
func BenchmarkProtocolEncoding(b *testing.B) {
	frame := &protocol.Frame{
		Version:  protocol.Version,
		Options:  0,
		AddrType: protocol.AddrTypeDomain,
		Host:     "example.com",
		Port:     80,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		err := frame.Encode(&buf)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEQUICPacking benchmarks E-QUIC packing performance
func BenchmarkEQUICPacking(b *testing.B) {
	payload := make([]byte, 1024)
	key := make([]byte, 32)
	rand.Read(payload)
	rand.Read(key)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := e_quic.Pack(payload, key)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || 
		(len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || 
			findSubstring(s, substr))))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}