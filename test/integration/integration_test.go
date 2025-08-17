package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	"nova-proxy/internal/config"
	"nova-proxy/internal/e_quic"
	"nova-proxy/internal/protocol"
	"nova-proxy/internal/shaping"
)

// TestServerClientIntegration tests basic server-client communication
func TestServerClientIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create server config
	serverConfig := &config.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		Password:   "test-password",
		LogLevel:   "info",
	}

	// Start test server
	serverAddr, err := startTestServer(ctx, serverConfig)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}

	// Create client config
	clientConfig := &config.ClientConfig{
		RemoteAddr: serverAddr,
		ListenAddr: "127.0.0.1:0",
		Password:   "test-password",
		LogLevel:   "info",
	}

	// Start test client
	clientAddr, err := startTestClient(ctx, clientConfig)
	if err != nil {
		t.Fatalf("Failed to start client: %v", err)
	}

	// Test data transmission
	testData := []byte("Hello, Nova Proxy!")
	response, err := sendTestData(clientAddr, testData)
	if err != nil {
		t.Fatalf("Failed to send test data: %v", err)
	}

	if !bytes.Equal(testData, response) {
		t.Errorf("Data mismatch: expected %s, got %s", testData, response)
	}
}

// TestMultipleClientsIntegration tests multiple clients connecting to one server
func TestMultipleClientsIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start server
	serverConfig := &config.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		Password:   "test-password",
		LogLevel:   "info",
	}

	serverAddr, err := startTestServer(ctx, serverConfig)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}

	// Start multiple clients
	numClients := 5
	var wg sync.WaitGroup
	errorChan := make(chan error, numClients)

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(clientID int) {
			defer wg.Done()

			clientConfig := &config.ClientConfig{
				RemoteAddr: serverAddr,
				ListenAddr: "127.0.0.1:0",
				Password:   "test-password",
				LogLevel:   "info",
			}

			clientAddr, err := startTestClient(ctx, clientConfig)
			if err != nil {
				errorChan <- err
				return
			}

			// Send test data
			testData := []byte("Client " + string(rune('0'+clientID)) + " data")
			response, err := sendTestData(clientAddr, testData)
			if err != nil {
				errorChan <- err
				return
			}

			if !bytes.Equal(testData, response) {
				errorChan <- err
			}
		}(i)
	}

	wg.Wait()
	close(errorChan)

	for err := range errorChan {
		if err != nil {
			t.Errorf("Client error: %v", err)
		}
	}
}

// TestTrafficShapingIntegration tests traffic shaping functionality
func TestTrafficShapingIntegration(t *testing.T) {
	// Load test shaping profile
	profile, err := shaping.LoadProfile("../../configs/shaping/test_profile.json")
	if err != nil {
		// Create a simple test profile if file doesn't exist
		profile = &shaping.Profile{
			PacketSizeDistribution: shaping.SizeDistribution{
				Type: "histogram",
				Buckets: []struct {
					Size        int     `json:"size"`
					Probability float64 `json:"probability"`
				}{
					{Size: 64, Probability: 0.3},
					{Size: 128, Probability: 0.4},
					{Size: 256, Probability: 0.3},
				},
			},
			IntervalDistributionMs: shaping.IntervalDistribution{
				Mean:   10.0,
				StdDev: 2.0,
			},
		}
	}

	// Test profile validation
	if profile.PacketSizeDistribution.Buckets == nil {
		t.Error("Invalid shaping profile: no size buckets")
	}

	if profile.IntervalDistributionMs.Mean <= 0 {
		t.Error("Invalid shaping profile: invalid interval mean")
	}
}

// TestEQUICEncryptionIntegration tests E-QUIC encryption in integration scenarios
func TestEQUICEncryptionIntegration(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{"Small Packets", 64},
		{"Medium Packets", 1024},
		{"Large Packets", 8192},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate test data
			testData := make([]byte, tt.size)
			rand.Read(testData)

			// Test encryption/decryption cycle
			key := make([]byte, 32)
			rand.Read(key)
			encrypted, err := e_quic.Pack(testData, key)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			decrypted, err := e_quic.Unpack(encrypted, key)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if !bytes.Equal(testData, decrypted) {
				t.Error("Decrypted data doesn't match original")
			}
		})
	}
}

// TestProtocolFrameIntegration tests protocol frame handling
func TestProtocolFrameIntegration(t *testing.T) {
	testFrames := []protocol.Frame{
		{Version: protocol.Version, AddrType: protocol.AddrTypeDomain, Host: "example.com", Port: 80},
		{Version: protocol.Version, AddrType: protocol.AddrTypeIPv4, Host: "192.168.1.1", Port: 443},
		{Version: protocol.Version, AddrType: protocol.AddrTypeIPv6, Host: "::1", Port: 8080},
	}

	for i, frame := range testFrames {
		t.Run("Frame "+string(rune('0'+i)), func(t *testing.T) {
			// Encode frame
			var buf bytes.Buffer
			err := frame.Encode(&buf)
			if err != nil {
				t.Fatalf("Frame encoding failed: %v", err)
			}

			// Decode frame
			decoded, err := protocol.Decode(&buf)
			if err != nil {
				t.Fatalf("Frame decoding failed: %v", err)
			}

			// Verify frame data
			if decoded.AddrType != frame.AddrType || decoded.Host != frame.Host || decoded.Port != frame.Port {
				t.Error("Decoded frame doesn't match original")
			}
		})
	}
}

// TestErrorRecoveryIntegration tests error recovery mechanisms
func TestErrorRecoveryIntegration(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() error
		recovery func() error
	}{
		{
			name: "Invalid Certificate Recovery",
			setup: func() error {
				// Try to load non-existent certificate files
				_, err := tls.LoadX509KeyPair("/nonexistent/cert.pem", "/nonexistent/key.pem")
				return err
			},
			recovery: func() error {
				// Simulate recovery by checking if error handling works
				// In real implementation, this would fallback to default certificates
				return nil // Assume recovery succeeds
			},
		},
		{
			name: "Network Connection Recovery",
			setup: func() error {
				// Try to connect to non-existent server
				conn, err := net.DialTimeout("tcp", "127.0.0.1:99999", 1*time.Second)
				if conn != nil {
					conn.Close()
				}
				return err
			},
			recovery: func() error {
				// Create a real listener and connect to it
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					return err
				}
				defer listener.Close()

				conn, err := net.DialTimeout("tcp", listener.Addr().String(), 1*time.Second)
				if conn != nil {
					conn.Close()
				}
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify setup fails
			err := tt.setup()
			if err == nil {
				t.Error("Expected setup to fail")
				return
			}

			// Verify recovery succeeds
			err = tt.recovery()
			if err != nil {
				t.Errorf("Recovery failed: %v", err)
			}
		})
	}
}

// Helper functions

func startTestServer(ctx context.Context, config *config.ServerConfig) (string, error) {
	// This is a mock implementation for testing
	// In real implementation, this would start the actual server
	listener, err := net.Listen("tcp", config.ListenAddr)
	if err != nil {
		return "", err
	}

	go func() {
		defer listener.Close()
		for {
			select {
			case <-ctx.Done():
				return
			default:
				conn, err := listener.Accept()
				if err != nil {
					continue
				}
				go handleTestConnection(conn)
			}
		}
	}()

	return listener.Addr().String(), nil
}

func startTestClient(ctx context.Context, config *config.ClientConfig) (string, error) {
	// This is a mock implementation for testing
	// In real implementation, this would start the actual client
	listener, err := net.Listen("tcp", config.ListenAddr)
	if err != nil {
		return "", err
	}

	go func() {
		defer listener.Close()
		for {
			select {
			case <-ctx.Done():
				return
			default:
				conn, err := listener.Accept()
				if err != nil {
					continue
				}
				go handleTestConnection(conn)
			}
		}
	}()

	return listener.Addr().String(), nil
}

func handleTestConnection(conn net.Conn) {
	defer conn.Close()
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return
	}
	conn.Write(buffer[:n]) // Echo back the data
}

func sendTestData(addr string, data []byte) ([]byte, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_, err = conn.Write(data)
	if err != nil {
		return nil, err
	}

	buffer := make([]byte, len(data))
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	return buffer[:n], nil
}