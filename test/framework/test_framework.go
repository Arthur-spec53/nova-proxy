package framework

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	quic "github.com/qdeconinck/mp-quic"
)

// TestFramework provides comprehensive testing utilities for Nova Proxy
type TestFramework struct {
	mu       sync.RWMutex
	servers  map[string]*TestServer
	clients  map[string]*TestClient
	metrics  *TestMetrics
	cleanup  []func()
}

// TestServer represents a test server instance
type TestServer struct {
	Addr     string
	UDPConn  *net.UDPConn
	TLSConf  *tls.Config
	QUICConf *quic.Config
	Cancel   context.CancelFunc
	Started  bool
}

// TestClient represents a test client instance
type TestClient struct {
	RemoteAddr string
	LocalAddr  string
	Conn       net.Conn
	TLSConf    *tls.Config
	QUICConf   *quic.Config
	Connected  bool
}

// TestMetrics collects test execution metrics
type TestMetrics struct {
	mu              sync.RWMutex
	ConnectionCount int64
	BytesTransferred int64
	LatencySum      time.Duration
	LatencyCount    int64
	ErrorCount      int64
	StartTime       time.Time
}

// NewTestFramework creates a new test framework instance
func NewTestFramework() *TestFramework {
	return &TestFramework{
		servers: make(map[string]*TestServer),
		clients: make(map[string]*TestClient),
		metrics: &TestMetrics{
			StartTime: time.Now(),
		},
	}
}

// CreateTestServer creates and starts a test server
func (tf *TestFramework) CreateTestServer(name, addr string, tlsConf *tls.Config, quicConf *quic.Config) (*TestServer, error) {
	tf.mu.Lock()
	defer tf.mu.Unlock()

	if _, exists := tf.servers[name]; exists {
		return nil, fmt.Errorf("server %s already exists", name)
	}

	ctx, cancel := context.WithCancel(context.Background())
	server := &TestServer{
		Addr:     addr,
		TLSConf:  tlsConf,
		QUICConf: quicConf,
		Cancel:   cancel,
	}

	// Start server in goroutine
	go func() {
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return
		}
		udpConn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return
		}
		defer udpConn.Close()

		server.UDPConn = udpConn
		server.Started = true

		// Handle connections until context is cancelled
		for {
			select {
			case <-ctx.Done():
				return
			default:
				// Accept and handle connections
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()

	// Wait for server to start
	for i := 0; i < 100; i++ {
		if server.Started {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	tf.servers[name] = server
	tf.cleanup = append(tf.cleanup, func() {
		cancel()
	})

	return server, nil
}

// CreateTestClient creates a test client
func (tf *TestFramework) CreateTestClient(name, remoteAddr, localAddr string, tlsConf *tls.Config, quicConf *quic.Config) (*TestClient, error) {
	tf.mu.Lock()
	defer tf.mu.Unlock()

	if _, exists := tf.clients[name]; exists {
		return nil, fmt.Errorf("client %s already exists", name)
	}

	client := &TestClient{
		RemoteAddr: remoteAddr,
		LocalAddr:  localAddr,
		TLSConf:    tlsConf,
		QUICConf:   quicConf,
	}

	tf.clients[name] = client
	return client, nil
}

// RecordLatency records a latency measurement
func (tf *TestFramework) RecordLatency(latency time.Duration) {
	tf.metrics.mu.Lock()
	defer tf.metrics.mu.Unlock()
	tf.metrics.LatencySum += latency
	tf.metrics.LatencyCount++
}

// RecordError records an error occurrence
func (tf *TestFramework) RecordError() {
	tf.metrics.mu.Lock()
	defer tf.metrics.mu.Unlock()
	tf.metrics.ErrorCount++
}

// RecordBytesTransferred records bytes transferred
func (tf *TestFramework) RecordBytesTransferred(bytes int64) {
	tf.metrics.mu.Lock()
	defer tf.metrics.mu.Unlock()
	tf.metrics.BytesTransferred += bytes
}

// GetMetrics returns current test metrics
func (tf *TestFramework) GetMetrics() TestMetrics {
	tf.metrics.mu.RLock()
	defer tf.metrics.mu.RUnlock()
	return *tf.metrics
}

// GetAverageLatency calculates average latency
func (tf *TestFramework) GetAverageLatency() time.Duration {
	tf.metrics.mu.RLock()
	defer tf.metrics.mu.RUnlock()
	if tf.metrics.LatencyCount == 0 {
		return 0
	}
	return tf.metrics.LatencySum / time.Duration(tf.metrics.LatencyCount)
}

// GetThroughput calculates throughput in bytes per second
func (tf *TestFramework) GetThroughput() float64 {
	tf.metrics.mu.RLock()
	defer tf.metrics.mu.RUnlock()
	elapsed := time.Since(tf.metrics.StartTime)
	if elapsed == 0 {
		return 0
	}
	return float64(tf.metrics.BytesTransferred) / elapsed.Seconds()
}

// Cleanup cleans up all test resources
func (tf *TestFramework) Cleanup() {
	tf.mu.Lock()
	defer tf.mu.Unlock()

	// Run all cleanup functions
	for _, cleanup := range tf.cleanup {
		cleanup()
	}

	// Close all client connections
	for _, client := range tf.clients {
		if client.Conn != nil {
			client.Conn.Close()
		}
	}

	// Clear maps
	tf.servers = make(map[string]*TestServer)
	tf.clients = make(map[string]*TestClient)
	tf.cleanup = nil
}

// AssertNoErrors fails the test if any errors were recorded
func (tf *TestFramework) AssertNoErrors(t *testing.T) {
	metrics := tf.GetMetrics()
	if metrics.ErrorCount > 0 {
		t.Fatalf("Expected no errors, but got %d errors", metrics.ErrorCount)
	}
}

// AssertMinThroughput fails the test if throughput is below threshold
func (tf *TestFramework) AssertMinThroughput(t *testing.T, minBytesPerSec float64) {
	throughput := tf.GetThroughput()
	if throughput < minBytesPerSec {
		t.Fatalf("Expected throughput >= %.2f bytes/sec, got %.2f bytes/sec", minBytesPerSec, throughput)
	}
}

// AssertMaxLatency fails the test if average latency exceeds threshold
func (tf *TestFramework) AssertMaxLatency(t *testing.T, maxLatency time.Duration) {
	avgLatency := tf.GetAverageLatency()
	if avgLatency > maxLatency {
		t.Fatalf("Expected average latency <= %v, got %v", maxLatency, avgLatency)
	}
}