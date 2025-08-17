package performance

import (
	"bytes"
	"context"
	"crypto/rand"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nova-proxy/internal/e_quic"
	"nova-proxy/internal/protocol"
	"nova-proxy/internal/shaping"
	"nova-proxy/test/framework"
)

// BenchmarkEQUICThroughput benchmarks E-QUIC encryption/decryption throughput
func BenchmarkEQUICThroughput(b *testing.B) {
	payloadSizes := []int{64, 256, 1024, 4096, 8192}

	for _, size := range payloadSizes {
		b.Run("Size_"+string(rune('0'+size/1000)), func(b *testing.B) {
			payload := make([]byte, size)
			key := make([]byte, 32)
			rand.Read(payload)
			rand.Read(key)

			b.ResetTimer()
			b.SetBytes(int64(size))

			for i := 0; i < b.N; i++ {
				packed, err := e_quic.Pack(payload, key)
				if err != nil {
					b.Fatal(err)
				}

				_, err = e_quic.Unpack(packed, key)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkProtocolFrameProcessing benchmarks protocol frame encoding/decoding
func BenchmarkProtocolFrameProcessing(b *testing.B) {
	frames := []*protocol.Frame{
		{
			Version:  protocol.Version,
			Options:  0,
			AddrType: protocol.AddrTypeDomain,
			Host:     "example.com",
			Port:     80,
		},
		{
			Version:  protocol.Version,
			Options:  0,
			AddrType: protocol.AddrTypeIPv4,
			Host:     "192.168.1.1",
			Port:     443,
		},
		{
			Version:  protocol.Version,
			Options:  0,
			AddrType: protocol.AddrTypeIPv6,
			Host:     "2001:db8::1",
			Port:     8080,
		},
	}

	for i, frame := range frames {
		b.Run("Frame_"+string(rune('0'+i)), func(b *testing.B) {
			b.ResetTimer()

			for j := 0; j < b.N; j++ {
				var buf bytes.Buffer
				err := frame.Encode(&buf)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkTrafficShaping benchmarks traffic shaping performance
func BenchmarkTrafficShaping(b *testing.B) {
	// Create a simple profile for benchmarking
	profile := &shaping.Profile{
		Name: "benchmark_profile",
		PacketSizeDistribution: shaping.SizeDistribution{
			Type: "histogram",
			Buckets: []struct {
				Size        int     `json:"size"`
				Probability float64 `json:"probability"`
			}{
				{Size: 1300, Probability: 0.7},
				{Size: 800, Probability: 0.3},
			},
		},
		IntervalDistributionMs: shaping.IntervalDistribution{
			Type:   "gaussian",
			Mean:   1.0,
			StdDev: 0.2,
		},
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = profile.GetRandomSize()
		_ = profile.GetRandomIntervalMs()
	}
}

// BenchmarkConcurrentConnections benchmarks handling of concurrent connections
func BenchmarkConcurrentConnections(b *testing.B) {
	concurrencyLevels := []int{1, 10, 50, 100, 500}

	for _, concurrency := range concurrencyLevels {
		b.Run("Concurrency_"+string(rune('0'+concurrency/100)), func(b *testing.B) {
			tf := framework.NewTestFramework()
			defer tf.Cleanup()

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				var wg sync.WaitGroup
				wg.Add(concurrency)

				for j := 0; j < concurrency; j++ {
					go func() {
						defer wg.Done()
						// Simulate connection work
						tf.RecordBytesTransferred(1024)
					}()
				}

				wg.Wait()
			}
		})
	}
}

// TestMemoryUsage tests memory usage under various loads
func TestMemoryUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory usage test in short mode")
	}

	tests := []struct {
		name           string
		operations     int
		payloadSize    int
		maxMemoryMB    int64
	}{
		{"Light Load", 1000, 1024, 50},
		{"Medium Load", 10000, 2048, 100},
		{"Heavy Load", 50000, 4096, 200},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runtime.GC()
			var m1 runtime.MemStats
			runtime.ReadMemStats(&m1)

			// Perform operations
			key := make([]byte, 32)
			rand.Read(key)

			for i := 0; i < tt.operations; i++ {
				payload := make([]byte, tt.payloadSize)
				rand.Read(payload)

				packed, err := e_quic.Pack(payload, key)
				if err != nil {
					t.Fatal(err)
				}

				_, err = e_quic.Unpack(packed, key)
				if err != nil {
					t.Fatal(err)
				}

				// Force GC every 1000 operations to prevent excessive memory buildup
				if i%1000 == 0 {
					runtime.GC()
				}
			}

			runtime.GC()
			var m2 runtime.MemStats
			runtime.ReadMemStats(&m2)

			memoryUsedMB := int64(m2.Alloc-m1.Alloc) / (1024 * 1024)
			if memoryUsedMB > tt.maxMemoryMB {
				t.Errorf("Memory usage too high: %d MB > %d MB", memoryUsedMB, tt.maxMemoryMB)
			}

			t.Logf("Memory used: %d MB (limit: %d MB)", memoryUsedMB, tt.maxMemoryMB)
		})
	}
}

// TestLatencyUnderLoad tests latency characteristics under various loads
func TestLatencyUnderLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping latency test in short mode")
	}

	loadLevels := []struct {
		name        string
		concurrency int
		operations  int
		maxLatencyMs int64
	}{
		{"Low Load", 5, 100, 10000},
		{"Medium Load", 10, 500, 10000},
		{"High Load", 20, 1000, 10000},
	}

	for _, load := range loadLevels {
		t.Run(load.name, func(t *testing.T) {
			key := make([]byte, 32)
			payload := make([]byte, 1024)
			rand.Read(key)
			rand.Read(payload)

			latencies := make([]time.Duration, load.operations)
			var wg sync.WaitGroup
			semaphore := make(chan struct{}, load.concurrency)

			start := time.Now()

			for i := 0; i < load.operations; i++ {
				wg.Add(1)
				go func(index int) {
					defer wg.Done()
					semaphore <- struct{}{}
					defer func() { <-semaphore }()

					opStart := time.Now()

					packed, err := e_quic.Pack(payload, key)
					if err != nil {
						t.Error(err)
						return
					}

					_, err = e_quic.Unpack(packed, key)
					if err != nil {
						t.Error(err)
						return
					}

					latencies[index] = time.Since(opStart)
				}(i)
			}

			wg.Wait()
			totalTime := time.Since(start)

			// Calculate statistics
			var totalLatency time.Duration
			maxLatency := time.Duration(0)
			for _, lat := range latencies {
				totalLatency += lat
				if lat > maxLatency {
					maxLatency = lat
				}
			}

			avgLatency := totalLatency / time.Duration(load.operations)
			throughput := float64(load.operations) / totalTime.Seconds()

			t.Logf("Average latency: %v", avgLatency)
			t.Logf("Max latency: %v", maxLatency)
			t.Logf("Throughput: %.2f ops/sec", throughput)

			if maxLatency.Milliseconds() > load.maxLatencyMs {
				t.Errorf("Max latency too high: %v > %dms", maxLatency, load.maxLatencyMs)
			}
		})
	}
}

// TestResourceLeaks tests for resource leaks (goroutines, file descriptors, etc.)
func TestResourceLeaks(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping resource leak test in short mode")
	}

	// Record initial state
	initialGoroutines := runtime.NumGoroutine()

	// Perform operations that might leak resources
	for i := 0; i < 100; i++ {
		tf := framework.NewTestFramework()

		// Simulate some work
		for j := 0; j < 10; j++ {
			tf.RecordBytesTransferred(1024)
		}

		tf.Cleanup()
	}

	// Force garbage collection
	runtime.GC()
	time.Sleep(100 * time.Millisecond) // Allow goroutines to finish

	// Check for goroutine leaks
	finalGoroutines := runtime.NumGoroutine()
	goroutineDiff := finalGoroutines - initialGoroutines

	if goroutineDiff > 5 { // Allow some tolerance
		t.Errorf("Potential goroutine leak: %d goroutines created and not cleaned up", goroutineDiff)
	}

	t.Logf("Goroutines: initial=%d, final=%d, diff=%d", initialGoroutines, finalGoroutines, goroutineDiff)
}

// TestStressTest performs a comprehensive stress test
func TestStressTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	const (
		duration     = 30 * time.Second
		concurrency  = 50
		payloadSize  = 2048
	)

	key := make([]byte, 32)
	rand.Read(key)

	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	var (
		operations int64
		errors     int64
		wg         sync.WaitGroup
	)

	// Start worker goroutines
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			payload := make([]byte, payloadSize)
			rand.Read(payload)

			for {
				select {
				case <-ctx.Done():
					return
				default:
					packed, err := e_quic.Pack(payload, key)
					if err != nil {
						atomic.AddInt64(&errors, 1)
						continue
					}

					_, err = e_quic.Unpack(packed, key)
					if err != nil {
						atomic.AddInt64(&errors, 1)
						continue
					}

					atomic.AddInt64(&operations, 1)
				}
			}
		}()
	}

	wg.Wait()

	throughput := float64(operations) / duration.Seconds()
	errorRate := float64(errors) / float64(operations+errors) * 100

	t.Logf("Stress test results:")
	t.Logf("  Duration: %v", duration)
	t.Logf("  Concurrency: %d", concurrency)
	t.Logf("  Operations: %d", operations)
	t.Logf("  Errors: %d", errors)
	t.Logf("  Throughput: %.2f ops/sec", throughput)
	t.Logf("  Error rate: %.2f%%", errorRate)

	if errorRate > 1.0 {
		t.Errorf("Error rate too high: %.2f%%", errorRate)
	}

	if throughput < 100 {
		t.Errorf("Throughput too low: %.2f ops/sec", throughput)
	}
}