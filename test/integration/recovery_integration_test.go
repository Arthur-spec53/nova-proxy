package integration

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"testing"
	"time"

	"nova-proxy/internal/recovery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEnhancedProxyIntegration 测试增强代理集成功能
func TestEnhancedProxyIntegration(t *testing.T) {
	config := recovery.DefaultEnhancedProxyConfig()
	config.Retry.MaxRetries = 2
	config.CircuitBreaker.FailureThreshold = 3
	config.HealthCheck.Interval = 1 * time.Second

	integration := recovery.NewProxyIntegration(config)
	require.NotNil(t, integration)

	// 测试初始化
	err := integration.Initialize()
	require.NoError(t, err)
	defer integration.Shutdown()

	// 验证健康状态
	assert.True(t, integration.IsHealthy())

	// 获取统计信息
	stats := integration.GetIntegrationStats()
	assert.True(t, stats["initialized"].(bool))
	assert.True(t, stats["running"].(bool))
}

// TestConnectionPoolIntegration 测试连接池集成
func TestConnectionPoolIntegration(t *testing.T) {
	config := recovery.DefaultEnhancedProxyConfig()
	config.ConnectionPool.MaxConnections = 5
	config.ConnectionPool.MaxIdleTime = 1 * time.Second

	integration := recovery.NewProxyIntegration(config)
	require.NotNil(t, integration)

	err := integration.Initialize()
	require.NoError(t, err)
	defer integration.Shutdown()

	// 模拟连接建立（这里只是测试接口，实际连接需要真实的QUIC服务器）
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 测试连接建立失败的情况
	_, err = integration.EstablishQUICConnection(ctx, "invalid-addr", nil, nil)
	assert.Error(t, err)

	// 验证统计信息更新
	stats := integration.GetIntegrationStats()
	proxyStats := stats["proxy_stats"].(*recovery.ProxyStats)
	assert.Greater(t, proxyStats.FailedConnections, int64(0))
}

// TestRetryMechanism 测试重试机制
func TestRetryMechanism(t *testing.T) {
	config := recovery.DefaultEnhancedProxyConfig()
	config.Retry.MaxRetries = 3
	config.Retry.InitialDelay = 10 * time.Millisecond

	integration := recovery.NewProxyIntegration(config)
	require.NotNil(t, integration)

	err := integration.Initialize()
	require.NoError(t, err)
	defer integration.Shutdown()

	// 测试重试机制
	attempts := 0
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = integration.ExecuteWithRecovery(ctx, func() error {
		attempts++
		if attempts < 3 {
			return errors.New("temporary failure")
		}
		return nil
	})

	assert.NoError(t, err)
	assert.Equal(t, 3, attempts)
}

// TestCircuitBreakerIntegration 测试断路器集成
func TestCircuitBreakerIntegration(t *testing.T) {
	config := recovery.DefaultEnhancedProxyConfig()
	config.CircuitBreaker.FailureThreshold = 2
	config.CircuitBreaker.RecoveryTimeout = 100 * time.Millisecond

	integration := recovery.NewProxyIntegration(config)
	require.NotNil(t, integration)

	err := integration.Initialize()
	require.NoError(t, err)
	defer integration.Shutdown()

	ctx := context.Background()

	// 触发断路器打开
	for i := 0; i < 3; i++ {
		err = integration.ExecuteWithRecovery(ctx, func() error {
			return errors.New("persistent failure")
		})
		assert.Error(t, err)
	}

	// 验证断路器状态
	stats := integration.GetIntegrationStats()
	cbStats := stats["circuit_breaker"].(map[string]interface{})
	assert.Contains(t, cbStats, "state")

	// 等待恢复超时
	time.Sleep(150 * time.Millisecond)

	// 测试断路器恢复
	err = integration.ExecuteWithRecovery(ctx, func() error {
		return nil
	})
	assert.NoError(t, err)
}

// TestHealthCheckerIntegration 测试健康检查集成
func TestHealthCheckerIntegration(t *testing.T) {
	config := recovery.DefaultEnhancedProxyConfig()
	config.HealthCheck.Interval = 100 * time.Millisecond
	config.HealthCheck.Enabled = true

	integration := recovery.NewProxyIntegration(config)
	require.NotNil(t, integration)

	err := integration.Initialize()
	require.NoError(t, err)
	defer integration.Shutdown()

	// 等待健康检查运行
	time.Sleep(200 * time.Millisecond)

	// 验证健康状态
	assert.True(t, integration.IsHealthy())

	healthStatus := integration.GetIntegrationStats()["health_status"].(map[string]bool)
	assert.Contains(t, healthStatus, "connection_pool")
	assert.Contains(t, healthStatus, "circuit_breaker")
}

// TestGracefulShutdown 测试优雅关闭
func TestGracefulShutdown(t *testing.T) {
	config := recovery.DefaultEnhancedProxyConfig()
	config.GracefulShutdown.Timeout = 1 * time.Second
	config.GracefulShutdown.Enabled = true

	integration := recovery.NewProxyIntegration(config)
	require.NotNil(t, integration)

	err := integration.Initialize()
	require.NoError(t, err)

	// 测试优雅关闭
	start := time.Now()
	err = integration.Shutdown()
	assert.NoError(t, err)

	// 验证关闭时间在合理范围内
	elapsed := time.Since(start)
	assert.Less(t, elapsed, 2*time.Second)

	// 验证状态
	assert.False(t, integration.IsHealthy())
}

// TestConcurrentOperations 测试并发操作
func TestConcurrentOperations(t *testing.T) {
	config := recovery.DefaultEnhancedProxyConfig()
	config.ConnectionPool.MaxConnections = 10

	integration := recovery.NewProxyIntegration(config)
	require.NotNil(t, integration)

	err := integration.Initialize()
	require.NoError(t, err)
	defer integration.Shutdown()

	// 并发执行操作
	var wg sync.WaitGroup
	operations := 20
	successCount := int64(0)

	for i := 0; i < operations; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			err := integration.ExecuteWithRecovery(ctx, func() error {
				// 模拟一些操作
				time.Sleep(10 * time.Millisecond)
				if id%5 == 0 {
					return errors.New("simulated error")
				}
				return nil
			})

			if err == nil {
				successCount++
			}
		}(i)
	}

	wg.Wait()

	// 验证大部分操作成功
	assert.Greater(t, successCount, int64(operations/2))

	// 验证统计信息
	stats := integration.GetIntegrationStats()
	proxyStats := stats["proxy_stats"].(*recovery.ProxyStats)
	assert.Greater(t, proxyStats.RetryAttempts, int64(0))
}

// TestGlobalIntegration 测试全局集成
func TestGlobalIntegration(t *testing.T) {
	// 确保全局集成未初始化
	recovery.ShutdownGlobalIntegration()

	config := recovery.DefaultEnhancedProxyConfig()
	err := recovery.InitializeGlobalIntegration(config)
	require.NoError(t, err)
	defer recovery.ShutdownGlobalIntegration()

	// 测试重复初始化
	err = recovery.InitializeGlobalIntegration(config)
	assert.Error(t, err)

	// 测试全局访问
	globalIntegration := recovery.GetGlobalIntegration()
	assert.NotNil(t, globalIntegration)
	assert.True(t, globalIntegration.IsHealthy())

	// 测试全局统计
	stats := recovery.GetGlobalIntegrationStats()
	assert.True(t, stats["initialized"].(bool))

	// 测试全局健康检查
	assert.True(t, recovery.IsGlobalIntegrationHealthy())
}

// TestConnectionWrapper 测试连接包装器
func TestConnectionWrapper(t *testing.T) {
	config := recovery.DefaultEnhancedProxyConfig()
	integration := recovery.NewProxyIntegration(config)
	require.NotNil(t, integration)

	err := integration.Initialize()
	require.NoError(t, err)
	defer integration.Shutdown()

	// 测试客户端连接包装器（模拟）
	// 注意：这里只是测试接口，实际使用需要真实的QUIC配置
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	// 测试连接建立失败的情况
	_, err = recovery.NewClientConnectionWrapper(integration, "invalid-addr", tlsConfig, nil)
	assert.Error(t, err)
}

// TestErrorHandling 测试错误处理
func TestErrorHandling(t *testing.T) {
	config := recovery.DefaultEnhancedProxyConfig()
	integration := recovery.NewProxyIntegration(config)
	require.NotNil(t, integration)

	err := integration.Initialize()
	require.NoError(t, err)
	defer integration.Shutdown()

	// 测试各种错误类型
	testCases := []struct {
		name  string
		error error
	}{
		{"network error", errors.New("network unreachable")},
		{"timeout error", errors.New("context deadline exceeded")},
		{"connection refused", errors.New("connection refused")},
		{"generic error", errors.New("generic failure")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			err := integration.ExecuteWithRecovery(ctx, func() error {
				return tc.error
			})

			assert.Error(t, err)
		})
	}
}

// BenchmarkEnhancedProxy 性能基准测试
func BenchmarkEnhancedProxy(b *testing.B) {
	config := recovery.DefaultEnhancedProxyConfig()
	integration := recovery.NewProxyIntegration(config)

	err := integration.Initialize()
	if err != nil {
		b.Fatal(err)
	}
	defer integration.Shutdown()

	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			integration.ExecuteWithRecovery(ctx, func() error {
				// 模拟轻量级操作
				return nil
			})
		}
	})
}