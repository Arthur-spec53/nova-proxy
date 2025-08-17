package recovery

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"time"

	"nova-proxy/pkg/log"
	"github.com/sirupsen/logrus"
	"github.com/qdeconinck/mp-quic"
)

// EnhancedProxyConfig 增强代理配置
type EnhancedProxyConfig struct {
	ConnectionPool    *ConnectionPoolConfig    `json:"connection_pool"`
	Retry            *RetryConfig             `json:"retry"`
	CircuitBreaker   *CircuitBreakerConfig    `json:"circuit_breaker"`
	HealthCheck      *HealthCheckConfig       `json:"health_check"`
	GracefulShutdown *GracefulShutdownConfig  `json:"graceful_shutdown"`
}

// HealthCheckConfig 健康检查配置
type HealthCheckConfig struct {
	Interval time.Duration `json:"interval"`
	Timeout  time.Duration `json:"timeout"`
	Enabled  bool          `json:"enabled"`
}

// GracefulShutdownConfig 优雅关闭配置
type GracefulShutdownConfig struct {
	Timeout time.Duration `json:"timeout"`
	Enabled bool          `json:"enabled"`
}

// DefaultEnhancedProxyConfig 返回默认增强代理配置
func DefaultEnhancedProxyConfig() *EnhancedProxyConfig {
	return &EnhancedProxyConfig{
		ConnectionPool: DefaultConnectionPoolConfig(),
		Retry:         DefaultRetryConfig(),
		CircuitBreaker: DefaultCircuitBreakerConfig(),
		HealthCheck: &HealthCheckConfig{
			Interval: 30 * time.Second,
			Timeout:  5 * time.Second,
			Enabled:  true,
		},
		GracefulShutdown: &GracefulShutdownConfig{
			Timeout: 30 * time.Second,
			Enabled: true,
		},
	}
}

// EnhancedProxy 增强代理
type EnhancedProxy struct {
	config           *EnhancedProxyConfig
	connectionPool   *ConnectionPool
	retryOp          *RetryableOperation
	circuitBreaker   *CircuitBreaker
	healthChecker    *HealthChecker
	gracefulShutdown *GracefulShutdown
	timeoutManager   *TimeoutManager
	mutex            sync.RWMutex
	running          bool
	stats            *ProxyStats
}

// ProxyStats 代理统计信息
type ProxyStats struct {
	TotalConnections    int64 `json:"total_connections"`
	ActiveConnections   int64 `json:"active_connections"`
	FailedConnections   int64 `json:"failed_connections"`
	RetryAttempts       int64 `json:"retry_attempts"`
	CircuitBreakerTrips int64 `json:"circuit_breaker_trips"`
	HealthCheckFailures int64 `json:"health_check_failures"`
}

// NewEnhancedProxy 创建增强代理
func NewEnhancedProxy(config *EnhancedProxyConfig) *EnhancedProxy {
	if config == nil {
		config = DefaultEnhancedProxyConfig()
	}

	proxy := &EnhancedProxy{
		config:         config,
		connectionPool: NewConnectionPool(config.ConnectionPool),
		retryOp:        NewRetryableOperation("proxy_connection", config.Retry, config.CircuitBreaker),
		circuitBreaker: NewCircuitBreaker(config.CircuitBreaker),
		timeoutManager: NewTimeoutManager(10 * time.Second),
		stats:          &ProxyStats{},
	}

	// 设置断路器状态变化回调
	proxy.circuitBreaker.SetStateChangeCallback(func(from, to CircuitBreakerState) {
		if to == StateOpen {
			proxy.stats.CircuitBreakerTrips++
		}
		log.Logger.WithFields(logrus.Fields{
			"from": from,
			"to":   to,
		}).Warn("Circuit breaker state changed")
	})

	// 初始化健康检查
	if config.HealthCheck.Enabled {
		proxy.healthChecker = NewHealthChecker(config.HealthCheck.Interval)
		proxy.setupHealthChecks()
	}

	// 初始化优雅关闭
	if config.GracefulShutdown.Enabled {
		proxy.gracefulShutdown = NewGracefulShutdown(config.GracefulShutdown.Timeout)
		proxy.setupGracefulShutdown()
	}

	return proxy
}

// setupHealthChecks 设置健康检查
func (ep *EnhancedProxy) setupHealthChecks() {
	// 连接池健康检查
	ep.healthChecker.AddCheck("connection_pool", func() error {
		stats := ep.connectionPool.GetStats()
		if stats.ConnectionErrors > 10 {
			return fmt.Errorf("too many connection errors: %d", stats.ConnectionErrors)
		}
		return nil
	})

	// 断路器健康检查
	ep.healthChecker.AddCheck("circuit_breaker", func() error {
		if ep.circuitBreaker.GetState() == StateOpen {
			return errors.New("circuit breaker is open")
		}
		return nil
	})

	// 内存使用检查（简单示例）
	ep.healthChecker.AddCheck("memory", func() error {
		// 这里可以添加实际的内存检查逻辑
		return nil
	})
}

// setupGracefulShutdown 设置优雅关闭
func (ep *EnhancedProxy) setupGracefulShutdown() {
	ep.gracefulShutdown.AddShutdownFunc(func() error {
		log.Logger.Info("Stopping health checker")
		if ep.healthChecker != nil {
			ep.healthChecker.Stop()
		}
		return nil
	})

	ep.gracefulShutdown.AddShutdownFunc(func() error {
		log.Logger.Info("Closing connection pool")
		return ep.connectionPool.Close()
	})

	ep.gracefulShutdown.AddShutdownFunc(func() error {
		log.Logger.Info("Enhanced proxy shutdown complete")
		ep.mutex.Lock()
		ep.running = false
		ep.mutex.Unlock()
		return nil
	})
}

// Start 启动增强代理
func (ep *EnhancedProxy) Start() error {
	ep.mutex.Lock()
	defer ep.mutex.Unlock()

	if ep.running {
		return errors.New("proxy is already running")
	}

	ep.running = true

	// 启动健康检查
	if ep.healthChecker != nil {
		ep.healthChecker.Start()
		log.Logger.Info("Health checker started")
	}

	log.Logger.Info("Enhanced proxy started")
	return nil
}

// Stop 停止增强代理
func (ep *EnhancedProxy) Stop() error {
	ep.mutex.Lock()
	defer ep.mutex.Unlock()

	if !ep.running {
		return errors.New("proxy is not running")
	}

	if ep.gracefulShutdown != nil {
		return ep.gracefulShutdown.Shutdown()
	}

	// 手动关闭各组件
	if ep.healthChecker != nil {
		ep.healthChecker.Stop()
	}

	if err := ep.connectionPool.Close(); err != nil {
		log.Logger.WithError(err).Error("Error closing connection pool")
	}

	ep.running = false
	log.Logger.Info("Enhanced proxy stopped")
	return nil
}

// EstablishConnection 建立增强连接
func (ep *EnhancedProxy) EstablishConnection(ctx context.Context, addr string, tlsConfig *tls.Config, quicConfig *quic.Config) (quic.Session, error) {
	ep.mutex.RLock()
	if !ep.running {
		ep.mutex.RUnlock()
		return nil, errors.New("proxy is not running")
	}
	ep.mutex.RUnlock()

	// 检查健康状态
	if ep.healthChecker != nil && !ep.healthChecker.IsHealthy("circuit_breaker") {
		ep.stats.FailedConnections++
		return nil, errors.New("circuit breaker is unhealthy")
	}

	// 使用超时管理器
	ctx, cancel := ep.timeoutManager.WithTimeout(ctx, "establish_connection")
	defer cancel()

	// 尝试从连接池获取连接
	conn, err := ep.connectionPool.GetConnection(ctx, addr, tlsConfig, quicConfig)
	if err != nil {
		ep.stats.FailedConnections++
		log.Logger.WithFields(logrus.Fields{
			"addr":  addr,
			"error": err,
		}).Error("Failed to establish connection")
		return nil, fmt.Errorf("failed to establish connection to %s: %w", addr, err)
	}

	ep.stats.TotalConnections++
	ep.stats.ActiveConnections++

	log.Logger.WithFields(logrus.Fields{
		"addr": addr,
		"type": "enhanced_connection",
	}).Debug("Enhanced connection established")

	return conn, nil
}

// ReleaseConnection 释放连接
func (ep *EnhancedProxy) ReleaseConnection(addr string, conn quic.Session) {
	if conn == nil {
		return
	}

	ep.connectionPool.ReturnConnection(addr, conn)
	ep.stats.ActiveConnections--

	log.Logger.WithFields(logrus.Fields{
		"addr": addr,
		"type": "connection_release",
	}).Debug("Connection released")
}

// ExecuteWithRetry 执行带重试的操作
func (ep *EnhancedProxy) ExecuteWithRetry(ctx context.Context, operation func() error) error {
	ep.stats.RetryAttempts++
	return ep.retryOp.Execute(ctx, operation)
}

// ExecuteWithCircuitBreaker 执行带断路器的操作
func (ep *EnhancedProxy) ExecuteWithCircuitBreaker(operation func() error) error {
	return ep.circuitBreaker.Execute(operation)
}

// GetStats 获取代理统计信息
func (ep *EnhancedProxy) GetStats() *ProxyStats {
	return &ProxyStats{
		TotalConnections:    ep.stats.TotalConnections,
		ActiveConnections:   ep.stats.ActiveConnections,
		FailedConnections:   ep.stats.FailedConnections,
		RetryAttempts:       ep.stats.RetryAttempts,
		CircuitBreakerTrips: ep.stats.CircuitBreakerTrips,
		HealthCheckFailures: ep.stats.HealthCheckFailures,
	}
}

// GetHealthStatus 获取健康状态
func (ep *EnhancedProxy) GetHealthStatus() map[string]bool {
	if ep.healthChecker == nil {
		return map[string]bool{"enabled": false}
	}
	return ep.healthChecker.GetStatus()
}

// GetConnectionPoolStats 获取连接池统计信息
func (ep *EnhancedProxy) GetConnectionPoolStats() *PoolStats {
	return ep.connectionPool.GetStats()
}

// GetCircuitBreakerStats 获取断路器统计信息
func (ep *EnhancedProxy) GetCircuitBreakerStats() map[string]interface{} {
	return ep.circuitBreaker.GetStats()
}

// IsRunning 检查代理是否运行中
func (ep *EnhancedProxy) IsRunning() bool {
	ep.mutex.RLock()
	defer ep.mutex.RUnlock()
	return ep.running
}

// SetTimeout 设置特定操作的超时时间
func (ep *EnhancedProxy) SetTimeout(operation string, timeout time.Duration) {
	ep.timeoutManager.SetTimeout(operation, timeout)
}

// HandleConnectionError 处理连接错误
func (ep *EnhancedProxy) HandleConnectionError(addr string, err error) {
	ep.stats.FailedConnections++

	// 记录错误
	log.Logger.WithFields(logrus.Fields{
		"addr":  addr,
		"error": err,
		"type":  "connection_error",
	}).Error("Connection error occurred")

	// 检查是否需要触发断路器
	if IsRetryableError(err) {
		log.Logger.WithFields(logrus.Fields{
			"addr":  addr,
			"error": err,
		}).Warn("Retryable error detected")
	} else {
		log.Logger.WithFields(logrus.Fields{
			"addr":  addr,
			"error": err,
		}).Error("Non-retryable error detected")
	}
}

// WaitForShutdown 等待关闭信号
func (ep *EnhancedProxy) WaitForShutdown() <-chan struct{} {
	if ep.gracefulShutdown != nil {
		return ep.gracefulShutdown.ShutdownChan()
	}
	// 返回一个永远不会关闭的通道
	ch := make(chan struct{})
	return ch
}