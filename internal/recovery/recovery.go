package recovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"nova-proxy/pkg/log"
	"github.com/sirupsen/logrus"
)

// RetryConfig 定义重试配置
type RetryConfig struct {
	MaxRetries    int           `json:"max_retries"`
	InitialDelay  time.Duration `json:"initial_delay"`
	MaxDelay      time.Duration `json:"max_delay"`
	BackoffFactor float64       `json:"backoff_factor"`
	Jitter        bool          `json:"jitter"`
}

// DefaultRetryConfig 返回默认重试配置
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxRetries:    3,
		InitialDelay:  100 * time.Millisecond,
		MaxDelay:      5 * time.Second,
		BackoffFactor: 2.0,
		Jitter:        true,
	}
}

// CircuitBreakerConfig 定义断路器配置
type CircuitBreakerConfig struct {
	FailureThreshold int           `json:"failure_threshold"`
	RecoveryTimeout  time.Duration `json:"recovery_timeout"`
	SuccessThreshold int           `json:"success_threshold"`
}

// DefaultCircuitBreakerConfig 返回默认断路器配置
func DefaultCircuitBreakerConfig() *CircuitBreakerConfig {
	return &CircuitBreakerConfig{
		FailureThreshold: 5,
		RecoveryTimeout:  30 * time.Second,
		SuccessThreshold: 3,
	}
}

// CircuitBreakerState 断路器状态
type CircuitBreakerState int

const (
	StateClosed CircuitBreakerState = iota
	StateOpen
	StateHalfOpen
)

// CircuitBreaker 断路器实现
type CircuitBreaker struct {
	config           *CircuitBreakerConfig
	state            int32 // atomic
	failureCount     int32 // atomic
	successCount     int32 // atomic
	lastFailureTime  int64 // atomic, unix nano
	mutex            sync.RWMutex
	onStateChange    func(from, to CircuitBreakerState)
}

// NewCircuitBreaker 创建新的断路器
func NewCircuitBreaker(config *CircuitBreakerConfig) *CircuitBreaker {
	if config == nil {
		config = DefaultCircuitBreakerConfig()
	}
	return &CircuitBreaker{
		config: config,
		state:  int32(StateClosed),
	}
}

// SetStateChangeCallback 设置状态变化回调
func (cb *CircuitBreaker) SetStateChangeCallback(callback func(from, to CircuitBreakerState)) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	cb.onStateChange = callback
}

// Execute 执行操作，如果断路器开启则直接返回错误
func (cb *CircuitBreaker) Execute(operation func() error) error {
	if !cb.canExecute() {
		return errors.New("circuit breaker is open")
	}

	err := operation()
	if err != nil {
		cb.recordFailure()
		return err
	}

	cb.recordSuccess()
	return nil
}

// canExecute 检查是否可以执行操作
func (cb *CircuitBreaker) canExecute() bool {
	state := CircuitBreakerState(atomic.LoadInt32(&cb.state))
	switch state {
	case StateClosed:
		return true
	case StateOpen:
		// 检查是否可以进入半开状态
		lastFailure := atomic.LoadInt64(&cb.lastFailureTime)
		if time.Since(time.Unix(0, lastFailure)) > cb.config.RecoveryTimeout {
			cb.setState(StateHalfOpen)
			return true
		}
		return false
	case StateHalfOpen:
		return true
	default:
		return false
	}
}

// recordFailure 记录失败
func (cb *CircuitBreaker) recordFailure() {
	atomic.StoreInt64(&cb.lastFailureTime, time.Now().UnixNano())
	atomic.StoreInt32(&cb.successCount, 0)
	failures := atomic.AddInt32(&cb.failureCount, 1)

	state := CircuitBreakerState(atomic.LoadInt32(&cb.state))
	if state == StateClosed && int(failures) >= cb.config.FailureThreshold {
		cb.setState(StateOpen)
	} else if state == StateHalfOpen {
		cb.setState(StateOpen)
	}
}

// recordSuccess 记录成功
func (cb *CircuitBreaker) recordSuccess() {
	atomic.StoreInt32(&cb.failureCount, 0)
	successes := atomic.AddInt32(&cb.successCount, 1)

	state := CircuitBreakerState(atomic.LoadInt32(&cb.state))
	if state == StateHalfOpen && int(successes) >= cb.config.SuccessThreshold {
		cb.setState(StateClosed)
	}
}

// setState 设置状态
func (cb *CircuitBreaker) setState(newState CircuitBreakerState) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	oldState := CircuitBreakerState(atomic.LoadInt32(&cb.state))
	if oldState == newState {
		return
	}

	atomic.StoreInt32(&cb.state, int32(newState))
	log.Logger.WithFields(logrus.Fields{
		"from": oldState,
		"to":   newState,
	}).Info("Circuit breaker state changed")

	if cb.onStateChange != nil {
		cb.onStateChange(oldState, newState)
	}
}

// GetState 获取当前状态
func (cb *CircuitBreaker) GetState() CircuitBreakerState {
	return CircuitBreakerState(atomic.LoadInt32(&cb.state))
}

// GetStats 获取统计信息
func (cb *CircuitBreaker) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"state":         cb.GetState(),
		"failure_count": atomic.LoadInt32(&cb.failureCount),
		"success_count": atomic.LoadInt32(&cb.successCount),
	}
}

// RetryableOperation 可重试操作的包装器
type RetryableOperation struct {
	config         *RetryConfig
	circuitBreaker *CircuitBreaker
	name           string
}

// NewRetryableOperation 创建可重试操作
func NewRetryableOperation(name string, retryConfig *RetryConfig, cbConfig *CircuitBreakerConfig) *RetryableOperation {
	if retryConfig == nil {
		retryConfig = DefaultRetryConfig()
	}

	var cb *CircuitBreaker
	if cbConfig != nil {
		cb = NewCircuitBreaker(cbConfig)
	}

	return &RetryableOperation{
		config:         retryConfig,
		circuitBreaker: cb,
		name:           name,
	}
}

// Execute 执行可重试操作
func (ro *RetryableOperation) Execute(ctx context.Context, operation func() error) error {
	return ro.ExecuteWithResult(ctx, func() (interface{}, error) {
		return nil, operation()
	})
}

// ExecuteWithResult 执行可重试操作并返回结果
func (ro *RetryableOperation) ExecuteWithResult(ctx context.Context, operation func() (interface{}, error)) error {
	var lastErr error

	for attempt := 0; attempt <= ro.config.MaxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// 如果有断路器，先检查断路器状态
		if ro.circuitBreaker != nil {
			err := ro.circuitBreaker.Execute(func() error {
				_, err := operation()
				return err
			})
			if err != nil {
				lastErr = err
				if err.Error() == "circuit breaker is open" {
					return fmt.Errorf("%s: %w", ro.name, err)
				}
			} else {
				return nil
			}
		} else {
			_, err := operation()
			if err != nil {
				lastErr = err
			} else {
				return nil
			}
		}

		// 如果是最后一次尝试，直接返回错误
		if attempt == ro.config.MaxRetries {
			break
		}

		// 计算延迟时间
		delay := ro.calculateDelay(attempt)
		log.Logger.WithFields(logrus.Fields{
			"operation": ro.name,
			"attempt":   attempt + 1,
			"delay":     delay,
			"error":     lastErr,
		}).Warn("Operation failed, retrying")

		// 等待重试
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
			continue
		}
	}

	return fmt.Errorf("%s failed after %d attempts: %w", ro.name, ro.config.MaxRetries+1, lastErr)
}

// calculateDelay 计算延迟时间
func (ro *RetryableOperation) calculateDelay(attempt int) time.Duration {
	delay := time.Duration(float64(ro.config.InitialDelay) * pow(ro.config.BackoffFactor, float64(attempt)))
	if delay > ro.config.MaxDelay {
		delay = ro.config.MaxDelay
	}

	// 添加抖动
	if ro.config.Jitter {
		jitter := time.Duration(float64(delay) * 0.1 * (2*rand() - 1))
		delay += jitter
	}

	return delay
}

// pow 简单的幂运算实现
func pow(base, exp float64) float64 {
	result := 1.0
	for i := 0; i < int(exp); i++ {
		result *= base
	}
	return result
}

// rand 简单的随机数生成
func rand() float64 {
	return float64(time.Now().UnixNano()%1000) / 1000.0
}

// IsRetryableError 判断错误是否可重试
func IsRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// 网络相关错误通常可重试
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout() || netErr.Temporary()
	}

	// 检查常见的可重试错误
	errorStr := err.Error()
	retryableErrors := []string{
		"connection refused",
		"connection reset",
		"connection timeout",
		"network unreachable",
		"host unreachable",
		"no route to host",
		"temporary failure",
		"service unavailable",
	}

	for _, retryableErr := range retryableErrors {
		if contains(errorStr, retryableErr) {
			return true
		}
	}

	return false
}

// contains 检查字符串是否包含子字符串
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// HealthChecker 健康检查器
type HealthChecker struct {
	checks   map[string]func() error
	mutex    sync.RWMutex
	interval time.Duration
	ctx      context.Context
	cancel   context.CancelFunc
	status   map[string]bool
}

// NewHealthChecker 创建健康检查器
func NewHealthChecker(interval time.Duration) *HealthChecker {
	ctx, cancel := context.WithCancel(context.Background())
	return &HealthChecker{
		checks:   make(map[string]func() error),
		interval: interval,
		ctx:      ctx,
		cancel:   cancel,
		status:   make(map[string]bool),
	}
}

// AddCheck 添加健康检查
func (hc *HealthChecker) AddCheck(name string, check func() error) {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()
	hc.checks[name] = check
	hc.status[name] = true // 默认健康
}

// Start 启动健康检查
func (hc *HealthChecker) Start() {
	go func() {
		ticker := time.NewTicker(hc.interval)
		defer ticker.Stop()

		for {
			select {
			case <-hc.ctx.Done():
				return
			case <-ticker.C:
				hc.runChecks()
			}
		}
	}()
}

// Stop 停止健康检查
func (hc *HealthChecker) Stop() {
	hc.cancel()
}

// runChecks 运行所有健康检查
func (hc *HealthChecker) runChecks() {
	hc.mutex.RLock()
	checks := make(map[string]func() error)
	for name, check := range hc.checks {
		checks[name] = check
	}
	hc.mutex.RUnlock()

	for name, check := range checks {
		err := check()
		hc.mutex.Lock()
		oldStatus := hc.status[name]
		newStatus := err == nil
		hc.status[name] = newStatus
		hc.mutex.Unlock()

		if oldStatus != newStatus {
			if newStatus {
				log.Logger.WithField("check", name).Info("Health check recovered")
			} else {
				log.Logger.WithFields(logrus.Fields{
					"check": name,
					"error": err,
				}).Error("Health check failed")
			}
		}
	}
}

// IsHealthy 检查指定组件是否健康
func (hc *HealthChecker) IsHealthy(name string) bool {
	hc.mutex.RLock()
	defer hc.mutex.RUnlock()
	return hc.status[name]
}

// GetStatus 获取所有组件的健康状态
func (hc *HealthChecker) GetStatus() map[string]bool {
	hc.mutex.RLock()
	defer hc.mutex.RUnlock()
	status := make(map[string]bool)
	for name, healthy := range hc.status {
		status[name] = healthy
	}
	return status
}