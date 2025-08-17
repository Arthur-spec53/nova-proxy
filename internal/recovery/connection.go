package recovery

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"nova-proxy/pkg/log"
	"github.com/sirupsen/logrus"
	"github.com/qdeconinck/mp-quic"
)

// ConnectionPoolConfig 连接池配置
type ConnectionPoolConfig struct {
	MaxConnections    int           `json:"max_connections"`
	MaxIdleTime       time.Duration `json:"max_idle_time"`
	ConnectionTimeout time.Duration `json:"connection_timeout"`
	KeepAlive         time.Duration `json:"keep_alive"`
	RetryConfig       *RetryConfig  `json:"retry_config"`
}

// DefaultConnectionPoolConfig 返回默认连接池配置
func DefaultConnectionPoolConfig() *ConnectionPoolConfig {
	return &ConnectionPoolConfig{
		MaxConnections:    100,
		MaxIdleTime:       5 * time.Minute,
		ConnectionTimeout: 10 * time.Second,
		KeepAlive:         30 * time.Second,
		RetryConfig:       DefaultRetryConfig(),
	}
}

// PooledConnection 池化连接
type PooledConnection struct {
	conn       quic.Session
	lastUsed   time.Time
	inUse      int32 // atomic
	createdAt  time.Time
	remoteAddr string
}

// IsIdle 检查连接是否空闲
func (pc *PooledConnection) IsIdle() bool {
	return atomic.LoadInt32(&pc.inUse) == 0
}

// IsExpired 检查连接是否过期
func (pc *PooledConnection) IsExpired(maxIdleTime time.Duration) bool {
	return time.Since(pc.lastUsed) > maxIdleTime
}

// Acquire 获取连接
func (pc *PooledConnection) Acquire() bool {
	return atomic.CompareAndSwapInt32(&pc.inUse, 0, 1)
}

// Release 释放连接
func (pc *PooledConnection) Release() {
	pc.lastUsed = time.Now()
	atomic.StoreInt32(&pc.inUse, 0)
}

// Close 关闭连接
func (pc *PooledConnection) Close() error {
	if pc.conn != nil {
		return pc.conn.Close(errors.New("connection closed"))
	}
	return nil
}

// ConnectionPool QUIC连接池
type ConnectionPool struct {
	config      *ConnectionPoolConfig
	connections map[string][]*PooledConnection
	mutex       sync.RWMutex
	closed      int32 // atomic
	cleanupDone chan struct{}
	retryOp     *RetryableOperation
	stats       *PoolStats
}

// PoolStats 连接池统计
type PoolStats struct {
	TotalConnections   int64 `json:"total_connections"`
	ActiveConnections  int64 `json:"active_connections"`
	IdleConnections    int64 `json:"idle_connections"`
	ConnectionsCreated int64 `json:"connections_created"`
	ConnectionsReused  int64 `json:"connections_reused"`
	ConnectionErrors   int64 `json:"connection_errors"`
}

// NewConnectionPool 创建连接池
func NewConnectionPool(config *ConnectionPoolConfig) *ConnectionPool {
	if config == nil {
		config = DefaultConnectionPoolConfig()
	}

	pool := &ConnectionPool{
		config:      config,
		connections: make(map[string][]*PooledConnection),
		cleanupDone: make(chan struct{}),
		retryOp:     NewRetryableOperation("connection_pool", config.RetryConfig, nil),
		stats:       &PoolStats{},
	}

	// 启动清理协程
	go pool.cleanupLoop()

	return pool
}

// GetConnection 获取连接
func (cp *ConnectionPool) GetConnection(ctx context.Context, addr string, tlsConfig *tls.Config, quicConfig *quic.Config) (quic.Session, error) {
	if atomic.LoadInt32(&cp.closed) == 1 {
		return nil, errors.New("connection pool is closed")
	}

	// 尝试从池中获取现有连接
	if conn := cp.getFromPool(addr); conn != nil {
		atomic.AddInt64(&cp.stats.ConnectionsReused, 1)
		return conn, nil
	}

	// 创建新连接
	var conn quic.Session
	err := cp.retryOp.Execute(ctx, func() error {
		var err error
		conn, err = quic.DialAddr(addr, tlsConfig, quicConfig)
		if err != nil {
			atomic.AddInt64(&cp.stats.ConnectionErrors, 1)
			return fmt.Errorf("failed to dial %s: %w", addr, err)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	atomic.AddInt64(&cp.stats.ConnectionsCreated, 1)
	atomic.AddInt64(&cp.stats.TotalConnections, 1)
	atomic.AddInt64(&cp.stats.ActiveConnections, 1)

	log.Logger.WithFields(logrus.Fields{
		"addr": addr,
		"type": "new_connection",
	}).Debug("Created new QUIC connection")

	return conn, nil
}

// getFromPool 从池中获取连接
func (cp *ConnectionPool) getFromPool(addr string) quic.Session {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	connections, exists := cp.connections[addr]
	if !exists || len(connections) == 0 {
		return nil
	}

	// 查找可用的连接
	for i, pooledConn := range connections {
		if pooledConn.IsIdle() && !pooledConn.IsExpired(cp.config.MaxIdleTime) {
			if pooledConn.Acquire() {
				// 从池中移除
				cp.connections[addr] = append(connections[:i], connections[i+1:]...)
				atomic.AddInt64(&cp.stats.IdleConnections, -1)
				atomic.AddInt64(&cp.stats.ActiveConnections, 1)
				return pooledConn.conn
			}
		}
	}

	return nil
}

// ReturnConnection 归还连接到池
func (cp *ConnectionPool) ReturnConnection(addr string, conn quic.Session) {
	if atomic.LoadInt32(&cp.closed) == 1 {
		if conn != nil {
			conn.Close(errors.New("pool closed"))
		}
		return
	}

	if conn == nil {
		return
	}

	// 检查连接是否仍然有效
	select {
	case <-conn.Context().Done():
		// 连接已关闭
		atomic.AddInt64(&cp.stats.ActiveConnections, -1)
		atomic.AddInt64(&cp.stats.TotalConnections, -1)
		return
	default:
	}

	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	// 检查池是否已满
	connections := cp.connections[addr]
	if len(connections) >= cp.config.MaxConnections {
		// 池已满，关闭连接
		conn.Close(errors.New("pool full"))
		atomic.AddInt64(&cp.stats.ActiveConnections, -1)
		atomic.AddInt64(&cp.stats.TotalConnections, -1)
		return
	}

	// 创建池化连接并添加到池中
	pooledConn := &PooledConnection{
		conn:       conn,
		lastUsed:   time.Now(),
		createdAt:  time.Now(),
		remoteAddr: addr,
	}
	pooledConn.Release()

	cp.connections[addr] = append(connections, pooledConn)
	atomic.AddInt64(&cp.stats.ActiveConnections, -1)
	atomic.AddInt64(&cp.stats.IdleConnections, 1)

	log.Logger.WithFields(logrus.Fields{
		"addr": addr,
		"type": "return_connection",
	}).Debug("Returned connection to pool")
}

// cleanupLoop 清理过期连接
func (cp *ConnectionPool) cleanupLoop() {
	ticker := time.NewTicker(cp.config.MaxIdleTime / 2)
	defer ticker.Stop()

	for {
		select {
		case <-cp.cleanupDone:
			return
		case <-ticker.C:
			cp.cleanup()
		}
	}
}

// cleanup 清理过期和无效连接
func (cp *ConnectionPool) cleanup() {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	for addr, connections := range cp.connections {
		var validConnections []*PooledConnection
		for _, pooledConn := range connections {
			// 检查连接是否过期或无效
			if pooledConn.IsExpired(cp.config.MaxIdleTime) {
				pooledConn.Close()
				atomic.AddInt64(&cp.stats.IdleConnections, -1)
				atomic.AddInt64(&cp.stats.TotalConnections, -1)
				continue
			}

			// 检查连接是否仍然活跃
			select {
			case <-pooledConn.conn.Context().Done():
				// 连接已关闭
				atomic.AddInt64(&cp.stats.IdleConnections, -1)
				atomic.AddInt64(&cp.stats.TotalConnections, -1)
				continue
			default:
				validConnections = append(validConnections, pooledConn)
			}
		}

		if len(validConnections) == 0 {
			delete(cp.connections, addr)
		} else {
			cp.connections[addr] = validConnections
		}
	}
}

// GetStats 获取连接池统计信息
func (cp *ConnectionPool) GetStats() *PoolStats {
	return &PoolStats{
		TotalConnections:   atomic.LoadInt64(&cp.stats.TotalConnections),
		ActiveConnections:  atomic.LoadInt64(&cp.stats.ActiveConnections),
		IdleConnections:    atomic.LoadInt64(&cp.stats.IdleConnections),
		ConnectionsCreated: atomic.LoadInt64(&cp.stats.ConnectionsCreated),
		ConnectionsReused:  atomic.LoadInt64(&cp.stats.ConnectionsReused),
		ConnectionErrors:   atomic.LoadInt64(&cp.stats.ConnectionErrors),
	}
}

// Close 关闭连接池
func (cp *ConnectionPool) Close() error {
	if !atomic.CompareAndSwapInt32(&cp.closed, 0, 1) {
		return errors.New("connection pool already closed")
	}

	// 停止清理协程
	close(cp.cleanupDone)

	// 关闭所有连接
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	for addr, connections := range cp.connections {
		for _, pooledConn := range connections {
			pooledConn.Close()
		}
		delete(cp.connections, addr)
	}

	log.Logger.Info("Connection pool closed")
	return nil
}

// TimeoutManager 超时管理器
type TimeoutManager struct {
	defaultTimeout time.Duration
	timeouts       map[string]time.Duration
	mutex          sync.RWMutex
}

// NewTimeoutManager 创建超时管理器
func NewTimeoutManager(defaultTimeout time.Duration) *TimeoutManager {
	return &TimeoutManager{
		defaultTimeout: defaultTimeout,
		timeouts:       make(map[string]time.Duration),
	}
}

// SetTimeout 设置特定操作的超时时间
func (tm *TimeoutManager) SetTimeout(operation string, timeout time.Duration) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()
	tm.timeouts[operation] = timeout
}

// GetTimeout 获取操作的超时时间
func (tm *TimeoutManager) GetTimeout(operation string) time.Duration {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()
	if timeout, exists := tm.timeouts[operation]; exists {
		return timeout
	}
	return tm.defaultTimeout
}

// WithTimeout 为操作添加超时上下文
func (tm *TimeoutManager) WithTimeout(ctx context.Context, operation string) (context.Context, context.CancelFunc) {
	timeout := tm.GetTimeout(operation)
	return context.WithTimeout(ctx, timeout)
}

// GracefulShutdown 优雅关闭管理器
type GracefulShutdown struct {
	shutdownTimeout time.Duration
	shutdownFuncs   []func() error
	mutex           sync.Mutex
	shutdownChan    chan struct{}
	once            sync.Once
}

// NewGracefulShutdown 创建优雅关闭管理器
func NewGracefulShutdown(timeout time.Duration) *GracefulShutdown {
	return &GracefulShutdown{
		shutdownTimeout: timeout,
		shutdownChan:    make(chan struct{}),
	}
}

// AddShutdownFunc 添加关闭函数
func (gs *GracefulShutdown) AddShutdownFunc(fn func() error) {
	gs.mutex.Lock()
	defer gs.mutex.Unlock()
	gs.shutdownFuncs = append(gs.shutdownFuncs, fn)
}

// Shutdown 执行优雅关闭
func (gs *GracefulShutdown) Shutdown() error {
	var shutdownErr error
	gs.once.Do(func() {
		log.Logger.Info("Starting graceful shutdown")
		close(gs.shutdownChan)

		ctx, cancel := context.WithTimeout(context.Background(), gs.shutdownTimeout)
		defer cancel()

		done := make(chan error, 1)
		go func() {
			gs.mutex.Lock()
			funcs := make([]func() error, len(gs.shutdownFuncs))
			copy(funcs, gs.shutdownFuncs)
			gs.mutex.Unlock()

			for i := len(funcs) - 1; i >= 0; i-- {
				if err := funcs[i](); err != nil {
					log.Logger.WithError(err).Error("Error during shutdown")
					if shutdownErr == nil {
						shutdownErr = err
					}
				}
			}
			done <- shutdownErr
		}()

		select {
		case err := <-done:
			shutdownErr = err
			log.Logger.Info("Graceful shutdown completed")
		case <-ctx.Done():
			shutdownErr = errors.New("shutdown timeout exceeded")
			log.Logger.Error("Graceful shutdown timeout")
		}
	})
	return shutdownErr
}

// ShutdownChan 返回关闭信号通道
func (gs *GracefulShutdown) ShutdownChan() <-chan struct{} {
	return gs.shutdownChan
}