package recovery

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"nova-proxy/pkg/log"
	"github.com/sirupsen/logrus"
	"github.com/qdeconinck/mp-quic"
)

// ProxyIntegration 代理集成器
type ProxyIntegration struct {
	enhancedProxy *EnhancedProxy
	config        *EnhancedProxyConfig
	mutex         sync.RWMutex
	initialized   bool
}

// NewProxyIntegration 创建代理集成器
func NewProxyIntegration(config *EnhancedProxyConfig) *ProxyIntegration {
	if config == nil {
		config = DefaultEnhancedProxyConfig()
	}

	return &ProxyIntegration{
		config: config,
	}
}

// Initialize 初始化集成器
func (pi *ProxyIntegration) Initialize() error {
	pi.mutex.Lock()
	defer pi.mutex.Unlock()

	if pi.initialized {
		return nil
	}

	pi.enhancedProxy = NewEnhancedProxy(pi.config)
	if err := pi.enhancedProxy.Start(); err != nil {
		return fmt.Errorf("failed to start enhanced proxy: %w", err)
	}

	pi.initialized = true
	log.Logger.Info("Proxy integration initialized successfully")
	return nil
}

// Shutdown 关闭集成器
func (pi *ProxyIntegration) Shutdown() error {
	pi.mutex.Lock()
	defer pi.mutex.Unlock()

	if !pi.initialized {
		return nil
	}

	if err := pi.enhancedProxy.Stop(); err != nil {
		return fmt.Errorf("failed to stop enhanced proxy: %w", err)
	}

	pi.initialized = false
	log.Logger.Info("Proxy integration shutdown successfully")
	return nil
}

// EstablishQUICConnection 建立增强的 QUIC 连接
func (pi *ProxyIntegration) EstablishQUICConnection(ctx context.Context, addr string, tlsConfig *tls.Config, quicConfig *quic.Config) (quic.Session, error) {
	pi.mutex.RLock()
	if !pi.initialized {
		pi.mutex.RUnlock()
		return nil, fmt.Errorf("proxy integration not initialized")
	}
	enhancedProxy := pi.enhancedProxy
	pi.mutex.RUnlock()

	return enhancedProxy.EstablishConnection(ctx, addr, tlsConfig, quicConfig)
}

// ReleaseQUICConnection 释放 QUIC 连接
func (pi *ProxyIntegration) ReleaseQUICConnection(addr string, session quic.Session) {
	pi.mutex.RLock()
	if !pi.initialized {
		pi.mutex.RUnlock()
		return
	}
	enhancedProxy := pi.enhancedProxy
	pi.mutex.RUnlock()

	enhancedProxy.ReleaseConnection(addr, session)
}

// ExecuteWithRecovery 执行带恢复机制的操作
func (pi *ProxyIntegration) ExecuteWithRecovery(ctx context.Context, operation func() error) error {
	pi.mutex.RLock()
	if !pi.initialized {
		pi.mutex.RUnlock()
		return fmt.Errorf("proxy integration not initialized")
	}
	enhancedProxy := pi.enhancedProxy
	pi.mutex.RUnlock()

	// 使用断路器和重试机制
	return enhancedProxy.ExecuteWithCircuitBreaker(func() error {
		return enhancedProxy.ExecuteWithRetry(ctx, operation)
	})
}

// GetIntegrationStats 获取集成统计信息
func (pi *ProxyIntegration) GetIntegrationStats() map[string]interface{} {
	pi.mutex.RLock()
	if !pi.initialized {
		pi.mutex.RUnlock()
		return map[string]interface{}{
			"initialized": false,
			"error":       "not initialized",
		}
	}
	enhancedProxy := pi.enhancedProxy
	pi.mutex.RUnlock()

	return map[string]interface{}{
		"initialized":         true,
		"proxy_stats":         enhancedProxy.GetStats(),
		"health_status":       enhancedProxy.GetHealthStatus(),
		"connection_pool":     enhancedProxy.GetConnectionPoolStats(),
		"circuit_breaker":     enhancedProxy.GetCircuitBreakerStats(),
		"running":             enhancedProxy.IsRunning(),
	}
}

// IsHealthy 检查集成器健康状态
func (pi *ProxyIntegration) IsHealthy() bool {
	pi.mutex.RLock()
	if !pi.initialized {
		pi.mutex.RUnlock()
		return false
	}
	enhancedProxy := pi.enhancedProxy
	pi.mutex.RUnlock()

	healthStatus := enhancedProxy.GetHealthStatus()
	for _, healthy := range healthStatus {
		if !healthy {
			return false
		}
	}
	return true
}

// ClientConnectionWrapper 客户端连接包装器
type ClientConnectionWrapper struct {
	integration *ProxyIntegration
	session     quic.Session
	addr        string
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewClientConnectionWrapper 创建客户端连接包装器
func NewClientConnectionWrapper(integration *ProxyIntegration, addr string, tlsConfig *tls.Config, quicConfig *quic.Config) (*ClientConnectionWrapper, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	session, err := integration.EstablishQUICConnection(ctx, addr, tlsConfig, quicConfig)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to establish QUIC connection: %w", err)
	}

	return &ClientConnectionWrapper{
		integration: integration,
		session:     session,
		addr:        addr,
		ctx:         ctx,
		cancel:      cancel,
	}, nil
}

// GetSession 获取 QUIC 会话
func (ccw *ClientConnectionWrapper) GetSession() quic.Session {
	return ccw.session
}

// OpenStream 打开流
func (ccw *ClientConnectionWrapper) OpenStream() (quic.Stream, error) {
	var stream quic.Stream
	err := ccw.integration.ExecuteWithRecovery(ccw.ctx, func() error {
		var err error
		stream, err = ccw.session.OpenStream()
		return err
	})
	return stream, err
}

// AcceptStream 接受流
func (ccw *ClientConnectionWrapper) AcceptStream() (quic.Stream, error) {
	var stream quic.Stream
	err := ccw.integration.ExecuteWithRecovery(ccw.ctx, func() error {
		var err error
		stream, err = ccw.session.AcceptStream()
		return err
	})
	return stream, err
}

// Close 关闭连接
func (ccw *ClientConnectionWrapper) Close() error {
	defer ccw.cancel()

	if ccw.session != nil {
		ccw.integration.ReleaseQUICConnection(ccw.addr, ccw.session)
		ccw.session = nil
	}

	log.Logger.WithFields(logrus.Fields{
		"addr": ccw.addr,
		"type": "client_connection_close",
	}).Debug("Client connection closed")

	return nil
}

// ServerConnectionWrapper 服务器连接包装器
type ServerConnectionWrapper struct {
	integration *ProxyIntegration
	session     quic.Session
	addr        string
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewServerConnectionWrapper 创建服务器连接包装器
func NewServerConnectionWrapper(integration *ProxyIntegration, session quic.Session) *ServerConnectionWrapper {
	ctx, cancel := context.WithCancel(context.Background())

	return &ServerConnectionWrapper{
		integration: integration,
		session:     session,
		addr:        session.RemoteAddr().String(),
		ctx:         ctx,
		cancel:      cancel,
	}
}

// GetSession 获取 QUIC 会话
func (scw *ServerConnectionWrapper) GetSession() quic.Session {
	return scw.session
}

// AcceptStream 接受流
func (scw *ServerConnectionWrapper) AcceptStream() (quic.Stream, error) {
	var stream quic.Stream
	err := scw.integration.ExecuteWithRecovery(scw.ctx, func() error {
		var err error
		stream, err = scw.session.AcceptStream()
		return err
	})
	return stream, err
}

// OpenStream 打开流
func (scw *ServerConnectionWrapper) OpenStream() (quic.Stream, error) {
	var stream quic.Stream
	err := scw.integration.ExecuteWithRecovery(scw.ctx, func() error {
		var err error
		stream, err = scw.session.OpenStream()
		return err
	})
	return stream, err
}

// Close 关闭连接
func (scw *ServerConnectionWrapper) Close() error {
	defer scw.cancel()

	if scw.session != nil {
		scw.integration.ReleaseQUICConnection(scw.addr, scw.session)
		scw.session = nil
	}

	log.Logger.WithFields(logrus.Fields{
		"addr": scw.addr,
		"type": "server_connection_close",
	}).Debug("Server connection closed")

	return nil
}

// HandleConnectionError 处理连接错误
func (scw *ServerConnectionWrapper) HandleConnectionError(err error) {
	scw.integration.enhancedProxy.HandleConnectionError(scw.addr, err)
}

// GlobalProxyIntegration 全局代理集成实例
var (
	globalIntegration *ProxyIntegration
	globalMutex       sync.RWMutex
)

// InitializeGlobalIntegration 初始化全局集成
func InitializeGlobalIntegration(config *EnhancedProxyConfig) error {
	globalMutex.Lock()
	defer globalMutex.Unlock()

	if globalIntegration != nil {
		return fmt.Errorf("global integration already initialized")
	}

	globalIntegration = NewProxyIntegration(config)
	if err := globalIntegration.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize global integration: %w", err)
	}

	log.Logger.Info("Global proxy integration initialized")
	return nil
}

// GetGlobalIntegration 获取全局集成实例
func GetGlobalIntegration() *ProxyIntegration {
	globalMutex.RLock()
	defer globalMutex.RUnlock()
	return globalIntegration
}

// ShutdownGlobalIntegration 关闭全局集成
func ShutdownGlobalIntegration() error {
	globalMutex.Lock()
	defer globalMutex.Unlock()

	if globalIntegration == nil {
		return nil
	}

	if err := globalIntegration.Shutdown(); err != nil {
		return fmt.Errorf("failed to shutdown global integration: %w", err)
	}

	globalIntegration = nil
	log.Logger.Info("Global proxy integration shutdown")
	return nil
}

// IsGlobalIntegrationHealthy 检查全局集成健康状态
func IsGlobalIntegrationHealthy() bool {
	globalMutex.RLock()
	defer globalMutex.RUnlock()

	if globalIntegration == nil {
		return false
	}

	return globalIntegration.IsHealthy()
}

// GetGlobalIntegrationStats 获取全局集成统计信息
func GetGlobalIntegrationStats() map[string]interface{} {
	globalMutex.RLock()
	defer globalMutex.RUnlock()

	if globalIntegration == nil {
		return map[string]interface{}{
			"initialized": false,
			"error":       "global integration not initialized",
		}
	}

	return globalIntegration.GetIntegrationStats()
}