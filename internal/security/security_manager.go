package security

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"sync"
	"time"
)

// SecurityManager 安全管理器
type SecurityManager struct {
	config        *SecurityConfig
	keyManager    *KeyManager
	certManager   *CertManager
	accessControl *AccessController
	auditLogger   *EnhancedAuditLogger
	mu            sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	running       bool
}

// NewSecurityManager 创建新的安全管理器
func NewSecurityManager(config *SecurityConfig) (*SecurityManager, error) {
	if config == nil {
		return nil, fmt.Errorf("security config cannot be nil")
	}

	ctx, cancel := context.WithCancel(context.Background())

	sm := &SecurityManager{
		config: config,
		ctx:    ctx,
		cancel: cancel,
	}

	// 初始化各个安全组件
	if err := sm.initializeComponents(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize security components: %w", err)
	}

	return sm, nil
}

// initializeComponents 初始化安全组件
func (sm *SecurityManager) initializeComponents() error {
	var err error

	// 初始化审计日志器（优先初始化，其他组件可能需要记录审计日志）
	if sm.config.AuditLogger != nil {
		sm.auditLogger, err = NewEnhancedAuditLogger(sm.config.AuditLogger)
		if err != nil {
			return fmt.Errorf("failed to initialize audit logger: %w", err)
		}
	}

	// 初始化密钥管理器
	if sm.config.KeyManager != nil {
		sm.keyManager, err = NewKeyManager(sm.config.KeyManager)
		if err != nil {
			return fmt.Errorf("failed to initialize key manager: %w", err)
		}
	}

	// 初始化证书管理器
	if sm.config.CertManager != nil {
		sm.certManager, err = NewCertManager(sm.config.CertManager, sm.keyManager)
		if err != nil {
			return fmt.Errorf("failed to initialize cert manager: %w", err)
		}
	}

	// 初始化访问控制器
	if sm.config.AccessControl != nil {
		sm.accessControl, err = NewAccessController(sm.config.AccessControl)
		if err != nil {
			return fmt.Errorf("failed to initialize access controller: %w", err)
		}
	}

	return nil
}

// Start 启动安全管理器
func (sm *SecurityManager) Start() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.running {
		return fmt.Errorf("security manager is already running")
	}

	// 启动各个组件的后台任务
	if sm.keyManager != nil {
		sm.wg.Add(1)
		go func() {
			defer sm.wg.Done()
			sm.keyManagerWorker()
		}()
	}

	if sm.certManager != nil {
		sm.wg.Add(1)
		go func() {
			defer sm.wg.Done()
			sm.certManagerWorker()
		}()
	}

	if sm.accessControl != nil {
		sm.wg.Add(1)
		go func() {
			defer sm.wg.Done()
			sm.accessControlWorker()
		}()
	}

	if sm.auditLogger != nil {
		sm.wg.Add(1)
		go func() {
			defer sm.wg.Done()
			sm.auditLoggerWorker()
		}()
	}

	// 启动安全监控
	if sm.config.Monitoring != nil && sm.config.Monitoring.Enabled {
		sm.wg.Add(1)
		go func() {
			defer sm.wg.Done()
			sm.securityMonitorWorker()
		}()
	}

	sm.running = true

	// 记录启动事件
	if sm.auditLogger != nil {
		sm.auditLogger.LogEvent(DetailedAuditEvent{
			Level:     AuditLevelInfo,
			Category:  AuditCategorySystem,
			Action:    "security_manager_start",
			Timestamp: time.Now(),
			Message:   "Security manager started successfully",
		})
	}

	return nil
}

// Stop 停止安全管理器
func (sm *SecurityManager) Stop() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if !sm.running {
		return nil
	}

	// 记录停止事件
	if sm.auditLogger != nil {
		sm.auditLogger.LogEvent(DetailedAuditEvent{
			Level:     AuditLevelInfo,
			Category:  AuditCategorySystem,
			Action:    "security_manager_stop",
			Timestamp: time.Now(),
			Message:   "Security manager stopping",
		})
	}

	// 取消上下文，停止所有工作协程
	sm.cancel()

	// 等待所有工作协程结束
	sm.wg.Wait()

	// 关闭各个组件
	if sm.keyManager != nil {
		if err := sm.keyManager.Close(); err != nil {
			log.Printf("Error closing key manager: %v", err)
		}
	}

	if sm.certManager != nil {
		if err := sm.certManager.Close(); err != nil {
			log.Printf("Error closing cert manager: %v", err)
		}
	}

	if sm.accessControl != nil {
		if err := sm.accessControl.Close(); err != nil {
			log.Printf("Error closing access controller: %v", err)
		}
	}

	if sm.auditLogger != nil {
		if err := sm.auditLogger.Close(); err != nil {
			log.Printf("Error closing audit logger: %v", err)
		}
	}

	sm.running = false
	return nil
}

// GetTLSConfig 获取TLS配置
func (sm *SecurityManager) GetTLSConfig(serverName string) (*tls.Config, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.certManager == nil {
		return nil, fmt.Errorf("cert manager not initialized")
	}

	return sm.certManager.LoadTLSConfig(serverName)
}

// ValidateAccess 验证访问权限
func (sm *SecurityManager) ValidateAccess(userID, resource, action string) error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.accessControl == nil {
		return fmt.Errorf("access controller not initialized")
	}

	// 将资源和动作转换为权限
	var permission Permission
	switch action {
	case "read":
		permission = PermissionRead
	case "write":
		permission = PermissionWrite
	case "execute":
		permission = PermissionExecute
	case "admin":
		permission = PermissionAdmin
	case "connect":
		permission = PermissionConnect
	case "proxy":
		permission = PermissionProxy
	default:
		permission = PermissionRead
	}

	if !sm.accessControl.CheckPermission(userID, permission) {
		return fmt.Errorf("access denied: user %s does not have %s permission for resource %s", userID, action, resource)
	}
	return nil
}

// AuthenticateUser 用户认证
func (sm *SecurityManager) AuthenticateUser(username, password string) (string, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.accessControl == nil {
		return "", fmt.Errorf("access controller not initialized")
	}

	session, err := sm.accessControl.Authenticate(username, password, "", "")
	if err != nil {
		return "", err
	}
	return session.Token, nil
}

// LogSecurityEvent 记录安全事件
func (sm *SecurityManager) LogSecurityEvent(event DetailedAuditEvent) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.auditLogger != nil {
		sm.auditLogger.LogEvent(event)
	}
}

// GetSecurityMetrics 获取安全指标
func (sm *SecurityManager) GetSecurityMetrics() map[string]interface{} {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	metrics := make(map[string]interface{})

	// 密钥管理指标
	if sm.keyManager != nil {
		keys := sm.keyManager.ListKeys()
		metrics["total_keys"] = len(keys)
		expiredKeys := 0
		for _, key := range keys {
			if time.Now().After(key.ExpiresAt) {
				expiredKeys++
			}
		}
		metrics["expired_keys"] = expiredKeys
	}

	// 证书管理指标
	if sm.certManager != nil {
		certs := sm.certManager.ListCertificates()
		metrics["total_certificates"] = len(certs)
		expiringSoon := 0
		for _, cert := range certs {
			if time.Until(cert.NotAfter) < 30*24*time.Hour {
				expiringSoon++
			}
		}
		metrics["certificates_expiring_soon"] = expiringSoon
	}

	// 访问控制指标
	if sm.accessControl != nil {
		metrics["active_sessions"] = sm.accessControl.GetActiveSessionCount()
	}

	// 审计日志指标
	if sm.auditLogger != nil {
		stats := sm.auditLogger.GetStatistics()
		metrics["audit_stats"] = stats
	}

	return metrics
}

// keyManagerWorker 密钥管理器工作协程
func (sm *SecurityManager) keyManagerWorker() {
	ticker := time.NewTicker(1 * time.Hour) // 每小时检查一次
	defer ticker.Stop()

	for {
		select {
		case <-sm.ctx.Done():
			return
		case <-ticker.C:
			// 检查密钥轮换
			if sm.keyManager != nil {
				keys := sm.keyManager.ListKeys()
				for _, key := range keys {
					if time.Now().After(key.RotationDue) {
						if err := sm.keyManager.RotateKey(key.ID); err != nil {
							log.Printf("Failed to rotate key %s: %v", key.ID, err)
							if sm.auditLogger != nil {
								sm.auditLogger.LogEvent(DetailedAuditEvent{
									Level:     AuditLevelError,
									Category:  "key_management",
									Action:    "key_rotation_failed",
									Timestamp: time.Now(),
									Message:   fmt.Sprintf("Failed to rotate key %s: %v", key.ID, err),
									Details: map[string]interface{}{
										"key_id": key.ID,
										"error":  err.Error(),
									},
								})
							}
						} else {
							if sm.auditLogger != nil {
								sm.auditLogger.LogEvent(DetailedAuditEvent{
									Level:     AuditLevelInfo,
									Category:  "key_management",
									Action:    "key_rotated",
									Timestamp: time.Now(),
									Message:   fmt.Sprintf("Key %s rotated successfully", key.ID),
									Details: map[string]interface{}{
										"key_id": key.ID,
									},
								})
							}
						}
					}
				}
			}
		}
	}
}

// certManagerWorker 证书管理器工作协程
func (sm *SecurityManager) certManagerWorker() {
	ticker := time.NewTicker(6 * time.Hour) // 每6小时检查一次
	defer ticker.Stop()

	for {
		select {
		case <-sm.ctx.Done():
			return
		case <-ticker.C:
			// 检查证书续期
			if sm.certManager != nil {
				// 这里可以添加证书续期检查逻辑
				// 由于CertManager结构体中没有列出证书的方法，这里暂时跳过
			}
		}
	}
}

// accessControlWorker 访问控制工作协程
func (sm *SecurityManager) accessControlWorker() {
	ticker := time.NewTicker(30 * time.Minute) // 每30分钟检查一次
	defer ticker.Stop()

	for {
		select {
		case <-sm.ctx.Done():
			return
		case <-ticker.C:
			// 清理过期会话
			if sm.accessControl != nil {
				sm.accessControl.cleanupExpiredSessions()
				if sm.auditLogger != nil {
					sm.auditLogger.LogEvent(DetailedAuditEvent{
						Level:     AuditLevelInfo,
						Category:  "session_management",
						Action:    "expired_sessions_cleaned",
						Timestamp: time.Now(),
						Message:   "Cleaned up expired sessions",
					})
				}
			}
		}
	}
}

// auditLoggerWorker 审计日志工作协程
func (sm *SecurityManager) auditLoggerWorker() {
	ticker := time.NewTicker(1 * time.Hour) // 每小时检查一次
	defer ticker.Stop()

	for {
		select {
		case <-sm.ctx.Done():
			return
		case <-ticker.C:
			// 执行日志轮转和清理
			if sm.auditLogger != nil {
				if err := sm.auditLogger.RotateLog(); err != nil {
					log.Printf("Failed to rotate audit log: %v", err)
				}
				// 清理旧文件的逻辑已经在 RotateLog 中处理
			}
		}
	}
}

// securityMonitorWorker 安全监控工作协程
func (sm *SecurityManager) securityMonitorWorker() {
	var reportingInterval time.Duration = 24 * time.Hour
	if sm.config.Monitoring.ReportingInterval > 0 {
		reportingInterval = sm.config.Monitoring.ReportingInterval
	}

	ticker := time.NewTicker(reportingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-sm.ctx.Done():
			return
		case <-ticker.C:
			// 生成安全报告
			metrics := sm.GetSecurityMetrics()
				if sm.auditLogger != nil {
					sm.auditLogger.LogEvent(DetailedAuditEvent{
						Level:     AuditLevelInfo,
						Category:  "monitoring",
						Action:    "security_report",
						Timestamp: time.Now(),
						Message:   "Security monitoring report generated",
						Details:   metrics,
					})
				}
		}
	}
}

// IsRunning 检查安全管理器是否正在运行
func (sm *SecurityManager) IsRunning() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.running
}

// GetConfig 获取安全配置
func (sm *SecurityManager) GetConfig() *SecurityConfig {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.config
}

// UpdateConfig 更新安全配置
func (sm *SecurityManager) UpdateConfig(newConfig *SecurityConfig) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if err := ValidateSecurityConfig(newConfig); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	sm.config = newConfig

	if sm.auditLogger != nil {
		sm.auditLogger.LogEvent(DetailedAuditEvent{
			Level:     AuditLevelInfo,
			Category:  "configuration",
			Action:    "config_updated",
			Timestamp: time.Now(),
			Message:   "Security configuration updated",
		})
	}

	return nil
}