package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"../internal/security"
)

func main() {
	// 1. 创建安全配置
	securityConfig := &security.SecurityConfig{
		KeyManager: security.KeyManagerConfig{
			KeyStorePath:     "./keys",
			MasterPassword:   "your-secure-master-password",
			RotationInterval: 24 * time.Hour,
			KeyExpiry:        30 * 24 * time.Hour,
			BackupEnabled:    true,
			BackupPath:       "./keys/backup",
			EncryptionAlgo:   "AES256",
			KDFIterations:    100000,
		},
		CertManager: security.CertManagerConfig{
			CertStorePath:    "./certs",
			CAKeyPath:        "./certs/ca.key",
			CACertPath:       "./certs/ca.crt",
			DefaultKeySize:   2048,
			DefaultValidDays: 365,
			RenewalThreshold: 30 * 24 * time.Hour,
			AutoRenewal:      true,
			BackupEnabled:    true,
			BackupPath:       "./certs/backup",
		},
		AccessControl: security.AccessControlConfig{
			DataPath:           "./access_control",
			SessionTimeout:     30 * time.Minute,
			MaxFailedAttempts:  5,
			LockoutDuration:    15 * time.Minute,
			PasswordMinLength:  8,
			PasswordComplexity: true,
			RateLimitEnabled:   true,
			DefaultRateLimit:   100,
			RateLimitWindow:    time.Minute,
		},
		AuditLogger: security.AuditLoggerConfig{
			LogPath:        "./logs/audit.log",
			MaxFileSize:    100 * 1024 * 1024, // 100MB
			MaxFiles:       10,
			MaxAge:         30, // 30 days
			Compress:       true,
			AsyncLogging:   true,
			BufferSize:     1000,
			FlushInterval:  5 * time.Second,
			MinLevel:       security.AuditLevelInfo,
			EncryptLogs:    true,
			EncryptionKey:  "audit-log-encryption-key",
		},
	}

	// 2. 验证配置
	if err := securityConfig.Validate(); err != nil {
		log.Fatalf("Invalid security configuration: %v", err)
	}

	// 3. 创建安全管理器
	securityManager, err := security.NewSecurityManager(securityConfig)
	if err != nil {
		log.Fatalf("Failed to create security manager: %v", err)
	}
	defer securityManager.Stop()

	// 4. 启动安全管理器
	ctx := context.Background()
	if err := securityManager.Start(ctx); err != nil {
		log.Fatalf("Failed to start security manager: %v", err)
	}

	fmt.Println("Security manager started successfully!")

	// 5. 演示密钥管理
	fmt.Println("\n=== Key Management Demo ===")
	demonstrateKeyManagement(securityManager)

	// 6. 演示证书管理
	fmt.Println("\n=== Certificate Management Demo ===")
	demonstrateCertificateManagement(securityManager)

	// 7. 演示访问控制
	fmt.Println("\n=== Access Control Demo ===")
	demonstrateAccessControl(securityManager)

	// 8. 演示安全审计
	fmt.Println("\n=== Security Audit Demo ===")
	demonstrateSecurityAudit(securityManager)

	// 9. 获取安全指标
	fmt.Println("\n=== Security Metrics ===")
	metrics := securityManager.GetSecurityMetrics()
	for key, value := range metrics {
		fmt.Printf("%s: %v\n", key, value)
	}

	fmt.Println("\nSecurity example completed successfully!")
}

func demonstrateKeyManagement(sm *security.SecurityManager) {
	// 这里可以添加密钥管理的演示代码
	// 由于 SecurityManager 没有直接暴露 KeyManager，
	// 在实际应用中，你可能需要通过 SecurityManager 提供的接口来操作
	fmt.Println("Key management operations would be performed here...")
	fmt.Println("- Generate encryption keys")
	fmt.Println("- Rotate keys automatically")
	fmt.Println("- Backup keys securely")
}

func demonstrateCertificateManagement(sm *security.SecurityManager) {
	// 获取 TLS 配置
	tlsConfig, err := sm.GetTLSConfig("server")
	if err != nil {
		fmt.Printf("Failed to get TLS config: %v\n", err)
		return
	}

	if tlsConfig != nil {
		fmt.Println("TLS configuration loaded successfully")
		fmt.Printf("- Certificates: %d\n", len(tlsConfig.Certificates))
		fmt.Printf("- Min TLS Version: %d\n", tlsConfig.MinVersion)
	} else {
		fmt.Println("Certificate management operations would be performed here...")
		fmt.Println("- Generate server certificates")
		fmt.Println("- Auto-renew expiring certificates")
		fmt.Println("- Manage CA certificates")
	}
}

func demonstrateAccessControl(sm *security.SecurityManager) {
	// 演示用户认证
	token, err := sm.AuthenticateUser("admin", "password123")
	if err != nil {
		fmt.Printf("Authentication failed: %v\n", err)
	} else {
		fmt.Printf("Authentication successful, token: %s\n", token[:10]+"...")
	}

	// 演示权限检查
	hasPermission := sm.CheckPermission("user123", "read", "config")
	fmt.Printf("User has read permission on config: %v\n", hasPermission)
}

func demonstrateSecurityAudit(sm *security.SecurityManager) {
	// 记录安全事件
	event := security.DetailedAuditEvent{
		Level:     security.AuditLevelInfo,
		Category:  "authentication",
		Action:    "user_login",
		Timestamp: time.Now(),
		Message:   "User logged in successfully",
		Details: map[string]interface{}{
			"user_id":    "user123",
			"ip_address": "192.168.1.100",
			"user_agent": "Mozilla/5.0...",
		},
	}

	sm.LogSecurityEvent(event)
	fmt.Println("Security event logged successfully")
}