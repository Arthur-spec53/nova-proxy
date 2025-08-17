package security

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"time"
)

// SecurityIntegration 安全集成示例
type SecurityIntegration struct {
	securityManager *SecurityManager
	server          *http.Server
}

// NewSecurityIntegration 创建安全集成实例
func NewSecurityIntegration(configPath string) (*SecurityIntegration, error) {
	// 加载安全配置
	config, err := LoadSecurityConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load security config: %v", err)
	}

	// 创建安全管理器
	securityManager, err := NewSecurityManager(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create security manager: %v", err)
	}

	return &SecurityIntegration{
		securityManager: securityManager,
	}, nil
}

// Start 启动安全集成服务
func (si *SecurityIntegration) Start(ctx context.Context, addr string) error {
	// 启动安全管理器
	if err := si.securityManager.Start(); err != nil {
		return fmt.Errorf("failed to start security manager: %v", err)
	}

	// 获取 TLS 配置
	tlsConfig, err := si.securityManager.GetTLSConfig("server")
	if err != nil {
		log.Printf("Warning: Failed to get TLS config, using default: %v", err)
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
		}
	}

	// 创建 HTTP 服务器
	mux := http.NewServeMux()
	si.setupRoutes(mux)

	si.server = &http.Server{
		Addr:      addr,
		Handler:   si.securityMiddleware(mux),
		TLSConfig: tlsConfig,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// 记录启动事件
	si.securityManager.LogSecurityEvent(DetailedAuditEvent{
		Level:     AuditLevelInfo,
		Category:  "system",
		Action:    "server_start",
		Timestamp: time.Now(),
		Message:   fmt.Sprintf("Security-enabled server starting on %s", addr),
		Details: map[string]interface{}{
			"address": addr,
			"tls_enabled": tlsConfig != nil,
		},
	})

	// 启动 HTTPS 服务器
	log.Printf("Starting secure server on %s", addr)
	return si.server.ListenAndServeTLS("", "")
}

// Stop 停止安全集成服务
func (si *SecurityIntegration) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 停止 HTTP 服务器
	if si.server != nil {
		if err := si.server.Shutdown(ctx); err != nil {
			log.Printf("Server shutdown error: %v", err)
		}
	}

	// 停止安全管理器
	if err := si.securityManager.Stop(); err != nil {
		log.Printf("Security manager stop error: %v", err)
	}

	// 记录停止事件
	si.securityManager.LogSecurityEvent(DetailedAuditEvent{
		Level:     AuditLevelInfo,
		Category:  "system",
		Action:    "server_stop",
		Timestamp: time.Now(),
		Message:   "Security-enabled server stopped",
	})

	return nil
}

// setupRoutes 设置路由
func (si *SecurityIntegration) setupRoutes(mux *http.ServeMux) {
	// 健康检查端点
	mux.HandleFunc("/health", si.healthHandler)
	
	// 安全指标端点
	mux.HandleFunc("/security/metrics", si.metricsHandler)
	
	// 认证端点
	mux.HandleFunc("/auth/login", si.loginHandler)
	mux.HandleFunc("/auth/logout", si.logoutHandler)
	
	// 受保护的资源端点
	mux.HandleFunc("/api/", si.protectedHandler)
}

// securityMiddleware 安全中间件
func (si *SecurityIntegration) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// 设置安全头
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		
		// 记录访问日志
		si.securityManager.LogSecurityEvent(DetailedAuditEvent{
			Level:     AuditLevelInfo,
			Category:  "access",
			Action:    "http_request",
			Timestamp: time.Now(),
			Message:   fmt.Sprintf("%s %s from %s", r.Method, r.URL.Path, r.RemoteAddr),
			Details: map[string]interface{}{
				"method":     r.Method,
				"path":       r.URL.Path,
				"remote_addr": r.RemoteAddr,
				"user_agent": r.UserAgent(),
			},
		})
		
		next.ServeHTTP(w, r)
		
		// 记录响应时间
		duration := time.Since(start)
		if duration > 5*time.Second {
			si.securityManager.LogSecurityEvent(DetailedAuditEvent{
				Level:     AuditLevelWarning,
				Category:  "performance",
				Action:    "slow_request",
				Timestamp: time.Now(),
				Message:   fmt.Sprintf("Slow request: %s %s took %v", r.Method, r.URL.Path, duration),
				Details: map[string]interface{}{
					"duration_ms": duration.Milliseconds(),
					"method":      r.Method,
					"path":        r.URL.Path,
				},
			})
		}
	})
}

// healthHandler 健康检查处理器
func (si *SecurityIntegration) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"healthy","timestamp":"%s"}`, time.Now().Format(time.RFC3339))
}

// metricsHandler 安全指标处理器
func (si *SecurityIntegration) metricsHandler(w http.ResponseWriter, r *http.Request) {
	// 简单的认证检查（实际应用中应该更严格）
	if !si.isAuthenticated(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	metrics := si.securityManager.GetSecurityMetrics()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	
	// 简单的 JSON 输出（实际应用中应该使用 json.Marshal）
	fmt.Fprintf(w, `{"metrics":%v,"timestamp":"%s"}`, metrics, time.Now().Format(time.RFC3339))
}

// loginHandler 登录处理器
func (si *SecurityIntegration) loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	username := r.FormValue("username")
	password := r.FormValue("password")
	
	if username == "" || password == "" {
		http.Error(w, "Username and password required", http.StatusBadRequest)
		return
	}
	
	// 尝试认证
	token, err := si.securityManager.AuthenticateUser(username, password)
	if err != nil {
		si.securityManager.LogSecurityEvent(DetailedAuditEvent{
			Level:     AuditLevelWarning,
			Category:  "authentication",
			Action:    "login_failed",
			Timestamp: time.Now(),
			Message:   fmt.Sprintf("Failed login attempt for user %s", username),
			Details: map[string]interface{}{
				"username":    username,
				"remote_addr": r.RemoteAddr,
				"error":       err.Error(),
			},
		})
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}
	
	// 认证成功
	si.securityManager.LogSecurityEvent(DetailedAuditEvent{
		Level:     AuditLevelInfo,
		Category:  "authentication",
		Action:    "login_success",
		Timestamp: time.Now(),
		Message:   fmt.Sprintf("User %s logged in successfully", username),
		Details: map[string]interface{}{
			"username":    username,
			"remote_addr": r.RemoteAddr,
		},
	})
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"token":"%s","expires_in":1800}`, token)
}

// logoutHandler 登出处理器
func (si *SecurityIntegration) logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	// 这里应该实现会话失效逻辑
	si.securityManager.LogSecurityEvent(DetailedAuditEvent{
		Level:     AuditLevelInfo,
		Category:  "authentication",
		Action:    "logout",
		Timestamp: time.Now(),
		Message:   "User logged out",
		Details: map[string]interface{}{
			"remote_addr": r.RemoteAddr,
		},
	})
	
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"message":"Logged out successfully"}`)
}

// protectedHandler 受保护资源处理器
func (si *SecurityIntegration) protectedHandler(w http.ResponseWriter, r *http.Request) {
	if !si.isAuthenticated(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	// 检查权限（简化版本，实际应该从令牌中获取用户信息）
	if !si.hasPermission(r, "read", "api") {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"message":"Access granted to protected resource","timestamp":"%s"}`, time.Now().Format(time.RFC3339))
}

// isAuthenticated 简单的认证检查
func (si *SecurityIntegration) isAuthenticated(r *http.Request) bool {
	// 这里应该实现真正的令牌验证逻辑
	token := r.Header.Get("Authorization")
	return token != "" && len(token) > 7 // 简单检查
}

// hasPermission 简单的权限检查
func (si *SecurityIntegration) hasPermission(r *http.Request, action, resource string) bool {
	// 这里应该实现真正的权限验证逻辑
	// 从令牌中提取用户信息，然后检查权限
	token := r.Header.Get("Authorization")
	if token == "" {
		return false
	}
	
	// 简化的权限检查逻辑
	// 实际应用中应该解析令牌，获取用户角色，然后检查权限
	return len(token) > 7 // 简单检查
}

// ExampleUsage 使用示例
func ExampleUsage() {
	// 创建安全集成实例
	integration, err := NewSecurityIntegration("./configs/security.json")
	if err != nil {
		log.Fatalf("Failed to create security integration: %v", err)
	}
	
	// 启动服务
	ctx := context.Background()
	go func() {
		if err := integration.Start(ctx, ":8443"); err != nil {
			log.Printf("Server error: %v", err)
		}
	}()
	
	// 等待信号后停止
	// 在实际应用中，这里应该监听系统信号
	time.Sleep(10 * time.Second)
	
	if err := integration.Stop(); err != nil {
		log.Printf("Stop error: %v", err)
	}
}