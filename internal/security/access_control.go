package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// Permission 权限类型
type Permission string

const (
	PermissionRead      Permission = "read"
	PermissionWrite     Permission = "write"
	PermissionExecute   Permission = "execute"
	PermissionAdmin     Permission = "admin"
	PermissionConnect   Permission = "connect"
	PermissionProxy     Permission = "proxy"
	PermissionMonitor   Permission = "monitor"
	PermissionCertMgmt  Permission = "cert_mgmt"
	PermissionKeyMgmt   Permission = "key_mgmt"
	PermissionUserMgmt  Permission = "user_mgmt"
	PermissionAudit     Permission = "audit"
)

// Role 角色定义
type Role struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Permissions []Permission `json:"permissions"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

// User 用户定义
type User struct {
	ID           string            `json:"id"`
	Username     string            `json:"username"`
	PasswordHash string            `json:"password_hash"`
	Salt         string            `json:"salt"`
	Roles        []string          `json:"roles"`
	Metadata     map[string]string `json:"metadata"`
	Active       bool              `json:"active"`
	LastLogin    time.Time         `json:"last_login"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
	ExpiresAt    *time.Time        `json:"expires_at,omitempty"`
}

// Session 会话信息
type Session struct {
	ID        string            `json:"id"`
	UserID    string            `json:"user_id"`
	Token     string            `json:"token"`
	IPAddress string            `json:"ip_address"`
	UserAgent string            `json:"user_agent"`
	Metadata  map[string]string `json:"metadata"`
	CreatedAt time.Time         `json:"created_at"`
	ExpiresAt time.Time         `json:"expires_at"`
	Active    bool              `json:"active"`
}

// IPRule IP访问规则
type IPRule struct {
	ID          string    `json:"id"`
	CIDR        string    `json:"cidr"`
	Action      string    `json:"action"` // allow, deny
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	Active      bool      `json:"active"`
}

// RateLimitRule 速率限制规则
type RateLimitRule struct {
	ID          string        `json:"id"`
	UserID      string        `json:"user_id,omitempty"`
	IPAddress   string        `json:"ip_address,omitempty"`
	MaxRequests int           `json:"max_requests"`
	TimeWindow  time.Duration `json:"time_window"`
	Description string        `json:"description"`
	CreatedAt   time.Time     `json:"created_at"`
	Active      bool          `json:"active"`
}

// AccessControlConfig 访问控制配置
type AccessControlConfig struct {
	DataPath           string        `json:"data_path"`
	SessionTimeout     time.Duration `json:"session_timeout"`
	MaxSessions        int           `json:"max_sessions"`
	PasswordMinLength  int           `json:"password_min_length"`
	PasswordComplexity bool          `json:"password_complexity"`
	EnableIPWhitelist  bool          `json:"enable_ip_whitelist"`
	EnableRateLimit    bool          `json:"enable_rate_limit"`
	DefaultRateLimit   int           `json:"default_rate_limit"`
	AuditLogEnabled    bool          `json:"audit_log_enabled"`
	AuditLogPath       string        `json:"audit_log_path"`
}

// AccessController 访问控制器
type AccessController struct {
	config      *AccessControlConfig
	users       map[string]*User
	roles       map[string]*Role
	sessions    map[string]*Session
	ipRules     []*IPRule
	rateLimits  map[string]*RateLimitRule
	requestCounts map[string]map[int64]int // IP -> timestamp -> count
	mu          sync.RWMutex
	auditLogger *AuditLogger
}

// AuditEvent 审计事件
type AuditEvent struct {
	Timestamp time.Time         `json:"timestamp"`
	EventType string            `json:"event_type"`
	UserID    string            `json:"user_id,omitempty"`
	IPAddress string            `json:"ip_address"`
	Resource  string            `json:"resource"`
	Action    string            `json:"action"`
	Result    string            `json:"result"` // success, failure, denied
	Details   map[string]string `json:"details,omitempty"`
}

// AuditLogger 审计日志记录器
type AuditLogger struct {
	logPath string
	mu      sync.Mutex
}

// NewAccessController 创建新的访问控制器
func NewAccessController(config *AccessControlConfig) (*AccessController, error) {
	if config == nil {
		return nil, errors.New("config cannot be nil")
	}

	// 设置默认值
	if config.SessionTimeout == 0 {
		config.SessionTimeout = 24 * time.Hour
	}
	if config.MaxSessions == 0 {
		config.MaxSessions = 100
	}
	if config.PasswordMinLength == 0 {
		config.PasswordMinLength = 8
	}
	if config.DefaultRateLimit == 0 {
		config.DefaultRateLimit = 100
	}

	ac := &AccessController{
		config:        config,
		users:         make(map[string]*User),
		roles:         make(map[string]*Role),
		sessions:      make(map[string]*Session),
		ipRules:       make([]*IPRule, 0),
		rateLimits:    make(map[string]*RateLimitRule),
		requestCounts: make(map[string]map[int64]int),
	}

	// 初始化审计日志记录器
	if config.AuditLogEnabled {
		ac.auditLogger = &AuditLogger{
			logPath: config.AuditLogPath,
		}
	}

	// 加载数据
	if err := ac.loadData(); err != nil {
		return nil, fmt.Errorf("failed to load access control data: %w", err)
	}

	// 创建默认角色和用户
	if err := ac.createDefaults(); err != nil {
		return nil, fmt.Errorf("failed to create defaults: %w", err)
	}

	return ac, nil
}

// CreateRole 创建角色
func (ac *AccessController) CreateRole(id, name, description string, permissions []Permission) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	if _, exists := ac.roles[id]; exists {
		return fmt.Errorf("role with ID %s already exists", id)
	}

	role := &Role{
		ID:          id,
		Name:        name,
		Description: description,
		Permissions: permissions,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	ac.roles[id] = role

	// 保存到文件
	if err := ac.saveRoles(); err != nil {
		return fmt.Errorf("failed to save roles: %w", err)
	}

	// 记录审计日志
	ac.logAuditEvent("role_created", "", "", "role", "create", "success", map[string]string{
		"role_id":   id,
		"role_name": name,
	})

	return nil
}

// CreateUser 创建用户
func (ac *AccessController) CreateUser(username, password string, roles []string) (*User, error) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	// 检查用户名是否已存在
	for _, user := range ac.users {
		if user.Username == username {
			return nil, fmt.Errorf("username %s already exists", username)
		}
	}

	// 验证密码强度
	if err := ac.validatePassword(password); err != nil {
		return nil, err
	}

	// 验证角色是否存在
	for _, roleID := range roles {
		if _, exists := ac.roles[roleID]; !exists {
			return nil, fmt.Errorf("role %s does not exist", roleID)
		}
	}

	// 生成用户ID和盐值
	userID := ac.generateID()
	salt := ac.generateSalt()

	// 计算密码哈希
	passwordHash := ac.hashPassword(password, salt)

	user := &User{
		ID:           userID,
		Username:     username,
		PasswordHash: passwordHash,
		Salt:         salt,
		Roles:        roles,
		Metadata:     make(map[string]string),
		Active:       true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	ac.users[userID] = user

	// 保存到文件
	if err := ac.saveUsers(); err != nil {
		return nil, fmt.Errorf("failed to save users: %w", err)
	}

	// 记录审计日志
	ac.logAuditEvent("user_created", userID, "", "user", "create", "success", map[string]string{
		"username": username,
	})

	return user, nil
}

// Authenticate 用户认证
func (ac *AccessController) Authenticate(username, password, ipAddress, userAgent string) (*Session, error) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	// 查找用户
	var user *User
	for _, u := range ac.users {
		if u.Username == username {
			user = u
			break
		}
	}

	if user == nil {
		ac.logAuditEvent("authentication_failed", "", ipAddress, "auth", "login", "failure", map[string]string{
			"username": username,
			"reason":   "user_not_found",
		})
		return nil, errors.New("invalid credentials")
	}

	// 检查用户是否激活
	if !user.Active {
		ac.logAuditEvent("authentication_failed", user.ID, ipAddress, "auth", "login", "failure", map[string]string{
			"username": username,
			"reason":   "user_inactive",
		})
		return nil, errors.New("user account is inactive")
	}

	// 检查用户是否过期
	if user.ExpiresAt != nil && time.Now().After(*user.ExpiresAt) {
		ac.logAuditEvent("authentication_failed", user.ID, ipAddress, "auth", "login", "failure", map[string]string{
			"username": username,
			"reason":   "user_expired",
		})
		return nil, errors.New("user account has expired")
	}

	// 验证密码
	if !ac.verifyPassword(password, user.PasswordHash, user.Salt) {
		ac.logAuditEvent("authentication_failed", user.ID, ipAddress, "auth", "login", "failure", map[string]string{
			"username": username,
			"reason":   "invalid_password",
		})
		return nil, errors.New("invalid credentials")
	}

	// 检查IP访问规则
	if !ac.checkIPAccess(ipAddress) {
		ac.logAuditEvent("authentication_failed", user.ID, ipAddress, "auth", "login", "failure", map[string]string{
			"username": username,
			"reason":   "ip_blocked",
		})
		return nil, errors.New("access denied from this IP address")
	}

	// 检查速率限制
	if !ac.checkRateLimit(user.ID, ipAddress) {
		ac.logAuditEvent("authentication_failed", user.ID, ipAddress, "auth", "login", "failure", map[string]string{
			"username": username,
			"reason":   "rate_limit_exceeded",
		})
		return nil, errors.New("rate limit exceeded")
	}

	// 清理过期会话
	ac.cleanupExpiredSessions()

	// 检查最大会话数
	userSessions := ac.getUserSessions(user.ID)
	if len(userSessions) >= ac.config.MaxSessions {
		// 删除最旧的会话
	oldestSession := userSessions[0]
		for _, session := range userSessions {
			if session.CreatedAt.Before(oldestSession.CreatedAt) {
				oldestSession = session
			}
		}
		delete(ac.sessions, oldestSession.ID)
	}

	// 创建新会话
	sessionID := ac.generateID()
	token := ac.generateToken()

	session := &Session{
		ID:        sessionID,
		UserID:    user.ID,
		Token:     token,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Metadata:  make(map[string]string),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(ac.config.SessionTimeout),
		Active:    true,
	}

	ac.sessions[sessionID] = session

	// 更新用户最后登录时间
	user.LastLogin = time.Now()
	user.UpdatedAt = time.Now()

	// 保存会话和用户数据
	if err := ac.saveSessions(); err != nil {
		return nil, fmt.Errorf("failed to save sessions: %w", err)
	}
	if err := ac.saveUsers(); err != nil {
		return nil, fmt.Errorf("failed to save users: %w", err)
	}

	// 记录审计日志
	ac.logAuditEvent("authentication_success", user.ID, ipAddress, "auth", "login", "success", map[string]string{
		"username":   username,
		"session_id": sessionID,
	})

	return session, nil
}

// ValidateSession 验证会话
func (ac *AccessController) ValidateSession(token, ipAddress string) (*User, error) {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	// 查找会话
	var session *Session
	for _, s := range ac.sessions {
		if s.Token == token {
			session = s
			break
		}
	}

	if session == nil {
		ac.logAuditEvent("session_validation_failed", "", ipAddress, "auth", "validate", "failure", map[string]string{
			"reason": "session_not_found",
		})
		return nil, errors.New("invalid session")
	}

	// 检查会话是否激活
	if !session.Active {
		ac.logAuditEvent("session_validation_failed", session.UserID, ipAddress, "auth", "validate", "failure", map[string]string{
			"session_id": session.ID,
			"reason":     "session_inactive",
		})
		return nil, errors.New("session is inactive")
	}

	// 检查会话是否过期
	if time.Now().After(session.ExpiresAt) {
		ac.logAuditEvent("session_validation_failed", session.UserID, ipAddress, "auth", "validate", "failure", map[string]string{
			"session_id": session.ID,
			"reason":     "session_expired",
		})
		return nil, errors.New("session has expired")
	}

	// 检查IP地址（可选）
	if session.IPAddress != ipAddress {
		ac.logAuditEvent("session_validation_failed", session.UserID, ipAddress, "auth", "validate", "failure", map[string]string{
			"session_id":      session.ID,
			"expected_ip":     session.IPAddress,
			"actual_ip":       ipAddress,
			"reason":          "ip_mismatch",
		})
		// 注意：这里可以选择是否严格检查IP，某些场景下用户IP可能会变化
		// return nil, errors.New("IP address mismatch")
	}

	// 获取用户信息
	user, exists := ac.users[session.UserID]
	if !exists {
		ac.logAuditEvent("session_validation_failed", session.UserID, ipAddress, "auth", "validate", "failure", map[string]string{
			"session_id": session.ID,
			"reason":     "user_not_found",
		})
		return nil, errors.New("user not found")
	}

	// 检查用户是否激活
	if !user.Active {
		ac.logAuditEvent("session_validation_failed", session.UserID, ipAddress, "auth", "validate", "failure", map[string]string{
			"session_id": session.ID,
			"reason":     "user_inactive",
		})
		return nil, errors.New("user account is inactive")
	}

	return user, nil
}

// CheckPermission 检查权限
func (ac *AccessController) CheckPermission(userID string, permission Permission) bool {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	user, exists := ac.users[userID]
	if !exists || !user.Active {
		return false
	}

	// 检查用户的所有角色
	for _, roleID := range user.Roles {
		role, exists := ac.roles[roleID]
		if !exists {
			continue
		}

		// 检查角色是否有该权限
		for _, perm := range role.Permissions {
			if perm == permission || perm == PermissionAdmin {
				return true
			}
		}
	}

	return false
}

// AddIPRule 添加IP访问规则
func (ac *AccessController) AddIPRule(cidr, action, description string) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	// 验证CIDR格式
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return fmt.Errorf("invalid CIDR format: %w", err)
	}

	// 验证动作
	if action != "allow" && action != "deny" {
		return errors.New("action must be 'allow' or 'deny'")
	}

	rule := &IPRule{
		ID:          ac.generateID(),
		CIDR:        cidr,
		Action:      action,
		Description: description,
		CreatedAt:   time.Now(),
		Active:      true,
	}

	ac.ipRules = append(ac.ipRules, rule)

	// 保存到文件
	if err := ac.saveIPRules(); err != nil {
		return fmt.Errorf("failed to save IP rules: %w", err)
	}

	// 记录审计日志
	ac.logAuditEvent("ip_rule_added", "", "", "ip_rule", "create", "success", map[string]string{
		"cidr":   cidr,
		"action": action,
	})

	return nil
}

// checkIPAccess 检查IP访问权限
func (ac *AccessController) checkIPAccess(ipAddress string) bool {
	if !ac.config.EnableIPWhitelist {
		return true
	}

	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return false
	}

	// 默认拒绝，除非明确允许
	allowed := false

	for _, rule := range ac.ipRules {
		if !rule.Active {
			continue
		}

		_, network, err := net.ParseCIDR(rule.CIDR)
		if err != nil {
			continue
		}

		if network.Contains(ip) {
			if rule.Action == "allow" {
				allowed = true
			} else if rule.Action == "deny" {
				return false // 明确拒绝
			}
		}
	}

	return allowed
}

// checkRateLimit 检查速率限制
func (ac *AccessController) checkRateLimit(userID, ipAddress string) bool {
	if !ac.config.EnableRateLimit {
		return true
	}

	now := time.Now().Unix()
	timeWindow := int64(60) // 1分钟窗口
	maxRequests := ac.config.DefaultRateLimit

	// 检查用户特定的速率限制
	if rule, exists := ac.rateLimits[userID]; exists && rule.Active {
		maxRequests = rule.MaxRequests
		timeWindow = int64(rule.TimeWindow.Seconds())
	}

	// 检查IP特定的速率限制
	if rule, exists := ac.rateLimits[ipAddress]; exists && rule.Active {
		maxRequests = rule.MaxRequests
		timeWindow = int64(rule.TimeWindow.Seconds())
	}

	// 获取或创建请求计数器
	key := userID + ":" + ipAddress
	if ac.requestCounts[key] == nil {
		ac.requestCounts[key] = make(map[int64]int)
	}

	// 清理过期的计数
	for timestamp := range ac.requestCounts[key] {
		if now-timestamp > timeWindow {
			delete(ac.requestCounts[key], timestamp)
		}
	}

	// 计算当前窗口内的请求数
	totalRequests := 0
	for timestamp, count := range ac.requestCounts[key] {
		if now-timestamp <= timeWindow {
			totalRequests += count
		}
	}

	// 检查是否超过限制
	if totalRequests >= maxRequests {
		return false
	}

	// 增加计数
	ac.requestCounts[key][now]++

	return true
}

// validatePassword 验证密码强度
func (ac *AccessController) validatePassword(password string) error {
	if len(password) < ac.config.PasswordMinLength {
		return fmt.Errorf("password must be at least %d characters long", ac.config.PasswordMinLength)
	}

	if ac.config.PasswordComplexity {
		// 检查密码复杂性：至少包含大写字母、小写字母、数字和特殊字符
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
		hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
		hasDigit := regexp.MustCompile(`[0-9]`).MatchString(password)
		hasSpecial := regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`).MatchString(password)

		if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
			return errors.New("password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character")
		}
	}

	return nil
}

// generateID 生成唯一ID
func (ac *AccessController) generateID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// generateSalt 生成盐值
func (ac *AccessController) generateSalt() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// generateToken 生成会话令牌
func (ac *AccessController) generateToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// hashPassword 计算密码哈希
func (ac *AccessController) hashPassword(password, salt string) string {
	hash := sha256.Sum256([]byte(password + salt))
	return hex.EncodeToString(hash[:])
}

// verifyPassword 验证密码
func (ac *AccessController) verifyPassword(password, hash, salt string) bool {
	return ac.hashPassword(password, salt) == hash
}

// cleanupExpiredSessions 清理过期会话
func (ac *AccessController) cleanupExpiredSessions() {
	now := time.Now()
	for sessionID, session := range ac.sessions {
		if now.After(session.ExpiresAt) {
			delete(ac.sessions, sessionID)
		}
	}
}

// getUserSessions 获取用户的所有会话
func (ac *AccessController) getUserSessions(userID string) []*Session {
	var sessions []*Session
	for _, session := range ac.sessions {
		if session.UserID == userID && session.Active {
			sessions = append(sessions, session)
		}
	}
	return sessions
}

// logAuditEvent 记录审计事件
func (ac *AccessController) logAuditEvent(eventType, userID, ipAddress, resource, action, result string, details map[string]string) {
	if ac.auditLogger == nil {
		return
	}

	event := AuditEvent{
		Timestamp: time.Now(),
		EventType: eventType,
		UserID:    userID,
		IPAddress: ipAddress,
		Resource:  resource,
		Action:    action,
		Result:    result,
		Details:   details,
	}

	ac.auditLogger.LogEvent(event)
}

// LogEvent 记录审计事件到文件
func (al *AuditLogger) LogEvent(event AuditEvent) {
	al.mu.Lock()
	defer al.mu.Unlock()

	if al.logPath == "" {
		return
	}

	// 确保日志目录存在
	logDir := filepath.Dir(al.logPath)
	if err := os.MkdirAll(logDir, 0700); err != nil {
		return
	}

	// 打开日志文件（追加模式）
	file, err := os.OpenFile(al.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return
	}
	defer file.Close()

	// 序列化事件
	data, err := json.Marshal(event)
	if err != nil {
		return
	}

	// 写入日志
	file.WriteString(string(data) + "\n")
}

// createDefaults 创建默认角色和用户
func (ac *AccessController) createDefaults() error {
	// 创建默认角色
	defaultRoles := map[string]struct {
		name        string
		description string
		permissions []Permission
	}{
		"admin": {
			name:        "Administrator",
			description: "Full system access",
			permissions: []Permission{PermissionAdmin},
		},
		"user": {
			name:        "Regular User",
			description: "Basic proxy access",
			permissions: []Permission{PermissionConnect, PermissionProxy},
		},
		"monitor": {
			name:        "Monitor",
			description: "Monitoring and read-only access",
			permissions: []Permission{PermissionRead, PermissionMonitor},
		},
	}

	for roleID, roleData := range defaultRoles {
		if _, exists := ac.roles[roleID]; !exists {
			if err := ac.CreateRole(roleID, roleData.name, roleData.description, roleData.permissions); err != nil {
				return fmt.Errorf("failed to create default role %s: %w", roleID, err)
			}
		}
	}

	// 创建默认管理员用户（如果不存在）
	adminExists := false
	for _, user := range ac.users {
		for _, roleID := range user.Roles {
			if roleID == "admin" {
				adminExists = true
				break
			}
		}
		if adminExists {
			break
		}
	}

	if !adminExists {
		_, err := ac.CreateUser("admin", "admin123!", []string{"admin"})
		if err != nil {
			return fmt.Errorf("failed to create default admin user: %w", err)
		}
	}

	return nil
}

// loadData 加载数据
func (ac *AccessController) loadData() error {
	if err := os.MkdirAll(ac.config.DataPath, 0700); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	// 加载角色
	if err := ac.loadRoles(); err != nil {
		return fmt.Errorf("failed to load roles: %w", err)
	}

	// 加载用户
	if err := ac.loadUsers(); err != nil {
		return fmt.Errorf("failed to load users: %w", err)
	}

	// 加载会话
	if err := ac.loadSessions(); err != nil {
		return fmt.Errorf("failed to load sessions: %w", err)
	}

	// 加载IP规则
	if err := ac.loadIPRules(); err != nil {
		return fmt.Errorf("failed to load IP rules: %w", err)
	}

	// 加载速率限制规则
	if err := ac.loadRateLimits(); err != nil {
		return fmt.Errorf("failed to load rate limits: %w", err)
	}

	return nil
}

// saveRoles 保存角色数据
func (ac *AccessController) saveRoles() error {
	data, err := json.MarshalIndent(ac.roles, "", "  ")
	if err != nil {
		return err
	}

	filePath := filepath.Join(ac.config.DataPath, "roles.json")
	return os.WriteFile(filePath, data, 0600)
}

// loadRoles 加载角色数据
func (ac *AccessController) loadRoles() error {
	filePath := filepath.Join(ac.config.DataPath, "roles.json")
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil // 文件不存在，跳过加载
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &ac.roles)
}

// saveUsers 保存用户数据
func (ac *AccessController) saveUsers() error {
	data, err := json.MarshalIndent(ac.users, "", "  ")
	if err != nil {
		return err
	}

	filePath := filepath.Join(ac.config.DataPath, "users.json")
	return os.WriteFile(filePath, data, 0600)
}

// loadUsers 加载用户数据
func (ac *AccessController) loadUsers() error {
	filePath := filepath.Join(ac.config.DataPath, "users.json")
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil // 文件不存在，跳过加载
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &ac.users)
}

// saveSessions 保存会话数据
func (ac *AccessController) saveSessions() error {
	data, err := json.MarshalIndent(ac.sessions, "", "  ")
	if err != nil {
		return err
	}

	filePath := filepath.Join(ac.config.DataPath, "sessions.json")
	return os.WriteFile(filePath, data, 0600)
}

// loadSessions 加载会话数据
func (ac *AccessController) loadSessions() error {
	filePath := filepath.Join(ac.config.DataPath, "sessions.json")
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil // 文件不存在，跳过加载
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &ac.sessions)
}

// saveIPRules 保存IP规则数据
func (ac *AccessController) saveIPRules() error {
	data, err := json.MarshalIndent(ac.ipRules, "", "  ")
	if err != nil {
		return err
	}

	filePath := filepath.Join(ac.config.DataPath, "ip_rules.json")
	return os.WriteFile(filePath, data, 0600)
}

// loadIPRules 加载IP规则数据
func (ac *AccessController) loadIPRules() error {
	filePath := filepath.Join(ac.config.DataPath, "ip_rules.json")
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil // 文件不存在，跳过加载
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &ac.ipRules)
}

// saveRateLimits 保存速率限制数据
func (ac *AccessController) saveRateLimits() error {
	data, err := json.MarshalIndent(ac.rateLimits, "", "  ")
	if err != nil {
		return err
	}

	filePath := filepath.Join(ac.config.DataPath, "rate_limits.json")
	return os.WriteFile(filePath, data, 0600)
}

// loadRateLimits 加载速率限制数据
func (ac *AccessController) loadRateLimits() error {
	filePath := filepath.Join(ac.config.DataPath, "rate_limits.json")
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil // 文件不存在，跳过加载
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &ac.rateLimits)
}

// GetActiveSessionCount 获取活跃会话数量
func (ac *AccessController) GetActiveSessionCount() int {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	return len(ac.sessions)
}

// Close 关闭访问控制器
func (ac *AccessController) Close() error {
	// 保存所有数据
	ac.mu.Lock()
	defer ac.mu.Unlock()

	if err := ac.saveRoles(); err != nil {
		return fmt.Errorf("failed to save roles: %w", err)
	}
	if err := ac.saveUsers(); err != nil {
		return fmt.Errorf("failed to save users: %w", err)
	}
	if err := ac.saveSessions(); err != nil {
		return fmt.Errorf("failed to save sessions: %w", err)
	}
	if err := ac.saveIPRules(); err != nil {
		return fmt.Errorf("failed to save IP rules: %w", err)
	}
	if err := ac.saveRateLimits(); err != nil {
		return fmt.Errorf("failed to save rate limits: %w", err)
	}

	return nil
}