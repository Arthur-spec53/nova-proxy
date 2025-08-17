package security

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SecurityConfig 安全配置
type SecurityConfig struct {
	// 密钥管理配置
	KeyManager *KeyManagerConfig `json:"key_manager"`

	// 证书管理配置
	CertManager *CertManagerConfig `json:"cert_manager"`

	// 访问控制配置
	AccessControl *AccessControlConfig `json:"access_control"`

	// 审计日志配置
	AuditLogger *AuditLoggerConfig `json:"audit_logger"`

	// TLS配置
	TLS *TLSConfig `json:"tls"`

	// 加密配置
	Encryption *EncryptionConfig `json:"encryption"`

	// 网络安全配置
	Network *NetworkSecurityConfig `json:"network"`

	// 安全策略配置
	Policy *SecurityPolicyConfig `json:"policy"`

	// 监控配置
	Monitoring *SecurityMonitoringConfig `json:"monitoring"`
}

// TLSConfig TLS配置
type TLSConfig struct {
	MinVersion       string   `json:"min_version"`        // TLS最小版本
	MaxVersion       string   `json:"max_version"`        // TLS最大版本
	CipherSuites     []string `json:"cipher_suites"`      // 允许的密码套件
	CurvePreferences []string `json:"curve_preferences"`  // 椭圆曲线偏好
	PreferServerCipherSuites bool `json:"prefer_server_cipher_suites"` // 优先使用服务器密码套件
	SessionTicketsDisabled   bool `json:"session_tickets_disabled"`   // 禁用会话票据
	RenegotiationSupport     int  `json:"renegotiation_support"`      // 重新协商支持级别
	InsecureSkipVerify       bool `json:"insecure_skip_verify"`       // 跳过证书验证（仅用于测试）
	ClientAuth               string `json:"client_auth"`               // 客户端认证模式
	NextProtos               []string `json:"next_protos"`             // 支持的协议
	ServerName               string `json:"server_name"`               // 服务器名称
	OCSPStapling             bool   `json:"ocsp_stapling"`             // OCSP装订
	HSTSEnabled              bool   `json:"hsts_enabled"`              // HSTS启用
	HSTSMaxAge               int    `json:"hsts_max_age"`              // HSTS最大年龄
	HSTSIncludeSubdomains    bool   `json:"hsts_include_subdomains"`   // HSTS包含子域名
}

// EncryptionConfig 加密配置
type EncryptionConfig struct {
	DefaultAlgorithm    string `json:"default_algorithm"`     // 默认加密算法
	KeyDerivationFunc   string `json:"key_derivation_func"`   // 密钥派生函数
	HashAlgorithm       string `json:"hash_algorithm"`        // 哈希算法
	SignatureAlgorithm  string `json:"signature_algorithm"`   // 签名算法
	CompressionEnabled  bool   `json:"compression_enabled"`   // 启用压缩
	CompressionLevel    int    `json:"compression_level"`     // 压缩级别
	EncryptionAtRest    bool   `json:"encryption_at_rest"`    // 静态加密
	EncryptionInTransit bool   `json:"encryption_in_transit"` // 传输加密
	PerfectForwardSecrecy bool `json:"perfect_forward_secrecy"` // 完美前向保密
}

// NetworkSecurityConfig 网络安全配置
type NetworkSecurityConfig struct {
	FirewallEnabled     bool     `json:"firewall_enabled"`      // 启用防火墙
	AllowedPorts        []int    `json:"allowed_ports"`         // 允许的端口
	BlockedPorts        []int    `json:"blocked_ports"`         // 阻止的端口
	AllowedIPs          []string `json:"allowed_ips"`           // 允许的IP地址
	BlockedIPs          []string `json:"blocked_ips"`           // 阻止的IP地址
	DDoSProtection      bool     `json:"ddos_protection"`       // DDoS保护
	RateLimitEnabled    bool     `json:"rate_limit_enabled"`    // 启用速率限制
	ConnectionLimit     int      `json:"connection_limit"`      // 连接限制
	TimeoutSettings     *TimeoutConfig `json:"timeout_settings"` // 超时设置
	ProxyProtocol       bool     `json:"proxy_protocol"`        // 代理协议支持
	GeoBlocking         bool     `json:"geo_blocking"`          // 地理位置阻止
	BlockedCountries    []string `json:"blocked_countries"`     // 阻止的国家
}

// TimeoutConfig 超时配置
type TimeoutConfig struct {
	ConnectionTimeout time.Duration `json:"connection_timeout"` // 连接超时
	ReadTimeout       time.Duration `json:"read_timeout"`       // 读取超时
	WriteTimeout      time.Duration `json:"write_timeout"`      // 写入超时
	IdleTimeout       time.Duration `json:"idle_timeout"`       // 空闲超时
	KeepAliveTimeout  time.Duration `json:"keep_alive_timeout"` // 保持连接超时
}

// SecurityPolicyConfig 安全策略配置
type SecurityPolicyConfig struct {
	PasswordPolicy      *PasswordPolicyConfig      `json:"password_policy"`       // 密码策略
	SessionPolicy       *SessionPolicyConfig       `json:"session_policy"`        // 会话策略
	AccessPolicy        *AccessPolicyConfig        `json:"access_policy"`         // 访问策略
	DataProtectionPolicy *DataProtectionPolicyConfig `json:"data_protection_policy"` // 数据保护策略
	IncidentResponse    *IncidentResponseConfig    `json:"incident_response"`     // 事件响应
}

// PasswordPolicyConfig 密码策略配置
type PasswordPolicyConfig struct {
	MinLength           int           `json:"min_length"`            // 最小长度
	MaxLength           int           `json:"max_length"`            // 最大长度
	RequireUppercase    bool          `json:"require_uppercase"`     // 要求大写字母
	RequireLowercase    bool          `json:"require_lowercase"`     // 要求小写字母
	RequireNumbers      bool          `json:"require_numbers"`       // 要求数字
	RequireSpecialChars bool          `json:"require_special_chars"` // 要求特殊字符
	ForbiddenPasswords  []string      `json:"forbidden_passwords"`   // 禁止的密码
	PasswordHistory     int           `json:"password_history"`      // 密码历史记录
	PasswordExpiry      time.Duration `json:"password_expiry"`       // 密码过期时间
	MaxFailedAttempts   int           `json:"max_failed_attempts"`   // 最大失败尝试次数
	LockoutDuration     time.Duration `json:"lockout_duration"`      // 锁定持续时间
}

// SessionPolicyConfig 会话策略配置
type SessionPolicyConfig struct {
	MaxSessionDuration    time.Duration `json:"max_session_duration"`     // 最大会话持续时间
	IdleSessionTimeout    time.Duration `json:"idle_session_timeout"`     // 空闲会话超时
	MaxConcurrentSessions int           `json:"max_concurrent_sessions"`  // 最大并发会话数
	SessionRotationInterval time.Duration `json:"session_rotation_interval"` // 会话轮换间隔
	SecureCookies         bool          `json:"secure_cookies"`           // 安全Cookie
	HttpOnlyCookies       bool          `json:"http_only_cookies"`        // HttpOnly Cookie
	SameSiteCookies       string        `json:"same_site_cookies"`        // SameSite Cookie设置
	CSRFProtection        bool          `json:"csrf_protection"`          // CSRF保护
}

// AccessPolicyConfig 访问策略配置
type AccessPolicyConfig struct {
	DefaultDenyAll        bool          `json:"default_deny_all"`         // 默认拒绝所有
	WhitelistMode         bool          `json:"whitelist_mode"`           // 白名单模式
	BlacklistMode         bool          `json:"blacklist_mode"`           // 黑名单模式
	GeoLocationRestrictions []string    `json:"geo_location_restrictions"` // 地理位置限制
	TimeBasedAccess       *TimeBasedAccessConfig `json:"time_based_access"` // 基于时间的访问
	DeviceRestrictions    bool          `json:"device_restrictions"`      // 设备限制
	MultiFactorAuth       bool          `json:"multi_factor_auth"`        // 多因素认证
	BiometricAuth         bool          `json:"biometric_auth"`           // 生物识别认证
}

// TimeBasedAccessConfig 基于时间的访问配置
type TimeBasedAccessConfig struct {
	Enabled       bool     `json:"enabled"`        // 启用
	AllowedHours  []int    `json:"allowed_hours"`  // 允许的小时
	AllowedDays   []string `json:"allowed_days"`   // 允许的天
	Timezone      string   `json:"timezone"`       // 时区
	HolidayBlocking bool   `json:"holiday_blocking"` // 节假日阻止
}

// DataProtectionPolicyConfig 数据保护策略配置
type DataProtectionPolicyConfig struct {
	DataClassification    bool          `json:"data_classification"`     // 数据分类
	DataEncryption        bool          `json:"data_encryption"`         // 数据加密
	DataMasking           bool          `json:"data_masking"`            // 数据脱敏
	DataRetentionPeriod   time.Duration `json:"data_retention_period"`   // 数据保留期
	DataBackupEnabled     bool          `json:"data_backup_enabled"`     // 数据备份启用
	DataBackupInterval    time.Duration `json:"data_backup_interval"`    // 数据备份间隔
	DataBackupRetention   time.Duration `json:"data_backup_retention"`   // 数据备份保留期
	DataAnonymization     bool          `json:"data_anonymization"`      // 数据匿名化
	GDPRCompliance        bool          `json:"gdpr_compliance"`         // GDPR合规
	CCPACompliance        bool          `json:"ccpa_compliance"`         // CCPA合规
}

// IncidentResponseConfig 事件响应配置
type IncidentResponseConfig struct {
	Enabled               bool          `json:"enabled"`                 // 启用
	AutoResponse          bool          `json:"auto_response"`           // 自动响应
	NotificationEnabled   bool          `json:"notification_enabled"`    // 通知启用
	NotificationChannels  []string      `json:"notification_channels"`   // 通知渠道
	EscalationRules       []string      `json:"escalation_rules"`        // 升级规则
	QuarantineEnabled     bool          `json:"quarantine_enabled"`      // 隔离启用
	ForensicsEnabled      bool          `json:"forensics_enabled"`       // 取证启用
	RecoveryProcedures    []string      `json:"recovery_procedures"`     // 恢复程序
	IncidentRetention     time.Duration `json:"incident_retention"`      // 事件保留期
}

// SecurityMonitoringConfig 安全监控配置
type SecurityMonitoringConfig struct {
	Enabled                bool          `json:"enabled"`                  // 启用
	RealTimeMonitoring     bool          `json:"real_time_monitoring"`     // 实时监控
	AnomalyDetection       bool          `json:"anomaly_detection"`        // 异常检测
	ThreatIntelligence     bool          `json:"threat_intelligence"`      // 威胁情报
	VulnerabilityScanning  bool          `json:"vulnerability_scanning"`   // 漏洞扫描
	PenetrationTesting     bool          `json:"penetration_testing"`      // 渗透测试
	SecurityMetrics        bool          `json:"security_metrics"`         // 安全指标
	ComplianceMonitoring   bool          `json:"compliance_monitoring"`    // 合规监控
	AlertThresholds        *AlertThresholdsConfig `json:"alert_thresholds"` // 告警阈值
	ReportingInterval      time.Duration `json:"reporting_interval"`       // 报告间隔
	DashboardEnabled       bool          `json:"dashboard_enabled"`        // 仪表板启用
}

// AlertThresholdsConfig 告警阈值配置
type AlertThresholdsConfig struct {
	FailedLoginAttempts   int           `json:"failed_login_attempts"`   // 失败登录尝试次数
	SuspiciousActivities  int           `json:"suspicious_activities"`   // 可疑活动次数
	HighRiskConnections   int           `json:"high_risk_connections"`   // 高风险连接次数
	DataExfiltrationSize  int64         `json:"data_exfiltration_size"`  // 数据泄露大小
	ConnectionsPerSecond  int           `json:"connections_per_second"`  // 每秒连接数
	BandwidthThreshold    int64         `json:"bandwidth_threshold"`     // 带宽阈值
	ErrorRateThreshold    float64       `json:"error_rate_threshold"`    // 错误率阈值
	ResponseTimeThreshold time.Duration `json:"response_time_threshold"` // 响应时间阈值
}

// DefaultSecurityConfig 返回默认安全配置
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		KeyManager: &KeyManagerConfig{
			KeyStorePath:     "./data/keys",
			MasterPassword:   "", // 将在运行时生成
			RotationInterval: 24 * time.Hour,
			KeyExpiry:        365 * 24 * time.Hour,
			BackupEnabled:    true,
			BackupPath:       "./data/keys/backup",
			EncryptionAlgo:   "AES-256-GCM",
			KDFIterations:    100000,
		},
		CertManager: &CertManagerConfig{
			CertStorePath:    "./data/certs",
			CAKeyPath:        "./data/certs/ca.key",
			CACertPath:       "./data/certs/ca.crt",
			DefaultKeySize:   2048,
			DefaultValidDays: 365,
			RenewalThreshold: 30 * 24 * time.Hour,
			AutoRenewal:      true,
			BackupEnabled:    true,
			BackupPath:       "./data/certs/backup",
			OCSPEnabled:      false,
			CRLEnabled:       false,
		},
		AccessControl: &AccessControlConfig{
			DataPath:           "./data/access",
			SessionTimeout:     24 * time.Hour,
			MaxSessions:        100,
			PasswordMinLength:  8,
			PasswordComplexity: true,
			EnableIPWhitelist:  false,
			EnableRateLimit:    true,
			DefaultRateLimit:   100,
			AuditLogEnabled:    true,
			AuditLogPath:       "./logs/audit.log",
		},
		AuditLogger: &AuditLoggerConfig{
			LogPath:           "./logs/security_audit.log",
			MaxFileSize:       100 * 1024 * 1024, // 100MB
			MaxFiles:          10,
			CompressionLevel:  6,
			FlushInterval:     5 * time.Second,
			BufferSize:        1000,
			AsyncLogging:      true,
			EnableRotation:    true,
			EnableCompression: true,
			MinLevel:          AuditLevelInfo,
			IncludeStackTrace: false,
		},
		TLS: &TLSConfig{
			MinVersion: "1.2",
			MaxVersion: "1.3",
			CipherSuites: []string{
				"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
				"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
				"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			},
			CurvePreferences: []string{
				"X25519",
				"P-256",
				"P-384",
			},
			PreferServerCipherSuites: true,
			SessionTicketsDisabled:   false,
			RenegotiationSupport:     0, // 禁用重新协商
			InsecureSkipVerify:       false,
			ClientAuth:               "RequireAndVerifyClientCert",
			NextProtos:               []string{"h2", "http/1.1"},
			OCSPStapling:             true,
			HSTSEnabled:              true,
			HSTSMaxAge:               31536000, // 1年
			HSTSIncludeSubdomains:    true,
		},
		Encryption: &EncryptionConfig{
			DefaultAlgorithm:      "AES-256-GCM",
			KeyDerivationFunc:     "PBKDF2",
			HashAlgorithm:         "SHA-256",
			SignatureAlgorithm:    "RSA-PSS",
			CompressionEnabled:    true,
			CompressionLevel:      6,
			EncryptionAtRest:      true,
			EncryptionInTransit:   true,
			PerfectForwardSecrecy: true,
		},
		Network: &NetworkSecurityConfig{
			FirewallEnabled:  true,
			AllowedPorts:     []int{443, 8443},
			BlockedPorts:     []int{},
			AllowedIPs:       []string{},
			BlockedIPs:       []string{},
			DDoSProtection:   true,
			RateLimitEnabled: true,
			ConnectionLimit:  1000,
			TimeoutSettings: &TimeoutConfig{
				ConnectionTimeout: 30 * time.Second,
				ReadTimeout:       30 * time.Second,
				WriteTimeout:      30 * time.Second,
				IdleTimeout:       120 * time.Second,
				KeepAliveTimeout:  60 * time.Second,
			},
			ProxyProtocol:    false,
			GeoBlocking:      false,
			BlockedCountries: []string{},
		},
		Policy: &SecurityPolicyConfig{
			PasswordPolicy: &PasswordPolicyConfig{
				MinLength:           8,
				MaxLength:           128,
				RequireUppercase:    true,
				RequireLowercase:    true,
				RequireNumbers:      true,
				RequireSpecialChars: true,
				ForbiddenPasswords:  []string{"password", "123456", "admin"},
				PasswordHistory:     5,
				PasswordExpiry:      90 * 24 * time.Hour,
				MaxFailedAttempts:   5,
				LockoutDuration:     15 * time.Minute,
			},
			SessionPolicy: &SessionPolicyConfig{
				MaxSessionDuration:      24 * time.Hour,
				IdleSessionTimeout:      2 * time.Hour,
				MaxConcurrentSessions:   5,
				SessionRotationInterval: 4 * time.Hour,
				SecureCookies:           true,
				HttpOnlyCookies:         true,
				SameSiteCookies:         "Strict",
				CSRFProtection:          true,
			},
			AccessPolicy: &AccessPolicyConfig{
				DefaultDenyAll:          false,
				WhitelistMode:           false,
				BlacklistMode:           true,
				GeoLocationRestrictions: []string{},
				TimeBasedAccess: &TimeBasedAccessConfig{
					Enabled:         false,
					AllowedHours:    []int{9, 10, 11, 12, 13, 14, 15, 16, 17},
					AllowedDays:     []string{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday"},
					Timezone:        "UTC",
					HolidayBlocking: false,
				},
				DeviceRestrictions: false,
				MultiFactorAuth:    false,
				BiometricAuth:      false,
			},
			DataProtectionPolicy: &DataProtectionPolicyConfig{
				DataClassification:  true,
				DataEncryption:      true,
				DataMasking:         true,
				DataRetentionPeriod: 365 * 24 * time.Hour,
				DataBackupEnabled:   true,
				DataBackupInterval:  24 * time.Hour,
				DataBackupRetention: 30 * 24 * time.Hour,
				DataAnonymization:   false,
				GDPRCompliance:      false,
				CCPACompliance:      false,
			},
			IncidentResponse: &IncidentResponseConfig{
				Enabled:              true,
				AutoResponse:         false,
				NotificationEnabled:  true,
				NotificationChannels: []string{"email", "log"},
				EscalationRules:      []string{},
				QuarantineEnabled:    false,
				ForensicsEnabled:     false,
				RecoveryProcedures:   []string{},
				IncidentRetention:    90 * 24 * time.Hour,
			},
		},
		Monitoring: &SecurityMonitoringConfig{
			Enabled:               true,
			RealTimeMonitoring:    true,
			AnomalyDetection:      false,
			ThreatIntelligence:    false,
			VulnerabilityScanning: false,
			PenetrationTesting:    false,
			SecurityMetrics:       true,
			ComplianceMonitoring:  false,
			AlertThresholds: &AlertThresholdsConfig{
				FailedLoginAttempts:   5,
				SuspiciousActivities:  10,
				HighRiskConnections:   20,
				DataExfiltrationSize:  100 * 1024 * 1024, // 100MB
				ConnectionsPerSecond:  100,
				BandwidthThreshold:    1024 * 1024 * 1024, // 1GB
				ErrorRateThreshold:    0.05,               // 5%
				ResponseTimeThreshold: 5 * time.Second,
			},
			ReportingInterval: 24 * time.Hour,
			DashboardEnabled:  false,
		},
	}
}

// LoadSecurityConfig 加载安全配置
func LoadSecurityConfig(configPath string) (*SecurityConfig, error) {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// 配置文件不存在，创建默认配置
		config := DefaultSecurityConfig()
		if err := SaveSecurityConfig(config, configPath); err != nil {
			return nil, fmt.Errorf("failed to save default config: %w", err)
		}
		return config, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config SecurityConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// 验证配置
	if err := ValidateSecurityConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &config, nil
}

// SaveSecurityConfig 保存安全配置
func SaveSecurityConfig(config *SecurityConfig, configPath string) error {
	// 创建配置目录
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// 序列化配置
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// 写入文件
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// ValidateSecurityConfig 验证安全配置
func ValidateSecurityConfig(config *SecurityConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}

	// 验证密钥管理配置
		if config.KeyManager != nil {
			if config.KeyManager.KeyStorePath == "" {
				return fmt.Errorf("key manager store path cannot be empty")
			}
			if config.KeyManager.RotationInterval <= 0 {
				return fmt.Errorf("key rotation interval must be positive")
			}
			if config.KeyManager.KDFIterations <= 0 {
				return fmt.Errorf("KDF iterations must be positive")
			}
		}

	// 验证证书管理配置
	if config.CertManager != nil {
		if config.CertManager.CertStorePath == "" {
			return fmt.Errorf("cert manager store path cannot be empty")
		}
		if config.CertManager.DefaultKeySize < 1024 {
			return fmt.Errorf("default key size must be at least 1024 bits")
		}
		if config.CertManager.DefaultValidDays <= 0 {
			return fmt.Errorf("default valid days must be positive")
		}
	}

	// 验证访问控制配置
	if config.AccessControl != nil {
		if config.AccessControl.DataPath == "" {
			return fmt.Errorf("access control data path cannot be empty")
		}
		if config.AccessControl.SessionTimeout <= 0 {
			return fmt.Errorf("session timeout must be positive")
		}
		if config.AccessControl.PasswordMinLength < 4 {
			return fmt.Errorf("password min length must be at least 4")
		}
	}

	// 验证审计日志配置
	if config.AuditLogger != nil {
		if config.AuditLogger.LogPath == "" {
			return fmt.Errorf("audit logger log path cannot be empty")
		}
		if config.AuditLogger.MaxFileSize <= 0 {
			return fmt.Errorf("max file size must be positive")
		}
		if config.AuditLogger.MaxFiles <= 0 {
			return fmt.Errorf("max files must be positive")
		}
	}

	// 验证TLS配置
	if config.TLS != nil {
		validVersions := map[string]bool{
			"1.0": true, "1.1": true, "1.2": true, "1.3": true,
		}
		if !validVersions[config.TLS.MinVersion] {
			return fmt.Errorf("invalid TLS min version: %s", config.TLS.MinVersion)
		}
		if !validVersions[config.TLS.MaxVersion] {
			return fmt.Errorf("invalid TLS max version: %s", config.TLS.MaxVersion)
		}
	}

	// 验证网络安全配置
	if config.Network != nil {
		if config.Network.ConnectionLimit < 0 {
			return fmt.Errorf("connection limit cannot be negative")
		}
		if config.Network.TimeoutSettings != nil {
			if config.Network.TimeoutSettings.ConnectionTimeout <= 0 {
				return fmt.Errorf("connection timeout must be positive")
			}
			if config.Network.TimeoutSettings.ReadTimeout <= 0 {
				return fmt.Errorf("read timeout must be positive")
			}
			if config.Network.TimeoutSettings.WriteTimeout <= 0 {
				return fmt.Errorf("write timeout must be positive")
			}
		}
	}

	// 验证密码策略
	if config.Policy != nil && config.Policy.PasswordPolicy != nil {
		pp := config.Policy.PasswordPolicy
		if pp.MinLength < 1 {
			return fmt.Errorf("password min length must be at least 1")
		}
		if pp.MaxLength < pp.MinLength {
			return fmt.Errorf("password max length must be greater than or equal to min length")
		}
		if pp.MaxFailedAttempts < 0 {
			return fmt.Errorf("max failed attempts cannot be negative")
		}
	}

	return nil
}

// MergeSecurityConfig 合并安全配置
func MergeSecurityConfig(base, override *SecurityConfig) *SecurityConfig {
	if base == nil {
		return override
	}
	if override == nil {
		return base
	}

	// 创建基础配置的副本
	result := *base

	// 合并各个子配置
	if override.KeyManager != nil {
		result.KeyManager = override.KeyManager
	}
	if override.CertManager != nil {
		result.CertManager = override.CertManager
	}
	if override.AccessControl != nil {
		result.AccessControl = override.AccessControl
	}
	if override.AuditLogger != nil {
		result.AuditLogger = override.AuditLogger
	}
	if override.TLS != nil {
		result.TLS = override.TLS
	}
	if override.Encryption != nil {
		result.Encryption = override.Encryption
	}
	if override.Network != nil {
		result.Network = override.Network
	}
	if override.Policy != nil {
		result.Policy = override.Policy
	}
	if override.Monitoring != nil {
		result.Monitoring = override.Monitoring
	}

	return &result
}