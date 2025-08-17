package recovery

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"nova-proxy/pkg/log"
	"github.com/sirupsen/logrus"
)

// RecoveryConfig 恢复配置文件结构
type RecoveryConfig struct {
	Enabled          bool                     `json:"enabled"`
	EnhancedProxy    *EnhancedProxyConfig     `json:"enhanced_proxy"`
	Logging          *LoggingConfig           `json:"logging"`
	Metrics          *MetricsConfig           `json:"metrics"`
	Version          string                   `json:"version"`
	LastUpdated      time.Time                `json:"last_updated"`
}

// LoggingConfig 日志配置
type LoggingConfig struct {
	Level           string `json:"level"`
	Format          string `json:"format"`
	ErrorTracking   bool   `json:"error_tracking"`
	PerformanceLog  bool   `json:"performance_log"`
	ConnectionLog   bool   `json:"connection_log"`
}

// MetricsConfig 指标配置
type MetricsConfig struct {
	Enabled         bool          `json:"enabled"`
	CollectInterval time.Duration `json:"collect_interval"`
	RetentionPeriod time.Duration `json:"retention_period"`
	ExportFormat    string        `json:"export_format"`
}

// DefaultRecoveryConfig 返回默认恢复配置
func DefaultRecoveryConfig() *RecoveryConfig {
	return &RecoveryConfig{
		Enabled:       true,
		EnhancedProxy: DefaultEnhancedProxyConfig(),
		Logging: &LoggingConfig{
			Level:          "info",
			Format:         "json",
			ErrorTracking:  true,
			PerformanceLog: true,
			ConnectionLog:  true,
		},
		Metrics: &MetricsConfig{
			Enabled:         true,
			CollectInterval: 30 * time.Second,
			RetentionPeriod: 24 * time.Hour,
			ExportFormat:    "prometheus",
		},
		Version:     "1.0.0",
		LastUpdated: time.Now(),
	}
}

// LoadRecoveryConfig 从文件加载恢复配置
func LoadRecoveryConfig(configPath string) (*RecoveryConfig, error) {
	if configPath == "" {
		log.Logger.Info("No recovery config path provided, using default configuration")
		return DefaultRecoveryConfig(), nil
	}

	// 检查文件是否存在
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Logger.WithFields(logrus.Fields{
			"path": configPath,
		}).Warn("Recovery config file not found, creating default configuration")
		
		defaultConfig := DefaultRecoveryConfig()
		if err := SaveRecoveryConfig(configPath, defaultConfig); err != nil {
			return nil, fmt.Errorf("failed to create default recovery config: %w", err)
		}
		return defaultConfig, nil
	}

	// 读取配置文件
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read recovery config file: %w", err)
	}

	var config RecoveryConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse recovery config: %w", err)
	}

	// 验证配置
	if err := validateRecoveryConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid recovery config: %w", err)
	}

	log.Logger.WithFields(logrus.Fields{
		"path":    configPath,
		"version": config.Version,
		"enabled": config.Enabled,
	}).Info("Recovery configuration loaded successfully")

	return &config, nil
}

// SaveRecoveryConfig 保存恢复配置到文件
func SaveRecoveryConfig(configPath string, config *RecoveryConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}

	// 更新时间戳
	config.LastUpdated = time.Now()

	// 序列化配置
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal recovery config: %w", err)
	}

	// 写入文件
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write recovery config file: %w", err)
	}

	log.Logger.WithFields(logrus.Fields{
		"path":    configPath,
		"version": config.Version,
	}).Info("Recovery configuration saved successfully")

	return nil
}

// validateRecoveryConfig 验证恢复配置
func validateRecoveryConfig(config *RecoveryConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}

	// 验证增强代理配置
	if config.EnhancedProxy != nil {
		if err := validateEnhancedProxyConfig(config.EnhancedProxy); err != nil {
			return fmt.Errorf("invalid enhanced proxy config: %w", err)
		}
	}

	// 验证日志配置
	if config.Logging != nil {
		if err := validateLoggingConfig(config.Logging); err != nil {
			return fmt.Errorf("invalid logging config: %w", err)
		}
	}

	// 验证指标配置
	if config.Metrics != nil {
		if err := validateMetricsConfig(config.Metrics); err != nil {
			return fmt.Errorf("invalid metrics config: %w", err)
		}
	}

	return nil
}

// validateEnhancedProxyConfig 验证增强代理配置
func validateEnhancedProxyConfig(config *EnhancedProxyConfig) error {
	if config == nil {
		return nil
	}

	// 验证连接池配置
	if config.ConnectionPool != nil {
		if config.ConnectionPool.MaxConnections <= 0 {
			return fmt.Errorf("connection pool max_connections must be positive")
		}
		if config.ConnectionPool.MaxIdleTime <= 0 {
			return fmt.Errorf("connection pool max_idle_time must be positive")
		}
	}

	// 验证重试配置
	if config.Retry != nil {
		if config.Retry.MaxRetries <= 0 {
			return fmt.Errorf("retry max_retries must be positive")
		}
		if config.Retry.InitialDelay <= 0 {
			return fmt.Errorf("retry initial_delay must be positive")
		}
	}

	// 验证断路器配置
	if config.CircuitBreaker != nil {
		if config.CircuitBreaker.FailureThreshold <= 0 {
			return fmt.Errorf("circuit breaker failure_threshold must be positive")
		}
		if config.CircuitBreaker.RecoveryTimeout <= 0 {
			return fmt.Errorf("circuit breaker recovery_timeout must be positive")
		}
	}

	return nil
}

// validateLoggingConfig 验证日志配置
func validateLoggingConfig(config *LoggingConfig) error {
	if config == nil {
		return nil
	}

	// 验证日志级别
	validLevels := []string{"trace", "debug", "info", "warn", "error", "fatal", "panic"}
	validLevel := false
	for _, level := range validLevels {
		if config.Level == level {
			validLevel = true
			break
		}
	}
	if !validLevel {
		return fmt.Errorf("invalid log level: %s, must be one of %v", config.Level, validLevels)
	}

	// 验证日志格式
	validFormats := []string{"json", "text"}
	validFormat := false
	for _, format := range validFormats {
		if config.Format == format {
			validFormat = true
			break
		}
	}
	if !validFormat {
		return fmt.Errorf("invalid log format: %s, must be one of %v", config.Format, validFormats)
	}

	return nil
}

// validateMetricsConfig 验证指标配置
func validateMetricsConfig(config *MetricsConfig) error {
	if config == nil {
		return nil
	}

	if config.Enabled {
		if config.CollectInterval <= 0 {
			return fmt.Errorf("metrics collect_interval must be positive")
		}
		if config.RetentionPeriod <= 0 {
			return fmt.Errorf("metrics retention_period must be positive")
		}

		// 验证导出格式
		validFormats := []string{"prometheus", "json", "csv"}
		validFormat := false
		for _, format := range validFormats {
			if config.ExportFormat == format {
				validFormat = true
				break
			}
		}
		if !validFormat {
			return fmt.Errorf("invalid export format: %s, must be one of %v", config.ExportFormat, validFormats)
		}
	}

	return nil
}

// UpdateRecoveryConfig 更新恢复配置
func UpdateRecoveryConfig(configPath string, updateFunc func(*RecoveryConfig) error) error {
	// 加载当前配置
	config, err := LoadRecoveryConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load current config: %w", err)
	}

	// 应用更新
	if err := updateFunc(config); err != nil {
		return fmt.Errorf("failed to update config: %w", err)
	}

	// 验证更新后的配置
	if err := validateRecoveryConfig(config); err != nil {
		return fmt.Errorf("invalid updated config: %w", err)
	}

	// 保存配置
	if err := SaveRecoveryConfig(configPath, config); err != nil {
		return fmt.Errorf("failed to save updated config: %w", err)
	}

	log.Logger.WithFields(logrus.Fields{
		"path": configPath,
	}).Info("Recovery configuration updated successfully")

	return nil
}

// GetConfigTemplate 获取配置模板
func GetConfigTemplate() string {
	config := DefaultRecoveryConfig()
	data, _ := json.MarshalIndent(config, "", "  ")
	return string(data)
}

// ConfigWatcher 配置监视器
type ConfigWatcher struct {
	configPath   string
	lastModTime  time.Time
	onChange     func(*RecoveryConfig) error
	stopChan     chan struct{}
	checkInterval time.Duration
}

// NewConfigWatcher 创建配置监视器
func NewConfigWatcher(configPath string, onChange func(*RecoveryConfig) error) *ConfigWatcher {
	return &ConfigWatcher{
		configPath:    configPath,
		onChange:      onChange,
		stopChan:      make(chan struct{}),
		checkInterval: 5 * time.Second,
	}
}

// Start 启动配置监视器
func (cw *ConfigWatcher) Start() error {
	// 获取初始修改时间
	stat, err := os.Stat(cw.configPath)
	if err != nil {
		return fmt.Errorf("failed to stat config file: %w", err)
	}
	cw.lastModTime = stat.ModTime()

	go cw.watchLoop()
	log.Logger.WithFields(logrus.Fields{
		"path":     cw.configPath,
		"interval": cw.checkInterval,
	}).Info("Config watcher started")

	return nil
}

// Stop 停止配置监视器
func (cw *ConfigWatcher) Stop() {
	close(cw.stopChan)
	log.Logger.Info("Config watcher stopped")
}

// watchLoop 监视循环
func (cw *ConfigWatcher) watchLoop() {
	ticker := time.NewTicker(cw.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-cw.stopChan:
			return
		case <-ticker.C:
			cw.checkForChanges()
		}
	}
}

// checkForChanges 检查配置文件变化
func (cw *ConfigWatcher) checkForChanges() {
	stat, err := os.Stat(cw.configPath)
	if err != nil {
		log.Logger.WithError(err).Error("Failed to stat config file")
		return
	}

	if stat.ModTime().After(cw.lastModTime) {
		cw.lastModTime = stat.ModTime()
		
		log.Logger.WithFields(logrus.Fields{
			"path": cw.configPath,
			"time": stat.ModTime(),
		}).Info("Config file changed, reloading")

		config, err := LoadRecoveryConfig(cw.configPath)
		if err != nil {
			log.Logger.WithError(err).Error("Failed to reload config")
			return
		}

		if cw.onChange != nil {
			if err := cw.onChange(config); err != nil {
				log.Logger.WithError(err).Error("Failed to apply config changes")
				return
			}
		}

		log.Logger.Info("Config reloaded successfully")
	}
}