package logging

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"
)

// LoggingConfig 日志配置
type LoggingConfig struct {
	// 基础配置
	Level      string `json:"level" yaml:"level"`           // 日志级别
	Format     string `json:"format" yaml:"format"`         // 日志格式 (json, text)
	Timestamp  bool   `json:"timestamp" yaml:"timestamp"`   // 是否包含时间戳
	Caller     bool   `json:"caller" yaml:"caller"`         // 是否包含调用者信息
	StackTrace bool   `json:"stacktrace" yaml:"stacktrace"` // 是否包含堆栈跟踪

	// 输出配置
	Outputs []OutputConfig `json:"outputs" yaml:"outputs"` // 输出配置列表

	// 轮转配置
	Rotation *LogRotatorConfig `json:"rotation,omitempty" yaml:"rotation,omitempty"`

	// 脱敏配置
	Sanitization *SanitizationConfig `json:"sanitization,omitempty" yaml:"sanitization,omitempty"`

	// 钩子配置
	Hooks []map[string]interface{} `json:"hooks,omitempty" yaml:"hooks,omitempty"`

	// 性能配置
	Performance *PerformanceConfig `json:"performance,omitempty" yaml:"performance,omitempty"`

	// 缓冲配置
	Buffering *BufferingConfig `json:"buffering,omitempty" yaml:"buffering,omitempty"`
}

// OutputConfig 输出配置
type OutputConfig struct {
	Type   string                 `json:"type" yaml:"type"`                         // 输出类型 (stdout, stderr, file, syslog)
	Path   string                 `json:"path,omitempty" yaml:"path,omitempty"`     // 文件路径 (仅file类型)
	Level  string                 `json:"level,omitempty" yaml:"level,omitempty"`   // 输出级别过滤
	Format string                 `json:"format,omitempty" yaml:"format,omitempty"` // 输出格式覆盖
	Config map[string]interface{} `json:"config,omitempty" yaml:"config,omitempty"` // 额外配置
}

// SanitizationConfig 脱敏配置
type SanitizationConfig struct {
	Enabled      bool     `json:"enabled" yaml:"enabled"`                                 // 是否启用脱敏
	CustomRules  []string `json:"custom_rules,omitempty" yaml:"custom_rules,omitempty"`   // 自定义脱敏规则
	ExcludeRules []string `json:"exclude_rules,omitempty" yaml:"exclude_rules,omitempty"` // 排除的默认规则
	MaskChar     string   `json:"mask_char,omitempty" yaml:"mask_char,omitempty"`         // 脱敏字符
	MaskLength   int      `json:"mask_length,omitempty" yaml:"mask_length,omitempty"`     // 脱敏长度
}

// PerformanceConfig 性能配置
type PerformanceConfig struct {
	AsyncLogging    bool          `json:"async_logging" yaml:"async_logging"`       // 异步日志
	WorkerCount     int           `json:"worker_count" yaml:"worker_count"`         // 工作协程数
	ChannelSize     int           `json:"channel_size" yaml:"channel_size"`         // 通道大小
	FlushInterval   time.Duration `json:"flush_interval" yaml:"flush_interval"`     // 刷新间隔
	BatchSize       int           `json:"batch_size" yaml:"batch_size"`             // 批处理大小
	MaxMemoryUsage  int64         `json:"max_memory_usage" yaml:"max_memory_usage"` // 最大内存使用
	CompressionType string        `json:"compression_type" yaml:"compression_type"` // 压缩类型
}

// BufferingConfig 缓冲配置
type BufferingConfig struct {
	Enabled       bool          `json:"enabled" yaml:"enabled"`               // 是否启用缓冲
	Size          int           `json:"size" yaml:"size"`                     // 缓冲区大小
	FlushInterval time.Duration `json:"flush_interval" yaml:"flush_interval"` // 刷新间隔
	FlushOnExit   bool          `json:"flush_on_exit" yaml:"flush_on_exit"`   // 退出时刷新
}

// DefaultLoggingConfig 默认日志配置
func DefaultLoggingConfig() *LoggingConfig {
	return &LoggingConfig{
		Level:     "info",
		Format:    "json",
		Timestamp: true,
		Caller:    true,
		Outputs: []OutputConfig{
			{
				Type: "stdout",
			},
		},
		Rotation: &LogRotatorConfig{
			MaxSize:  100, // 100MB
			MaxFiles: 10,
			MaxAge:   30 * 24 * time.Hour, // 30天
			Compress: true,
		},
		Sanitization: &SanitizationConfig{
			Enabled:    true,
			MaskChar:   "*",
			MaskLength: 8,
		},
		Performance: &PerformanceConfig{
			AsyncLogging:  false,
			WorkerCount:   2,
			ChannelSize:   1000,
			FlushInterval: 5 * time.Second,
			BatchSize:     100,
		},
		Buffering: &BufferingConfig{
			Enabled:       true,
			Size:          1000,
			FlushInterval: 1 * time.Second,
			FlushOnExit:   true,
		},
	}
}

// LoadLoggingConfig 从文件加载日志配置
func LoadLoggingConfig(configPath string) (*LoggingConfig, error) {
	if configPath == "" {
		return DefaultLoggingConfig(), nil
	}

	// 检查文件是否存在
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file not found: %s", configPath)
	}

	// 读取配置文件
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// 解析配置
	var config LoggingConfig
	switch filepath.Ext(configPath) {
	case ".json":
		if err := json.Unmarshal(data, &config); err != nil {
			return nil, fmt.Errorf("failed to parse JSON config: %w", err)
		}
	case ".yaml", ".yml":
		// 这里需要yaml库，暂时不实现
		return nil, fmt.Errorf("YAML config not supported yet")
	default:
		return nil, fmt.Errorf("unsupported config file format: %s", filepath.Ext(configPath))
	}

	// 验证配置
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &config, nil
}

// Validate 验证配置
func (c *LoggingConfig) Validate() error {
	// 验证日志级别
	if _, err := logrus.ParseLevel(c.Level); err != nil {
		return fmt.Errorf("invalid log level: %s", c.Level)
	}

	// 验证日志格式
	if c.Format != "json" && c.Format != "text" {
		return fmt.Errorf("invalid log format: %s (must be 'json' or 'text')", c.Format)
	}

	// 验证输出配置
	if len(c.Outputs) == 0 {
		return fmt.Errorf("at least one output must be configured")
	}

	for i, output := range c.Outputs {
		if err := output.Validate(); err != nil {
			return fmt.Errorf("invalid output config at index %d: %w", i, err)
		}
	}

	// 验证轮转配置
	if c.Rotation != nil {
		if c.Rotation.MaxSize <= 0 {
			return fmt.Errorf("rotation max_size must be positive")
		}
		if c.Rotation.MaxFiles <= 0 {
			return fmt.Errorf("rotation max_files must be positive")
		}
	}

	// 验证性能配置
	if c.Performance != nil {
		if c.Performance.WorkerCount <= 0 {
			c.Performance.WorkerCount = 2
		}
		if c.Performance.ChannelSize <= 0 {
			c.Performance.ChannelSize = 1000
		}
		if c.Performance.BatchSize <= 0 {
			c.Performance.BatchSize = 100
		}
	}

	// 验证缓冲配置
	if c.Buffering != nil {
		if c.Buffering.Size <= 0 {
			c.Buffering.Size = 1000
		}
	}

	return nil
}

// Validate 验证输出配置
func (o *OutputConfig) Validate() error {
	// 验证输出类型
	validTypes := []string{"stdout", "stderr", "file", "syslog"}
	valid := false
	for _, validType := range validTypes {
		if o.Type == validType {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("invalid output type: %s (must be one of: %v)", o.Type, validTypes)
	}

	// 文件类型必须指定路径
	if o.Type == "file" && o.Path == "" {
		return fmt.Errorf("file output type requires path")
	}

	// 验证级别
	if o.Level != "" {
		if _, err := logrus.ParseLevel(o.Level); err != nil {
			return fmt.Errorf("invalid output level: %s", o.Level)
		}
	}

	// 验证格式
	if o.Format != "" && o.Format != "json" && o.Format != "text" {
		return fmt.Errorf("invalid output format: %s (must be 'json' or 'text')", o.Format)
	}

	return nil
}

// SaveLoggingConfig 保存日志配置到文件
func SaveLoggingConfig(config *LoggingConfig, configPath string) error {
	// 创建目录
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// 序列化配置
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// 写入文件
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// GetLogLevel 获取logrus日志级别
func (c *LoggingConfig) GetLogLevel() logrus.Level {
	level, err := logrus.ParseLevel(c.Level)
	if err != nil {
		return logrus.InfoLevel
	}
	return level
}

// IsAsyncEnabled 是否启用异步日志
func (c *LoggingConfig) IsAsyncEnabled() bool {
	return c.Performance != nil && c.Performance.AsyncLogging
}

// IsBufferingEnabled 是否启用缓冲
func (c *LoggingConfig) IsBufferingEnabled() bool {
	return c.Buffering != nil && c.Buffering.Enabled
}

// IsSanitizationEnabled 是否启用脱敏
func (c *LoggingConfig) IsSanitizationEnabled() bool {
	return c.Sanitization != nil && c.Sanitization.Enabled
}

// GetEnabledHooks 获取启用的钩子配置
func (c *LoggingConfig) GetEnabledHooks() []map[string]interface{} {
	var enabled []map[string]interface{}
	for _, hook := range c.Hooks {
		if hookEnabled, ok := hook["enabled"].(bool); ok && hookEnabled {
			enabled = append(enabled, hook)
		}
	}
	return enabled
}
