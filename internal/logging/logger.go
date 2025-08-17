package logging

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// LogLevel 日志级别
type LogLevel string

const (
	LogLevelTrace LogLevel = "trace"
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
	LogLevelFatal LogLevel = "fatal"
	LogLevelPanic LogLevel = "panic"
)

// LogFormat 日志格式
type LogFormat string

const (
	LogFormatJSON LogFormat = "json"
	LogFormatText LogFormat = "text"
)

// LogOutput 日志输出
type LogOutput string

const (
	LogOutputStdout LogOutput = "stdout"
	LogOutputStderr LogOutput = "stderr"
	LogOutputFile   LogOutput = "file"
	LogOutputSyslog LogOutput = "syslog"
)

// LoggerConfig 日志配置
type LoggerConfig struct {
	Level           LogLevel          `json:"level"`
	Format          LogFormat         `json:"format"`
	Output          LogOutput         `json:"output"`
	FilePath        string            `json:"file_path"`
	MaxFileSize     int64             `json:"max_file_size"`    // 字节
	MaxFiles        int               `json:"max_files"`        // 保留文件数
	MaxAge          time.Duration     `json:"max_age"`          // 保留时间
	Compress        bool              `json:"compress"`         // 压缩旧文件
	LocalTime       bool              `json:"local_time"`       // 使用本地时间
	EnableRotation  bool              `json:"enable_rotation"`  // 启用日志轮转
	EnableSanitizer bool              `json:"enable_sanitizer"` // 启用敏感信息脱敏
	SanitizeRules   []SanitizeRule    `json:"sanitize_rules"`   // 脱敏规则
	Fields          map[string]string `json:"fields"`           // 全局字段
	Hooks           []HookConfig      `json:"hooks"`            // 钩子配置
	SyslogNetwork   string            `json:"syslog_network"`   // syslog网络类型
	SyslogAddress   string            `json:"syslog_address"`   // syslog地址
	SyslogTag       string            `json:"syslog_tag"`       // syslog标签
}

// SanitizeRule 敏感信息脱敏规则
type SanitizeRule struct {
	Name        string   `json:"name"`
	Pattern     string   `json:"pattern"`
	Replacement string   `json:"replacement"`
	Fields      []string `json:"fields"` // 应用到的字段，空表示所有字段
}

// HookConfig 钩子配置
type HookConfig struct {
	Type   string                 `json:"type"`   // elasticsearch, logstash, webhook, etc.
	Config map[string]interface{} `json:"config"` // 钩子特定配置
}

// StructuredLogger 结构化日志记录器
type StructuredLogger struct {
	logger    *logrus.Logger
	config    *LoggerConfig
	rotator   *LogRotator
	sanitizer *LogSanitizer
	mu        sync.RWMutex
	fields    logrus.Fields
}

// LogEntry 日志条目
type LogEntry struct {
	logger *StructuredLogger
	entry  *logrus.Entry
}

// NewStructuredLogger 创建结构化日志记录器
func NewStructuredLogger(config *LoggerConfig) (*StructuredLogger, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	// 设置默认值
	if config.Level == "" {
		config.Level = LogLevelInfo
	}
	if config.Format == "" {
		config.Format = LogFormatJSON
	}
	if config.Output == "" {
		config.Output = LogOutputStdout
	}
	if config.MaxFileSize == 0 {
		config.MaxFileSize = 100 * 1024 * 1024 // 100MB
	}
	if config.MaxFiles == 0 {
		config.MaxFiles = 10
	}
	if config.MaxAge == 0 {
		config.MaxAge = 30 * 24 * time.Hour // 30天
	}

	// 创建logrus实例
	logger := logrus.New()

	// 设置日志级别
	level, err := logrus.ParseLevel(string(config.Level))
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %w", err)
	}
	logger.SetLevel(level)

	// 设置日志格式
	switch config.Format {
	case LogFormatJSON:
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339Nano,
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime:  "timestamp",
				logrus.FieldKeyLevel: "level",
				logrus.FieldKeyMsg:   "message",
				logrus.FieldKeyFunc:  "function",
				logrus.FieldKeyFile:  "file",
			},
		})
	case LogFormatText:
		logger.SetFormatter(&logrus.TextFormatter{
			TimestampFormat: time.RFC3339,
			FullTimestamp:   true,
		})
	default:
		return nil, fmt.Errorf("unsupported log format: %s", config.Format)
	}

	// 设置输出
	var output io.Writer
	switch config.Output {
	case LogOutputStdout:
		output = os.Stdout
	case LogOutputStderr:
		output = os.Stderr
	case LogOutputFile:
		if config.FilePath == "" {
			return nil, fmt.Errorf("file path is required for file output")
		}
		// 创建日志目录
		logDir := filepath.Dir(config.FilePath)
		if err := os.MkdirAll(logDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %w", err)
		}
		// 打开日志文件
		file, err := os.OpenFile(config.FilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		output = file
	case LogOutputSyslog:
		// Syslog输出将在后面通过hook实现
		output = os.Stdout
	default:
		return nil, fmt.Errorf("unsupported log output: %s", config.Output)
	}

	logger.SetOutput(output)

	// 启用调用者信息
	logger.SetReportCaller(true)

	// 创建结构化日志记录器
	sl := &StructuredLogger{
		logger: logger,
		config: config,
		fields: make(logrus.Fields),
	}

	// 添加全局字段
	for key, value := range config.Fields {
		sl.fields[key] = value
	}

	// 创建日志轮转器
	if config.EnableRotation && config.Output == LogOutputFile {
		rotator, err := NewLogRotator(&LogRotatorConfig{
			Filename:  config.FilePath,
			MaxSize:   config.MaxFileSize,
			MaxFiles:  config.MaxFiles,
			MaxAge:    config.MaxAge,
			Compress:  config.Compress,
			LocalTime: config.LocalTime,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create log rotator: %w", err)
		}
		sl.rotator = rotator
		logger.SetOutput(rotator)
	}

	// 创建敏感信息脱敏器
	if config.EnableSanitizer {
		sanitizer, err := NewLogSanitizer(config.SanitizeRules)
		if err != nil {
			return nil, fmt.Errorf("failed to create log sanitizer: %w", err)
		}
		sl.sanitizer = sanitizer
	}

	// 添加钩子
	for _, hookConfig := range config.Hooks {
		hook, err := createHook(hookConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create hook %s: %w", hookConfig.Type, err)
		}
		logger.AddHook(hook)
	}

	return sl, nil
}

// WithField 添加字段
func (sl *StructuredLogger) WithField(key string, value interface{}) *LogEntry {
	sl.mu.RLock()
	fields := make(logrus.Fields, len(sl.fields)+1)
	for k, v := range sl.fields {
		fields[k] = v
	}
	sl.mu.RUnlock()

	fields[key] = sl.sanitizeValue(value)
	return &LogEntry{
		logger: sl,
		entry:  sl.logger.WithFields(fields),
	}
}

// WithFields 添加多个字段
func (sl *StructuredLogger) WithFields(fields logrus.Fields) *LogEntry {
	sl.mu.RLock()
	allFields := make(logrus.Fields, len(sl.fields)+len(fields))
	for k, v := range sl.fields {
		allFields[k] = v
	}
	sl.mu.RUnlock()

	for k, v := range fields {
		allFields[k] = sl.sanitizeValue(v)
	}
	return &LogEntry{
		logger: sl,
		entry:  sl.logger.WithFields(allFields),
	}
}

// WithContext 添加上下文
func (sl *StructuredLogger) WithContext(ctx context.Context) *LogEntry {
	sl.mu.RLock()
	fields := make(logrus.Fields, len(sl.fields))
	for k, v := range sl.fields {
		fields[k] = v
	}
	sl.mu.RUnlock()

	// 从上下文中提取字段
	if requestID := ctx.Value("request_id"); requestID != nil {
		fields["request_id"] = requestID
	}
	if userID := ctx.Value("user_id"); userID != nil {
		fields["user_id"] = userID
	}
	if traceID := ctx.Value("trace_id"); traceID != nil {
		fields["trace_id"] = traceID
	}

	return &LogEntry{
		logger: sl,
		entry:  sl.logger.WithContext(ctx).WithFields(fields),
	}
}

// WithError 添加错误
func (sl *StructuredLogger) WithError(err error) *LogEntry {
	sl.mu.RLock()
	fields := make(logrus.Fields, len(sl.fields)+1)
	for k, v := range sl.fields {
		fields[k] = v
	}
	sl.mu.RUnlock()

	fields["error"] = err.Error()
	// 添加堆栈跟踪
	if sl.config.Level == LogLevelDebug || sl.config.Level == LogLevelTrace {
		fields["stack_trace"] = getStackTrace()
	}

	return &LogEntry{
		logger: sl,
		entry:  sl.logger.WithFields(fields),
	}
}

// Trace 记录trace级别日志
func (sl *StructuredLogger) Trace(args ...interface{}) {
	sl.logger.Trace(sl.sanitizeMessage(fmt.Sprint(args...)))
}

// Tracef 记录trace级别格式化日志
func (sl *StructuredLogger) Tracef(format string, args ...interface{}) {
	sl.logger.Tracef(sl.sanitizeMessage(format), sl.sanitizeArgs(args...)...)
}

// Debug 记录debug级别日志
func (sl *StructuredLogger) Debug(args ...interface{}) {
	sl.logger.Debug(sl.sanitizeMessage(fmt.Sprint(args...)))
}

// Debugf 记录debug级别格式化日志
func (sl *StructuredLogger) Debugf(format string, args ...interface{}) {
	sl.logger.Debugf(sl.sanitizeMessage(format), sl.sanitizeArgs(args...)...)
}

// Info 记录info级别日志
func (sl *StructuredLogger) Info(args ...interface{}) {
	sl.logger.Info(sl.sanitizeMessage(fmt.Sprint(args...)))
}

// Infof 记录info级别格式化日志
func (sl *StructuredLogger) Infof(format string, args ...interface{}) {
	sl.logger.Infof(sl.sanitizeMessage(format), sl.sanitizeArgs(args...)...)
}

// Warn 记录warn级别日志
func (sl *StructuredLogger) Warn(args ...interface{}) {
	sl.logger.Warn(sl.sanitizeMessage(fmt.Sprint(args...)))
}

// Warnf 记录warn级别格式化日志
func (sl *StructuredLogger) Warnf(format string, args ...interface{}) {
	sl.logger.Warnf(sl.sanitizeMessage(format), sl.sanitizeArgs(args...)...)
}

// Error 记录error级别日志
func (sl *StructuredLogger) Error(args ...interface{}) {
	sl.logger.Error(sl.sanitizeMessage(fmt.Sprint(args...)))
}

// Errorf 记录error级别格式化日志
func (sl *StructuredLogger) Errorf(format string, args ...interface{}) {
	sl.logger.Errorf(sl.sanitizeMessage(format), sl.sanitizeArgs(args...)...)
}

// Fatal 记录fatal级别日志
func (sl *StructuredLogger) Fatal(args ...interface{}) {
	sl.logger.Fatal(sl.sanitizeMessage(fmt.Sprint(args...)))
}

// Fatalf 记录fatal级别格式化日志
func (sl *StructuredLogger) Fatalf(format string, args ...interface{}) {
	sl.logger.Fatalf(sl.sanitizeMessage(format), sl.sanitizeArgs(args...)...)
}

// Panic 记录panic级别日志
func (sl *StructuredLogger) Panic(args ...interface{}) {
	sl.logger.Panic(sl.sanitizeMessage(fmt.Sprint(args...)))
}

// Panicf 记录panic级别格式化日志
func (sl *StructuredLogger) Panicf(format string, args ...interface{}) {
	sl.logger.Panicf(sl.sanitizeMessage(format), sl.sanitizeArgs(args...)...)
}

// SetLevel 设置日志级别
func (sl *StructuredLogger) SetLevel(level LogLevel) error {
	logrusLevel, err := logrus.ParseLevel(string(level))
	if err != nil {
		return fmt.Errorf("invalid log level: %w", err)
	}
	sl.logger.SetLevel(logrusLevel)
	sl.config.Level = level
	return nil
}

// GetLevel 获取当前日志级别
func (sl *StructuredLogger) GetLevel() LogLevel {
	return LogLevel(sl.logger.GetLevel().String())
}

// Close 关闭日志记录器
func (sl *StructuredLogger) Close() error {
	if sl.rotator != nil {
		return sl.rotator.Close()
	}
	return nil
}

// LogEntry 方法

// WithField 添加字段到日志条目
func (le *LogEntry) WithField(key string, value interface{}) *LogEntry {
	return &LogEntry{
		logger: le.logger,
		entry:  le.entry.WithField(key, le.logger.sanitizeValue(value)),
	}
}

// WithFields 添加多个字段到日志条目
func (le *LogEntry) WithFields(fields logrus.Fields) *LogEntry {
	sanitizedFields := make(logrus.Fields, len(fields))
	for k, v := range fields {
		sanitizedFields[k] = le.logger.sanitizeValue(v)
	}
	return &LogEntry{
		logger: le.logger,
		entry:  le.entry.WithFields(sanitizedFields),
	}
}

// WithError 添加错误到日志条目
func (le *LogEntry) WithError(err error) *LogEntry {
	fields := logrus.Fields{"error": err.Error()}
	if le.logger.config.Level == LogLevelDebug || le.logger.config.Level == LogLevelTrace {
		fields["stack_trace"] = getStackTrace()
	}
	return &LogEntry{
		logger: le.logger,
		entry:  le.entry.WithFields(fields),
	}
}

// Trace 记录trace级别日志
func (le *LogEntry) Trace(args ...interface{}) {
	le.entry.Trace(le.logger.sanitizeMessage(fmt.Sprint(args...)))
}

// Tracef 记录trace级别格式化日志
func (le *LogEntry) Tracef(format string, args ...interface{}) {
	le.entry.Tracef(le.logger.sanitizeMessage(format), le.logger.sanitizeArgs(args...)...)
}

// Debug 记录debug级别日志
func (le *LogEntry) Debug(args ...interface{}) {
	le.entry.Debug(le.logger.sanitizeMessage(fmt.Sprint(args...)))
}

// Debugf 记录debug级别格式化日志
func (le *LogEntry) Debugf(format string, args ...interface{}) {
	le.entry.Debugf(le.logger.sanitizeMessage(format), le.logger.sanitizeArgs(args...)...)
}

// Info 记录info级别日志
func (le *LogEntry) Info(args ...interface{}) {
	le.entry.Info(le.logger.sanitizeMessage(fmt.Sprint(args...)))
}

// Infof 记录info级别格式化日志
func (le *LogEntry) Infof(format string, args ...interface{}) {
	le.entry.Infof(le.logger.sanitizeMessage(format), le.logger.sanitizeArgs(args...)...)
}

// Warn 记录warn级别日志
func (le *LogEntry) Warn(args ...interface{}) {
	le.entry.Warn(le.logger.sanitizeMessage(fmt.Sprint(args...)))
}

// Warnf 记录warn级别格式化日志
func (le *LogEntry) Warnf(format string, args ...interface{}) {
	le.entry.Warnf(le.logger.sanitizeMessage(format), le.logger.sanitizeArgs(args...)...)
}

// Error 记录error级别日志
func (le *LogEntry) Error(args ...interface{}) {
	le.entry.Error(le.logger.sanitizeMessage(fmt.Sprint(args...)))
}

// Errorf 记录error级别格式化日志
func (le *LogEntry) Errorf(format string, args ...interface{}) {
	le.entry.Errorf(le.logger.sanitizeMessage(format), le.logger.sanitizeArgs(args...)...)
}

// Fatal 记录fatal级别日志
func (le *LogEntry) Fatal(args ...interface{}) {
	le.entry.Fatal(le.logger.sanitizeMessage(fmt.Sprint(args...)))
}

// Fatalf 记录fatal级别格式化日志
func (le *LogEntry) Fatalf(format string, args ...interface{}) {
	le.entry.Fatalf(le.logger.sanitizeMessage(format), le.logger.sanitizeArgs(args...)...)
}

// Panic 记录panic级别日志
func (le *LogEntry) Panic(args ...interface{}) {
	le.entry.Panic(le.logger.sanitizeMessage(fmt.Sprint(args...)))
}

// Panicf 记录panic级别格式化日志
func (le *LogEntry) Panicf(format string, args ...interface{}) {
	le.entry.Panicf(le.logger.sanitizeMessage(format), le.logger.sanitizeArgs(args...)...)
}

// 私有方法

// sanitizeMessage 脱敏消息
func (sl *StructuredLogger) sanitizeMessage(message string) string {
	if sl.sanitizer == nil {
		return message
	}
	return sl.sanitizer.SanitizeString(message)
}

// sanitizeValue 脱敏值
func (sl *StructuredLogger) sanitizeValue(value interface{}) interface{} {
	if sl.sanitizer == nil {
		return value
	}
	return sl.sanitizer.SanitizeValue(value)
}

// sanitizeArgs 脱敏参数
func (sl *StructuredLogger) sanitizeArgs(args ...interface{}) []interface{} {
	if sl.sanitizer == nil {
		return args
	}
	sanitized := make([]interface{}, len(args))
	for i, arg := range args {
		sanitized[i] = sl.sanitizer.SanitizeValue(arg)
	}
	return sanitized
}

// getStackTrace 获取堆栈跟踪
func getStackTrace() string {
	buf := make([]byte, 4096)
	n := runtime.Stack(buf, false)
	return string(buf[:n])
}

// createHook 创建钩子
func createHook(config HookConfig) (logrus.Hook, error) {
	switch config.Type {
	case "syslog":
		return createSyslogHook(config.Config)
	case "webhook":
		return createWebhookHook(config.Config)
	case "elasticsearch":
		return createElasticsearchHook(config.Config)
	default:
		return nil, fmt.Errorf("unsupported hook type: %s", config.Type)
	}
}

// createSyslogHook 创建syslog钩子
func createSyslogHook(config map[string]interface{}) (logrus.Hook, error) {
	network, _ := config["network"].(string)
	address, _ := config["address"].(string)
	tag, _ := config["tag"].(string)

	if network == "" {
		network = "udp"
	}
	if address == "" {
		address = "localhost:514"
	}
	if tag == "" {
		tag = "nova-proxy"
	}

	return NewSyslogHook(network, address, tag)
}

// createWebhookHook 创建webhook钩子
func createWebhookHook(config map[string]interface{}) (logrus.Hook, error) {
	url, _ := config["url"].(string)
	method, _ := config["method"].(string)
	timeout, _ := config["timeout"].(time.Duration)

	headersInterface, _ := config["headers"].(map[string]interface{})
	headers := make(map[string]string)
	for k, v := range headersInterface {
		if str, ok := v.(string); ok {
			headers[k] = str
		}
	}

	levelsInterface, _ := config["levels"].([]interface{})
	var levels []string
	for _, level := range levelsInterface {
		if str, ok := level.(string); ok {
			levels = append(levels, str)
		}
	}

	return NewWebhookHook(WebhookConfig{
		URL:     url,
		Method:  method,
		Headers: headers,
		Timeout: timeout,
		Levels:  levels,
	})
}

// createElasticsearchHook 创建elasticsearch钩子
func createElasticsearchHook(config map[string]interface{}) (logrus.Hook, error) {
	url, _ := config["url"].(string)
	index, _ := config["index"].(string)
	timeout, _ := config["timeout"].(time.Duration)

	levelsInterface, _ := config["levels"].([]interface{})
	var levels []string
	for _, level := range levelsInterface {
		if str, ok := level.(string); ok {
			levels = append(levels, str)
		}
	}

	return NewElasticsearchHook(ElasticsearchConfig{
		URL:     url,
		Index:   index,
		Timeout: timeout,
		Levels:  levels,
	})
}
