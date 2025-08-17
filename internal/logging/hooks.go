package logging

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/syslog"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

// SyslogHook syslog钩子
type SyslogHook struct {
	writer *syslog.Writer
	levels []logrus.Level
}

// NewSyslogHook 创建syslog钩子
func NewSyslogHook(network, address, tag string) (*SyslogHook, error) {
	writer, err := syslog.Dial(network, address, syslog.LOG_INFO, tag)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to syslog: %w", err)
	}

	return &SyslogHook{
		writer: writer,
		levels: logrus.AllLevels,
	}, nil
}

// Fire 实现logrus.Hook接口
func (sh *SyslogHook) Fire(entry *logrus.Entry) error {
	line, err := entry.String()
	if err != nil {
		return err
	}

	switch entry.Level {
	case logrus.PanicLevel:
		return sh.writer.Crit(line)
	case logrus.FatalLevel:
		return sh.writer.Crit(line)
	case logrus.ErrorLevel:
		return sh.writer.Err(line)
	case logrus.WarnLevel:
		return sh.writer.Warning(line)
	case logrus.InfoLevel:
		return sh.writer.Info(line)
	case logrus.DebugLevel:
		return sh.writer.Debug(line)
	case logrus.TraceLevel:
		return sh.writer.Debug(line)
	default:
		return sh.writer.Info(line)
	}
}

// Levels 实现logrus.Hook接口
func (sh *SyslogHook) Levels() []logrus.Level {
	return sh.levels
}

// Close 关闭syslog连接
func (sh *SyslogHook) Close() error {
	if sh.writer != nil {
		return sh.writer.Close()
	}
	return nil
}

// WebhookHook webhook钩子
type WebhookHook struct {
	url     string
	method  string
	headers map[string]string
	timeout time.Duration
	levels  []logrus.Level
	client  *http.Client
}

// WebhookConfig webhook配置
type WebhookConfig struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Timeout time.Duration     `json:"timeout"`
	Levels  []string          `json:"levels"`
}

// NewWebhookHook 创建webhook钩子
func NewWebhookHook(config WebhookConfig) (*WebhookHook, error) {
	if config.URL == "" {
		return nil, fmt.Errorf("webhook URL is required")
	}

	if config.Method == "" {
		config.Method = "POST"
	}

	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}

	if config.Headers == nil {
		config.Headers = make(map[string]string)
	}
	if config.Headers["Content-Type"] == "" {
		config.Headers["Content-Type"] = "application/json"
	}

	// 解析日志级别
	var levels []logrus.Level
	if len(config.Levels) == 0 {
		levels = logrus.AllLevels
	} else {
		for _, levelStr := range config.Levels {
			level, err := logrus.ParseLevel(levelStr)
			if err != nil {
				return nil, fmt.Errorf("invalid log level %s: %w", levelStr, err)
			}
			levels = append(levels, level)
		}
	}

	return &WebhookHook{
		url:     config.URL,
		method:  config.Method,
		headers: config.Headers,
		timeout: config.Timeout,
		levels:  levels,
		client: &http.Client{
			Timeout: config.Timeout,
		},
	}, nil
}

// Fire 实现logrus.Hook接口
func (wh *WebhookHook) Fire(entry *logrus.Entry) error {
	// 构造payload
	payload := map[string]interface{}{
		"timestamp": entry.Time.Format(time.RFC3339Nano),
		"level":     entry.Level.String(),
		"message":   entry.Message,
		"fields":    entry.Data,
	}

	// 序列化为JSON
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	// 创建HTTP请求
	req, err := http.NewRequest(wh.method, wh.url, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}

	// 设置请求头
	for key, value := range wh.headers {
		req.Header.Set(key, value)
	}

	// 发送请求
	resp, err := wh.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook request: %w", err)
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook request failed with status %d", resp.StatusCode)
	}

	return nil
}

// Levels 实现logrus.Hook接口
func (wh *WebhookHook) Levels() []logrus.Level {
	return wh.levels
}

// ElasticsearchHook elasticsearch钩子
type ElasticsearchHook struct {
	url     string
	index   string
	timeout time.Duration
	levels  []logrus.Level
	client  *http.Client
}

// ElasticsearchConfig elasticsearch配置
type ElasticsearchConfig struct {
	URL     string        `json:"url"`
	Index   string        `json:"index"`
	Timeout time.Duration `json:"timeout"`
	Levels  []string      `json:"levels"`
}

// NewElasticsearchHook 创建elasticsearch钩子
func NewElasticsearchHook(config ElasticsearchConfig) (*ElasticsearchHook, error) {
	if config.URL == "" {
		return nil, fmt.Errorf("elasticsearch URL is required")
	}

	if config.Index == "" {
		config.Index = "logs"
	}

	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}

	// 解析日志级别
	var levels []logrus.Level
	if len(config.Levels) == 0 {
		levels = logrus.AllLevels
	} else {
		for _, levelStr := range config.Levels {
			level, err := logrus.ParseLevel(levelStr)
			if err != nil {
				return nil, fmt.Errorf("invalid log level %s: %w", levelStr, err)
			}
			levels = append(levels, level)
		}
	}

	return &ElasticsearchHook{
		url:     config.URL,
		index:   config.Index,
		timeout: config.Timeout,
		levels:  levels,
		client: &http.Client{
			Timeout: config.Timeout,
		},
	}, nil
}

// Fire 实现logrus.Hook接口
func (eh *ElasticsearchHook) Fire(entry *logrus.Entry) error {
	// 构造文档
	doc := map[string]interface{}{
		"@timestamp": entry.Time.Format(time.RFC3339Nano),
		"level":      entry.Level.String(),
		"message":    entry.Message,
	}

	// 添加字段
	for key, value := range entry.Data {
		doc[key] = value
	}

	// 序列化为JSON
	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("failed to marshal elasticsearch document: %w", err)
	}

	// 构造URL
	url := fmt.Sprintf("%s/%s/_doc", eh.url, eh.index)

	// 创建HTTP请求
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to create elasticsearch request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// 发送请求
	resp, err := eh.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send elasticsearch request: %w", err)
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode >= 400 {
		return fmt.Errorf("elasticsearch request failed with status %d", resp.StatusCode)
	}

	return nil
}

// Levels 实现logrus.Hook接口
func (eh *ElasticsearchHook) Levels() []logrus.Level {
	return eh.levels
}
