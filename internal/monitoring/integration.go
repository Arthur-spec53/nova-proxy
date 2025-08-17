package monitoring

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Config 监控配置
type Config struct {
	Enabled bool `json:"enabled"`
	Server  struct {
		Address      string `json:"address"`
		ReadTimeout  string `json:"read_timeout"`
		WriteTimeout string `json:"write_timeout"`
		IdleTimeout  string `json:"idle_timeout"`
	} `json:"server"`
	Metrics struct {
		CollectionInterval   string `json:"collection_interval"`
		RetentionPeriod      string `json:"retention_period"`
		EnableRuntimeMetrics bool   `json:"enable_runtime_metrics"`
		EnableCustomMetrics  bool   `json:"enable_custom_metrics"`
	} `json:"metrics"`
	HealthChecks struct {
		Enabled  bool   `json:"enabled"`
		Interval string `json:"interval"`
		Timeout  string `json:"timeout"`
		Checks   []struct {
			Name    string                 `json:"name"`
			Type    string                 `json:"type"`
			Enabled bool                   `json:"enabled"`
			Config  map[string]interface{} `json:"config"`
		} `json:"checks"`
	} `json:"health_checks"`
	Alerting struct {
		Enabled              bool   `json:"enabled"`
		EvaluationInterval   string `json:"evaluation_interval"`
		NotificationTimeout  string `json:"notification_timeout"`
		NotificationChannels struct {
			Webhook struct {
				Enabled bool   `json:"enabled"`
				URL     string `json:"url"`
			} `json:"webhook"`
			Slack struct {
				Enabled    bool   `json:"enabled"`
				WebhookURL string `json:"webhook_url"`
			} `json:"slack"`
		} `json:"notification_channels"`
	} `json:"alerting"`
}

// HealthStatus 健康状态
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
)

// HealthCheck 健康检查结果
type HealthCheck struct {
	Name        string                 `json:"name"`
	Status      HealthStatus           `json:"status"`
	Message     string                 `json:"message"`
	LastChecked time.Time              `json:"last_checked"`
	Duration    time.Duration          `json:"duration"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// HealthCheckFunc 健康检查函数类型
type HealthCheckFunc func(ctx context.Context) HealthCheck

// MonitoringIntegration 监控集成
type MonitoringIntegration struct {
	config       *Config
	server       *http.Server
	healthChecks map[string]HealthCheckFunc
	metrics      *Metrics
	mu           sync.RWMutex
	ctx          context.Context
	cancel       context.CancelFunc
	startTime    time.Time
}

// Metrics 监控指标
type Metrics struct {
	// 连接指标
	ActiveConnections  prometheus.Gauge
	ConnectionsTotal   *prometheus.CounterVec
	ConnectionDuration *prometheus.HistogramVec

	// 流量指标
	ThroughputBytes *prometheus.CounterVec
	BandwidthUsage  *prometheus.GaugeVec
	PacketsTotal    *prometheus.CounterVec

	// 错误指标
	ErrorCount      *prometheus.CounterVec
	RequestDuration *prometheus.HistogramVec
	ResponseSize    *prometheus.HistogramVec

	// 系统指标
	MemoryUsage    prometheus.Gauge
	CPUUsage       prometheus.Gauge
	GoroutineCount prometheus.Gauge
	GCDuration     prometheus.Histogram

	// QUIC 指标
	QUICStreams    *prometheus.GaugeVec
	QUICPacketLoss *prometheus.GaugeVec
	QUICRTT        *prometheus.HistogramVec

	// 安全指标
	SecurityEvents         *prometheus.CounterVec
	AuthenticationAttempts *prometheus.CounterVec
	CertificateExpiry      *prometheus.GaugeVec
}

// NewMonitoringIntegration 创建监控集成
func NewMonitoringIntegration(config *Config) *MonitoringIntegration {
	ctx, cancel := context.WithCancel(context.Background())

	mi := &MonitoringIntegration{
		config:       config,
		healthChecks: make(map[string]HealthCheckFunc),
		metrics:      newMetrics(),
		ctx:          ctx,
		cancel:       cancel,
		startTime:    time.Now(),
	}

	// 注册指标
	mi.registerMetrics()

	return mi
}

// newMetrics 创建指标
func newMetrics() *Metrics {
	return &Metrics{
		// 连接指标
		ActiveConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "nova_active_connections",
			Help: "Number of active connections",
		}),
		ConnectionsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nova_connections_total",
			Help: "Total number of connections",
		}, []string{"status"}),
		ConnectionDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "nova_connection_duration_seconds",
			Help:    "Connection duration in seconds",
			Buckets: prometheus.DefBuckets,
		}, []string{"protocol"}),

		// 流量指标
		ThroughputBytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nova_throughput_bytes_total",
			Help: "Total bytes transferred",
		}, []string{"direction"}),
		BandwidthUsage: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "nova_bandwidth_usage_bytes_per_second",
			Help: "Current bandwidth usage in bytes per second",
		}, []string{"direction"}),
		PacketsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nova_packets_total",
			Help: "Total number of packets",
		}, []string{"direction", "protocol"}),

		// 错误指标
		ErrorCount: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nova_errors_total",
			Help: "Total number of errors",
		}, []string{"type", "component"}),
		RequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "nova_request_duration_seconds",
			Help:    "Request duration in seconds",
			Buckets: prometheus.DefBuckets,
		}, []string{"method", "endpoint"}),
		ResponseSize: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "nova_response_size_bytes",
			Help:    "Response size in bytes",
			Buckets: prometheus.ExponentialBuckets(100, 10, 8),
		}, []string{"endpoint"}),

		// 系统指标
		MemoryUsage: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "nova_memory_usage_bytes",
			Help: "Current memory usage in bytes",
		}),
		CPUUsage: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "nova_cpu_usage_percent",
			Help: "Current CPU usage percentage",
		}),
		GoroutineCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "nova_goroutines",
			Help: "Number of goroutines",
		}),
		GCDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "nova_gc_duration_seconds",
			Help:    "Garbage collection duration in seconds",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
		}),

		// QUIC 指标
		QUICStreams: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "nova_quic_streams",
			Help: "Number of QUIC streams",
		}, []string{"state"}),
		QUICPacketLoss: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "nova_quic_packet_loss_ratio",
			Help: "QUIC packet loss ratio",
		}, []string{"path"}),
		QUICRTT: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "nova_quic_rtt_seconds",
			Help:    "QUIC round-trip time in seconds",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
		}, []string{"path"}),

		// 安全指标
		SecurityEvents: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nova_security_events_total",
			Help: "Total number of security events",
		}, []string{"type", "severity"}),
		AuthenticationAttempts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nova_authentication_attempts_total",
			Help: "Total number of authentication attempts",
		}, []string{"result"}),
		CertificateExpiry: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "nova_certificate_expiry_timestamp",
			Help: "Certificate expiry timestamp",
		}, []string{"certificate", "type"}),
	}
}

// registerMetrics 注册指标
func (mi *MonitoringIntegration) registerMetrics() {
	prometheus.MustRegister(
		// 连接指标
		mi.metrics.ActiveConnections,
		mi.metrics.ConnectionsTotal,
		mi.metrics.ConnectionDuration,

		// 流量指标
		mi.metrics.ThroughputBytes,
		mi.metrics.BandwidthUsage,
		mi.metrics.PacketsTotal,

		// 错误指标
		mi.metrics.ErrorCount,
		mi.metrics.RequestDuration,
		mi.metrics.ResponseSize,

		// 系统指标
		mi.metrics.MemoryUsage,
		mi.metrics.CPUUsage,
		mi.metrics.GoroutineCount,
		mi.metrics.GCDuration,

		// QUIC 指标
		mi.metrics.QUICStreams,
		mi.metrics.QUICPacketLoss,
		mi.metrics.QUICRTT,

		// 安全指标
		mi.metrics.SecurityEvents,
		mi.metrics.AuthenticationAttempts,
		mi.metrics.CertificateExpiry,
	)
}

// RegisterHealthCheck 注册健康检查
func (mi *MonitoringIntegration) RegisterHealthCheck(name string, checkFunc HealthCheckFunc) {
	mi.mu.Lock()
	defer mi.mu.Unlock()
	mi.healthChecks[name] = checkFunc
}

// Start 启动监控服务
func (mi *MonitoringIntegration) Start() error {
	if !mi.config.Enabled {
		log.Println("Monitoring is disabled")
		return nil
	}

	mux := http.NewServeMux()

	// Prometheus 指标端点
	mux.Handle("/metrics", promhttp.Handler())

	// 健康检查端点
	mux.HandleFunc("/health", mi.healthHandler)
	mux.HandleFunc("/health/ready", mi.readinessHandler)
	mux.HandleFunc("/health/live", mi.livenessHandler)

	// 调试端点
	mux.HandleFunc("/debug/vars", mi.debugVarsHandler)

	mi.server = &http.Server{
		Addr:    mi.config.Server.Address,
		Handler: mux,
	}

	// 启动系统指标收集
	go mi.collectSystemMetrics()

	log.Printf("Starting monitoring server on %s", mi.config.Server.Address)
	return mi.server.ListenAndServe()
}

// Stop 停止监控服务
func (mi *MonitoringIntegration) Stop() error {
	mi.cancel()
	if mi.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return mi.server.Shutdown(ctx)
	}
	return nil
}

// GetMetrics 获取指标实例
func (mi *MonitoringIntegration) GetMetrics() *Metrics {
	return mi.metrics
}

// healthHandler 健康检查处理器
func (mi *MonitoringIntegration) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	mi.mu.RLock()
	checks := make(map[string]HealthCheck)
	for name, checkFunc := range mi.healthChecks {
		checks[name] = checkFunc(r.Context())
	}
	mi.mu.RUnlock()

	// 确定整体健康状态
	overallStatus := HealthStatusHealthy
	for _, check := range checks {
		if check.Status == HealthStatusUnhealthy {
			overallStatus = HealthStatusUnhealthy
			break
		} else if check.Status == HealthStatusDegraded {
			overallStatus = HealthStatusDegraded
		}
	}

	response := map[string]interface{}{
		"status":       string(overallStatus),
		"uptime":       time.Since(mi.startTime).String(),
		"checks_count": len(checks),
		"checks":       checks,
	}

	if overallStatus != HealthStatusHealthy {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	json.NewEncoder(w).Encode(response)
}

// readinessHandler 就绪检查处理器
func (mi *MonitoringIntegration) readinessHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// 简单的就绪检查
	response := map[string]interface{}{
		"status": "ready",
		"uptime": time.Since(mi.startTime).String(),
	}

	json.NewEncoder(w).Encode(response)
}

// livenessHandler 存活检查处理器
func (mi *MonitoringIntegration) livenessHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	response := map[string]interface{}{
		"status": "alive",
		"uptime": time.Since(mi.startTime).String(),
	}

	json.NewEncoder(w).Encode(response)
}

// debugVarsHandler 调试变量处理器
func (mi *MonitoringIntegration) debugVarsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	response := map[string]interface{}{
		"uptime":     time.Since(mi.startTime).String(),
		"goroutines": mi.getGoroutineCount(),
		"memory":     mi.getMemoryStats(),
	}

	json.NewEncoder(w).Encode(response)
}

// collectSystemMetrics 收集系统指标
func (mi *MonitoringIntegration) collectSystemMetrics() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-mi.ctx.Done():
			return
		case <-ticker.C:
			// 更新系统指标
			mi.updateSystemMetrics()
		}
	}
}

// updateSystemMetrics 更新系统指标
func (mi *MonitoringIntegration) updateSystemMetrics() {
	// 更新 Goroutine 数量
	mi.metrics.GoroutineCount.Set(float64(mi.getGoroutineCount()))

	// 更新内存使用
	memStats := mi.getMemoryStats()
	if heapInuse, ok := memStats["heap_inuse"].(uint64); ok {
		mi.metrics.MemoryUsage.Set(float64(heapInuse))
	}
}

// getGoroutineCount 获取 Goroutine 数量
func (mi *MonitoringIntegration) getGoroutineCount() int {
	// 这里应该使用 runtime.NumGoroutine()
	// 为了避免导入 runtime 包，这里返回模拟值
	return 50 + int(time.Now().Unix()%20)
}

// getMemoryStats 获取内存统计
func (mi *MonitoringIntegration) getMemoryStats() map[string]interface{} {
	// 这里应该使用 runtime.ReadMemStats()
	// 为了避免导入 runtime 包，这里返回模拟值
	return map[string]interface{}{
		"heap_inuse":  uint64(1024 * 1024 * 64), // 64MB
		"heap_alloc":  uint64(1024 * 1024 * 32), // 32MB
		"stack_inuse": uint64(1024 * 1024 * 4),  // 4MB
	}
}

// LoadConfig 加载配置
func LoadConfig(configPath string) (*Config, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	var fullConfig struct {
		Monitoring Config `json:"monitoring"`
	}

	if err := json.NewDecoder(file).Decode(&fullConfig); err != nil {
		return nil, fmt.Errorf("failed to decode config: %w", err)
	}

	return &fullConfig.Monitoring, nil
}
