# Nova Proxy 监控系统

Nova Proxy 提供了完整的企业级监控解决方案，包括 Prometheus 指标、健康检查、告警系统和性能监控。

## 目录

- [功能特性](#功能特性)
- [快速开始](#快速开始)
- [配置说明](#配置说明)
- [指标说明](#指标说明)
- [健康检查](#健康检查)
- [告警系统](#告警系统)
- [集成指南](#集成指南)
- [最佳实践](#最佳实践)
- [故障排查](#故障排查)

## 功能特性

### 🎯 核心功能

- **Prometheus 指标**: 全面的性能和业务指标收集
- **健康检查**: 多层次的服务健康状态监控
- **告警系统**: 智能告警规则和多渠道通知
- **性能监控**: 实时性能指标和系统资源监控
- **可视化**: 支持 Grafana 仪表盘集成

### 📊 监控指标分类

#### 连接指标
- `nova_active_connections`: 当前活跃连接数
- `nova_connections_total`: 连接总数（按状态分类）
- `nova_connection_duration_seconds`: 连接持续时间分布

#### 流量指标
- `nova_throughput_bytes_total`: 总传输字节数
- `nova_bandwidth_usage_bytes_per_second`: 带宽使用率
- `nova_packets_total`: 数据包统计

#### 错误指标
- `nova_errors_total`: 错误计数
- `nova_request_duration_seconds`: 请求延迟分布
- `nova_response_size_bytes`: 响应大小分布

#### 系统指标
- `nova_memory_usage_bytes`: 内存使用量
- `nova_cpu_usage_percent`: CPU 使用率
- `nova_goroutines`: Goroutine 数量
- `nova_gc_duration_seconds`: GC 耗时

#### QUIC 指标
- `nova_quic_streams`: QUIC 流状态
- `nova_quic_packet_loss_ratio`: 丢包率
- `nova_quic_rtt_seconds`: 往返时延

#### 安全指标
- `nova_security_events_total`: 安全事件计数
- `nova_authentication_attempts_total`: 认证尝试统计
- `nova_certificate_expiry_timestamp`: 证书过期时间

## 快速开始

### 1. 基本配置

创建监控配置文件 `configs/monitoring.json`：

```json
{
  "monitoring": {
    "enabled": true,
    "server": {
      "address": ":9090",
      "read_timeout": "30s",
      "write_timeout": "30s",
      "idle_timeout": "120s"
    },
    "metrics": {
      "collection_interval": "10s",
      "retention_period": "24h",
      "enable_runtime_metrics": true,
      "enable_custom_metrics": true
    },
    "health_checks": {
      "enabled": true,
      "interval": "30s",
      "timeout": "10s"
    },
    "alerting": {
      "enabled": true,
      "evaluation_interval": "30s",
      "notification_timeout": "10s"
    }
  }
}
```

### 2. 代码集成

```go
package main

import (
    "log"
    "nova-proxy/internal/monitoring"
)

func main() {
    // 加载配置
    config, err := monitoring.LoadConfig("configs/monitoring.json")
    if err != nil {
        log.Fatal(err)
    }

    // 创建监控实例
    monitor := monitoring.NewMonitoringIntegration(config)

    // 注册健康检查
    monitor.RegisterHealthCheck("database", checkDatabase)
    monitor.RegisterHealthCheck("redis", checkRedis)

    // 启动监控服务
    go func() {
        if err := monitor.Start(); err != nil {
            log.Printf("Monitoring server error: %v", err)
        }
    }()

    // 在业务逻辑中更新指标
    metrics := monitor.GetMetrics()
    metrics.ActiveConnections.Set(100)
    metrics.ErrorCount.WithLabelValues("timeout", "proxy").Inc()

    // 应用主逻辑...
}

func checkDatabase(ctx context.Context) monitoring.HealthCheck {
    // 实现数据库健康检查逻辑
    return monitoring.HealthCheck{
        Name:    "database",
        Status:  monitoring.HealthStatusHealthy,
        Message: "Database connection is healthy",
    }
}
```

### 3. 启动服务

```bash
# 启动 Nova Proxy
go run cmd/nova-proxy/main.go

# 监控端点将在 :9090 端口启动
# 访问 http://localhost:9090/metrics 查看 Prometheus 指标
# 访问 http://localhost:9090/health 查看健康状态
```

## 配置说明

### 服务器配置

```json
{
  "server": {
    "address": ":9090",           // 监控服务器地址
    "read_timeout": "30s",        // 读取超时
    "write_timeout": "30s",       // 写入超时
    "idle_timeout": "120s"        // 空闲超时
  }
}
```

### 指标配置

```json
{
  "metrics": {
    "collection_interval": "10s",     // 指标收集间隔
    "retention_period": "24h",        // 指标保留时间
    "enable_runtime_metrics": true,   // 启用运行时指标
    "enable_custom_metrics": true     // 启用自定义指标
  }
}
```

### 健康检查配置

```json
{
  "health_checks": {
    "enabled": true,
    "interval": "30s",    // 检查间隔
    "timeout": "10s",     // 检查超时
    "checks": [
      {
        "name": "database",
        "type": "tcp",
        "enabled": true,
        "config": {
          "host": "localhost",
          "port": 5432,
          "timeout": "5s"
        }
      }
    ]
  }
}
```

### 告警配置

```json
{
  "alerting": {
    "enabled": true,
    "evaluation_interval": "30s",
    "notification_timeout": "10s",
    "rules": [
      {
        "name": "HighErrorRate",
        "condition": "rate(nova_errors_total[5m]) > 0.1",
        "severity": "warning",
        "description": "Error rate is above 10%"
      }
    ],
    "notification_channels": {
      "webhook": {
        "enabled": true,
        "url": "https://hooks.slack.com/services/..."
      },
      "email": {
        "enabled": true,
        "smtp_host": "smtp.example.com",
        "smtp_port": 587,
        "from": "alerts@example.com",
        "to": ["admin@example.com"]
      }
    }
  }
}
```

## 指标说明

### 指标类型

#### Counter（计数器）
- 只能增加的累计指标
- 适用于：请求总数、错误总数、字节传输总数
- 示例：`nova_connections_total`、`nova_errors_total`

#### Gauge（仪表盘）
- 可增可减的瞬时值指标
- 适用于：当前连接数、内存使用量、CPU 使用率
- 示例：`nova_active_connections`、`nova_memory_usage_bytes`

#### Histogram（直方图）
- 观察值的分布统计
- 适用于：请求延迟、响应大小、连接持续时间
- 示例：`nova_request_duration_seconds`、`nova_response_size_bytes`

### 标签使用

标签用于对指标进行分类和过滤：

```go
// 按方向分类的流量指标
metrics.ThroughputBytes.WithLabelValues("inbound").Add(1024)
metrics.ThroughputBytes.WithLabelValues("outbound").Add(2048)

// 按错误类型和组件分类的错误指标
metrics.ErrorCount.WithLabelValues("timeout", "proxy").Inc()
metrics.ErrorCount.WithLabelValues("connection", "backend").Inc()

// 按协议分类的连接持续时间
metrics.ConnectionDuration.WithLabelValues("quic").Observe(1.5)
metrics.ConnectionDuration.WithLabelValues("tcp").Observe(2.1)
```

## 健康检查

### 健康检查端点

- `GET /health`: 综合健康状态
- `GET /health/ready`: 就绪检查（用于负载均衡器）
- `GET /health/live`: 存活检查（用于容器编排）

### 健康状态

- `healthy`: 服务正常
- `degraded`: 服务降级（部分功能受影响）
- `unhealthy`: 服务异常

### 自定义健康检查

```go
// 数据库健康检查
func checkDatabase(ctx context.Context) monitoring.HealthCheck {
    start := time.Now()
    
    // 执行数据库连接测试
    if err := db.PingContext(ctx); err != nil {
        return monitoring.HealthCheck{
            Name:        "database",
            Status:      monitoring.HealthStatusUnhealthy,
            Message:     fmt.Sprintf("Database connection failed: %v", err),
            LastChecked: time.Now(),
            Duration:    time.Since(start),
        }
    }
    
    return monitoring.HealthCheck{
        Name:        "database",
        Status:      monitoring.HealthStatusHealthy,
        Message:     "Database connection is healthy",
        LastChecked: time.Now(),
        Duration:    time.Since(start),
        Metadata: map[string]interface{}{
            "connection_pool_size": 20,
            "active_connections":   12,
        },
    }
}
```

## 告警系统

### 告警规则

告警规则基于 Prometheus 查询语言（PromQL）：

```json
{
  "rules": [
    {
      "name": "HighErrorRate",
      "condition": "rate(nova_errors_total[5m]) > 0.1",
      "severity": "warning",
      "description": "Error rate is above 10% for 5 minutes",
      "for": "2m"
    },
    {
      "name": "HighMemoryUsage",
      "condition": "nova_memory_usage_bytes > 2147483648",
      "severity": "critical",
      "description": "Memory usage is above 2GB",
      "for": "1m"
    },
    {
      "name": "ServiceDown",
      "condition": "up{job=\"nova-proxy\"} == 0",
      "severity": "critical",
      "description": "Nova Proxy service is down",
      "for": "30s"
    }
  ]
}
```

### 通知渠道

#### Webhook 通知

```json
{
  "webhook": {
    "enabled": true,
    "url": "https://hooks.example.com/webhook",
    "timeout": "10s",
    "headers": {
      "Authorization": "Bearer token123"
    }
  }
}
```

#### Slack 通知

```json
{
  "slack": {
    "enabled": true,
    "webhook_url": "https://hooks.slack.com/services/...",
    "channel": "#alerts",
    "username": "Nova Proxy",
    "icon_emoji": ":warning:"
  }
}
```

#### 邮件通知

```json
{
  "email": {
    "enabled": true,
    "smtp_host": "smtp.example.com",
    "smtp_port": 587,
    "username": "alerts@example.com",
    "password": "password",
    "from": "alerts@example.com",
    "to": ["admin@example.com", "ops@example.com"],
    "subject_template": "[{{.Severity}}] {{.Name}}: {{.Message}}"
  }
}
```

## 集成指南

### Prometheus 集成

在 Prometheus 配置文件中添加 Nova Proxy 作为监控目标：

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'nova-proxy'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 15s
    metrics_path: /metrics
```

### Grafana 仪表盘

创建 Grafana 仪表盘来可视化监控数据：

```json
{
  "dashboard": {
    "title": "Nova Proxy Monitoring",
    "panels": [
      {
        "title": "Active Connections",
        "type": "graph",
        "targets": [
          {
            "expr": "nova_active_connections",
            "legendFormat": "Active Connections"
          }
        ]
      },
      {
        "title": "Error Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(nova_errors_total[5m])",
            "legendFormat": "Error Rate"
          }
        ]
      }
    ]
  }
}
```

### Kubernetes 集成

在 Kubernetes 中部署时，添加监控相关的注解：

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nova-proxy
spec:
  template:
    metadata:
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"
        prometheus.io/path: "/metrics"
    spec:
      containers:
      - name: nova-proxy
        image: nova-proxy:latest
        ports:
        - containerPort: 8080  # 主服务端口
        - containerPort: 9090  # 监控端口
        livenessProbe:
          httpGet:
            path: /health/live
            port: 9090
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 9090
          initialDelaySeconds: 5
          periodSeconds: 5
```

## 最佳实践

### 1. 指标命名规范

- 使用一致的前缀：`nova_`
- 使用描述性的名称：`nova_active_connections` 而不是 `nova_conn`
- 包含单位信息：`nova_memory_usage_bytes`、`nova_request_duration_seconds`

### 2. 标签使用原则

- 保持标签基数较低（避免高基数标签）
- 使用有意义的标签名称
- 避免在标签值中包含动态内容（如时间戳、用户ID）

### 3. 健康检查设计

- 检查关键依赖项（数据库、缓存、外部API）
- 设置合理的超时时间
- 提供详细的错误信息
- 包含相关的元数据

### 4. 告警规则设计

- 基于症状而非原因设置告警
- 设置合理的阈值和持续时间
- 避免告警风暴
- 提供可操作的告警信息

### 5. 性能优化

- 合理设置指标收集间隔
- 避免过度监控
- 使用采样来减少高频指标的开销
- 定期清理不再使用的指标

## 故障排查

### 常见问题

#### 1. 监控服务无法启动

**症状**: 监控端口无法绑定

**解决方案**:
```bash
# 检查端口是否被占用
netstat -tlnp | grep :9090

# 修改配置文件中的端口
# 或者停止占用端口的进程
```

#### 2. 指标数据缺失

**症状**: Prometheus 无法抓取到指标数据

**解决方案**:
```bash
# 检查监控端点是否可访问
curl http://localhost:9090/metrics

# 检查 Prometheus 配置
# 确认 scrape_configs 中的目标地址正确
```

#### 3. 健康检查失败

**症状**: 健康检查端点返回 503 状态码

**解决方案**:
```bash
# 检查健康检查详情
curl http://localhost:9090/health

# 查看应用日志
tail -f /var/log/nova-proxy/app.log

# 检查依赖服务状态
```

#### 4. 告警不触发

**症状**: 满足条件但告警未发送

**解决方案**:
- 检查告警规则语法
- 验证通知渠道配置
- 查看告警管理器日志
- 确认告警规则的 `for` 持续时间设置

### 调试工具

#### 1. 指标查询

```bash
# 查看所有指标
curl http://localhost:9090/metrics

# 查看特定指标
curl http://localhost:9090/metrics | grep nova_active_connections
```

#### 2. 健康检查调试

```bash
# 综合健康状态
curl -s http://localhost:9090/health | jq .

# 就绪检查
curl -s http://localhost:9090/health/ready | jq .

# 存活检查
curl -s http://localhost:9090/health/live | jq .
```

#### 3. 调试变量

```bash
# 查看调试信息
curl -s http://localhost:9090/debug/vars | jq .
```

### 日志分析

监控系统的日志通常包含以下信息：

```
2024-01-15 10:30:00 INFO  Starting monitoring server on :9090
2024-01-15 10:30:01 INFO  Health check 'database' registered
2024-01-15 10:30:01 INFO  Health check 'redis' registered
2024-01-15 10:30:02 INFO  Alert rule 'HighErrorRate' added
2024-01-15 10:30:02 INFO  Notification channel 'webhook' configured
2024-01-15 10:30:05 WARN  Health check 'external_api' failed: connection timeout
2024-01-15 10:30:10 ERROR Alert 'HighMemoryUsage' fired: Memory usage is 2.1GB
```

## 示例和模板

### 完整配置示例

参考 `configs/monitoring.json` 文件获取完整的配置示例。

### 集成示例

参考以下示例文件：
- `examples/monitoring_example.go`: 基本监控使用示例
- `examples/monitoring_integration_example.go`: 完整集成示例

### Grafana 仪表盘模板

在 `configs/grafana/` 目录下提供了预配置的 Grafana 仪表盘模板。

---

## 支持和贡献

如果您在使用监控系统时遇到问题，请：

1. 查看本文档的故障排查部分
2. 检查项目的 GitHub Issues
3. 提交新的 Issue 或 Pull Request

监控系统是 Nova Proxy 的重要组成部分，我们欢迎社区的反馈和贡献！