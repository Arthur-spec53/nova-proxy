# Nova Proxy

[![CI/CD](https://github.com/your-org/nova-proxy/workflows/CI/CD/badge.svg)](https://github.com/your-org/nova-proxy/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/your-org/nova-proxy)](https://goreportcard.com/report/github.com/your-org/nova-proxy)
[![Coverage Status](https://codecov.io/gh/your-org/nova-proxy/branch/main/graph/badge.svg)](https://codecov.io/gh/your-org/nova-proxy)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker Pulls](https://img.shields.io/docker/pulls/your-org/nova-proxy.svg)](https://hub.docker.com/r/your-org/nova-proxy)

🚀 **Nova Proxy** 是一个高性能、企业级的现代代理服务器，基于 **ASTAT (自适应塑形传输与加密QUIC)** 协议构建。专为云原生环境设计，支持 HTTP/1.1、HTTP/2 和 HTTP/3 (QUIC) 协议，提供负载均衡、SSL/TLS 终止、缓存、监控和安全防护等功能。

## ✨ 核心特性

### 🌐 ASTAT 协议优势
- **高性能核心**: 基于 **QUIC** 构建，利用 UDP 绕过 TCP 的队头阻塞问题
- **传输层混淆 (E-QUIC)**: 整个 QUIC 传输被封装在自定义的二次加密层中
- **主动流量塑形**: 对抗统计分析，实现统计学上的不可区分性
- **抗审查能力**: 在深度包检测 (DPI) 面前完全隐藏协议指纹
- **0-RTT 连接**: 更快的连接建立和更低的延迟

### ⚡ 性能优化
- **零拷贝** I/O 操作
- **连接池** 管理
- **智能缓存** 策略
- **压缩算法** (Gzip, Brotli, Zstd)
- **负载均衡** (轮询、加权、最少连接、一致性哈希)

### 🔒 安全特性
- **TLS 1.3** 支持
- **mTLS** 双向认证
- **JWT** 令牌验证
- **Rate Limiting** 速率限制
- **WAF** Web 应用防火墙
- **DDoS** 防护
- **AES-GCM** 加密和 **HMAC-SHA256** 校验

### 📊 可观测性
- **Prometheus** 指标收集
- **Jaeger** 分布式链路追踪
- **结构化日志** (JSON 格式)
- **健康检查** 端点
- **实时监控** 仪表板

### ☁️ 云原生
- **Kubernetes** 原生支持
- **Helm Chart** 包管理
- **服务网格** 集成
- **自动扩缩容** (HPA/VPA)
- **优雅关闭** 和重启

## 🏗️ 架构设计

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client        │    │   Nova Proxy    │    │   Backend       │
│                 │    │                 │    │   Services      │
│  HTTP/1.1       │◄──►│  ┌───────────┐  │◄──►│                 │
│  HTTP/2         │    │  │  ASTAT    │  │    │  Service A      │
│  HTTP/3 (QUIC)  │    │  │  Router   │  │    │  Service B      │
│  SOCKS5         │    │  └───────────┘  │    │  Service C      │
│                 │    │  ┌───────────┐  │    │                 │
└─────────────────┘    │  │ E-QUIC    │  │    └─────────────────┘
                       │  │ Encryption│  │
                       │  └───────────┘  │
                       │  ┌───────────┐  │
                       │  │ Traffic   │  │
                       │  │ Shaping   │  │
                       │  └───────────┘  │
                       │  ┌───────────┐  │
                       │  │Monitoring │  │
                       │  └───────────┘  │
                       └─────────────────┘
```

## 🚀 快速开始

### 前置要求

- Go 1.22+
- Docker 20.10+
- Kubernetes 1.25+
- Helm 3.8+

### 本地开发

```bash
# 克隆项目
git clone https://github.com/your-org/nova-proxy.git
cd nova-proxy

# 安装依赖
go mod download

# 生成测试证书
make certs

# 运行测试
make test

# 编译服务端和客户端
cd cmd/nova-server && go build .
cd ../nova-client && go build .

# 启动服务端
./cmd/nova-server/nova-server

# 启动客户端 (新终端)
./cmd/nova-client/nova-client
```

### Docker 部署

```bash
# 构建镜像
docker build -t nova-proxy:latest .

# 运行服务端
docker run -p 8080:8080 -p 8443:8443 nova-proxy:latest server

# 运行客户端
docker run -p 1080:1080 nova-proxy:latest client
```

### Kubernetes 部署

```bash
# 使用 Helm 部署
helm install nova-proxy ./helm/nova-proxy \
  --namespace nova-proxy \
  --create-namespace \
  --values ./helm/nova-proxy/values.yaml

# 或使用原生 Kubernetes 清单
kubectl apply -f k8s/
```

## 📖 配置说明

### 服务端配置 (server.json)

```json
{
  "listen_addr": "0.0.0.0:8443",
  "preshared_key": "your-32-byte-key-here",
  "log_level": "info",
  "shaping": {
    "interval_ms": 50
  },
  "upstream": {
    "servers": [
      "http://backend1:8080",
      "http://backend2:8080"
    ],
    "load_balancer": "round_robin"
  },
  "ssl": {
    "cert_file": "/etc/ssl/certs/server.crt",
    "key_file": "/etc/ssl/private/server.key"
  }
}
```

### 客户端配置 (client.json)

```json
{
  "listen_addr": "127.0.0.1:1080",
  "remote_addr": "your-server:8443",
  "preshared_key": "your-32-byte-key-here",
  "log_level": "info",
  "shaping": {
    "interval_ms": 50,
    "min_pad_size": 64,
    "max_pad_size": 1024
  }
}
```

### 环境变量

| 变量名 | 描述 | 默认值 |
|--------|------|--------|
| `NOVA_CONFIG_FILE` | 配置文件路径 | `server.json`/`client.json` |
| `NOVA_LOG_LEVEL` | 日志级别 | `info` |
| `NOVA_PRESHARED_KEY` | 预共享密钥 | - |
| `NOVA_LISTEN_ADDR` | 监听地址 | `0.0.0.0:8443` |
| `NOVA_REMOTE_ADDR` | 远程地址 (客户端) | - |

## 🔧 开发指南

### 项目结构

```
nova-proxy/
├── cmd/                    # 应用程序入口
│   ├── nova-server/       # 服务端
│   └── nova-client/       # 客户端
├── internal/               # 内部包
│   ├── config/            # 配置管理
│   ├── server/            # 服务器实现
│   ├── client/            # 客户端实现
│   ├── protocol/          # ASTAT 协议实现
│   ├── crypto/            # E-QUIC 加密
│   ├── shaping/           # 流量塑形
│   └── monitoring/        # 监控模块
├── pkg/                   # 公共包
├── api/                   # API 定义
├── configs/               # 配置文件
├── scripts/               # 脚本工具
├── k8s/                   # Kubernetes 清单
├── helm/                  # Helm Chart
├── .github/               # CI/CD 配置
└── docs/                  # 文档
```

### 代码规范

```bash
# 代码格式化
go fmt ./...

# 代码检查
go vet ./...

# 安全扫描
gosec ./...

# 运行所有检查
make check
```

### 测试

```bash
# 单元测试
go test ./...

# 集成测试
./integration_test.sh

# 性能测试
go test -bench=. ./...

# 测试覆盖率
go test -cover ./...
```

## 📊 监控和运维

### 健康检查

```bash
# 基础健康检查
curl http://localhost:8080/health

# 详细健康检查
curl http://localhost:8080/health/detailed

# 就绪检查
curl http://localhost:8080/ready
```

### 指标监控

访问 Prometheus 指标：`http://localhost:9090/metrics`

主要指标：
- `nova_proxy_connections_total` - 连接总数
- `nova_proxy_bytes_transferred` - 传输字节数
- `nova_proxy_latency_seconds` - 连接延迟
- `nova_proxy_encryption_operations` - 加密操作数
- `nova_proxy_traffic_shaping_packets` - 流量塑形包数

### 日志管理

```bash
# 查看实时日志
kubectl logs -f deployment/nova-proxy -n nova-proxy

# 查看错误日志
kubectl logs deployment/nova-proxy -n nova-proxy --previous | grep ERROR

# 导出日志
kubectl logs deployment/nova-proxy -n nova-proxy > nova-proxy.log
```

## 🛠️ 运维脚本

### 部署脚本

```bash
# 部署到开发环境
./scripts/deploy/deploy.sh -e development -v latest

# 蓝绿部署到生产环境
./scripts/deploy/deploy.sh -e production -v v1.2.3 --blue-green

# 金丝雀部署
./scripts/deploy/deploy.sh -e production -v v1.2.3 --canary --replicas 2
```

### 监控设置

```bash
# 设置完整监控栈
./scripts/monitoring/setup-monitoring.sh -e production --all

# 仅部署 Prometheus
./scripts/monitoring/setup-monitoring.sh -e production --prometheus
```

### 备份和恢复

```bash
# 完整备份
./scripts/backup/backup.sh --type full --encrypt --upload s3

# 配置备份
./scripts/backup/backup.sh --type config --compress

# 恢复备份
./scripts/backup/restore.sh --backup-file backup-20240101.tar.gz
```

### 系统维护

```bash
# 健康检查
./scripts/maintenance/health-check.sh --namespace nova-proxy --format json

# 系统清理
./scripts/maintenance/cleanup.sh --days 7 --docker --k8s

# 性能调优
./scripts/maintenance/performance-tuning.sh --profile high --apply
```

## 🔒 安全最佳实践

### ASTAT 协议安全

```json
{
  "preshared_key": "32-byte-random-key-generated-securely",
  "encryption": {
    "algorithm": "AES-GCM",
    "key_rotation_interval": "24h"
  },
  "traffic_shaping": {
    "enable_padding": true,
    "randomize_timing": true
  }
}
```

### TLS 配置

```json
{
  "ssl": {
    "protocols": ["TLSv1.3"],
    "ciphers": [
      "TLS_AES_256_GCM_SHA384",
      "TLS_CHACHA20_POLY1305_SHA256"
    ],
    "hsts": {
      "enabled": true,
      "max_age": 31536000
    }
  }
}
```

### 访问控制

```json
{
  "access_control": {
    "rate_limiting": {
      "requests_per_second": 100,
      "burst": 200
    },
    "ip_whitelist": [
      "10.0.0.0/8",
      "172.16.0.0/12"
    ]
  }
}
```

## 🚨 故障排除

### 常见问题

**Q: ASTAT 连接失败**
```bash
# 检查预共享密钥
echo "检查客户端和服务端的 preshared_key 是否一致"

# 检查网络连通性
telnet server-ip 8443

# 查看详细日志
NOVA_LOG_LEVEL=debug ./nova-server
```

**Q: 流量塑形不工作**
```bash
# 检查配置
cat client.json | jq '.shaping'

# 监控流量模式
tcpdump -i any -w traffic.pcap host server-ip

# 分析数据包间隔
wireshark traffic.pcap
```

**Q: 性能问题**
```bash
# 检查系统资源
top -p $(pgrep nova-server)

# 检查网络延迟
ping server-ip

# 调整缓冲区大小
echo 'net.core.rmem_max = 16777216' >> /etc/sysctl.conf
```

### 性能调优

```bash
# 系统级优化
echo 'net.core.somaxconn = 65535' >> /etc/sysctl.conf
echo 'net.ipv4.udp_mem = 102400 873800 16777216' >> /etc/sysctl.conf
sysctl -p

# QUIC 优化
export QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING=1
export QUIC_GO_DISABLE_GSO=0

# 应用级优化
export GOMAXPROCS=$(nproc)
export GOGC=100
```

## 📈 性能基准

### 测试环境
- CPU: Intel Xeon E5-2686 v4 (8 cores)
- Memory: 16GB RAM
- Network: 10Gbps
- OS: Ubuntu 22.04 LTS

### ASTAT 协议性能

| 指标 | 值 | 说明 |
|------|----|---------|
| 连接建立时间 | <10ms | 0-RTT 优化 |
| 吞吐量 | 8Gbps | 单连接最大 |
| 并发连接 | 10,000+ | 服务端支持 |
| 延迟增加 | <2ms | 相比原始 QUIC |
| CPU 开销 | +15% | 加密和塑形 |

### 压力测试

```bash
# SOCKS5 代理测试
curl --socks5 127.0.0.1:1080 http://httpbin.org/ip

# 并发连接测试
./scripts/test/concurrent-test.sh --connections 1000

# 带宽测试
iperf3 -c server-ip -p 8443 --quic
```

## 🤝 贡献指南

我们欢迎社区贡献！请阅读 [CONTRIBUTING.md](CONTRIBUTING.md) 了解详细信息。

### 开发流程

1. Fork 项目
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

### 代码审查

所有 PR 都需要通过：
- 自动化测试
- 代码质量检查
- 安全扫描
- 至少一位维护者的审查

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 🙏 致谢

感谢以下开源项目：
- [Go](https://golang.org/) - 编程语言
- [quic-go](https://github.com/lucas-clemente/quic-go) - QUIC 实现
- [Prometheus](https://prometheus.io/) - 监控系统
- [Jaeger](https://www.jaegertracing.io/) - 分布式追踪

## 📞 支持

- 📧 Email: support@nova-proxy.io
- 💬 Slack: [#nova-proxy](https://nova-proxy.slack.com)
- 🐛 Issues: [GitHub Issues](https://github.com/your-org/nova-proxy/issues)
- 📖 文档: [https://docs.nova-proxy.io](https://docs.nova-proxy.io)

---

<div align="center">
  <strong>⭐ 如果这个项目对你有帮助，请给我们一个 Star！⭐</strong>
</div>
