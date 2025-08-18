# Nova Proxy

[![CI/CD](https://github.com/Arthur-spec53/nova-proxy/workflows/CI/CD/badge.svg)](https://github.com/Arthur-spec53/nova-proxy/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/Arthur-spec53/nova-proxy)](https://goreportcard.com/report/github.com/Arthur-spec53/nova-proxy)
[![Coverage Status](https://codecov.io/gh/Arthur-spec53/nova-proxy/branch/main/graph/badge.svg)](https://codecov.io/gh/Arthur-spec53/nova-proxy)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker Pulls](https://img.shields.io/docker/pulls/arthur-spec53/nova-proxy.svg)](https://hub.docker.com/r/arthur-spec53/nova-proxy)

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

## 🎯 管理工具 (推荐)

**Nova Proxy** 提供了一个保姆级的命令行管理工具，让部署和维护变得简单易用：

```bash
# 启动交互式管理工具
./scripts/nova-manager.sh
```

### 🌟 管理工具特性

- **🔍 智能系统检查**: 自动评估硬件资源并推荐最适合的部署方案
- **🚀 多种部署模式**: 
  - 核心服务部署 (Nova Server + 基础监控)
  - 轻量级部署 (最小化资源占用)
  - 完整部署 (包含完整监控栈)
  - 生产环境部署 (企业级配置)
- **📊 实时监控**: 服务状态、资源使用、容器健康检查
- **⚙️ 服务管理**: 启动、停止、重启、日志查看
- **🌐 监控面板**: 一键访问 Grafana、Prometheus、Jaeger 等监控工具
- **📋 保姆级指导**: 每个操作都有详细说明和确认提示

**快速体验**: 查看 [快速入门指南](QUICK_START.md) 或 [详细管理指南](README_MANAGER.md)

## 🚀 快速开始

### 方法一：使用管理工具 (推荐)

```bash
# 1. 运行系统检查，获取部署建议
./scripts/system-check.sh

# 2. 启动管理工具，按提示操作
./scripts/nova-manager.sh

# 管理工具菜单选项：
# 1. 系统检查和环境评估
# 2. 核心服务部署 (推荐首次使用)
# 3. 轻量级部署
# 4. 完整部署 (包含完整监控栈)
# 5. 生产环境部署
# 6. 查看服务状态
# 8. 停止服务
# 13. 获取监控面板访问地址
```

### 方法二：直接使用 Docker Compose

```bash
# 核心服务部署 (推荐)
docker compose -f docker-compose.dev.yml up -d

# 轻量级部署
docker compose -f docker-compose.minimal.yml up -d

# 完整部署
docker compose up -d

# 查看服务状态
docker compose ps

# 访问服务
# Nova Proxy: http://localhost:8080
# Grafana: http://localhost:3000 (admin/admin)
# Prometheus: http://localhost:9090
```

### 前置要求

- Docker 20.10+ 和 Docker Compose
- 至少 2GB 可用内存
- 至少 10GB 可用磁盘空间

### 本地开发

```bash
# 克隆项目
git clone https://github.com/Arthur-spec53/nova-proxy.git
cd nova-proxy

# 使用开发环境配置
cp .env.example .env

# 启动开发环境
docker compose -f docker-compose.dev.yml up -d

# 查看日志
docker compose -f docker-compose.dev.yml logs -f
```

### 生产部署

```bash
# 配置生产环境变量
cp .env.example .env
# 编辑 .env 文件，设置域名和密码

# 创建外部网络
docker network create traefik-public

# 启动生产环境
docker compose -f docker-compose.prod.yml up -d
```

### Kubernetes 部署

```bash
# 使用 Helm 部署
helm install nova-proxy ./helm/nova-proxy \
  --namespace nova-proxy \
  --create-namespace

# 或使用 Kubernetes 清单
kubectl apply -f deployments/k8s/
```

## 📖 配置说明

### 环境变量配置 (.env)

```bash
# 基础配置
BUILD_VERSION=latest
LOG_LEVEL=info
ENVIRONMENT=development

# 域名配置 (生产环境)
NOVA_DOMAIN=localhost
PROMETHEUS_DOMAIN=localhost
GRAFANA_DOMAIN=localhost
JAEGER_DOMAIN=localhost
ALERTMANAGER_DOMAIN=localhost

# 认证配置
GRAFANA_ADMIN_PASSWORD=admin123
REDIS_PASSWORD=redis123
ELASTICSEARCH_PASSWORD=elastic123
HTTP_BASIC_AUTH_USER=admin
HTTP_BASIC_AUTH_PASSWORD=admin123

# 镜像配置
REGISTRY=
VERSION=latest
```

### Docker Compose 配置文件

项目提供了多种部署配置：

- `docker-compose.dev.yml` - 开发环境 (Nova Server + 基础监控)
- `docker-compose.minimal.yml` - 轻量级部署 (最小资源)
- `docker-compose.yml` - 完整部署 (完整监控栈)
- `docker-compose.prod.yml` - 生产环境 (企业级配置)

### 主要环境变量

| 变量名 | 描述 | 默认值 |
|--------|------|--------|
| `BUILD_VERSION` | 构建版本 | `latest` |
| `LOG_LEVEL` | 日志级别 | `info` |
| `ENVIRONMENT` | 运行环境 | `development` |
| `NOVA_DOMAIN` | Nova Proxy 域名 | `localhost` |
| `GRAFANA_ADMIN_PASSWORD` | Grafana 管理员密码 | `admin123` |
| `PROMETHEUS_DOMAIN` | Prometheus 域名 | `localhost` |
| `GRAFANA_DOMAIN` | Grafana 域名 | `localhost` |

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

### 服务访问地址

```bash
# 使用管理工具获取访问地址
./scripts/nova-manager.sh
# 选择选项 13: 监控面板访问地址

# 或直接访问以下地址：
# Nova Proxy 服务: http://localhost:8080
# Prometheus: http://localhost:9090
# Grafana: http://localhost:3000 (admin/admin123)
# Jaeger: http://localhost:16686
```

### 健康检查

```bash
# Nova Server 健康检查
curl http://localhost:8080/health

# 检查容器状态
docker compose ps

# 查看服务日志
docker compose logs nova-server
```

### 指标监控

访问 Prometheus 指标：`http://localhost:9090`

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

**Q: Docker Compose 启动失败**
```bash
# 检查 Docker 和 Docker Compose 版本
docker --version
docker compose version

# 检查端口占用
sudo netstat -tlnp | grep :8080
sudo netstat -tlnp | grep :3000

# 清理并重新启动
docker compose down
docker compose up -d
```

**Q: 健康检查失败**
```bash
# 检查容器状态
docker compose ps

# 查看容器日志
docker compose logs nova-server
docker compose logs nova-grafana

# 检查健康检查脚本
docker exec nova-server /app/bin/healthcheck.sh
```

**Q: 监控服务无法访问**
```bash
# 检查服务是否运行
curl -f http://localhost:8080/health || echo "Nova Server 不可访问"
curl -f http://localhost:9090/-/healthy || echo "Prometheus 不可访问"
curl -f http://localhost:3000/api/health || echo "Grafana 不可访问"

# 检查防火墙设置
sudo ufw status

# 重启服务
docker compose restart
```

**Q: 镜像拉取失败**
```bash
# 检查网络连接
ping docker.io
ping ghcr.io

# 使用本地构建
docker compose build

# 或修改 .env 文件使用本地镜像
echo "REGISTRY=" >> .env
echo "VERSION=latest" >> .env
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

### 测试说明

本项目提供了完整的性能测试框架，包括基准测试、压力测试和性能分析工具。实际性能表现会根据硬件配置、网络环境和负载情况而有所不同。

### 性能测试工具

项目包含以下性能测试组件：

- **基准测试**: `test/performance/performance_test.go` - Go 基准测试套件
- **压力测试脚本**: `scripts/performance.sh` - 自动化性能测试工具
- **监控工具**: 支持 Prometheus 指标收集和性能监控

### 运行性能测试

```bash
# 运行 Go 基准测试
go test -bench=. ./test/performance/

# 使用性能测试脚本
./scripts/performance.sh --benchmark

# SOCKS5 代理功能测试
curl --socks5 127.0.0.1:1080 http://httpbin.org/ip

# 并发连接测试
./scripts/performance.sh --load-test --connections 100
```

### 性能优化特性

- **ASTAT 协议优化**: 基于 QUIC 的增强传输协议
- **多路径支持**: MP-QUIC 实现提升网络利用率
- **智能流量塑形**: 自适应带宽管理
- **连接复用**: 减少连接建立开销
- **0-RTT 连接**: 支持快速连接恢复

> **注意**: 具体性能数据请通过实际测试获得。不同环境下的表现可能存在显著差异。

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

- 📧 Email: arthur-spec53@haoxicloud.top
- 💬 GitHub: [Arthur-spec53](https://github.com/Arthur-spec53)
- 🐛 Issues: [GitHub Issues](https://github.com/Arthur-spec53/nova-proxy/issues)
- 📖 文档: [项目文档](https://github.com/Arthur-spec53/nova-proxy/wiki)

---

<div align="center">
  <strong>⭐ 如果这个项目对你有帮助，请给我们一个 Star！⭐</strong>
</div>
