# Nova Proxy 运维脚本集合

本目录包含了 Nova Proxy 项目的完整运维脚本集合，涵盖部署、监控、故障排除、性能优化、备份恢复和安全扫描等各个方面。

## 脚本概览

| 脚本名称 | 功能描述 | 主要用途 |
|---------|---------|----------|
| `deploy.sh` | 一键部署脚本 | 快速部署到不同环境 |
| `env-manager.sh` | 环境管理脚本 | 多环境配置管理和切换 |
| `monitor.sh` | 监控脚本 | 应用性能和健康状态监控 |
| `troubleshoot.sh` | 故障排除脚本 | 诊断和修复常见问题 |
| `performance.sh` | 性能优化脚本 | 性能测试和调优 |
| `backup.sh` | 备份恢复脚本 | 数据备份和恢复管理 |
| `security-scan.sh` | 安全扫描脚本 | 安全漏洞检测和合规检查 |

## 快速开始

### 1. 一键部署

```bash
# 部署到开发环境
./scripts/deploy.sh development

# 部署到生产环境
./scripts/deploy.sh production --build --push
```

### 2. 环境管理

```bash
# 查看所有环境状态
./scripts/env-manager.sh status

# 切换到生产环境
./scripts/env-manager.sh switch production

# 扩容应用
./scripts/env-manager.sh scale production 5
```

### 3. 监控检查

```bash
# 健康检查
./scripts/monitor.sh health

# 性能监控
./scripts/monitor.sh performance

# 实时监控
./scripts/monitor.sh watch
```

### 4. 故障排除

```bash
# 全面诊断
./scripts/troubleshoot.sh diagnose

# 网络问题诊断
./scripts/troubleshoot.sh network

# 自动修复
./scripts/troubleshoot.sh diagnose --fix
```

### 5. 性能测试

```bash
# 基准测试
./scripts/performance.sh benchmark

# 负载测试
./scripts/performance.sh load-test --duration 300

# 性能分析
./scripts/performance.sh profile --type cpu
```

### 6. 备份恢复

```bash
# 完整备份
./scripts/backup.sh backup --type full

# 恢复数据
./scripts/backup.sh restore --backup-id backup-20240101-120000

# 列出备份
./scripts/backup.sh list
```

### 7. 安全扫描

```bash
# 全面安全扫描
./scripts/security-scan.sh scan-all

# 容器镜像扫描
./scripts/security-scan.sh scan-container -i nova-proxy:latest

# 自动修复安全问题
./scripts/security-scan.sh fix-issues --fix
```

## 详细使用指南

### deploy.sh - 一键部署脚本

**功能特性：**
- 支持多环境部署（development, staging, production）
- 自动构建和推送 Docker 镜像
- Kubernetes 命名空间管理
- Helm Chart 部署和升级
- 部署验证和健康检查
- 部署信息展示

**常用命令：**
```bash
# 基本部署
./scripts/deploy.sh <environment>

# 构建并推送镜像后部署
./scripts/deploy.sh production --build --push

# 指定镜像标签
./scripts/deploy.sh staging --tag v1.2.3

# 强制重新部署
./scripts/deploy.sh development --force

# 详细输出
./scripts/deploy.sh production --verbose
```

### env-manager.sh - 环境管理脚本

**功能特性：**
- 多环境配置管理
- 环境状态监控
- 应用扩缩容
- 配置备份和恢复
- 环境清理

**常用命令：**
```bash
# 环境管理
./scripts/env-manager.sh list                    # 列出所有环境
./scripts/env-manager.sh status [env]            # 查看环境状态
./scripts/env-manager.sh switch <env>            # 切换环境
./scripts/env-manager.sh create <env>            # 创建新环境
./scripts/env-manager.sh delete <env>            # 删除环境

# 应用管理
./scripts/env-manager.sh scale <env> <replicas>  # 扩缩容
./scripts/env-manager.sh restart <env>           # 重启应用
./scripts/env-manager.sh logs <env>              # 查看日志

# 配置管理
./scripts/env-manager.sh backup <env>            # 备份配置
./scripts/env-manager.sh validate <env>          # 验证配置
```

### monitor.sh - 监控脚本

**功能特性：**
- 健康状态检查
- 性能指标监控
- 资源使用监控
- 日志分析
- 告警检查
- 实时监控

**常用命令：**
```bash
# 监控检查
./scripts/monitor.sh health                      # 健康检查
./scripts/monitor.sh metrics                     # 获取指标
./scripts/monitor.sh performance                 # 性能测试
./scripts/monitor.sh resources                   # 资源检查
./scripts/monitor.sh logs                        # 日志分析
./scripts/monitor.sh alerts                      # 告警检查
./scripts/monitor.sh watch                       # 实时监控
./scripts/monitor.sh report                      # 生成报告
```

### troubleshoot.sh - 故障排除脚本

**功能特性：**
- 全面系统诊断
- 网络连接测试
- 存储问题检查
- 配置验证
- 自动问题修复
- 诊断报告生成

**常用命令：**
```bash
# 诊断命令
./scripts/troubleshoot.sh diagnose              # 全面诊断
./scripts/troubleshoot.sh pods                  # Pod 问题诊断
./scripts/troubleshoot.sh network               # 网络诊断
./scripts/troubleshoot.sh storage               # 存储诊断
./scripts/troubleshoot.sh config                # 配置诊断
./scripts/troubleshoot.sh resources             # 资源诊断
./scripts/troubleshoot.sh connectivity          # 连接性测试

# 修复选项
./scripts/troubleshoot.sh diagnose --fix        # 自动修复
./scripts/troubleshoot.sh collect               # 收集诊断信息
```

### performance.sh - 性能优化脚本

**功能特性：**
- 基准测试
- 负载测试
- 压力测试
- 性能分析（CPU、内存、Goroutine）
- 实时监控
- 性能报告
- 自动调优

**常用命令：**
```bash
# 性能测试
./scripts/performance.sh benchmark              # 基准测试
./scripts/performance.sh load-test              # 负载测试
./scripts/performance.sh stress-test            # 压力测试

# 性能分析
./scripts/performance.sh profile --type cpu     # CPU 分析
./scripts/performance.sh profile --type memory  # 内存分析
./scripts/performance.sh profile --type goroutine # Goroutine 分析

# 监控和报告
./scripts/performance.sh monitor                # 实时监控
./scripts/performance.sh analyze                # 数据分析
./scripts/performance.sh report                 # 生成报告
./scripts/performance.sh tune                   # 自动调优
```

### backup.sh - 备份恢复脚本

**功能特性：**
- 完整备份（配置、数据、Helm 发布）
- 增量备份
- 数据恢复
- 备份验证
- 备份清理
- 加密备份

**常用命令：**
```bash
# 备份操作
./scripts/backup.sh backup --type full          # 完整备份
./scripts/backup.sh backup --type config        # 配置备份
./scripts/backup.sh backup --type data          # 数据备份

# 恢复操作
./scripts/backup.sh restore --backup-id <id>    # 恢复备份
./scripts/backup.sh restore --type config       # 恢复配置
./scripts/backup.sh restore --type data         # 恢复数据

# 备份管理
./scripts/backup.sh list                        # 列出备份
./scripts/backup.sh verify --backup-id <id>     # 验证备份
./scripts/backup.sh cleanup --days 30           # 清理旧备份
```

### security-scan.sh - 安全扫描脚本

**功能特性：**
- 代码安全扫描
- 依赖漏洞扫描
- 容器镜像扫描
- Kubernetes 安全检查
- 网络安全扫描
- 密钥泄露检测
- 合规性检查
- 自动修复

**常用命令：**
```bash
# 安全扫描
./scripts/security-scan.sh scan-all             # 全面扫描
./scripts/security-scan.sh scan-code            # 代码扫描
./scripts/security-scan.sh scan-dependencies    # 依赖扫描
./scripts/security-scan.sh scan-container       # 容器扫描
./scripts/security-scan.sh scan-k8s             # K8s 安全扫描
./scripts/security-scan.sh scan-network         # 网络扫描
./scripts/security-scan.sh scan-secrets         # 密钥扫描
./scripts/security-scan.sh scan-compliance      # 合规检查

# 报告和修复
./scripts/security-scan.sh generate-report      # 生成报告
./scripts/security-scan.sh fix-issues --fix     # 自动修复
```

## 环境变量配置

所有脚本都支持通过环境变量进行配置：

```bash
# 通用配置
export NOVA_ENVIRONMENT=production
export NOVA_NAMESPACE=nova-proxy-prod
export NOVA_IMAGE_REGISTRY=your-registry.com
export NOVA_IMAGE_TAG=latest

# Kubernetes 配置
export KUBECONFIG=/path/to/kubeconfig
export KUBECTL_CONTEXT=production-cluster

# 监控配置
export PROMETHEUS_URL=http://prometheus:9090
export GRAFANA_URL=http://grafana:3000

# 备份配置
export BACKUP_STORAGE_TYPE=s3
export BACKUP_S3_BUCKET=nova-proxy-backups
export BACKUP_ENCRYPTION_KEY=your-encryption-key
```

## 最佳实践

### 1. 部署流程

```bash
# 1. 代码质量检查
./scripts/security-scan.sh scan-code

# 2. 部署到测试环境
./scripts/deploy.sh staging --build --push

# 3. 运行测试
./scripts/performance.sh benchmark
./scripts/monitor.sh health

# 4. 部署到生产环境
./scripts/deploy.sh production --tag stable

# 5. 生产环境验证
./scripts/monitor.sh performance
./scripts/troubleshoot.sh connectivity
```

### 2. 日常运维

```bash
# 每日健康检查
./scripts/monitor.sh health --environment production

# 每周性能报告
./scripts/performance.sh report --period weekly

# 每月安全扫描
./scripts/security-scan.sh scan-all --environment production

# 每日备份
./scripts/backup.sh backup --type incremental
```

### 3. 故障处理

```bash
# 1. 快速诊断
./scripts/troubleshoot.sh diagnose --environment production

# 2. 收集信息
./scripts/troubleshoot.sh collect --output /tmp/diagnostics

# 3. 尝试自动修复
./scripts/troubleshoot.sh diagnose --fix

# 4. 如果需要，回滚到上一个版本
./scripts/env-manager.sh rollback production
```

## 脚本依赖

### 必需工具
- `kubectl` - Kubernetes 命令行工具
- `helm` - Helm 包管理器
- `docker` - Docker 容器引擎
- `jq` - JSON 处理工具

### 可选工具
- `trivy` - 容器安全扫描
- `gosec` - Go 代码安全扫描
- `hey` - HTTP 负载测试工具
- `pprof` - Go 性能分析工具

### 安装依赖

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y kubectl helm docker.io jq

# CentOS/RHEL
sudo yum install -y kubectl helm docker jq

# macOS
brew install kubectl helm docker jq

# 安装安全扫描工具
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
```

## 故障排除

### 常见问题

1. **权限问题**
   ```bash
   chmod +x scripts/*.sh
   ```

2. **Kubernetes 连接问题**
   ```bash
   kubectl cluster-info
   export KUBECONFIG=/path/to/your/kubeconfig
   ```

3. **Docker 权限问题**
   ```bash
   sudo usermod -aG docker $USER
   newgrp docker
   ```

4. **Helm 仓库问题**
   ```bash
   helm repo update
   helm repo list
   ```

### 获取帮助

每个脚本都支持 `--help` 参数：

```bash
./scripts/deploy.sh --help
./scripts/monitor.sh --help
./scripts/troubleshoot.sh --help
# ... 等等
```

## 贡献指南

如果您想为这些脚本贡献代码或报告问题：

1. 确保脚本遵循 Bash 最佳实践
2. 添加适当的错误处理和日志记录
3. 更新相关文档
4. 测试脚本在不同环境下的兼容性

## 许可证

这些脚本遵循项目的开源许可证。详情请参阅项目根目录的 LICENSE 文件。