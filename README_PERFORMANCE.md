# Nova Proxy 性能优化指南

## 概述

Nova Proxy 提供了多种部署方案，以适应不同配置的服务器环境。本指南帮助您根据系统资源选择最合适的部署方案，确保在低配置环境下也能获得良好的性能体验。

## 🎯 核心理念

**"按需部署，渐进式扩展"**

我们的设计理念是让用户能够：
- 在低配置环境下运行核心功能
- 根据需要选择性启用监控组件
- 随着资源增加逐步扩展功能
- 保持系统稳定性和响应速度

## 📊 部署方案对比

| 方案 | 内存需求 | CPU需求 | 磁盘需求 | 适用场景 |
|------|----------|---------|----------|----------|
| **核心部署** | 256MB | 0.5 Core | 1GB | 个人开发、资源极限环境 |
| **轻量级部署** | 1-2GB | 1-2 Core | 2GB | 小型项目、低配置服务器 |
| **完整部署** | 4-6GB | 2-4 Core | 10GB | 生产环境、高配置服务器 |

## 🚀 快速开始

### 1. 系统资源检查

首先运行系统检查工具，获取个性化的部署建议：

```bash
./scripts/system-check.sh
```

### 2. 选择部署方案

根据检查结果选择合适的部署方案：

#### 🔧 核心部署（最小资源）

仅运行Nova Server核心功能：

```bash
# 使用轻量级配置
cp .env.minimal .env

# 仅启动核心服务
docker compose -f docker-compose.minimal.yml up -d nova-server
```

#### 💡 轻量级部署（推荐）

包含核心功能和可选监控：

```bash
# 使用轻量级配置
cp .env.minimal .env

# 启动轻量级部署
docker compose -f docker-compose.minimal.yml up -d

# 可选：启用监控
docker compose -f docker-compose.minimal.yml --profile monitoring up -d
```

#### 🚀 完整部署（高配置）

包含所有功能和完整监控栈：

```bash
# 使用完整配置
cp .env.example .env

# 启动完整部署
docker compose up -d
```

## ⚡ 性能优化技巧

### 环境变量优化

```bash
# 减少日志输出
export LOG_LEVEL=warn

# 禁用指标收集
export METRICS_ENABLED=false

# 优化Go运行时
export GOMAXPROCS=1
export GOGC=200
```

### 容器资源限制

轻量级部署已预配置资源限制：

```yaml
deploy:
  resources:
    limits:
      memory: 256M
      cpus: '0.5'
    reservations:
      memory: 128M
      cpus: '0.25'
```

### 监控组件管理

```bash
# 启用监控（当需要时）
docker compose -f docker-compose.minimal.yml --profile monitoring up -d

# 禁用监控（节省资源）
docker compose -f docker-compose.minimal.yml stop prometheus grafana
docker compose -f docker-compose.minimal.yml rm -f prometheus grafana
```

## 📈 资源监控

### 实时监控

```bash
# 监控容器资源使用
docker stats

# 检查系统资源
free -h
df -h
```

### 性能指标

关键性能指标和建议阈值：

- **内存使用率**: < 80%
- **CPU使用率**: < 70%
- **磁盘使用率**: < 85%
- **响应时间**: < 100ms
- **错误率**: < 1%

## 🔧 故障排除

### 常见问题及解决方案

#### 1. 内存不足

**症状**: 容器频繁重启，OOM错误

**解决方案**:
```bash
# 切换到核心部署
docker compose -f docker-compose.minimal.yml up -d nova-server

# 调整内存限制
export GOGC=300  # 减少GC频率
```

#### 2. CPU使用率过高

**症状**: 系统响应缓慢，负载过高

**解决方案**:
```bash
# 限制CPU使用
export GOMAXPROCS=1

# 减少日志输出
export LOG_LEVEL=error

# 禁用指标收集
export METRICS_ENABLED=false
```

#### 3. 磁盘空间不足

**症状**: 容器无法启动，写入错误

**解决方案**:
```bash
# 清理Docker数据
docker system prune -a

# 减少数据保留时间
export PROMETHEUS_RETENTION_TIME=3d
export PROMETHEUS_RETENTION_SIZE=500MB
```

## 🎛️ 高级配置

### 自定义资源限制

创建自定义的docker-compose覆盖文件：

```yaml
# docker-compose.override.yml
services:
  nova-server:
    deploy:
      resources:
        limits:
          memory: 128M  # 进一步限制内存
          cpus: '0.25'  # 进一步限制CPU
```

### 动态配置调整

```bash
# 运行时调整配置
docker exec nova-server sh -c 'export GOGC=400'
docker restart nova-server
```

## 📋 最佳实践

### 1. 渐进式部署

1. 从核心部署开始
2. 验证基本功能正常
3. 根据需要逐步添加监控组件
4. 监控资源使用情况
5. 根据实际负载调整配置

### 2. 监控策略

- **低配置环境**: 使用外部监控或定期检查
- **中等配置**: 启用基础监控（Prometheus + Grafana）
- **高配置环境**: 启用完整监控栈

### 3. 维护建议

```bash
# 定期清理
docker system prune -f

# 日志轮转
docker logs --tail=1000 nova-server > nova-server.log
docker exec nova-server truncate -s 0 /app/logs/*.log

# 健康检查
curl -f http://localhost:8081/health || echo "Service unhealthy"
```

## 🔄 升级路径

### 从轻量级升级到完整部署

```bash
# 1. 备份数据
docker run --rm -v nova-proxy_nova-data:/data -v $(pwd):/backup alpine tar czf /backup/backup.tar.gz -C /data .

# 2. 停止轻量级部署
docker compose -f docker-compose.minimal.yml down

# 3. 启动完整部署
cp .env.example .env
docker compose up -d

# 4. 恢复数据（如需要）
docker run --rm -v nova-proxy_nova-data:/data -v $(pwd):/backup alpine tar xzf /backup/backup.tar.gz -C /data
```

## 📞 支持与反馈

如果您在使用过程中遇到性能问题或有优化建议，请：

1. 查看 [DEPLOYMENT_GUIDE.md](./DEPLOYMENT_GUIDE.md) 获取详细部署说明
2. 运行 `./scripts/system-check.sh` 获取系统分析报告
3. 提交 Issue 并附上系统信息和错误日志

## 📈 性能测试

我们提供了性能测试工具来验证不同配置下的表现：

```bash
# 运行性能测试
./scripts/performance.sh

# 压力测试
./scripts/stress-test.sh
```

---

**记住**: 性能优化是一个持续的过程。根据实际使用情况和资源变化，定期调整配置以获得最佳性能体验。