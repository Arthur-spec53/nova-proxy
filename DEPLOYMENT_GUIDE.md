# Nova Proxy 部署指南

本指南帮助您根据系统配置选择合适的部署方案。

## 部署方案对比

### 🚀 完整部署 (docker-compose.yml)

**适用场景：**
- 生产环境
- 开发和测试环境
- 高配置服务器 (4GB+ RAM, 2+ CPU cores)
- 需要完整监控和可观测性

**包含组件：**
- Nova Server & Client
- Prometheus (完整监控)
- Grafana (可视化面板)
- Jaeger (分布式追踪)
- Redis (缓存)
- Nginx (负载均衡)
- Traefik (反向代理)

**资源需求：**
- 内存: ~4-6GB
- CPU: 2-4 cores
- 磁盘: 10GB+

### 💡 轻量级部署 (docker-compose.minimal.yml)

**适用场景：**
- 低配置服务器 (1-2GB RAM, 1-2 CPU cores)
- 个人开发环境
- 资源受限的云实例
- 仅需要核心功能

**包含组件：**
- Nova Server (资源优化)
- Prometheus (可选，轻量配置)
- Grafana (可选，基础配置)

**资源需求：**
- 内存: ~1-2GB
- CPU: 1-2 cores
- 磁盘: 2GB+

## 快速开始

### 完整部署

```bash
# 1. 复制环境配置
cp .env.example .env

# 2. 启动所有服务
docker compose up -d

# 3. 检查服务状态
docker compose ps
```

### 轻量级部署

```bash
# 1. 使用轻量级环境配置
cp .env.minimal .env

# 2. 仅启动核心服务
docker compose -f docker-compose.minimal.yml up -d

# 3. 可选：启动监控组件
docker compose -f docker-compose.minimal.yml --profile monitoring up -d
```

## 性能优化建议

### 低配置环境优化

1. **禁用不必要的监控**
   ```bash
   # 设置环境变量
   export METRICS_ENABLED=false
   export LOG_LEVEL=warn
   ```

2. **调整资源限制**
   ```yaml
   # 在 docker-compose.minimal.yml 中已预配置
   deploy:
     resources:
       limits:
         memory: 256M
         cpus: '0.5'
   ```

3. **优化Go运行时**
   ```bash
   export GOMAXPROCS=1
   export GOGC=200
   ```

### 监控组件选择性启用

```bash
# 仅启动核心服务
docker compose -f docker-compose.minimal.yml up -d nova-server

# 需要监控时再启动
docker compose -f docker-compose.minimal.yml --profile monitoring up -d
```

## 资源监控

### 检查资源使用情况

```bash
# 查看容器资源使用
docker stats

# 查看系统资源
free -h
df -h
```

### 性能调优

1. **内存优化**
   - 调整 `GOGC` 参数控制垃圾回收频率
   - 限制容器内存使用
   - 减少日志输出级别

2. **CPU优化**
   - 设置 `GOMAXPROCS` 限制Go程序CPU使用
   - 使用Docker资源限制
   - 延长健康检查间隔

3. **磁盘优化**
   - 减少日志保留时间
   - 限制Prometheus数据存储大小
   - 使用日志轮转

## 故障排除

### 常见问题

1. **内存不足**
   ```bash
   # 检查内存使用
   docker stats --no-stream
   
   # 减少服务数量
   docker compose -f docker-compose.minimal.yml up -d nova-server
   ```

2. **CPU使用率过高**
   ```bash
   # 调整CPU限制
   export GOMAXPROCS=1
   
   # 重启服务
   docker compose restart nova-server
   ```

3. **磁盘空间不足**
   ```bash
   # 清理Docker数据
   docker system prune -a
   
   # 清理日志
   docker compose logs --tail=0 -f
   ```

## 升级路径

### 从轻量级升级到完整部署

```bash
# 1. 停止轻量级部署
docker compose -f docker-compose.minimal.yml down

# 2. 备份数据
docker run --rm -v nova-proxy_nova-data:/data -v $(pwd):/backup alpine tar czf /backup/nova-data-backup.tar.gz -C /data .

# 3. 启动完整部署
cp .env.example .env
docker compose up -d
```

## 监控指标

### 关键性能指标

- **内存使用率**: < 80%
- **CPU使用率**: < 70%
- **磁盘使用率**: < 85%
- **网络延迟**: < 100ms
- **错误率**: < 1%

### 告警阈值建议

```yaml
# 低配置环境告警阈值
memory_usage: > 90%
cpu_usage: > 80%
disk_usage: > 90%
response_time: > 500ms
error_rate: > 5%
```

## 总结

选择合适的部署方案可以显著提升系统性能和用户体验：

- **高配置环境**: 使用完整部署获得最佳监控体验
- **低配置环境**: 使用轻量级部署确保核心功能稳定运行
- **按需扩展**: 可以随时从轻量级升级到完整部署

记住：**性能优化是一个持续的过程，需要根据实际使用情况不断调整配置。**