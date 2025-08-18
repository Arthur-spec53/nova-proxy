# Nova Proxy 快速入门指南

## 🚀 5分钟快速部署

### 方法一：使用管理工具 (推荐)

```bash
# 1. 启动管理工具
./scripts/nova-manager.sh
# 或者
make manager

# 2. 在菜单中选择:
# - 选项 1: 系统检查和部署建议
# - 根据建议选择合适的部署方案 (选项 2-5)
# - 选项 6: 查看服务状态
# - 选项 13: 获取访问地址
```

### 方法二：直接命令部署

```bash
# 系统检查
./scripts/system-check.sh

# 根据系统配置选择部署方案:

# 低配置环境 (< 1GB 内存)
make deploy-minimal

# 中等配置环境 (1-4GB 内存)
make deploy-minimal-with-monitoring

# 高配置环境 (4GB+ 内存)
make deploy-full
```

## 📋 部署方案对比

| 部署方案 | 内存需求 | 包含服务 | 适用场景 |
|---------|---------|---------|----------|
| 核心部署 | ~256MB | Nova Server | 资源极度受限 |
| 轻量级部署 | ~1GB | Nova Server + 可选监控 | 一般开发/测试 |
| 完整部署 | ~4-6GB | 全套服务 + 监控 | 生产环境 |
| 开发部署 | ~2-4GB | 开发模式 + 调试工具 | 开发调试 |

## 🎯 常用操作

### 服务管理

```bash
# 启动管理工具
./scripts/nova-manager.sh

# 常用菜单选项:
# 6 - 查看服务状态
# 7 - 启动服务
# 8 - 停止服务
# 9 - 重启服务
# 10 - 查看日志
# 23 - 完全卸载服务 (⚠️ 不可恢复)
```

### 监控管理

```bash
# 启用/禁用监控 (菜单选项 11/12)
# 或直接使用 make 命令:
make enable-monitoring   # 启用监控
make disable-monitoring  # 禁用监控
```

### 配置修改

```bash
# 使用管理工具 (推荐)
./scripts/nova-manager.sh
# 选择菜单选项 16 - 修改环境变量

# 或直接编辑配置文件
nano .env
```

## 🌐 服务访问地址

部署完成后，可以通过以下地址访问服务：

### Nova Proxy 服务
- **HTTP**: http://localhost:8080
- **HTTPS**: https://localhost:8443
- **管理接口**: http://localhost:8081/admin

### 监控服务 (如果启用)
- **Prometheus**: http://localhost:9090
- **Grafana**: http://localhost:3000
  - 用户名: `admin`
  - 密码: `admin123`
- **Jaeger** (完整部署): http://localhost:16686

## 🔧 故障排除

### 常见问题快速解决

1. **服务无法启动**
   ```bash
   # 使用管理工具故障排除
   ./scripts/nova-manager.sh
   # 选择菜单选项 22 - 故障排除
   ```

2. **端口冲突**
   ```bash
   # 检查端口占用
   netstat -tlnp | grep -E ':(8080|8443|9090|3000)'
   
   # 修改端口配置
   ./scripts/nova-manager.sh
   # 选择菜单选项 16.2 - 服务端口配置
   ```

3. **内存不足**
   ```bash
   # 切换到轻量级部署
   ./scripts/nova-manager.sh
   # 选择菜单选项 2 - 核心服务部署
   ```

4. **查看详细错误**
   ```bash
   # 查看服务日志
   ./scripts/nova-manager.sh
   # 选择菜单选项 10 - 查看服务日志
   ```

5. **完全重新开始**
   ```bash
   # 如果遇到严重问题，可以完全卸载后重新部署
   ./scripts/nova-manager.sh
   # 选择菜单选项 23 - 完全卸载服务
   # ⚠️ 警告: 此操作将删除所有数据，请确保已备份重要配置
   ```

## 📊 性能优化建议

### 低配置环境优化

```bash
# 1. 使用轻量级配置
cp .env.minimal .env

# 2. 禁用不必要的监控
./scripts/nova-manager.sh
# 选择菜单选项 12 - 禁用监控组件

# 3. 调整资源限制
./scripts/nova-manager.sh
# 选择菜单选项 16.3 - 资源限制设置
```

### 生产环境优化

```bash
# 1. 使用完整部署
./scripts/nova-manager.sh
# 选择菜单选项 4 - 完整部署

# 2. 配置备份
./scripts/nova-manager.sh
# 选择菜单选项 17 - 备份配置

# 3. 性能测试
./scripts/nova-manager.sh
# 选择菜单选项 19 - 性能测试
```

## 🛠️ 维护任务

### 日常维护

```bash
# 检查服务状态
./scripts/nova-manager.sh  # 选项 6

# 查看资源使用
./scripts/nova-manager.sh  # 选项 14

# 查看日志
./scripts/nova-manager.sh  # 选项 10
```

### 定期维护

```bash
# 备份配置 (建议每周)
./scripts/nova-manager.sh  # 选项 17

# 清理数据 (建议每月)
./scripts/nova-manager.sh  # 选项 20

# 更新镜像 (按需)
./scripts/nova-manager.sh  # 选项 21
```

## 📚 更多资源

- **详细管理指南**: [README_MANAGER.md](README_MANAGER.md)
- **性能优化指南**: [README_PERFORMANCE.md](README_PERFORMANCE.md)
- **部署指南**: [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)
- **项目文档**: [README.md](README.md)

## 💡 使用技巧

1. **首次使用**: 先运行系统检查，根据建议选择部署方案
2. **资源监控**: 定期检查资源使用情况，及时调整配置
3. **配置备份**: 重要配置更改前先备份
4. **渐进部署**: 从核心服务开始，逐步添加监控组件
5. **日志分析**: 遇到问题时优先查看服务日志

---

**需要帮助？** 使用管理工具的故障排除功能 (选项 22) 或查看详细文档。