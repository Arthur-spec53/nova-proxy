# Nova Proxy 部署指南

## 项目概述

Nova Proxy 是一个高性能的现代化代理服务器，支持 HTTP/1.1、HTTP/2 和 HTTP/3 (QUIC) 协议。本项目已完成企业级生产环境的完整配置，包括容器化部署、Kubernetes 编排、CI/CD 流水线和完整的运维工具链。

## 架构特性

### 核心功能
- **多协议支持**：HTTP/1.1、HTTP/2、HTTP/3 (QUIC)
- **高性能**：基于 Go 语言，支持高并发处理
- **负载均衡**：多种负载均衡算法（轮询、加权轮询、最少连接、IP 哈希）
- **健康检查**：主动和被动健康检查机制
- **安全加固**：TLS 1.3、证书管理、访问控制
- **可观测性**：Prometheus 指标、结构化日志、分布式追踪

### 企业级特性
- **高可用性**：多副本部署、优雅降级、故障转移
- **可扩展性**：水平扩展、自动扩缩容（HPA/VPA）
- **安全性**：网络策略、Pod 安全策略、RBAC 权限控制
- **监控告警**：完整的监控体系和告警机制
- **备份恢复**：自动化备份和灾难恢复

## 快速开始

### 前置要求

- Kubernetes 集群 (v1.20+)
- Helm 3.0+
- Docker
- kubectl

### 一键部署

```bash
# 克隆项目
git clone <repository-url>
cd nova-proxy

# 部署到开发环境
./scripts/deploy.sh development

# 部署到生产环境
./scripts/deploy.sh production --build --push
```

### 验证部署

```bash
# 检查应用状态
./scripts/monitor.sh health

# 运行性能测试
./scripts/performance.sh benchmark

# 查看监控指标
kubectl port-forward svc/prometheus 9090:9090
```

## 部署架构

### 容器化

- **多阶段构建**：优化镜像大小和安全性
- **非 root 用户**：增强容器安全性
- **健康检查**：内置健康检查端点
- **资源限制**：CPU 和内存资源控制

### Kubernetes 部署

```
Nova Proxy 部署架构
├── Namespace: nova-proxy-{env}
├── Deployment: 应用主体
│   ├── 多副本部署
│   ├── 滚动更新策略
│   ├── 资源限制和请求
│   └── 安全上下文
├── Service: 服务发现
│   ├── ClusterIP/LoadBalancer
│   └── 多端口支持
├── Ingress: 外部访问
│   ├── TLS 终止
│   ├── 路径路由
│   └── 证书管理
├── ConfigMap: 配置管理
│   ├── 应用配置
│   ├── 代理规则
│   └── 监控配置
├── Secret: 敏感信息
│   ├── TLS 证书
│   ├── 数据库密码
│   └── API 密钥
├── PVC: 持久化存储
│   ├── 日志存储
│   ├── 缓存存储
│   └── 备份存储
└── RBAC: 权限控制
    ├── ServiceAccount
    ├── Role/ClusterRole
    └── RoleBinding
```

### Helm Chart 结构

```
helm/nova-proxy/
├── Chart.yaml              # Chart 元数据
├── values.yaml             # 默认配置
├── values-staging.yaml     # 测试环境配置
├── values-production.yaml  # 生产环境配置
└── templates/
    ├── deployment.yaml     # 应用部署
    ├── service.yaml        # 服务定义
    ├── ingress.yaml        # 入口配置
    ├── configmap.yaml      # 配置映射
    ├── secret.yaml         # 密钥管理
    ├── pvc.yaml           # 存储声明
    ├── rbac.yaml          # 权限控制
    ├── hpa.yaml           # 水平扩缩容
    ├── vpa.yaml           # 垂直扩缩容
    ├── networkpolicy.yaml # 网络策略
    ├── podsecuritypolicy.yaml # Pod 安全策略
    ├── servicemonitor.yaml    # Prometheus 监控
    └── prometheusrule.yaml    # 告警规则
```

## CI/CD 流水线

### GitHub Actions 工作流

```
CI/CD 流水线
├── 代码质量检查
│   ├── Go 代码格式化
│   ├── 静态代码分析
│   ├── 安全漏洞扫描
│   └── 依赖检查
├── 测试阶段
│   ├── 单元测试 (多 Go 版本)
│   ├── 集成测试 (Redis + Jaeger)
│   ├── 性能测试 (HTTP/2 + QUIC)
│   └── 覆盖率报告
├── 安全扫描
│   ├── 容器镜像扫描 (Trivy)
│   ├── 依赖漏洞扫描 (Nancy)
│   └── SARIF 报告上传
├── 构建阶段
│   ├── Docker 镜像构建
│   ├── 多架构支持 (amd64/arm64)
│   ├── 镜像签名 (Cosign)
│   ├── SBOM 生成
│   └── 镜像推送
└── 部署阶段
    ├── Staging 环境部署
    ├── Smoke 测试
    ├── 生产环境部署 (蓝绿部署)
    ├── 健康检查
    └── 通知发送
```

### 部署策略

- **开发环境**：每次推送自动部署
- **测试环境**：PR 合并后自动部署
- **生产环境**：标签推送或手动触发，采用蓝绿部署

## 运维工具链

### 脚本工具

| 脚本 | 功能 | 使用场景 |
|------|------|----------|
| `deploy.sh` | 一键部署 | 快速部署到各环境 |
| `env-manager.sh` | 环境管理 | 多环境配置和切换 |
| `monitor.sh` | 监控检查 | 健康状态和性能监控 |
| `troubleshoot.sh` | 故障排除 | 问题诊断和自动修复 |
| `performance.sh` | 性能测试 | 基准测试和性能调优 |
| `backup.sh` | 备份恢复 | 数据备份和灾难恢复 |
| `security-scan.sh` | 安全扫描 | 安全漏洞检测和合规检查 |

### 监控体系

```
监控架构
├── 指标收集
│   ├── Prometheus (指标存储)
│   ├── Node Exporter (节点指标)
│   ├── cAdvisor (容器指标)
│   └── 应用自定义指标
├── 可视化
│   ├── Grafana 仪表板
│   ├── 应用性能面板
│   ├── 基础设施面板
│   └── 业务指标面板
├── 告警
│   ├── Alertmanager
│   ├── 告警规则配置
│   ├── 通知渠道 (Slack/Email)
│   └── 告警抑制和分组
└── 追踪
    ├── Jaeger (分布式追踪)
    ├── OpenTelemetry
    ├── 请求链路追踪
    └── 性能瓶颈分析
```

## 安全加固

### 网络安全

- **网络策略**：Pod 间通信控制
- **TLS 加密**：端到端加密通信
- **证书管理**：自动证书轮换
- **防火墙规则**：入站和出站流量控制

### 容器安全

- **非 root 用户**：容器以非特权用户运行
- **只读文件系统**：减少攻击面
- **资源限制**：防止资源耗尽攻击
- **安全上下文**：严格的安全策略

### 访问控制

- **RBAC**：基于角色的访问控制
- **ServiceAccount**：服务账户隔离
- **Pod 安全策略**：Pod 安全标准
- **准入控制器**：资源创建验证

## 故障排除

### 常见问题

1. **Pod 启动失败**
   ```bash
   ./scripts/troubleshoot.sh pods
   kubectl describe pod <pod-name>
   kubectl logs <pod-name>
   ```

2. **网络连接问题**
   ```bash
   ./scripts/troubleshoot.sh network
   kubectl exec -it <pod-name> -- nslookup <service-name>
   ```

3. **存储问题**
   ```bash
   ./scripts/troubleshoot.sh storage
   kubectl get pv,pvc
   ```

4. **性能问题**
   ```bash
   ./scripts/performance.sh profile --type cpu
   ./scripts/monitor.sh resources
   ```

### 诊断工具

- **全面诊断**：`./scripts/troubleshoot.sh diagnose`
- **自动修复**：`./scripts/troubleshoot.sh diagnose --fix`
- **收集信息**：`./scripts/troubleshoot.sh collect`
- **生成报告**：诊断报告和建议

## 最佳实践

### 开发最佳实践

1. **代码质量**
   - 遵循 Go 编码规范
   - 编写单元测试和集成测试
   - 使用静态代码分析工具
   - 定期进行代码审查

2. **安全实践**
   - 不在代码中硬编码密钥
   - 使用最小权限原则
   - 定期更新依赖包
   - 进行安全漏洞扫描

### 运维最佳实践

1. **部署实践**
   - 使用蓝绿部署或滚动更新
   - 部署前进行充分测试
   - 保持部署脚本的幂等性
   - 记录部署变更和回滚计划

2. **监控实践**
   - 设置合理的告警阈值
   - 建立监控仪表板
   - 定期检查监控系统健康状态
   - 进行告警疲劳管理

---

## 总结

Nova Proxy 项目已完成企业级生产环境的完整配置，具备：

✅ **完整的容器化部署方案**
✅ **企业级 Kubernetes 编排**
✅ **自动化 CI/CD 流水线**
✅ **全面的监控和告警体系**
✅ **完善的安全加固措施**
✅ **自动化运维工具链**
✅ **备份和灾难恢复机制**
✅ **性能优化和调优**
✅ **详细的文档和最佳实践**

项目已准备好用于生产环境部署，具备高可用、高性能、高安全性的企业级特性。