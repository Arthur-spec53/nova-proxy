# 变更日志

本文档记录了 Nova Proxy 项目的所有重要变更。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
并且本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [未发布]

### 新增
- 初始项目结构和核心功能
- ASTAT (自适应塑形传输与加密QUIC) 协议实现
- E-QUIC 传输层混淆功能
- 主动流量塑形和填充
- 企业级监控和可观测性
- Kubernetes 和 Helm 部署支持
- 完整的 CI/CD 流水线
- 运维脚本和工具集

## [1.0.0] - 2024-01-15

### 新增
- **核心协议**
  - ASTAT 协议完整实现
  - QUIC 基础传输层
  - E-QUIC 二次加密层 (AES-GCM + HMAC-SHA256)
  - 0-RTT 连接建立支持
  
- **流量塑形**
  - 步调控制 (Pacing) 机制
  - 智能流量填充 (Padding)
  - 统计学不可区分性优化
  - 可配置的塑形参数
  
- **安全特性**
  - 预共享密钥 (PSK) 认证
  - 抗深度包检测 (DPI) 能力
  - 协议指纹隐藏
  - 安全的密钥管理
  
- **性能优化**
  - 零拷贝 I/O 操作
  - 连接池管理
  - 内存优化和垃圾回收调优
  - 高并发连接支持
  
- **可观测性**
  - 结构化 JSON 日志
  - Prometheus 指标收集
  - Jaeger 分布式链路追踪
  - 健康检查端点
  - 实时性能监控
  
- **部署支持**
  - Docker 容器化
  - Kubernetes 原生支持
  - Helm Chart 包管理
  - 多环境配置
  
- **运维工具**
  - 自动化部署脚本
  - 监控系统设置
  - 备份和恢复工具
  - 系统维护脚本
  - 性能调优工具
  
- **测试体系**
  - 单元测试覆盖 (80%+)
  - 集成测试套件
  - 端到端测试
  - 性能基准测试
  - 安全扫描集成
  
- **文档**
  - 完整的 README 文档
  - 详细的配置指南
  - 故障排除手册
  - 贡献者指南
  - API 文档

### 技术规格
- **支持的协议**: QUIC, HTTP/1.1, HTTP/2, HTTP/3, SOCKS5
- **加密算法**: AES-256-GCM, HMAC-SHA256, TLS 1.3
- **性能指标**: 
  - 连接建立: <10ms (0-RTT)
  - 吞吐量: 8Gbps (单连接)
  - 并发连接: 10,000+
  - 延迟增加: <2ms (相比原始 QUIC)
- **平台支持**: Linux, macOS, Windows
- **容器支持**: Docker, Kubernetes, Helm

### 依赖项
- Go 1.22+
- quic-go v0.40+
- Prometheus client
- Jaeger client
- 其他第三方库 (详见 go.mod)

---

## 版本说明

### 版本号格式
- **主版本号 (MAJOR)**: 不兼容的 API 更改
- **次版本号 (MINOR)**: 向后兼容的功能新增
- **修订号 (PATCH)**: 向后兼容的问题修复

### 变更类型
- **新增 (Added)**: 新功能
- **变更 (Changed)**: 现有功能的更改
- **弃用 (Deprecated)**: 即将移除的功能
- **移除 (Removed)**: 已移除的功能
- **修复 (Fixed)**: 问题修复
- **安全 (Security)**: 安全相关的更改

### 发布周期
- **主版本**: 根据需要发布 (重大架构变更)
- **次版本**: 每月发布 (新功能和改进)
- **修订版本**: 每周发布 (问题修复和小改进)

### 支持政策
- **当前版本**: 完全支持，包括新功能和安全更新
- **前一个主版本**: 安全更新和关键问题修复
- **更早版本**: 仅提供安全更新 (6个月)

---

## 贡献指南

如果您想为 Nova Proxy 项目做出贡献，请：

1. 阅读 [CONTRIBUTING.md](CONTRIBUTING.md)
2. 查看 [开放的 Issues](https://github.com/your-org/nova-proxy/issues)
3. 提交 Pull Request

## 获取帮助

- 📖 [项目文档](https://docs.nova-proxy.io)
- 🐛 [问题报告](https://github.com/your-org/nova-proxy/issues)
- 💬 [讨论区](https://github.com/your-org/nova-proxy/discussions)
- 📧 [邮件支持](mailto:support@nova-proxy.io)