# Nova Proxy 安全组件

本目录包含 Nova Proxy 的完整安全框架，提供企业级的安全功能，包括密钥管理、证书管理、访问控制和安全审计。

## 🔒 核心安全组件

### 1. 密钥管理器 (KeyManager)
- **文件**: `key_manager.go`
- **功能**: 
  - 支持多种密钥类型：AES256、ChaCha20、HMAC、PreShared
  - 自动密钥轮换和过期管理
  - 安全的密钥存储和备份
  - PBKDF2 密钥派生
  - 密钥加密存储

### 2. 证书管理器 (CertManager)
- **文件**: `cert_manager.go`
- **功能**:
  - 自动生成和管理 X.509 证书
  - 支持服务器、客户端和 CA 证书
  - 自动证书续期
  - 证书验证和指纹计算
  - 证书备份和恢复

### 3. 访问控制器 (AccessController)
- **文件**: `access_control.go`
- **功能**:
  - 基于角色的访问控制 (RBAC)
  - 用户认证和会话管理
  - IP 白名单/黑名单
  - 速率限制和防暴力破解
  - 密码强度验证

### 4. 安全审计日志 (EnhancedAuditLogger)
- **文件**: `audit_logger.go`
- **功能**:
  - 详细的安全事件记录
  - 异步日志写入
  - 日志轮转和压缩
  - 日志加密存储
  - 事件查询和统计

### 5. 安全管理器 (SecurityManager)
- **文件**: `security_manager.go`
- **功能**:
  - 统一管理所有安全组件
  - 自动化安全任务
  - 安全指标监控
  - 配置热重载

## 📋 配置文件

### 安全配置 (`configs/security.json`)
```json
{
  "key_manager": {
    "key_store_path": "./data/keys",
    "master_password": "${NOVA_MASTER_PASSWORD}",
    "rotation_interval": "24h",
    "key_expiry": "720h",
    "backup_enabled": true,
    "encryption_algo": "AES256",
    "kdf_iterations": 100000
  },
  "cert_manager": {
    "cert_store_path": "./data/certs",
    "auto_renewal": true,
    "renewal_threshold": "720h",
    "default_key_size": 2048,
    "default_valid_days": 365
  },
  "access_control": {
    "session_timeout": "30m",
    "max_failed_attempts": 5,
    "lockout_duration": "15m",
    "password_complexity": true,
    "rate_limit_enabled": true
  },
  "audit_logger": {
    "log_path": "./logs/audit.log",
    "max_file_size": 104857600,
    "encrypt_logs": true,
    "async_logging": true
  }
}
```

## 🚀 快速开始

### 1. 基本使用

```go
package main

import (
    "context"
    "log"
    "./internal/security"
)

func main() {
    // 加载安全配置
    config, err := security.LoadSecurityConfig("./configs/security.json")
    if err != nil {
        log.Fatal(err)
    }

    // 创建安全管理器
    securityManager, err := security.NewSecurityManager(config)
    if err != nil {
        log.Fatal(err)
    }
    defer securityManager.Stop()

    // 启动安全管理器
    if err := securityManager.Start(); err != nil {
        log.Fatal(err)
    }

    // 获取 TLS 配置
    tlsConfig, err := securityManager.GetTLSConfig("server")
    if err != nil {
        log.Printf("Warning: %v", err)
    }

    // 用户认证
    token, err := securityManager.AuthenticateUser("admin", "password")
    if err != nil {
        log.Printf("Authentication failed: %v", err)
    } else {
        log.Printf("Authentication successful: %s", token)
    }

    // 记录安全事件
    securityManager.LogSecurityEvent(security.DetailedAuditEvent{
        Level:     security.AuditLevelInfo,
        Category:  "system",
        Action:    "startup",
        Message:   "System started with security enabled",
        Timestamp: time.Now(),
    })

    // 获取安全指标
    metrics := securityManager.GetSecurityMetrics()
    log.Printf("Security metrics: %+v", metrics)
}
```

### 2. Web 服务集成

参考 `integration_example.go` 文件，展示了如何在 HTTP 服务中集成安全组件：

- TLS 配置
- 安全中间件
- 认证端点
- 权限检查
- 安全审计

## 🔐 安全特性

### 密钥安全
- 使用 PBKDF2 进行密钥派生
- 密钥加密存储
- 自动密钥轮换
- 安全的随机数生成

### 证书安全
- 强加密算法 (RSA 2048+)
- 自动证书续期
- 证书链验证
- OCSP 和 CRL 支持

### 访问控制
- 基于角色的权限模型
- 会话超时管理
- 防暴力破解保护
- IP 访问控制

### 审计安全
- 完整的安全事件记录
- 日志完整性保护
- 敏感信息脱敏
- 日志加密存储

## 📊 监控和指标

安全管理器提供以下监控指标：

- `total_keys`: 总密钥数量
- `expired_keys`: 过期密钥数量
- `total_certificates`: 总证书数量
- `certificates_expiring_soon`: 即将过期的证书数量
- `active_sessions`: 活跃会话数量
- `audit_stats`: 审计日志统计信息

## 🛡️ 安全最佳实践

### 1. 环境变量
```bash
# 设置主密码
export NOVA_MASTER_PASSWORD="your-secure-master-password"

# 设置审计日志加密密钥
export NOVA_AUDIT_ENCRYPTION_KEY="your-audit-encryption-key"
```

### 2. 文件权限
```bash
# 设置密钥文件权限
chmod 600 ./data/keys/*
chmod 700 ./data/keys/

# 设置证书文件权限
chmod 644 ./data/certs/*.crt
chmod 600 ./data/certs/*.key
chmod 700 ./data/certs/
```

### 3. 网络安全
- 使用 TLS 1.2+ 进行所有通信
- 配置强密码套件
- 启用 HSTS
- 实施 IP 白名单

### 4. 运维安全
- 定期轮换密钥和证书
- 监控安全事件
- 定期备份安全数据
- 实施最小权限原则

## 🔧 故障排查

### 常见问题

1. **密钥管理器启动失败**
   - 检查主密码是否正确
   - 验证密钥存储路径权限
   - 查看审计日志了解详细错误

2. **证书生成失败**
   - 确保 CA 证书和密钥存在
   - 检查证书存储路径权限
   - 验证证书配置参数

3. **认证失败**
   - 检查用户数据文件
   - 验证密码复杂度要求
   - 查看失败尝试次数是否超限

4. **审计日志问题**
   - 检查日志文件权限
   - 验证磁盘空间
   - 确认加密密钥正确

### 调试模式

```go
// 启用详细日志
config.AuditLogger.MinLevel = security.AuditLevelDebug

// 禁用日志加密（仅用于调试）
config.AuditLogger.EncryptLogs = false
```

## 📚 API 参考

详细的 API 文档请参考各个组件的源代码注释。主要接口包括：

- `SecurityManager`: 主要安全管理接口
- `KeyManager`: 密钥管理接口
- `CertManager`: 证书管理接口
- `AccessController`: 访问控制接口
- `EnhancedAuditLogger`: 审计日志接口

## 🤝 贡献

欢迎提交 Issue 和 Pull Request 来改进安全组件。在提交代码前，请确保：

1. 通过所有安全测试
2. 遵循代码规范
3. 更新相关文档
4. 添加适当的测试用例

## 📄 许可证

本项目采用 MIT 许可证，详见 LICENSE 文件。