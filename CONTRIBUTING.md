# 贡献指南

感谢您对 Nova Proxy 项目的关注！我们欢迎所有形式的贡献，包括但不限于代码、文档、测试、问题报告和功能建议。

## 🤝 如何贡献

### 报告问题

如果您发现了 bug 或有功能建议，请：

1. 首先搜索 [现有 Issues](https://github.com/your-org/nova-proxy/issues) 确保问题未被报告
2. 使用相应的 Issue 模板创建新的 Issue
3. 提供尽可能详细的信息，包括：
   - 操作系统和版本
   - Go 版本
   - Nova Proxy 版本
   - 重现步骤
   - 预期行为和实际行为
   - 相关日志和错误信息

### 提交代码

#### 开发环境设置

1. **Fork 项目**
   ```bash
   # 在 GitHub 上 Fork 项目，然后克隆您的 Fork
   git clone https://github.com/YOUR_USERNAME/nova-proxy.git
   cd nova-proxy
   ```

2. **设置上游仓库**
   ```bash
   git remote add upstream https://github.com/your-org/nova-proxy.git
   ```

3. **安装依赖**
   ```bash
   go mod download
   ```

4. **安装开发工具**
   ```bash
   # 安装代码质量工具
   go install honnef.co/go/tools/cmd/staticcheck@latest
   go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
   go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
   
   # 安装测试工具
   go install github.com/onsi/ginkgo/v2/ginkgo@latest
   go install github.com/rakyll/hey@latest
   ```

#### 开发流程

1. **创建功能分支**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **进行开发**
   - 遵循项目的代码规范
   - 编写测试用例
   - 更新相关文档

3. **运行测试**
   ```bash
   # 运行所有测试
   make test
   
   # 运行代码质量检查
   make lint
   
   # 运行安全扫描
   make security
   
   # 检查测试覆盖率
   make coverage
   ```

4. **提交更改**
   ```bash
   git add .
   git commit -m "feat: add your feature description"
   ```

5. **推送分支**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **创建 Pull Request**
   - 在 GitHub 上创建 Pull Request
   - 填写 PR 模板
   - 等待代码审查

## 📝 代码规范

### Go 代码风格

我们遵循标准的 Go 代码风格：

```go
// 包注释应该以包名开头
// Package server implements the Nova Proxy server functionality.
package server

import (
    // 标准库
    "context"
    "fmt"
    "net/http"
    
    // 第三方库
    "github.com/prometheus/client_golang/prometheus"
    
    // 项目内部包
    "github.com/your-org/nova-proxy/internal/config"
)

// 常量使用驼峰命名
const (
    DefaultTimeout = 30 * time.Second
    MaxRetries     = 3
)

// 结构体和接口使用 PascalCase
type ProxyServer struct {
    config *config.Config
    logger *slog.Logger
}

// 方法注释应该以方法名开头
// Start starts the proxy server on the configured address.
func (s *ProxyServer) Start(ctx context.Context) error {
    // 实现...
}
```

### 错误处理

```go
// 使用 fmt.Errorf 包装错误
if err != nil {
    return fmt.Errorf("failed to start server: %w", err)
}

// 定义自定义错误类型
type ConfigError struct {
    Field string
    Value interface{}
}

func (e *ConfigError) Error() string {
    return fmt.Sprintf("invalid config field %s: %v", e.Field, e.Value)
}
```

### 日志记录

```go
// 使用结构化日志
logger.Info("server started",
    slog.String("address", addr),
    slog.Int("port", port),
)

logger.Error("failed to process request",
    slog.String("error", err.Error()),
    slog.String("request_id", requestID),
)
```

### 测试规范

```go
func TestProxyServer_Start(t *testing.T) {
    tests := []struct {
        name    string
        config  *config.Config
        wantErr bool
    }{
        {
            name: "valid config",
            config: &config.Config{
                ListenAddr: "127.0.0.1:8080",
            },
            wantErr: false,
        },
        {
            name: "invalid address",
            config: &config.Config{
                ListenAddr: "invalid",
            },
            wantErr: true,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            server := NewProxyServer(tt.config)
            err := server.Start(context.Background())
            if (err != nil) != tt.wantErr {
                t.Errorf("Start() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
```

## 🧪 测试指南

### 测试类型

1. **单元测试** - 测试单个函数或方法
2. **集成测试** - 测试组件间的交互
3. **端到端测试** - 测试完整的用户场景
4. **性能测试** - 测试系统性能和负载能力

### 测试覆盖率

- 新代码的测试覆盖率应该达到 **80%** 以上
- 关键路径和错误处理必须有测试覆盖
- 使用 `make coverage` 检查覆盖率

### 测试数据

```go
// 使用 testdata 目录存放测试数据
// testdata/server_config.json
{
  "listen_addr": "127.0.0.1:8080",
  "preshared_key": "test-key-32-bytes-long-for-testing"
}

// 在测试中加载
func loadTestConfig(t *testing.T) *config.Config {
    data, err := os.ReadFile("testdata/server_config.json")
    if err != nil {
        t.Fatalf("failed to load test config: %v", err)
    }
    
    var cfg config.Config
    if err := json.Unmarshal(data, &cfg); err != nil {
        t.Fatalf("failed to parse test config: %v", err)
    }
    
    return &cfg
}
```

## 📚 文档规范

### 代码文档

- 所有公开的函数、方法、类型都必须有文档注释
- 文档注释应该以被注释的标识符名称开头
- 使用完整的句子，以句号结尾

### README 更新

如果您的更改影响了用户接口，请更新相应的文档：

- `README.md` - 项目概述和快速开始
- `docs/` 目录下的详细文档
- API 文档（如果适用）

### 变更日志

重要的更改应该记录在 `CHANGELOG.md` 中：

```markdown
## [1.2.0] - 2024-01-15

### Added
- 新增 HTTP/3 支持
- 添加 Prometheus 指标收集

### Changed
- 优化 QUIC 连接性能
- 更新依赖版本

### Fixed
- 修复内存泄漏问题
- 解决并发访问竞态条件

### Security
- 加强 TLS 配置安全性
```

## 🔍 代码审查

### 审查清单

**功能性**
- [ ] 代码实现了预期的功能
- [ ] 边界条件得到正确处理
- [ ] 错误处理完整且合理
- [ ] 性能影响可接受

**代码质量**
- [ ] 代码清晰易读
- [ ] 命名规范且有意义
- [ ] 没有重复代码
- [ ] 遵循项目架构模式

**测试**
- [ ] 有足够的测试覆盖
- [ ] 测试用例覆盖正常和异常情况
- [ ] 测试可以稳定通过

**文档**
- [ ] 公开 API 有文档注释
- [ ] 复杂逻辑有解释注释
- [ ] 相关文档已更新

**安全性**
- [ ] 没有硬编码的敏感信息
- [ ] 输入验证充分
- [ ] 权限检查正确

### 审查流程

1. **自动检查** - CI 流水线会自动运行测试和代码质量检查
2. **人工审查** - 至少需要一位维护者的批准
3. **讨论** - 通过 GitHub 评论进行讨论和改进
4. **合并** - 审查通过后合并到主分支

## 🚀 发布流程

### 版本号规范

我们使用 [语义化版本](https://semver.org/lang/zh-CN/)：

- `MAJOR.MINOR.PATCH` (例如：1.2.3)
- **MAJOR**: 不兼容的 API 更改
- **MINOR**: 向后兼容的功能新增
- **PATCH**: 向后兼容的问题修复

### 发布步骤

1. **更新版本号**
   ```bash
   # 更新 version.go
   echo 'package version\n\nconst Version = "1.2.3"' > internal/version/version.go
   ```

2. **更新变更日志**
   ```bash
   # 在 CHANGELOG.md 中添加新版本的更改
   ```

3. **创建标签**
   ```bash
   git tag -a v1.2.3 -m "Release version 1.2.3"
   git push origin v1.2.3
   ```

4. **GitHub Actions** 会自动构建和发布

## 🛡️ 安全政策

### 报告安全漏洞

如果您发现了安全漏洞，请：

1. **不要** 在公开的 Issue 中报告
2. 发送邮件到 security@nova-proxy.io
3. 包含详细的漏洞描述和重现步骤
4. 我们会在 48 小时内回复

### 安全最佳实践

- 不要在代码中硬编码密钥或密码
- 使用安全的随机数生成器
- 验证所有外部输入
- 使用最新的依赖版本
- 定期运行安全扫描

## 📞 获取帮助

如果您在贡献过程中遇到问题，可以通过以下方式获取帮助：

- 💬 [GitHub Discussions](https://github.com/your-org/nova-proxy/discussions)
- 📧 Email: dev@nova-proxy.io
- 💬 Slack: [#nova-proxy-dev](https://nova-proxy.slack.com)

## 🙏 致谢

感谢所有为 Nova Proxy 项目做出贡献的开发者！您的贡献让这个项目变得更好。

### 贡献者

<!-- 这里会自动生成贡献者列表 -->

---

再次感谢您的贡献！🎉