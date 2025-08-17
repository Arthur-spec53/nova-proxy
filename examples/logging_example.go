package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"nova-proxy/internal/logging"
)

// runLoggingExample 演示企业级日志系统的使用
func runLoggingExample() {
	fmt.Println("=== Nova Proxy 企业级日志系统示例 ===")

	// 1. 使用默认配置创建日志器
	fmt.Println("\n1. 创建默认日志器...")
	defaultLogger, err := logging.NewStructuredLogger(&logging.LoggerConfig{
		Level:  logging.LogLevelInfo,
		Format: logging.LogFormatText,
		Output: logging.LogOutputStdout,
	})
	if err != nil {
		fmt.Printf("创建默认日志器失败: %v\n", err)
		return
	}
	defer defaultLogger.Close()

	// 基础日志记录
	defaultLogger.Info("应用启动", "version", "1.0.0", "port", 8080)
	defaultLogger.Warn("配置文件未找到，使用默认配置")
	defaultLogger.Error("数据库连接失败", "error", "connection timeout")

	// 2. 使用自定义配置
	fmt.Println("\n2. 创建自定义配置日志器...")
	customLogger, err := logging.NewStructuredLogger(&logging.LoggerConfig{
		Level:           logging.LogLevelDebug,
		Format:          logging.LogFormatJSON,
		Output:          logging.LogOutputFile,
		FilePath:        "/tmp/nova-proxy.log",
		MaxFileSize:     10 * 1024 * 1024, // 10MB
		MaxFiles:        5,
		MaxAge:          7 * 24 * time.Hour,
		Compress:        true,
		EnableRotation:  true,
		EnableSanitizer: true,
		Fields: map[string]string{
			"service": "nova-proxy",
			"version": "1.0.0",
		},
	})
	if err != nil {
		fmt.Printf("创建自定义日志器失败: %v\n", err)
		return
	}
	defer customLogger.Close()

	// 3. 结构化日志记录
	fmt.Println("\n3. 结构化日志记录...")
	customLogger.WithFields(map[string]interface{}{
		"user_id":    12345,
		"session_id": "abc123",
		"ip":         "192.168.1.100",
	}).Info("用户登录成功")

	// 4. 上下文日志记录
	fmt.Println("\n4. 上下文日志记录...")
	ctx := context.WithValue(context.Background(), "request_id", "req-789")
	customLogger.WithContext(ctx).Debug("开始处理请求")
	customLogger.WithContext(ctx).Info("请求处理完成")

	// 5. 错误日志记录
	fmt.Println("\n5. 错误日志记录...")
	err = fmt.Errorf("数据库查询失败: %w", fmt.Errorf("连接超时"))
	customLogger.WithError(err).Error("业务操作失败")

	// 6. 敏感信息脱敏测试
	fmt.Println("\n6. 敏感信息脱敏测试...")
	customLogger.Info("用户注册",
		"email", "user@example.com",
		"password", "secret123",
		"phone", "13812345678",
		"credit_card", "4111-1111-1111-1111",
	)

	fmt.Println("\n=== 日志系统示例完成 ===")
}

// demonstrateLogRotation 演示日志轮转功能
func demonstrateLogRotation() {
	fmt.Println("\n=== 日志轮转演示 ===")

	// 创建轮转配置
	rotatorConfig := &logging.LogRotatorConfig{
		Filename: "/tmp/rotation-test.log",
		MaxSize:  1, // 1MB
		MaxFiles: 3,
		MaxAge:   24 * time.Hour,
		Compress: true,
	}

	rotator, err := logging.NewLogRotator(rotatorConfig)
	if err != nil {
		fmt.Printf("创建日志轮转器失败: %v\n", err)
		return
	}
	defer rotator.Close()

	// 写入大量日志触发轮转
	for i := 0; i < 1000; i++ {
		logLine := fmt.Sprintf("这是第 %d 行日志，包含一些测试数据用于填充文件大小\n", i)
		if _, err := rotator.Write([]byte(logLine)); err != nil {
			fmt.Printf("写入日志失败: %v\n", err)
			break
		}
	}

	fmt.Println("日志轮转演示完成")
}

// demonstrateSanitization 演示敏感信息脱敏功能
func demonstrateSanitization() {
	fmt.Println("\n=== 敏感信息脱敏演示 ===")

	sanitizer, err := logging.NewLogSanitizer(nil)
	if err != nil {
		fmt.Printf("创建脱敏器失败: %v\n", err)
		return
	}

	// 测试各种敏感信息
	testCases := []string{
		"用户密码: password123",
		"邮箱地址: john.doe@example.com",
		"手机号码: 13812345678",
		"信用卡号: 4111-1111-1111-1111",
		"IP地址: 192.168.1.100",
		"JWT令牌: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		"API密钥: sk-1234567890abcdef",
	}

	for _, testCase := range testCases {
		sanitized := sanitizer.SanitizeString(testCase)
		fmt.Printf("原始: %s\n", testCase)
		fmt.Printf("脱敏: %s\n\n", sanitized)
	}

	fmt.Println("敏感信息脱敏演示完成")
}

func main() {
	// 确保日志目录存在
	if err := os.MkdirAll("/tmp", 0755); err != nil {
		fmt.Printf("创建日志目录失败: %v\n", err)
		return
	}

	// 运行各种演示
	runLoggingExample()
	demonstrateSanitization()
	demonstrateLogRotation()

	fmt.Println("\n所有演示完成！")
}
