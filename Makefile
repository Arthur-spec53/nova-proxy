# Nova Proxy Makefile
# 提供常用的开发、构建、测试和部署命令

# 项目信息
PROJECT_NAME := nova-proxy
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')

# Go 相关变量
GO := go
GOFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)"
GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)

# Docker 相关变量
DOCKER_REGISTRY := your-registry.com
DOCKER_IMAGE := $(DOCKER_REGISTRY)/$(PROJECT_NAME)
DOCKER_TAG := $(VERSION)

# Kubernetes 相关变量
KUBE_NAMESPACE := nova-proxy
HELM_CHART := ./helm/nova-proxy

# 目录定义
BIN_DIR := bin
CMD_DIR := cmd
INTERNAL_DIR := internal
PKG_DIR := pkg
TEST_DIR := test
DOCS_DIR := docs
SCRIPTS_DIR := scripts

# 颜色定义
RED := \033[31m
GREEN := \033[32m
YELLOW := \033[33m
BLUE := \033[34m
MAGENTA := \033[35m
CYAN := \033[36m
WHITE := \033[37m
RESET := \033[0m

# 默认目标
.DEFAULT_GOAL := help

# 帮助信息
.PHONY: help
help: ## 显示帮助信息
	@echo "$(CYAN)Nova Proxy - 构建和开发工具$(RESET)"
	@echo ""
	@echo "$(YELLOW)可用命令:$(RESET)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(GREEN)%-20s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(YELLOW)示例:$(RESET)"
	@echo "  make build          # 构建所有二进制文件"
	@echo "  make test           # 运行所有测试"
	@echo "  make docker-build   # 构建 Docker 镜像"
	@echo "  make deploy-dev     # 部署到开发环境"
	@echo "  make system-check   # 检查系统资源并推荐部署方案"
	@echo "  make deploy-minimal # 轻量级部署"

# ============================================================================
# 系统检查和部署建议
# ============================================================================

.PHONY: system-check
system-check: ## 检查系统资源并推荐合适的部署方案
	@echo "$(YELLOW)检查系统资源...$(RESET)"
	@./scripts/system-check.sh

.PHONY: deploy-minimal
deploy-minimal: ## 轻量级部署（适合低配置环境）
	@echo "$(YELLOW)启动轻量级部署...$(RESET)"
	@if [ ! -f .env ]; then \
		echo "$(BLUE)复制轻量级环境配置...$(RESET)"; \
		cp .env.minimal .env; \
	fi
	@docker compose -f docker-compose.minimal.yml up -d
	@echo "$(GREEN)轻量级部署完成$(RESET)"
	@echo "$(CYAN)访问地址:$(RESET)"
	@echo "  Nova Server: http://localhost:8080"
	@echo "  健康检查: http://localhost:8081/health"
	@echo "$(YELLOW)可选启用监控:$(RESET)"
	@echo "  make enable-monitoring"

.PHONY: deploy-minimal-with-monitoring
deploy-minimal-with-monitoring: ## 轻量级部署并启用监控
	@echo "$(YELLOW)启动轻量级部署（含监控）...$(RESET)"
	@if [ ! -f .env ]; then \
		echo "$(BLUE)复制轻量级环境配置...$(RESET)"; \
		cp .env.minimal .env; \
	fi
	@docker compose -f docker-compose.minimal.yml --profile monitoring up -d
	@echo "$(GREEN)轻量级部署（含监控）完成$(RESET)"
	@echo "$(CYAN)访问地址:$(RESET)"
	@echo "  Nova Server: http://localhost:8080"
	@echo "  Prometheus: http://localhost:9091"
	@echo "  Grafana: http://localhost:3000 (admin/admin123)"

.PHONY: enable-monitoring
enable-monitoring: ## 为现有轻量级部署启用监控
	@echo "$(YELLOW)启用监控组件...$(RESET)"
	@docker compose -f docker-compose.minimal.yml --profile monitoring up -d
	@echo "$(GREEN)监控组件已启用$(RESET)"

.PHONY: disable-monitoring
disable-monitoring: ## 禁用监控组件以节省资源
	@echo "$(YELLOW)禁用监控组件...$(RESET)"
	@docker compose -f docker-compose.minimal.yml stop prometheus grafana
	@docker compose -f docker-compose.minimal.yml rm -f prometheus grafana
	@echo "$(GREEN)监控组件已禁用$(RESET)"

.PHONY: deploy-full
deploy-full: ## 完整部署（适合高配置环境）
	@echo "$(YELLOW)启动完整部署...$(RESET)"
	@if [ ! -f .env ]; then \
		echo "$(BLUE)复制完整环境配置...$(RESET)"; \
		cp .env.example .env; \
	fi
	@docker compose up -d
	@echo "$(GREEN)完整部署完成$(RESET)"
	@echo "$(CYAN)访问地址:$(RESET)"
	@echo "  Nova Server: http://localhost:8080"
	@echo "  Prometheus: http://localhost:9091"
	@echo "  Grafana: http://localhost:3000 (admin/admin123)"
	@echo "  Jaeger: http://localhost:16686"
	@echo "  Traefik: http://localhost:8080"

# 管理工具
.PHONY: manager nova-manager
manager: nova-manager ## 启动 Nova Proxy 管理工具 (交互式菜单)

nova-manager: ## 启动保姆级管理工具，提供完整的部署和维护功能
	@echo "$(CYAN)启动 Nova Proxy 管理工具...$(RESET)"
	@if [ -f "scripts/nova-manager.sh" ]; then \
		chmod +x scripts/nova-manager.sh && ./scripts/nova-manager.sh; \
	else \
		echo "$(RED)错误: 管理脚本不存在$(RESET)"; \
		echo "请确保 scripts/nova-manager.sh 文件存在"; \
		exit 1; \
	fi

.PHONY: uninstall
uninstall: ## 快速卸载 Nova Proxy (危险操作)
	@echo "$(RED)⚠️  警告: 此操作将完全删除所有 Nova Proxy 相关的服务和数据！$(RESET)"
	@echo "如需继续，请使用管理工具进行安全卸载:"
	@echo "  make manager"
	@echo "  然后选择选项 23 - 完全卸载服务"
	@echo ""
	@read -p "确定要直接执行卸载吗？输入 'UNINSTALL' 确认: " confirm; \
	if [ "$$confirm" = "UNINSTALL" ]; then \
		if [ -f "scripts/nova-manager.sh" ]; then \
			chmod +x scripts/nova-manager.sh; \
			echo "23" | ./scripts/nova-manager.sh; \
		else \
			echo "$(YELLOW)管理脚本不存在，执行基本清理...$(RESET)"; \
			docker-compose down --remove-orphans || true; \
			docker system prune -f; \
		fi; \
	else \
		echo "$(GREEN)操作已取消$(RESET)"; \
	fi

.PHONY: resource-monitor
resource-monitor: ## 监控Docker容器资源使用情况
	@echo "$(YELLOW)监控容器资源使用...$(RESET)"
	@echo "$(CYAN)按 Ctrl+C 退出监控$(RESET)"
	@docker stats

.PHONY: performance-test
performance-test: ## 运行性能测试
	@echo "$(YELLOW)运行性能测试...$(RESET)"
	@./scripts/performance.sh

.PHONY: deployment-status
deployment-status: ## 检查部署状态
	@echo "$(YELLOW)检查部署状态...$(RESET)"
	@docker compose ps
	@echo ""
	@echo "$(CYAN)容器资源使用:$(RESET)"
	@docker stats --no-stream
	@echo ""
	@echo "$(CYAN)系统资源:$(RESET)"
	@free -h
	@df -h .

# 清理
.PHONY: clean
clean: ## 清理构建产物
	@echo "$(YELLOW)清理构建产物...$(RESET)"
	rm -rf $(BIN_DIR)
	rm -rf coverage.out
	rm -rf *.log
	$(GO) clean -cache -testcache -modcache
	@echo "$(GREEN)清理完成$(RESET)"

# 创建目录
$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# 依赖管理
.PHONY: deps
deps: ## 下载和整理依赖
	@echo "$(YELLOW)下载依赖...$(RESET)"
	$(GO) mod download
	$(GO) mod tidy
	@echo "$(GREEN)依赖管理完成$(RESET)"

.PHONY: deps-update
deps-update: ## 更新依赖到最新版本
	@echo "$(YELLOW)更新依赖...$(RESET)"
	$(GO) get -u ./...
	$(GO) mod tidy
	@echo "$(GREEN)依赖更新完成$(RESET)"

# 代码格式化和检查
.PHONY: fmt
fmt: ## 格式化代码
	@echo "$(YELLOW)格式化代码...$(RESET)"
	$(GO) fmt ./...
	gofumpt -w .
	@echo "$(GREEN)代码格式化完成$(RESET)"

.PHONY: lint
lint: ## 运行代码检查
	@echo "$(YELLOW)运行代码检查...$(RESET)"
	$(GO) vet ./...
	staticcheck ./...
	golangci-lint run
	@echo "$(GREEN)代码检查完成$(RESET)"

.PHONY: security
security: ## 运行安全扫描
	@echo "$(YELLOW)运行安全扫描...$(RESET)"
	gosec ./...
	nancy sleuth
	@echo "$(GREEN)安全扫描完成$(RESET)"

.PHONY: check
check: fmt lint security ## 运行所有代码质量检查
	@echo "$(GREEN)所有检查完成$(RESET)"

# 构建
.PHONY: build
build: $(BIN_DIR) ## 构建所有二进制文件
	@echo "$(YELLOW)构建二进制文件...$(RESET)"
	$(GO) build $(GOFLAGS) -o $(BIN_DIR)/nova-server ./$(CMD_DIR)/nova-server
	$(GO) build $(GOFLAGS) -o $(BIN_DIR)/nova-client ./$(CMD_DIR)/nova-client
	@echo "$(GREEN)构建完成$(RESET)"

.PHONY: build-server
build-server: $(BIN_DIR) ## 构建服务端
	@echo "$(YELLOW)构建服务端...$(RESET)"
	$(GO) build $(GOFLAGS) -o $(BIN_DIR)/nova-server ./$(CMD_DIR)/nova-server
	@echo "$(GREEN)服务端构建完成$(RESET)"

.PHONY: build-client
build-client: $(BIN_DIR) ## 构建客户端
	@echo "$(YELLOW)构建客户端...$(RESET)"
	$(GO) build $(GOFLAGS) -o $(BIN_DIR)/nova-client ./$(CMD_DIR)/nova-client
	@echo "$(GREEN)客户端构建完成$(RESET)"

.PHONY: build-cross
build-cross: $(BIN_DIR) ## 交叉编译多平台二进制文件
	@echo "$(YELLOW)交叉编译多平台二进制文件...$(RESET)"
	# Linux AMD64
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BIN_DIR)/nova-server-linux-amd64 ./$(CMD_DIR)/nova-server
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BIN_DIR)/nova-client-linux-amd64 ./$(CMD_DIR)/nova-client
	# Linux ARM64
	GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) -o $(BIN_DIR)/nova-server-linux-arm64 ./$(CMD_DIR)/nova-server
	GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) -o $(BIN_DIR)/nova-client-linux-arm64 ./$(CMD_DIR)/nova-client
	# macOS AMD64
	GOOS=darwin GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BIN_DIR)/nova-server-darwin-amd64 ./$(CMD_DIR)/nova-server
	GOOS=darwin GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BIN_DIR)/nova-client-darwin-amd64 ./$(CMD_DIR)/nova-client
	# macOS ARM64
	GOOS=darwin GOARCH=arm64 $(GO) build $(GOFLAGS) -o $(BIN_DIR)/nova-server-darwin-arm64 ./$(CMD_DIR)/nova-server
	GOOS=darwin GOARCH=arm64 $(GO) build $(GOFLAGS) -o $(BIN_DIR)/nova-client-darwin-arm64 ./$(CMD_DIR)/nova-client
	# Windows AMD64
	GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BIN_DIR)/nova-server-windows-amd64.exe ./$(CMD_DIR)/nova-server
	GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BIN_DIR)/nova-client-windows-amd64.exe ./$(CMD_DIR)/nova-client
	@echo "$(GREEN)交叉编译完成$(RESET)"

# 测试
.PHONY: test
test: ## 运行所有测试
	@echo "$(YELLOW)运行单元测试...$(RESET)"
	$(GO) test -v -race -timeout 30s ./...
	@echo "$(GREEN)测试完成$(RESET)"

.PHONY: test-unit
test-unit: ## 运行单元测试
	@echo "$(YELLOW)运行单元测试...$(RESET)"
	$(GO) test -v -race -short ./...
	@echo "$(GREEN)单元测试完成$(RESET)"

.PHONY: test-integration
test-integration: ## 运行集成测试
	@echo "$(YELLOW)运行集成测试...$(RESET)"
	./integration_test.sh
	@echo "$(GREEN)集成测试完成$(RESET)"

.PHONY: test-e2e
test-e2e: ## 运行端到端测试
	@echo "$(YELLOW)运行端到端测试...$(RESET)"
	$(GO) test -v -tags=e2e ./$(TEST_DIR)/e2e/...
	@echo "$(GREEN)端到端测试完成$(RESET)"

.PHONY: test-performance
test-performance: ## 运行性能测试
	@echo "$(YELLOW)运行性能测试...$(RESET)"
	$(GO) test -v -bench=. -benchmem ./...
	@echo "$(GREEN)性能测试完成$(RESET)"

.PHONY: coverage
coverage: ## 生成测试覆盖率报告
	@echo "$(YELLOW)生成测试覆盖率报告...$(RESET)"
	$(GO) test -v -race -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)覆盖率报告生成完成: coverage.html$(RESET)"

# 运行
.PHONY: run-server
run-server: build-server ## 运行服务端
	@echo "$(YELLOW)启动服务端...$(RESET)"
	./$(BIN_DIR)/nova-server

.PHONY: run-client
run-client: build-client ## 运行客户端
	@echo "$(YELLOW)启动客户端...$(RESET)"
	./$(BIN_DIR)/nova-client

# 证书生成
.PHONY: certs
certs: ## 生成测试证书
	@echo "$(YELLOW)生成测试证书...$(RESET)"
	mkdir -p certs
	openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/C=US/ST=CA/L=SF/O=Nova/CN=localhost"
	openssl req -x509 -newkey rsa:4096 -keyout certs/client.key -out certs/client.crt -days 365 -nodes -subj "/C=US/ST=CA/L=SF/O=Nova/CN=client"
	@echo "$(GREEN)测试证书生成完成$(RESET)"

# Docker
.PHONY: docker-build
docker-build: ## 构建 Docker 镜像
	@echo "$(YELLOW)构建 Docker 镜像...$(RESET)"
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_IMAGE):latest
	@echo "$(GREEN)Docker 镜像构建完成$(RESET)"

.PHONY: docker-push
docker-push: docker-build ## 推送 Docker 镜像
	@echo "$(YELLOW)推送 Docker 镜像...$(RESET)"
	docker push $(DOCKER_IMAGE):$(DOCKER_TAG)
	docker push $(DOCKER_IMAGE):latest
	@echo "$(GREEN)Docker 镜像推送完成$(RESET)"

.PHONY: docker-run-server
docker-run-server: ## 运行服务端 Docker 容器
	@echo "$(YELLOW)运行服务端容器...$(RESET)"
	docker run -d --name nova-server -p 8443:8443 $(DOCKER_IMAGE):$(DOCKER_TAG) server

.PHONY: docker-run-client
docker-run-client: ## 运行客户端 Docker 容器
	@echo "$(YELLOW)运行客户端容器...$(RESET)"
	docker run -d --name nova-client -p 1080:1080 $(DOCKER_IMAGE):$(DOCKER_TAG) client

.PHONY: docker-stop
docker-stop: ## 停止 Docker 容器
	@echo "$(YELLOW)停止 Docker 容器...$(RESET)"
	docker stop nova-server nova-client || true
	docker rm nova-server nova-client || true

# Kubernetes 部署
.PHONY: k8s-deploy
k8s-deploy: ## 使用 kubectl 部署到 Kubernetes
	@echo "$(YELLOW)部署到 Kubernetes...$(RESET)"
	kubectl apply -f k8s/
	@echo "$(GREEN)Kubernetes 部署完成$(RESET)"

.PHONY: k8s-delete
k8s-delete: ## 从 Kubernetes 删除部署
	@echo "$(YELLOW)从 Kubernetes 删除部署...$(RESET)"
	kubectl delete -f k8s/
	@echo "$(GREEN)Kubernetes 删除完成$(RESET)"

# Helm 部署
.PHONY: helm-install
helm-install: ## 使用 Helm 安装
	@echo "$(YELLOW)使用 Helm 安装...$(RESET)"
	helm install $(PROJECT_NAME) $(HELM_CHART) --namespace $(KUBE_NAMESPACE) --create-namespace
	@echo "$(GREEN)Helm 安装完成$(RESET)"

.PHONY: helm-upgrade
helm-upgrade: ## 使用 Helm 升级
	@echo "$(YELLOW)使用 Helm 升级...$(RESET)"
	helm upgrade $(PROJECT_NAME) $(HELM_CHART) --namespace $(KUBE_NAMESPACE)
	@echo "$(GREEN)Helm 升级完成$(RESET)"

.PHONY: helm-uninstall
helm-uninstall: ## 使用 Helm 卸载
	@echo "$(YELLOW)使用 Helm 卸载...$(RESET)"
	helm uninstall $(PROJECT_NAME) --namespace $(KUBE_NAMESPACE)
	@echo "$(GREEN)Helm 卸载完成$(RESET)"

.PHONY: helm-template
helm-template: ## 生成 Helm 模板
	@echo "$(YELLOW)生成 Helm 模板...$(RESET)"
	helm template $(PROJECT_NAME) $(HELM_CHART) --namespace $(KUBE_NAMESPACE)

# 环境部署
.PHONY: deploy-dev
deploy-dev: ## 部署到开发环境
	@echo "$(YELLOW)部署到开发环境...$(RESET)"
	./$(SCRIPTS_DIR)/deploy/deploy.sh -e development -v $(VERSION)
	@echo "$(GREEN)开发环境部署完成$(RESET)"

.PHONY: deploy-staging
deploy-staging: ## 部署到预发布环境
	@echo "$(YELLOW)部署到预发布环境...$(RESET)"
	./$(SCRIPTS_DIR)/deploy/deploy.sh -e staging -v $(VERSION)
	@echo "$(GREEN)预发布环境部署完成$(RESET)"

.PHONY: deploy-prod
deploy-prod: ## 部署到生产环境
	@echo "$(YELLOW)部署到生产环境...$(RESET)"
	./$(SCRIPTS_DIR)/deploy/deploy.sh -e production -v $(VERSION)
	@echo "$(GREEN)生产环境部署完成$(RESET)"

# 监控和运维
.PHONY: setup-monitoring
setup-monitoring: ## 设置监控系统
	@echo "$(YELLOW)设置监控系统...$(RESET)"
	./$(SCRIPTS_DIR)/monitoring/setup-monitoring.sh -e production --all
	@echo "$(GREEN)监控系统设置完成$(RESET)"

.PHONY: health-check
health-check: ## 运行健康检查
	@echo "$(YELLOW)运行健康检查...$(RESET)"
	./$(SCRIPTS_DIR)/maintenance/health-check.sh --namespace $(KUBE_NAMESPACE)

.PHONY: backup
backup: ## 创建备份
	@echo "$(YELLOW)创建备份...$(RESET)"
	./$(SCRIPTS_DIR)/backup/backup.sh --type full --encrypt
	@echo "$(GREEN)备份完成$(RESET)"

.PHONY: cleanup
cleanup: ## 清理系统
	@echo "$(YELLOW)清理系统...$(RESET)"
	./$(SCRIPTS_DIR)/maintenance/cleanup.sh --days 7 --docker --k8s
	@echo "$(GREEN)系统清理完成$(RESET)"

# 文档
.PHONY: docs
docs: ## 生成文档
	@echo "$(YELLOW)生成文档...$(RESET)"
	godoc -http=:6060 &
	@echo "$(GREEN)文档服务启动: http://localhost:6060$(RESET)"

.PHONY: docs-build
docs-build: ## 构建静态文档
	@echo "$(YELLOW)构建静态文档...$(RESET)"
	# 这里可以添加文档构建命令，如 mkdocs, gitbook 等
	@echo "$(GREEN)文档构建完成$(RESET)"

# 发布
.PHONY: release
release: ## 创建发布版本
	@echo "$(YELLOW)创建发布版本...$(RESET)"
	@if [ -z "$(TAG)" ]; then echo "$(RED)请指定 TAG: make release TAG=v1.0.0$(RESET)"; exit 1; fi
	git tag -a $(TAG) -m "Release $(TAG)"
	git push origin $(TAG)
	@echo "$(GREEN)发布版本 $(TAG) 创建完成$(RESET)"

# 开发工具
.PHONY: install-tools
install-tools: ## 安装开发工具
	@echo "$(YELLOW)安装开发工具...$(RESET)"
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	go install mvdan.cc/gofumpt@latest
	go install github.com/onsi/ginkgo/v2/ginkgo@latest
	go install github.com/rakyll/hey@latest
	@echo "$(GREEN)开发工具安装完成$(RESET)"

# 信息显示
.PHONY: info
info: ## 显示项目信息
	@echo "$(CYAN)项目信息:$(RESET)"
	@echo "  项目名称: $(PROJECT_NAME)"
	@echo "  版本: $(VERSION)"
	@echo "  提交: $(COMMIT)"
	@echo "  构建时间: $(BUILD_TIME)"
	@echo "  Go 版本: $(shell $(GO) version)"
	@echo "  操作系统: $(GOOS)"
	@echo "  架构: $(GOARCH)"
	@echo "  Docker 镜像: $(DOCKER_IMAGE):$(DOCKER_TAG)"

# 完整的 CI 流程
.PHONY: ci
ci: deps check test coverage build ## 运行完整的 CI 流程
	@echo "$(GREEN)CI 流程完成$(RESET)"

# 完整的 CD 流程
.PHONY: cd
cd: ci docker-build docker-push ## 运行完整的 CD 流程
	@echo "$(GREEN)CD 流程完成$(RESET)"

# 开发环境设置
.PHONY: dev-setup
dev-setup: install-tools deps certs ## 设置开发环境
	@echo "$(GREEN)开发环境设置完成$(RESET)"

# 快速开始
.PHONY: quick-start
quick-start: dev-setup build ## 快速开始开发
	@echo "$(GREEN)快速开始完成，现在可以运行:$(RESET)"
	@echo "  make run-server  # 启动服务端"
	@echo "  make run-client  # 启动客户端"

# 全面测试
.PHONY: test-all
test-all: test-unit test-integration test-e2e test-performance ## 运行所有测试
	@echo "$(GREEN)所有测试完成$(RESET)"

.PHONY: version
version: ## 显示版本信息
	@echo $(VERSION)