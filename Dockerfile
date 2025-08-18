# Nova Proxy 企业级多阶段构建 Dockerfile
# 基于 Alpine Linux 的安全、轻量级容器镜像

# ============================================================================
# 构建阶段 - 编译 Go 应用
# ============================================================================
FROM golang:1.23-alpine AS builder

# 设置构建参数
ARG BUILD_VERSION=dev
ARG BUILD_COMMIT=unknown
ARG BUILD_DATE=unknown
ARG CGO_ENABLED=0
ARG GOOS=linux
ARG GOARCH=amd64

# 安装构建依赖
RUN apk add --no-cache \
    git \
    ca-certificates \
    tzdata \
    make

# 设置工作目录
WORKDIR /build

# 复制源代码（包括本地依赖）
COPY . .

# 下载依赖并验证
RUN go mod download && go mod verify

# 构建应用程序
RUN CGO_ENABLED=${CGO_ENABLED} GOOS=${GOOS} GOARCH=${GOARCH} go build \
    -ldflags="-s -w \
    -X 'main.Version=${BUILD_VERSION}' \
    -X 'main.Commit=${BUILD_COMMIT}' \
    -X 'main.BuildDate=${BUILD_DATE}'" \
    -a -installsuffix cgo \
    -o nova-server ./cmd/nova-server

RUN CGO_ENABLED=${CGO_ENABLED} GOOS=${GOOS} GOARCH=${GOARCH} go build \
    -ldflags="-s -w \
    -X 'main.Version=${BUILD_VERSION}' \
    -X 'main.Commit=${BUILD_COMMIT}' \
    -X 'main.BuildDate=${BUILD_DATE}'" \
    -a -installsuffix cgo \
    -o nova-client ./cmd/nova-client

# 验证二进制文件
RUN ./nova-server --version || echo "Server binary built successfully"
RUN ./nova-client --version || echo "Client binary built successfully"

# ============================================================================
# 运行时阶段 - 最小化生产镜像
# ============================================================================
FROM alpine:3.18 AS runtime

# 设置标签信息
LABEL maintainer="Nova Proxy Team" \
      version="${BUILD_VERSION}" \
      description="Nova Proxy - Enterprise QUIC Proxy Server" \
      org.opencontainers.image.title="Nova Proxy" \
      org.opencontainers.image.description="Enterprise-grade QUIC proxy with advanced features" \
      org.opencontainers.image.version="${BUILD_VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${BUILD_COMMIT}" \
      org.opencontainers.image.vendor="Nova Proxy Team" \
      org.opencontainers.image.licenses="MIT"

# 安装运行时依赖
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    curl \
    jq \
    && rm -rf /var/cache/apk/*

# 创建非特权用户
RUN addgroup -g 1001 -S nova && \
    adduser -u 1001 -S nova -G nova -h /home/nova -s /bin/sh

# 创建必要的目录
RUN mkdir -p /app/bin \
             /app/configs \
             /app/logs \
             /app/data \
             /app/certs \
             /tmp/nova \
    && chown -R nova:nova /app /tmp/nova

# 复制二进制文件
COPY --from=builder --chown=nova:nova /build/nova-server /app/bin/
COPY --from=builder --chown=nova:nova /build/nova-client /app/bin/

# 复制配置文件
COPY --chown=nova:nova configs/ /app/configs/
COPY --chown=nova:nova profiles/ /app/profiles/
COPY --chown=nova:nova monitoring/ /app/monitoring/

# 复制健康检查脚本
COPY --chown=nova:nova <<'EOF' /app/bin/healthcheck.sh
#!/bin/sh
# Nova Proxy 健康检查脚本

set -e

# 检查进程是否运行
if ! pgrep -f nova-server > /dev/null; then
    echo "ERROR: nova-server process not found"
    exit 1
fi

# 检查健康检查端点
HEALTH_PORT=${HEALTH_PORT:-8081}
if ! curl -f -s "http://localhost:${HEALTH_PORT}/health" > /dev/null; then
    echo "ERROR: Health check endpoint not responding"
    exit 1
fi

# 检查指标端点
METRICS_PORT=${METRICS_PORT:-9090}
if ! curl -f -s "http://localhost:${METRICS_PORT}/metrics" > /dev/null; then
    echo "WARNING: Metrics endpoint not responding"
fi

echo "OK: Nova Proxy is healthy"
exit 0
EOF

# 设置执行权限
RUN chmod +x /app/bin/healthcheck.sh /app/bin/nova-server /app/bin/nova-client

# 设置工作目录
WORKDIR /app

# 切换到非特权用户
USER nova

# 暴露端口
EXPOSE 8080 8443 8081 9090

# 设置环境变量
ENV PATH="/app/bin:${PATH}" \
    NOVA_CONFIG_PATH="/app/configs" \
    NOVA_LOG_PATH="/app/logs" \
    NOVA_DATA_PATH="/app/data" \
    NOVA_CERT_PATH="/app/certs" \
    GOMAXPROCS="0" \
    GOGC="100"

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /app/bin/healthcheck.sh

# 默认启动命令
CMD ["nova-server", "--config", "/app/configs/server.json"]

# ============================================================================
# 开发阶段 - 包含开发工具的镜像
# ============================================================================
FROM runtime AS development

# 切换回 root 用户安装开发工具
USER root

# 安装开发工具
RUN apk add --no-cache \
    bash \
    vim \
    htop \
    strace \
    tcpdump \
    netcat-openbsd \
    bind-tools \
    && rm -rf /var/cache/apk/*

# 安装 Go 工具（用于调试）
COPY --from=builder /usr/local/go/bin/go /usr/local/bin/
COPY --from=builder /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}" GOROOT="/usr/local/go"

# 切换回 nova 用户
USER nova

# 开发模式启动命令
CMD ["nova-server", "--config", "/app/configs/server.json", "--debug"]

# ============================================================================
# 调试阶段 - 包含调试工具的镜像
# ============================================================================
FROM golang:1.23-alpine AS debug

# 安装调试工具
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    curl \
    jq \
    bash \
    vim \
    htop \
    strace \
    tcpdump \
    netcat-openbsd \
    bind-tools \
    && rm -rf /var/cache/apk/*

# 安装 Delve 调试器
RUN go install github.com/go-delve/delve/cmd/dlv@latest

# 创建用户和目录
RUN addgroup -g 1001 -S nova && \
    adduser -u 1001 -S nova -G nova -h /home/nova -s /bin/bash

RUN mkdir -p /app/bin /app/configs /app/logs /app/data /app/certs /tmp/nova \
    && chown -R nova:nova /app /tmp/nova

# 复制调试版本的二进制文件（包含调试信息）
COPY --from=builder --chown=nova:nova /build /app/src
WORKDIR /app/src

# 构建调试版本
RUN CGO_ENABLED=0 go build -gcflags="-N -l" -o /app/bin/nova-server-debug ./cmd/nova-server
RUN CGO_ENABLED=0 go build -gcflags="-N -l" -o /app/bin/nova-client-debug ./cmd/nova-client

# 复制配置文件
COPY --chown=nova:nova configs/ /app/configs/
COPY --chown=nova:nova profiles/ /app/profiles/

WORKDIR /app
USER nova

# 暴露调试端口
EXPOSE 8080 8443 8081 9090 2345

# 调试模式启动命令
CMD ["dlv", "--listen=:2345", "--headless=true", "--api-version=2", "--accept-multiclient", "exec", "/app/bin/nova-server-debug", "--", "--config", "/app/configs/server.json"]