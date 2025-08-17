#!/bin/bash

# Nova Proxy 监控系统设置脚本
# 部署 Prometheus, Grafana, Jaeger 等监控组件

set -euo pipefail

# 脚本配置
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LOG_FILE="/tmp/nova-proxy-monitoring-$(date +%Y%m%d-%H%M%S).log"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 日志函数
log() {
    echo -e "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log_info() {
    log "${BLUE}[INFO]${NC} $1"
}

log_warn() {
    log "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    log "${RED}[ERROR]${NC} $1"
}

log_success() {
    log "${GREEN}[SUCCESS]${NC} $1"
}

# 错误处理
error_exit() {
    log_error "$1"
    exit 1
}

# 显示帮助信息
show_help() {
    cat << EOF
Nova Proxy 监控系统设置脚本

用法: $0 [选项] <环境>

环境:
  development    开发环境
  staging        预发布环境
  production     生产环境

选项:
  -h, --help              显示帮助信息
  -n, --namespace NS      指定命名空间 (默认: monitoring)
  -d, --dry-run          干运行模式
  -f, --force            强制部署
  --prometheus           只部署 Prometheus
  --grafana              只部署 Grafana
  --jaeger               只部署 Jaeger
  --alertmanager         只部署 Alertmanager
  --node-exporter        只部署 Node Exporter
  --all                  部署所有组件 (默认)
  --external-url URL     设置外部访问 URL
  --storage-class CLASS  设置存储类
  --retention DAYS       设置数据保留天数 (默认: 15)

示例:
  $0 production                    # 部署所有监控组件到生产环境
  $0 staging --prometheus          # 只部署 Prometheus 到预发布环境
  $0 development --dry-run         # 干运行模式

EOF
}

# 检查依赖
check_dependencies() {
    log_info "检查依赖工具..."
    
    local deps=("kubectl" "helm")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            error_exit "缺少依赖工具: $dep"
        fi
    done
    
    # 检查 kubectl 连接
    if ! kubectl cluster-info &> /dev/null; then
        error_exit "无法连接到 Kubernetes 集群"
    fi
    
    # 检查 Helm
    if ! helm version &> /dev/null; then
        error_exit "Helm 未正确安装或配置"
    fi
    
    log_success "依赖检查完成"
}

# 添加 Helm 仓库
add_helm_repos() {
    log_info "添加 Helm 仓库..."
    
    # Prometheus Community
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    
    # Grafana
    helm repo add grafana https://grafana.github.io/helm-charts
    
    # Jaeger
    helm repo add jaegertracing https://jaegertracing.github.io/helm-charts
    
    # 更新仓库
    helm repo update
    
    log_success "Helm 仓库添加完成"
}

# 创建命名空间
create_namespace() {
    local namespace="$1"
    
    log_info "创建监控命名空间: $namespace"
    
    if kubectl get namespace "$namespace" &> /dev/null; then
        log_info "命名空间 $namespace 已存在"
    else
        kubectl create namespace "$namespace"
        
        # 添加标签
        kubectl label namespace "$namespace" \
            name="$namespace" \
            app.kubernetes.io/name=monitoring \
            app.kubernetes.io/managed-by=helm
        
        log_success "命名空间 $namespace 创建成功"
    fi
}

# 部署 Prometheus
deploy_prometheus() {
    local namespace="$1"
    local environment="$2"
    local storage_class="$3"
    local retention="$4"
    local external_url="$5"
    local dry_run="$6"
    
    log_info "部署 Prometheus..."
    
    # 创建 Prometheus 配置
    local values_file="/tmp/prometheus-values.yaml"
    cat > "$values_file" << EOF
# Prometheus 配置
prometheus:
  prometheusSpec:
    # 数据保留
    retention: ${retention}d
    retentionSize: 50GiB
    
    # 存储配置
    storageSpec:
      volumeClaimTemplate:
        spec:
          storageClassName: $storage_class
          accessModes: ["ReadWriteOnce"]
          resources:
            requests:
              storage: 100Gi
    
    # 资源配置
    resources:
      requests:
        memory: 2Gi
        cpu: 1000m
      limits:
        memory: 4Gi
        cpu: 2000m
    
    # 外部 URL
    externalUrl: ${external_url}/prometheus
    
    # 规则配置
    ruleSelector:
      matchLabels:
        app: nova-proxy
        prometheus: kube-prometheus
    
    # 服务监控配置
    serviceMonitorSelector:
      matchLabels:
        app: nova-proxy
    
    # Pod 监控配置
    podMonitorSelector:
      matchLabels:
        app: nova-proxy
    
    # 额外的抓取配置
    additionalScrapeConfigs:
      - job_name: 'nova-proxy'
        static_configs:
          - targets: ['nova-proxy:8080']
        metrics_path: '/metrics'
        scrape_interval: 15s
        scrape_timeout: 10s
      
      - job_name: 'nova-proxy-quic'
        static_configs:
          - targets: ['nova-proxy:8443']
        metrics_path: '/metrics'
        scrape_interval: 15s
        scrape_timeout: 10s
        scheme: https
        tls_config:
          insecure_skip_verify: true

# Grafana 配置
grafana:
  enabled: true
  
  # 管理员密码
  adminPassword: $(openssl rand -base64 32)
  
  # 持久化存储
  persistence:
    enabled: true
    storageClassName: $storage_class
    size: 10Gi
  
  # 资源配置
  resources:
    requests:
      memory: 256Mi
      cpu: 100m
    limits:
      memory: 512Mi
      cpu: 200m
  
  # 数据源配置
  datasources:
    datasources.yaml:
      apiVersion: 1
      datasources:
        - name: Prometheus
          type: prometheus
          url: http://prometheus-server:80
          access: proxy
          isDefault: true
        
        - name: Jaeger
          type: jaeger
          url: http://jaeger-query:16686
          access: proxy
  
  # 仪表板配置
  dashboardProviders:
    dashboardproviders.yaml:
      apiVersion: 1
      providers:
        - name: 'nova-proxy'
          orgId: 1
          folder: 'Nova Proxy'
          type: file
          disableDeletion: false
          editable: true
          options:
            path: /var/lib/grafana/dashboards/nova-proxy
  
  # 外部访问
  ingress:
    enabled: true
    annotations:
      kubernetes.io/ingress.class: nginx
      cert-manager.io/cluster-issuer: letsencrypt-prod
    hosts:
      - grafana.${environment}.nova-proxy.com
    tls:
      - secretName: grafana-tls
        hosts:
          - grafana.${environment}.nova-proxy.com

# Alertmanager 配置
alertmanager:
  alertmanagerSpec:
    # 存储配置
    storage:
      volumeClaimTemplate:
        spec:
          storageClassName: $storage_class
          accessModes: ["ReadWriteOnce"]
          resources:
            requests:
              storage: 10Gi
    
    # 资源配置
    resources:
      requests:
        memory: 128Mi
        cpu: 100m
      limits:
        memory: 256Mi
        cpu: 200m
    
    # 外部 URL
    externalUrl: ${external_url}/alertmanager

# Node Exporter 配置
nodeExporter:
  enabled: true
  
# Kube State Metrics 配置
kubeStateMetrics:
  enabled: true

# Prometheus Operator 配置
prometheusOperator:
  enabled: true
  
  # 资源配置
  resources:
    requests:
      memory: 128Mi
      cpu: 100m
    limits:
      memory: 256Mi
      cpu: 200m
EOF
    
    # 部署 Prometheus Stack
    local helm_args=(
        "upgrade" "--install" "prometheus"
        "prometheus-community/kube-prometheus-stack"
        "--namespace" "$namespace"
        "--create-namespace"
        "--values" "$values_file"
        "--wait" "--timeout=15m"
    )
    
    if [[ "$dry_run" == "true" ]]; then
        helm_args+=("--dry-run")
    fi
    
    helm "${helm_args[@]}"
    
    # 清理临时文件
    rm -f "$values_file"
    
    if [[ "$dry_run" != "true" ]]; then
        log_success "Prometheus 部署完成"
    else
        log_info "[DRY RUN] Prometheus 部署模拟完成"
    fi
}

# 部署 Jaeger
deploy_jaeger() {
    local namespace="$1"
    local environment="$2"
    local storage_class="$3"
    local dry_run="$4"
    
    log_info "部署 Jaeger..."
    
    # 创建 Jaeger 配置
    local values_file="/tmp/jaeger-values.yaml"
    cat > "$values_file" << EOF
# Jaeger 配置
strategy: production

# Elasticsearch 存储
storage:
  type: elasticsearch
  elasticsearch:
    host: elasticsearch
    port: 9200
    scheme: http
    user: elastic
    password: changeme

# Collector 配置
collector:
  replicaCount: 2
  resources:
    requests:
      memory: 256Mi
      cpu: 100m
    limits:
      memory: 512Mi
      cpu: 200m
  
  service:
    type: ClusterIP
    grpc:
      port: 14250
    http:
      port: 14268
    zipkin:
      port: 9411

# Query 配置
query:
  replicaCount: 2
  resources:
    requests:
      memory: 128Mi
      cpu: 100m
    limits:
      memory: 256Mi
      cpu: 200m
  
  ingress:
    enabled: true
    annotations:
      kubernetes.io/ingress.class: nginx
      cert-manager.io/cluster-issuer: letsencrypt-prod
    hosts:
      - jaeger.${environment}.nova-proxy.com
    tls:
      - secretName: jaeger-tls
        hosts:
          - jaeger.${environment}.nova-proxy.com

# Agent 配置
agent:
  daemonset:
    useHostNetwork: true
  resources:
    requests:
      memory: 64Mi
      cpu: 50m
    limits:
      memory: 128Mi
      cpu: 100m

# Elasticsearch 配置
elasticsearch:
  enabled: true
  replicas: 3
  minimumMasterNodes: 2
  
  persistence:
    enabled: true
    storageClass: $storage_class
    size: 100Gi
  
  resources:
    requests:
      memory: 1Gi
      cpu: 500m
    limits:
      memory: 2Gi
      cpu: 1000m
EOF
    
    # 部署 Jaeger
    local helm_args=(
        "upgrade" "--install" "jaeger"
        "jaegertracing/jaeger"
        "--namespace" "$namespace"
        "--create-namespace"
        "--values" "$values_file"
        "--wait" "--timeout=15m"
    )
    
    if [[ "$dry_run" == "true" ]]; then
        helm_args+=("--dry-run")
    fi
    
    helm "${helm_args[@]}"
    
    # 清理临时文件
    rm -f "$values_file"
    
    if [[ "$dry_run" != "true" ]]; then
        log_success "Jaeger 部署完成"
    else
        log_info "[DRY RUN] Jaeger 部署模拟完成"
    fi
}

# 部署 Grafana 仪表板
deploy_grafana_dashboards() {
    local namespace="$1"
    local dry_run="$2"
    
    log_info "部署 Grafana 仪表板..."
    
    if [[ "$dry_run" == "true" ]]; then
        log_info "[DRY RUN] Grafana 仪表板部署模拟完成"
        return
    fi
    
    # 等待 Grafana 就绪
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=grafana -n "$namespace" --timeout=300s
    
    # 创建仪表板 ConfigMap
    kubectl create configmap grafana-dashboards \
        --from-file="${PROJECT_ROOT}/kubernetes/monitoring/grafana.yaml" \
        -n "$namespace" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    # 重启 Grafana 以加载仪表板
    kubectl rollout restart deployment/prometheus-grafana -n "$namespace"
    
    log_success "Grafana 仪表板部署完成"
}

# 配置告警规则
setup_alert_rules() {
    local namespace="$1"
    local dry_run="$2"
    
    log_info "配置告警规则..."
    
    if [[ "$dry_run" == "true" ]]; then
        log_info "[DRY RUN] 告警规则配置模拟完成"
        return
    fi
    
    # 创建告警规则
    cat << EOF | kubectl apply -f -
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: nova-proxy-alerts
  namespace: $namespace
  labels:
    app: nova-proxy
    prometheus: kube-prometheus
spec:
  groups:
    - name: nova-proxy.rules
      rules:
        - alert: NovaProxyHighErrorRate
          expr: rate(nova_proxy_requests_total{status=~"5.."}[5m]) / rate(nova_proxy_requests_total[5m]) > 0.05
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "Nova Proxy high error rate"
            description: "Nova Proxy error rate is {{ \$value | humanizePercentage }} for more than 5 minutes."
        
        - alert: NovaProxyHighLatency
          expr: histogram_quantile(0.95, rate(nova_proxy_request_duration_seconds_bucket[5m])) > 1
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "Nova Proxy high latency"
            description: "Nova Proxy 95th percentile latency is {{ \$value }}s for more than 5 minutes."
        
        - alert: NovaProxyDown
          expr: up{job="nova-proxy"} == 0
          for: 1m
          labels:
            severity: critical
          annotations:
            summary: "Nova Proxy is down"
            description: "Nova Proxy has been down for more than 1 minute."
EOF
    
    log_success "告警规则配置完成"
}

# 验证部署
verify_deployment() {
    local namespace="$1"
    
    log_info "验证监控系统部署..."
    
    # 检查 Pod 状态
    log_info "检查 Pod 状态..."
    kubectl get pods -n "$namespace"
    
    # 检查服务状态
    log_info "检查服务状态..."
    kubectl get services -n "$namespace"
    
    # 检查 Ingress 状态
    log_info "检查 Ingress 状态..."
    kubectl get ingress -n "$namespace"
    
    # 检查 Prometheus 目标
    log_info "检查 Prometheus 目标..."
    kubectl port-forward service/prometheus-server 9090:80 -n "$namespace" &
    local port_forward_pid=$!
    sleep 5
    
    if curl -s http://localhost:9090/api/v1/targets | jq -r '.data.activeTargets[] | select(.labels.job=="nova-proxy") | .health' | grep -q "up"; then
        log_success "Nova Proxy 目标状态正常"
    else
        log_warn "Nova Proxy 目标状态异常"
    fi
    
    kill $port_forward_pid 2>/dev/null || true
    
    log_success "监控系统验证完成"
}

# 显示访问信息
show_access_info() {
    local namespace="$1"
    local environment="$2"
    
    log_info "监控系统访问信息:"
    
    echo "=== Prometheus ==="
    echo "URL: https://prometheus.${environment}.nova-proxy.com"
    echo "Port Forward: kubectl port-forward service/prometheus-server 9090:80 -n $namespace"
    
    echo "\n=== Grafana ==="
    echo "URL: https://grafana.${environment}.nova-proxy.com"
    echo "Port Forward: kubectl port-forward service/prometheus-grafana 3000:80 -n $namespace"
    echo "Username: admin"
    echo "Password: $(kubectl get secret prometheus-grafana -n $namespace -o jsonpath='{.data.admin-password}' | base64 -d)"
    
    echo "\n=== Jaeger ==="
    echo "URL: https://jaeger.${environment}.nova-proxy.com"
    echo "Port Forward: kubectl port-forward service/jaeger-query 16686:16686 -n $namespace"
    
    echo "\n=== Alertmanager ==="
    echo "URL: https://alertmanager.${environment}.nova-proxy.com"
    echo "Port Forward: kubectl port-forward service/prometheus-alertmanager 9093:9093 -n $namespace"
}

# 主函数
main() {
    # 默认值
    local environment=""
    local namespace="monitoring"
    local dry_run="false"
    local force="false"
    local deploy_prometheus="false"
    local deploy_grafana="false"
    local deploy_jaeger="false"
    local deploy_alertmanager="false"
    local deploy_node_exporter="false"
    local deploy_all="true"
    local external_url="https://monitoring.nova-proxy.com"
    local storage_class="fast-ssd"
    local retention="15"
    
    # 解析命令行参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -n|--namespace)
                namespace="$2"
                shift 2
                ;;
            -d|--dry-run)
                dry_run="true"
                shift
                ;;
            -f|--force)
                force="true"
                shift
                ;;
            --prometheus)
                deploy_prometheus="true"
                deploy_all="false"
                shift
                ;;
            --grafana)
                deploy_grafana="true"
                deploy_all="false"
                shift
                ;;
            --jaeger)
                deploy_jaeger="true"
                deploy_all="false"
                shift
                ;;
            --alertmanager)
                deploy_alertmanager="true"
                deploy_all="false"
                shift
                ;;
            --node-exporter)
                deploy_node_exporter="true"
                deploy_all="false"
                shift
                ;;
            --all)
                deploy_all="true"
                shift
                ;;
            --external-url)
                external_url="$2"
                shift 2
                ;;
            --storage-class)
                storage_class="$2"
                shift 2
                ;;
            --retention)
                retention="$2"
                shift 2
                ;;
            -*)
                error_exit "未知选项: $1"
                ;;
            *)
                if [[ -z "$environment" ]]; then
                    environment="$1"
                else
                    error_exit "多余的参数: $1"
                fi
                shift
                ;;
        esac
    done
    
    # 验证必需参数
    if [[ -z "$environment" ]]; then
        error_exit "请指定部署环境"
    fi
    
    # 显示部署信息
    log_info "Nova Proxy 监控系统部署开始"
    log_info "环境: $environment"
    log_info "命名空间: $namespace"
    log_info "存储类: $storage_class"
    log_info "数据保留: ${retention} 天"
    log_info "外部 URL: $external_url"
    log_info "日志文件: $LOG_FILE"
    
    if [[ "$dry_run" == "true" ]]; then
        log_warn "干运行模式，不会执行实际部署"
    fi
    
    # 确认部署
    if [[ "$force" != "true" && "$dry_run" != "true" ]]; then
        read -p "确认部署监控系统? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "部署已取消"
            exit 0
        fi
    fi
    
    # 执行部署流程
    check_dependencies
    add_helm_repos
    create_namespace "$namespace"
    
    # 根据选项部署组件
    if [[ "$deploy_all" == "true" || "$deploy_prometheus" == "true" ]]; then
        deploy_prometheus "$namespace" "$environment" "$storage_class" "$retention" "$external_url" "$dry_run"
    fi
    
    if [[ "$deploy_all" == "true" || "$deploy_jaeger" == "true" ]]; then
        deploy_jaeger "$namespace" "$environment" "$storage_class" "$dry_run"
    fi
    
    if [[ "$dry_run" != "true" ]]; then
        deploy_grafana_dashboards "$namespace" "$dry_run"
        setup_alert_rules "$namespace" "$dry_run"
        verify_deployment "$namespace"
        show_access_info "$namespace" "$environment"
    fi
    
    log_success "Nova Proxy 监控系统部署完成!"
    log_info "日志文件: $LOG_FILE"
}

# 执行主函数
main "$@"