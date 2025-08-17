#!/bin/bash

# Nova Proxy 健康检查脚本
# 全面检查系统健康状态

set -euo pipefail

# 脚本配置
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LOG_FILE="/tmp/nova-proxy-health-$(date +%Y%m%d-%H%M%S).log"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 健康状态
HEALTH_STATUS="HEALTHY"
WARNING_COUNT=0
ERROR_COUNT=0

# 日志函数
log() {
    echo -e "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log_info() {
    log "${BLUE}[INFO]${NC} $1"
}

log_warn() {
    log "${YELLOW}[WARN]${NC} $1"
    WARNING_COUNT=$((WARNING_COUNT + 1))
    if [[ "$HEALTH_STATUS" == "HEALTHY" ]]; then
        HEALTH_STATUS="WARNING"
    fi
}

log_error() {
    log "${RED}[ERROR]${NC} $1"
    ERROR_COUNT=$((ERROR_COUNT + 1))
    HEALTH_STATUS="CRITICAL"
}

log_success() {
    log "${GREEN}[OK]${NC} $1"
}

# 显示帮助信息
show_help() {
    cat << EOF
Nova Proxy 健康检查脚本

用法: $0 [选项]

选项:
  -h, --help              显示帮助信息
  -n, --namespace NS      指定命名空间
  -e, --endpoint URL      指定健康检查端点
  -t, --timeout SECONDS  设置超时时间 (默认: 30)
  -v, --verbose          详细输出
  -q, --quiet            静默模式
  --k8s                  检查 Kubernetes 资源
  --monitoring           检查监控系统
  --network              检查网络连接
  --performance          检查性能指标
  --security             检查安全配置
  --all                  执行所有检查 (默认)
  --json                 JSON 格式输出
  --prometheus           输出 Prometheus 指标

示例:
  $0                              # 执行所有健康检查
  $0 --k8s -n nova-proxy-prod    # 检查生产环境 K8s 资源
  $0 --monitoring --json          # 检查监控系统并输出 JSON
  $0 --performance -v             # 详细检查性能指标

EOF
}

# 检查 Kubernetes 资源健康状态
check_k8s_health() {
    local namespace="$1"
    
    log_info "检查 Kubernetes 资源健康状态..."
    
    if [[ -z "$namespace" ]]; then
        log_warn "未指定命名空间，跳过 K8s 检查"
        return
    fi
    
    # 检查命名空间
    if ! kubectl get namespace "$namespace" &> /dev/null; then
        log_error "命名空间 $namespace 不存在"
        return
    fi
    
    # 检查 Deployment
    log_info "检查 Deployment 状态..."
    local deployments
    deployments=$(kubectl get deployment -n "$namespace" -l app.kubernetes.io/name=nova-proxy -o jsonpath='{.items[*].metadata.name}')
    
    if [[ -z "$deployments" ]]; then
        log_error "未找到 Nova Proxy Deployment"
    else
        for deployment in $deployments; do
            local ready_replicas
            local desired_replicas
            ready_replicas=$(kubectl get deployment "$deployment" -n "$namespace" -o jsonpath='{.status.readyReplicas}')
            desired_replicas=$(kubectl get deployment "$deployment" -n "$namespace" -o jsonpath='{.spec.replicas}')
            
            if [[ "$ready_replicas" == "$desired_replicas" ]]; then
                log_success "Deployment $deployment: $ready_replicas/$desired_replicas 副本就绪"
            else
                log_error "Deployment $deployment: $ready_replicas/$desired_replicas 副本就绪"
            fi
        done
    fi
    
    # 检查 Pod 状态
    log_info "检查 Pod 状态..."
    local pods_status
    pods_status=$(kubectl get pods -n "$namespace" -l app.kubernetes.io/name=nova-proxy -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.phase}{"\t"}{.status.containerStatuses[0].ready}{"\n"}{end}')
    
    if [[ -z "$pods_status" ]]; then
        log_error "未找到 Nova Proxy Pod"
    else
        while IFS=$'\t' read -r pod_name phase ready; do
            if [[ "$phase" == "Running" && "$ready" == "true" ]]; then
                log_success "Pod $pod_name: $phase (Ready)"
            else
                log_error "Pod $pod_name: $phase (Ready: $ready)"
            fi
        done <<< "$pods_status"
    fi
    
    # 检查服务
    log_info "检查服务状态..."
    local services
    services=$(kubectl get service -n "$namespace" -l app.kubernetes.io/name=nova-proxy -o jsonpath='{.items[*].metadata.name}')
    
    if [[ -z "$services" ]]; then
        log_error "未找到 Nova Proxy Service"
    else
        for service in $services; do
            local endpoints
            endpoints=$(kubectl get endpoints "$service" -n "$namespace" -o jsonpath='{.subsets[*].addresses[*].ip}' | wc -w)
            
            if [[ "$endpoints" -gt 0 ]]; then
                log_success "Service $service: $endpoints 个端点"
            else
                log_error "Service $service: 无可用端点"
            fi
        done
    fi
    
    # 检查 Ingress
    log_info "检查 Ingress 状态..."
    if kubectl get ingress nova-proxy -n "$namespace" &> /dev/null; then
        local ingress_ready
        ingress_ready=$(kubectl get ingress nova-proxy -n "$namespace" -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
        
        if [[ -n "$ingress_ready" ]]; then
            log_success "Ingress nova-proxy: 负载均衡器 IP $ingress_ready"
        else
            log_warn "Ingress nova-proxy: 负载均衡器 IP 未分配"
        fi
    else
        log_info "未找到 Ingress 资源"
    fi
    
    # 检查 PVC
    log_info "检查持久化卷状态..."
    local pvcs
    pvcs=$(kubectl get pvc -n "$namespace" -l app.kubernetes.io/name=nova-proxy -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.phase}{"\n"}{end}')
    
    if [[ -n "$pvcs" ]]; then
        while IFS=$'\t' read -r pvc_name phase; do
            if [[ "$phase" == "Bound" ]]; then
                log_success "PVC $pvc_name: $phase"
            else
                log_error "PVC $pvc_name: $phase"
            fi
        done <<< "$pvcs"
    fi
}

# 检查应用健康端点
check_app_health() {
    local endpoint="$1"
    local timeout="$2"
    
    log_info "检查应用健康端点..."
    
    if [[ -z "$endpoint" ]]; then
        log_warn "未指定健康检查端点，跳过应用检查"
        return
    fi
    
    # 健康检查端点
    local health_endpoints=(
        "$endpoint/health"
        "$endpoint/health/ready"
        "$endpoint/health/live"
        "$endpoint/metrics"
    )
    
    for health_url in "${health_endpoints[@]}"; do
        log_info "检查端点: $health_url"
        
        local response_code
        local response_time
        
        if response_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$timeout" "$health_url"); then
            response_time=$(curl -s -o /dev/null -w "%{time_total}" --max-time "$timeout" "$health_url")
            
            if [[ "$response_code" == "200" ]]; then
                log_success "端点 $health_url: HTTP $response_code (${response_time}s)"
            else
                log_warn "端点 $health_url: HTTP $response_code (${response_time}s)"
            fi
        else
            log_error "端点 $health_url: 连接失败"
        fi
    done
    
    # 检查 QUIC 端点
    if command -v "curl" &> /dev/null && curl --version | grep -q "HTTP/3"; then
        log_info "检查 QUIC/HTTP3 端点..."
        local quic_url="${endpoint/http:/https:}"
        
        if curl -s --http3 --max-time "$timeout" "$quic_url/health" &> /dev/null; then
            log_success "QUIC 端点可访问"
        else
            log_warn "QUIC 端点不可访问"
        fi
    fi
}

# 检查网络连接
check_network() {
    local namespace="$1"
    
    log_info "检查网络连接..."
    
    # 检查 DNS 解析
    log_info "检查 DNS 解析..."
    local dns_targets=("google.com" "github.com" "registry.nova-proxy.com")
    
    for target in "${dns_targets[@]}"; do
        if nslookup "$target" &> /dev/null; then
            log_success "DNS 解析 $target: 成功"
        else
            log_error "DNS 解析 $target: 失败"
        fi
    done
    
    # 检查外部连接
    log_info "检查外部连接..."
    local external_targets=("8.8.8.8:53" "1.1.1.1:53" "github.com:443")
    
    for target in "${external_targets[@]}"; do
        local host port
        IFS=':' read -r host port <<< "$target"
        
        if timeout 5 bash -c "</dev/tcp/$host/$port"; then
            log_success "外部连接 $target: 成功"
        else
            log_error "外部连接 $target: 失败"
        fi
    done
    
    # 检查集群内部连接
    if [[ -n "$namespace" ]]; then
        log_info "检查集群内部连接..."
        
        # 检查 kube-dns
        if kubectl get service kube-dns -n kube-system &> /dev/null; then
            local dns_ip
            dns_ip=$(kubectl get service kube-dns -n kube-system -o jsonpath='{.spec.clusterIP}')
            
            if timeout 5 bash -c "</dev/tcp/$dns_ip/53"; then
                log_success "集群 DNS $dns_ip:53: 可访问"
            else
                log_error "集群 DNS $dns_ip:53: 不可访问"
            fi
        fi
        
        # 检查服务连接
        local services
        services=$(kubectl get service -n "$namespace" -l app.kubernetes.io/name=nova-proxy -o jsonpath='{.items[*].metadata.name}')
        
        for service in $services; do
            local service_ip port
            service_ip=$(kubectl get service "$service" -n "$namespace" -o jsonpath='{.spec.clusterIP}')
            port=$(kubectl get service "$service" -n "$namespace" -o jsonpath='{.spec.ports[0].port}')
            
            if timeout 5 bash -c "</dev/tcp/$service_ip/$port"; then
                log_success "服务连接 $service ($service_ip:$port): 可访问"
            else
                log_error "服务连接 $service ($service_ip:$port): 不可访问"
            fi
        done
    fi
}

# 检查性能指标
check_performance() {
    local namespace="$1"
    local endpoint="$2"
    
    log_info "检查性能指标..."
    
    # 检查系统资源
    log_info "检查系统资源使用情况..."
    
    # CPU 使用率
    local cpu_usage
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    
    if (( $(echo "$cpu_usage > 80" | bc -l) )); then
        log_error "CPU 使用率过高: ${cpu_usage}%"
    elif (( $(echo "$cpu_usage > 60" | bc -l) )); then
        log_warn "CPU 使用率较高: ${cpu_usage}%"
    else
        log_success "CPU 使用率正常: ${cpu_usage}%"
    fi
    
    # 内存使用率
    local mem_usage
    mem_usage=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
    
    if (( $(echo "$mem_usage > 85" | bc -l) )); then
        log_error "内存使用率过高: ${mem_usage}%"
    elif (( $(echo "$mem_usage > 70" | bc -l) )); then
        log_warn "内存使用率较高: ${mem_usage}%"
    else
        log_success "内存使用率正常: ${mem_usage}%"
    fi
    
    # 磁盘使用率
    local disk_usage
    disk_usage=$(df / | tail -1 | awk '{print $5}' | cut -d'%' -f1)
    
    if (( disk_usage > 90 )); then
        log_error "磁盘使用率过高: ${disk_usage}%"
    elif (( disk_usage > 80 )); then
        log_warn "磁盘使用率较高: ${disk_usage}%"
    else
        log_success "磁盘使用率正常: ${disk_usage}%"
    fi
    
    # 检查 Pod 资源使用
    if [[ -n "$namespace" ]]; then
        log_info "检查 Pod 资源使用情况..."
        
        if command -v "kubectl" &> /dev/null && kubectl top pod -n "$namespace" &> /dev/null; then
            kubectl top pod -n "$namespace" -l app.kubernetes.io/name=nova-proxy | while read -r line; do
                if [[ "$line" != *"NAME"* ]]; then
                    local pod_name cpu_usage mem_usage
                    read -r pod_name cpu_usage mem_usage <<< "$line"
                    
                    log_info "Pod $pod_name: CPU $cpu_usage, Memory $mem_usage"
                fi
            done
        else
            log_warn "无法获取 Pod 资源使用情况"
        fi
    fi
    
    # 检查应用性能指标
    if [[ -n "$endpoint" ]]; then
        log_info "检查应用性能指标..."
        
        # 响应时间测试
        local response_times=()
        for i in {1..5}; do
            local response_time
            response_time=$(curl -s -o /dev/null -w "%{time_total}" --max-time 10 "$endpoint/health" 2>/dev/null || echo "timeout")
            
            if [[ "$response_time" != "timeout" ]]; then
                response_times+=("$response_time")
            fi
        done
        
        if [[ ${#response_times[@]} -gt 0 ]]; then
            local avg_response_time
            avg_response_time=$(printf '%s\n' "${response_times[@]}" | awk '{sum+=$1} END {print sum/NR}')
            
            if (( $(echo "$avg_response_time > 2" | bc -l) )); then
                log_error "平均响应时间过长: ${avg_response_time}s"
            elif (( $(echo "$avg_response_time > 1" | bc -l) )); then
                log_warn "平均响应时间较长: ${avg_response_time}s"
            else
                log_success "平均响应时间正常: ${avg_response_time}s"
            fi
        else
            log_error "无法获取响应时间"
        fi
    fi
}

# 检查监控系统
check_monitoring() {
    local monitoring_namespace="${MONITORING_NAMESPACE:-monitoring}"
    
    log_info "检查监控系统..."
    
    # 检查 Prometheus
    if kubectl get pod -l app.kubernetes.io/name=prometheus -n "$monitoring_namespace" &> /dev/null; then
        local prometheus_pods
        prometheus_pods=$(kubectl get pod -l app.kubernetes.io/name=prometheus -n "$monitoring_namespace" --field-selector=status.phase=Running | wc -l)
        
        if [[ "$prometheus_pods" -gt 1 ]]; then
            log_success "Prometheus: $((prometheus_pods - 1)) 个 Pod 运行中"
        else
            log_error "Prometheus: 无运行中的 Pod"
        fi
    else
        log_warn "未找到 Prometheus"
    fi
    
    # 检查 Grafana
    if kubectl get pod -l app.kubernetes.io/name=grafana -n "$monitoring_namespace" &> /dev/null; then
        local grafana_pods
        grafana_pods=$(kubectl get pod -l app.kubernetes.io/name=grafana -n "$monitoring_namespace" --field-selector=status.phase=Running | wc -l)
        
        if [[ "$grafana_pods" -gt 1 ]]; then
            log_success "Grafana: $((grafana_pods - 1)) 个 Pod 运行中"
        else
            log_error "Grafana: 无运行中的 Pod"
        fi
    else
        log_warn "未找到 Grafana"
    fi
    
    # 检查 Alertmanager
    if kubectl get pod -l app.kubernetes.io/name=alertmanager -n "$monitoring_namespace" &> /dev/null; then
        local alertmanager_pods
        alertmanager_pods=$(kubectl get pod -l app.kubernetes.io/name=alertmanager -n "$monitoring_namespace" --field-selector=status.phase=Running | wc -l)
        
        if [[ "$alertmanager_pods" -gt 1 ]]; then
            log_success "Alertmanager: $((alertmanager_pods - 1)) 个 Pod 运行中"
        else
            log_error "Alertmanager: 无运行中的 Pod"
        fi
    else
        log_warn "未找到 Alertmanager"
    fi
}

# 检查安全配置
check_security() {
    local namespace="$1"
    
    log_info "检查安全配置..."
    
    # 检查 RBAC
    log_info "检查 RBAC 配置..."
    if kubectl get serviceaccount nova-proxy -n "$namespace" &> /dev/null; then
        log_success "ServiceAccount nova-proxy 存在"
    else
        log_warn "ServiceAccount nova-proxy 不存在"
    fi
    
    # 检查网络策略
    log_info "检查网络策略..."
    local network_policies
    network_policies=$(kubectl get networkpolicy -n "$namespace" | wc -l)
    
    if [[ "$network_policies" -gt 1 ]]; then
        log_success "网络策略: $((network_policies - 1)) 个策略"
    else
        log_warn "未配置网络策略"
    fi
    
    # 检查 Pod 安全策略
    log_info "检查 Pod 安全配置..."
    local pods
    pods=$(kubectl get pod -n "$namespace" -l app.kubernetes.io/name=nova-proxy -o jsonpath='{.items[*].metadata.name}')
    
    for pod in $pods; do
        local security_context
        security_context=$(kubectl get pod "$pod" -n "$namespace" -o jsonpath='{.spec.securityContext.runAsNonRoot}')
        
        if [[ "$security_context" == "true" ]]; then
            log_success "Pod $pod: 以非 root 用户运行"
        else
            log_warn "Pod $pod: 可能以 root 用户运行"
        fi
    done
    
    # 检查 TLS 证书
    log_info "检查 TLS 证书..."
    local tls_secrets
    tls_secrets=$(kubectl get secret -n "$namespace" -o jsonpath='{.items[?(@.type=="kubernetes.io/tls")].metadata.name}')
    
    if [[ -n "$tls_secrets" ]]; then
        for secret in $tls_secrets; do
            local cert_expiry
            cert_expiry=$(kubectl get secret "$secret" -n "$namespace" -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -enddate | cut -d= -f2)
            
            local expiry_timestamp
            expiry_timestamp=$(date -d "$cert_expiry" +%s)
            local current_timestamp
            current_timestamp=$(date +%s)
            local days_until_expiry
            days_until_expiry=$(( (expiry_timestamp - current_timestamp) / 86400 ))
            
            if [[ "$days_until_expiry" -lt 7 ]]; then
                log_error "证书 $secret: $days_until_expiry 天后过期"
            elif [[ "$days_until_expiry" -lt 30 ]]; then
                log_warn "证书 $secret: $days_until_expiry 天后过期"
            else
                log_success "证书 $secret: $days_until_expiry 天后过期"
            fi
        done
    else
        log_warn "未找到 TLS 证书"
    fi
}

# 生成健康报告
generate_report() {
    local output_format="$1"
    
    case "$output_format" in
        json)
            cat << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "status": "$HEALTH_STATUS",
  "summary": {
    "warnings": $WARNING_COUNT,
    "errors": $ERROR_COUNT
  },
  "checks": {
    "kubernetes": "$([ $ERROR_COUNT -eq 0 ] && echo 'PASS' || echo 'FAIL')",
    "application": "$([ $ERROR_COUNT -eq 0 ] && echo 'PASS' || echo 'FAIL')",
    "network": "$([ $ERROR_COUNT -eq 0 ] && echo 'PASS' || echo 'FAIL')",
    "performance": "$([ $ERROR_COUNT -eq 0 ] && echo 'PASS' || echo 'FAIL')",
    "monitoring": "$([ $ERROR_COUNT -eq 0 ] && echo 'PASS' || echo 'FAIL')",
    "security": "$([ $ERROR_COUNT -eq 0 ] && echo 'PASS' || echo 'FAIL')"
  }
}
EOF
            ;;
        
        prometheus)
            cat << EOF
# HELP nova_proxy_health_status Nova Proxy health status (0=healthy, 1=warning, 2=critical)
# TYPE nova_proxy_health_status gauge
nova_proxy_health_status{status="$HEALTH_STATUS"} $([ "$HEALTH_STATUS" == "HEALTHY" ] && echo 0 || [ "$HEALTH_STATUS" == "WARNING" ] && echo 1 || echo 2)

# HELP nova_proxy_health_warnings Number of health check warnings
# TYPE nova_proxy_health_warnings counter
nova_proxy_health_warnings $WARNING_COUNT

# HELP nova_proxy_health_errors Number of health check errors
# TYPE nova_proxy_health_errors counter
nova_proxy_health_errors $ERROR_COUNT
EOF
            ;;
        
        *)
            log_info "健康检查总结:"
            echo "状态: $HEALTH_STATUS"
            echo "警告: $WARNING_COUNT"
            echo "错误: $ERROR_COUNT"
            echo "日志: $LOG_FILE"
            ;;
    esac
}

# 主函数
main() {
    # 默认值
    local namespace=""
    local endpoint=""
    local timeout="30"
    local verbose="false"
    local quiet="false"
    local check_k8s="false"
    local check_monitoring="false"
    local check_network="false"
    local check_performance="false"
    local check_security="false"
    local check_all="true"
    local output_format="text"
    
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
            -e|--endpoint)
                endpoint="$2"
                shift 2
                ;;
            -t|--timeout)
                timeout="$2"
                shift 2
                ;;
            -v|--verbose)
                verbose="true"
                shift
                ;;
            -q|--quiet)
                quiet="true"
                shift
                ;;
            --k8s)
                check_k8s="true"
                check_all="false"
                shift
                ;;
            --monitoring)
                check_monitoring="true"
                check_all="false"
                shift
                ;;
            --network)
                check_network="true"
                check_all="false"
                shift
                ;;
            --performance)
                check_performance="true"
                check_all="false"
                shift
                ;;
            --security)
                check_security="true"
                check_all="false"
                shift
                ;;
            --all)
                check_all="true"
                shift
                ;;
            --json)
                output_format="json"
                shift
                ;;
            --prometheus)
                output_format="prometheus"
                shift
                ;;
            -*)
                echo "未知选项: $1" >&2
                exit 1
                ;;
            *)
                echo "多余的参数: $1" >&2
                exit 1
                ;;
        esac
    done
    
    # 静默模式处理
    if [[ "$quiet" == "true" ]]; then
        exec > /dev/null 2>&1
    fi
    
    # 开始健康检查
    if [[ "$quiet" != "true" ]]; then
        log_info "Nova Proxy 健康检查开始"
        log_info "时间戳: $(date)"
        log_info "日志文件: $LOG_FILE"
    fi
    
    # 执行检查
    if [[ "$check_all" == "true" || "$check_k8s" == "true" ]]; then
        check_k8s_health "$namespace"
    fi
    
    if [[ "$check_all" == "true" ]] || [[ -n "$endpoint" ]]; then
        check_app_health "$endpoint" "$timeout"
    fi
    
    if [[ "$check_all" == "true" || "$check_network" == "true" ]]; then
        check_network "$namespace"
    fi
    
    if [[ "$check_all" == "true" || "$check_performance" == "true" ]]; then
        check_performance "$namespace" "$endpoint"
    fi
    
    if [[ "$check_all" == "true" || "$check_monitoring" == "true" ]]; then
        check_monitoring
    fi
    
    if [[ "$check_all" == "true" || "$check_security" == "true" ]]; then
        check_security "$namespace"
    fi
    
    # 生成报告
    generate_report "$output_format"
    
    # 返回适当的退出码
    case "$HEALTH_STATUS" in
        HEALTHY)
            exit 0
            ;;
        WARNING)
            exit 1
            ;;
        CRITICAL)
            exit 2
            ;;
    esac
}

# 执行主函数
main "$@"