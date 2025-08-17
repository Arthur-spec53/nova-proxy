#!/bin/bash

# Nova Proxy 监控脚本
# 用于监控应用性能、健康状态和资源使用情况

set -euo pipefail

# 脚本配置
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_DIR="$PROJECT_ROOT/logs"
REPORT_DIR="$PROJECT_ROOT/reports"

# 默认配置
DEFAULT_ENVIRONMENT="development"
DEFAULT_NAMESPACE="nova-proxy"
DEFAULT_INTERVAL="30"
DEFAULT_DURATION="300"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
}

log_metric() {
    echo -e "${CYAN}[METRIC]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
}

# 显示帮助信息
show_help() {
    cat << EOF
Nova Proxy 监控脚本

用法: $0 <命令> [选项]

命令:
  health                    检查应用健康状态
  metrics                   获取应用指标
  performance               性能测试
  resources                 资源使用情况
  logs                      日志分析
  alerts                    检查告警
  dashboard                 启动监控面板
  report                    生成监控报告
  watch                     实时监控
  benchmark                 基准测试
  trace                     链路追踪
  profile                   性能分析

选项:
  -e, --environment ENV     环境名称 [默认: $DEFAULT_ENVIRONMENT]
  -n, --namespace NS        命名空间 [默认: $DEFAULT_NAMESPACE]
  -i, --interval SEC        监控间隔（秒） [默认: $DEFAULT_INTERVAL]
  -d, --duration SEC        监控持续时间（秒） [默认: $DEFAULT_DURATION]
  -o, --output FILE         输出文件
  -f, --format FORMAT       输出格式 (json|yaml|table) [默认: table]
  -v, --verbose             详细输出
  -h, --help                显示此帮助信息

示例:
  $0 health -e production                    # 检查生产环境健康状态
  $0 metrics -e staging -f json              # 获取 staging 环境指标（JSON 格式）
  $0 watch -e production -i 10 -d 600        # 实时监控生产环境 10 分钟
  $0 performance -e staging                   # 运行性能测试
  $0 report -e production -o report.html     # 生成监控报告

EOF
}

# 解析命令行参数
parse_args() {
    COMMAND=""
    ENVIRONMENT="$DEFAULT_ENVIRONMENT"
    NAMESPACE="$DEFAULT_NAMESPACE"
    INTERVAL="$DEFAULT_INTERVAL"
    DURATION="$DEFAULT_DURATION"
    OUTPUT_FILE=""
    FORMAT="table"
    VERBOSE=false
    EXTRA_ARGS=()

    if [[ $# -eq 0 ]]; then
        show_help
        exit 1
    fi

    COMMAND="$1"
    shift

    while [[ $# -gt 0 ]]; do
        case $1 in
            -e|--environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -n|--namespace)
                NAMESPACE="$2"
                shift 2
                ;;
            -i|--interval)
                INTERVAL="$2"
                shift 2
                ;;
            -d|--duration)
                DURATION="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -f|--format)
                FORMAT="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                EXTRA_ARGS+=("$1")
                shift
                ;;
        esac
    done

    # 设置命名空间
    if [[ "$NAMESPACE" == "$DEFAULT_NAMESPACE" ]]; then
        NAMESPACE="nova-proxy-$ENVIRONMENT"
    fi
}

# 检查依赖
check_dependencies() {
    local missing_deps=()
    local required_commands=("kubectl" "curl" "jq")
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "缺少以下依赖: ${missing_deps[*]}"
        exit 1
    fi
    
    # 检查 Kubernetes 连接
    if ! kubectl cluster-info &> /dev/null; then
        log_error "无法连接到 Kubernetes 集群"
        exit 1
    fi
    
    # 检查命名空间
    if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log_error "命名空间不存在: $NAMESPACE"
        exit 1
    fi
}

# 获取 Pod 信息
get_pods() {
    kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name=nova-proxy -o json
}

# 获取服务信息
get_service_endpoint() {
    local service_name="nova-proxy"
    local port="8081"  # 健康检查端口
    
    # 尝试获取 LoadBalancer 外部 IP
    local external_ip
    external_ip=$(kubectl get service -n "$NAMESPACE" "$service_name" -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "")
    
    if [[ -n "$external_ip" ]]; then
        echo "http://$external_ip:$port"
        return
    fi
    
    # 尝试获取 NodePort
    local node_port
    node_port=$(kubectl get service -n "$NAMESPACE" "$service_name" -o jsonpath='{.spec.ports[?(@.name=="health")].nodePort}' 2>/dev/null || echo "")
    
    if [[ -n "$node_port" ]]; then
        local node_ip
        node_ip=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="ExternalIP")].address}' 2>/dev/null || \
                 kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null)
        if [[ -n "$node_ip" ]]; then
            echo "http://$node_ip:$node_port"
            return
        fi
    fi
    
    # 使用端口转发
    echo "port-forward"
}

# 健康检查
check_health() {
    log_info "检查应用健康状态..."
    
    local pods_json
    pods_json=$(get_pods)
    local pod_count
    pod_count=$(echo "$pods_json" | jq '.items | length')
    
    if [[ "$pod_count" -eq 0 ]]; then
        log_error "没有找到运行中的 Pod"
        return 1
    fi
    
    log_info "找到 $pod_count 个 Pod"
    
    local healthy_pods=0
    local unhealthy_pods=0
    
    # 检查每个 Pod 的健康状态
    for i in $(seq 0 $((pod_count - 1))); do
        local pod_name
        pod_name=$(echo "$pods_json" | jq -r ".items[$i].metadata.name")
        local pod_phase
        pod_phase=$(echo "$pods_json" | jq -r ".items[$i].status.phase")
        local ready_condition
        ready_condition=$(echo "$pods_json" | jq -r ".items[$i].status.conditions[] | select(.type==\"Ready\") | .status")
        
        if [[ "$pod_phase" == "Running" && "$ready_condition" == "True" ]]; then
            log_success "Pod $pod_name: 健康"
            ((healthy_pods++))
            
            # 检查健康检查端点
            if kubectl exec -n "$NAMESPACE" "$pod_name" -- curl -f -s http://localhost:8081/health > /dev/null 2>&1; then
                log_success "Pod $pod_name: 健康检查端点正常"
            else
                log_warning "Pod $pod_name: 健康检查端点异常"
            fi
        else
            log_error "Pod $pod_name: 不健康 (Phase: $pod_phase, Ready: $ready_condition)"
            ((unhealthy_pods++))
        fi
    done
    
    # 输出健康状态摘要
    log_info "健康状态摘要:"
    echo "  总 Pod 数: $pod_count"
    echo "  健康 Pod 数: $healthy_pods"
    echo "  不健康 Pod 数: $unhealthy_pods"
    echo "  健康率: $(( healthy_pods * 100 / pod_count ))%"
    
    if [[ "$unhealthy_pods" -gt 0 ]]; then
        return 1
    fi
    
    return 0
}

# 获取应用指标
get_metrics() {
    log_info "获取应用指标..."
    
    local endpoint
    endpoint=$(get_service_endpoint)
    
    if [[ "$endpoint" == "port-forward" ]]; then
        log_info "使用端口转发获取指标..."
        
        # 启动端口转发
        kubectl port-forward -n "$NAMESPACE" service/nova-proxy 9090:9090 &
        local pf_pid=$!
        
        # 等待端口转发就绪
        sleep 3
        
        # 获取指标
        local metrics
        if metrics=$(curl -s http://localhost:9090/metrics 2>/dev/null); then
            log_success "成功获取指标"
            
            # 解析关键指标
            parse_metrics "$metrics"
        else
            log_error "无法获取指标"
        fi
        
        # 停止端口转发
        kill $pf_pid 2>/dev/null || true
    else
        # 直接访问指标端点
        local metrics_url="${endpoint/8081/9090}/metrics"
        log_info "从 $metrics_url 获取指标..."
        
        local metrics
        if metrics=$(curl -s "$metrics_url" 2>/dev/null); then
            log_success "成功获取指标"
            parse_metrics "$metrics"
        else
            log_error "无法获取指标"
        fi
    fi
}

# 解析指标
parse_metrics() {
    local metrics="$1"
    
    log_info "解析关键指标..."
    
    # HTTP 请求指标
    local total_requests
    total_requests=$(echo "$metrics" | grep -E '^nova_proxy_requests_total' | awk '{sum += $2} END {print sum+0}')
    log_metric "总请求数: $total_requests"
    
    # 错误率
    local error_requests
    error_requests=$(echo "$metrics" | grep -E '^nova_proxy_requests_total.*status=~"5.."' | awk '{sum += $2} END {print sum+0}')
    if [[ "$total_requests" -gt 0 ]]; then
        local error_rate
        error_rate=$(echo "scale=2; $error_requests * 100 / $total_requests" | bc -l 2>/dev/null || echo "0")
        log_metric "错误率: ${error_rate}%"
    fi
    
    # 响应时间
    local avg_response_time
    avg_response_time=$(echo "$metrics" | grep -E '^nova_proxy_request_duration_seconds_sum' | awk '{print $2}' | head -1)
    local request_count
    request_count=$(echo "$metrics" | grep -E '^nova_proxy_request_duration_seconds_count' | awk '{print $2}' | head -1)
    if [[ -n "$avg_response_time" && -n "$request_count" && "$request_count" -gt 0 ]]; then
        local avg_time
        avg_time=$(echo "scale=3; $avg_response_time / $request_count" | bc -l 2>/dev/null || echo "0")
        log_metric "平均响应时间: ${avg_time}s"
    fi
    
    # 连接数
    local active_connections
    active_connections=$(echo "$metrics" | grep -E '^nova_proxy_active_connections' | awk '{print $2}' | head -1)
    if [[ -n "$active_connections" ]]; then
        log_metric "活跃连接数: $active_connections"
    fi
    
    # Go 运行时指标
    local goroutines
    goroutines=$(echo "$metrics" | grep -E '^go_goroutines' | awk '{print $2}' | head -1)
    if [[ -n "$goroutines" ]]; then
        log_metric "Goroutine 数量: $goroutines"
    fi
    
    local heap_size
    heap_size=$(echo "$metrics" | grep -E '^go_memstats_heap_inuse_bytes' | awk '{print $2}' | head -1)
    if [[ -n "$heap_size" ]]; then
        local heap_mb
        heap_mb=$(echo "scale=2; $heap_size / 1024 / 1024" | bc -l 2>/dev/null || echo "0")
        log_metric "堆内存使用: ${heap_mb}MB"
    fi
}

# 性能测试
run_performance_test() {
    log_info "运行性能测试..."
    
    # 检查是否安装了性能测试工具
    if ! command -v hey &> /dev/null; then
        log_warning "hey 工具未安装，尝试安装..."
        if command -v go &> /dev/null; then
            go install github.com/rakyll/hey@latest
        else
            log_error "请安装 hey 工具: https://github.com/rakyll/hey"
            return 1
        fi
    fi
    
    local endpoint
    endpoint=$(get_service_endpoint)
    
    if [[ "$endpoint" == "port-forward" ]]; then
        log_info "使用端口转发进行性能测试..."
        
        # 启动端口转发
        kubectl port-forward -n "$NAMESPACE" service/nova-proxy 8080:8080 &
        local pf_pid=$!
        
        # 等待端口转发就绪
        sleep 3
        
        local test_url="http://localhost:8080/health"
    else
        local test_url="${endpoint/8081/8080}/health"
    fi
    
    log_info "测试 URL: $test_url"
    
    # 运行性能测试
    local test_results
    test_results=$(hey -n 1000 -c 10 -t 30 "$test_url" 2>&1 || true)
    
    # 停止端口转发
    if [[ -n "${pf_pid:-}" ]]; then
        kill $pf_pid 2>/dev/null || true
    fi
    
    # 解析测试结果
    log_info "性能测试结果:"
    echo "$test_results" | grep -E "(Total:|Slowest:|Fastest:|Average:|Requests/sec:)"
}

# 资源使用情况
check_resources() {
    log_info "检查资源使用情况..."
    
    # Pod 资源使用
    if kubectl top pods -n "$NAMESPACE" -l app.kubernetes.io/name=nova-proxy &> /dev/null; then
        log_info "Pod 资源使用情况:"
        kubectl top pods -n "$NAMESPACE" -l app.kubernetes.io/name=nova-proxy
    else
        log_warning "无法获取 Pod 资源使用情况（需要 metrics-server）"
    fi
    
    # 节点资源使用
    if kubectl top nodes &> /dev/null; then
        log_info "节点资源使用情况:"
        kubectl top nodes
    else
        log_warning "无法获取节点资源使用情况（需要 metrics-server）"
    fi
    
    # 存储使用情况
    log_info "存储使用情况:"
    kubectl get pvc -n "$NAMESPACE" 2>/dev/null || log_info "没有找到 PVC"
}

# 日志分析
analyze_logs() {
    log_info "分析应用日志..."
    
    local log_lines="1000"
    if [[ ${#EXTRA_ARGS[@]} -gt 0 ]]; then
        log_lines="${EXTRA_ARGS[0]}"
    fi
    
    log_info "分析最近 $log_lines 行日志..."
    
    # 获取日志
    local logs
    logs=$(kubectl logs -n "$NAMESPACE" -l app.kubernetes.io/name=nova-proxy --tail="$log_lines" 2>/dev/null || echo "")
    
    if [[ -z "$logs" ]]; then
        log_warning "没有找到日志"
        return
    fi
    
    # 分析错误日志
    local error_count
    error_count=$(echo "$logs" | grep -i error | wc -l)
    log_metric "错误日志数量: $error_count"
    
    # 分析警告日志
    local warning_count
    warning_count=$(echo "$logs" | grep -i warning | wc -l)
    log_metric "警告日志数量: $warning_count"
    
    # 分析请求日志
    local request_count
    request_count=$(echo "$logs" | grep -E '(GET|POST|PUT|DELETE|PATCH)' | wc -l)
    log_metric "请求日志数量: $request_count"
    
    # 显示最近的错误
    if [[ "$error_count" -gt 0 ]]; then
        log_warning "最近的错误日志:"
        echo "$logs" | grep -i error | tail -5
    fi
}

# 检查告警
check_alerts() {
    log_info "检查告警状态..."
    
    # 检查 Pod 状态告警
    local pods_json
    pods_json=$(get_pods)
    local pod_count
    pod_count=$(echo "$pods_json" | jq '.items | length')
    
    if [[ "$pod_count" -eq 0 ]]; then
        log_error "[ALERT] 没有运行中的 Pod"
    fi
    
    # 检查重启次数
    for i in $(seq 0 $((pod_count - 1))); do
        local pod_name
        pod_name=$(echo "$pods_json" | jq -r ".items[$i].metadata.name")
        local restart_count
        restart_count=$(echo "$pods_json" | jq -r ".items[$i].status.containerStatuses[0].restartCount")
        
        if [[ "$restart_count" -gt 5 ]]; then
            log_error "[ALERT] Pod $pod_name 重启次数过多: $restart_count"
        fi
    done
    
    # 检查资源使用告警
    if kubectl top pods -n "$NAMESPACE" -l app.kubernetes.io/name=nova-proxy &> /dev/null; then
        local resource_usage
        resource_usage=$(kubectl top pods -n "$NAMESPACE" -l app.kubernetes.io/name=nova-proxy --no-headers)
        
        while IFS= read -r line; do
            local pod_name cpu_usage memory_usage
            read -r pod_name cpu_usage memory_usage <<< "$line"
            
            # 检查 CPU 使用率（假设限制为 1000m）
            local cpu_value
            cpu_value=$(echo "$cpu_usage" | sed 's/m//')
            if [[ "$cpu_value" -gt 800 ]]; then
                log_warning "[ALERT] Pod $pod_name CPU 使用率过高: $cpu_usage"
            fi
            
            # 检查内存使用率（假设限制为 2Gi）
            local memory_value
            memory_value=$(echo "$memory_usage" | sed 's/Mi//')
            if [[ "$memory_value" -gt 1600 ]]; then
                log_warning "[ALERT] Pod $pod_name 内存使用率过高: $memory_usage"
            fi
        done <<< "$resource_usage"
    fi
}

# 实时监控
watch_metrics() {
    log_info "开始实时监控 (间隔: ${INTERVAL}s, 持续: ${DURATION}s)..."
    
    local start_time
    start_time=$(date +%s)
    local end_time
    end_time=$((start_time + DURATION))
    
    while [[ $(date +%s) -lt $end_time ]]; do
        clear
        echo "=== Nova Proxy 实时监控 ==="
        echo "环境: $ENVIRONMENT | 命名空间: $NAMESPACE"
        echo "时间: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "剩余时间: $((end_time - $(date +%s)))s"
        echo ""
        
        # 检查健康状态
        check_health
        echo ""
        
        # 获取指标
        get_metrics
        echo ""
        
        # 检查资源
        check_resources
        echo ""
        
        sleep "$INTERVAL"
    done
    
    log_success "监控完成"
}

# 生成监控报告
generate_report() {
    log_info "生成监控报告..."
    
    local report_file
    if [[ -n "$OUTPUT_FILE" ]]; then
        report_file="$OUTPUT_FILE"
    else
        report_file="$REPORT_DIR/nova-proxy-report-$(date +%Y%m%d_%H%M%S).html"
    fi
    
    mkdir -p "$(dirname "$report_file")"
    
    # 生成 HTML 报告
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Nova Proxy 监控报告</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .metric { margin: 10px 0; }
        .success { color: green; }
        .warning { color: orange; }
        .error { color: red; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Nova Proxy 监控报告</h1>
        <p>生成时间: $(date '+%Y-%m-%d %H:%M:%S')</p>
        <p>环境: $ENVIRONMENT</p>
        <p>命名空间: $NAMESPACE</p>
    </div>
EOF
    
    # 添加健康检查结果
    echo '    <div class="section">' >> "$report_file"
    echo '        <h2>健康检查</h2>' >> "$report_file"
    if check_health &> /dev/null; then
        echo '        <p class="success">✓ 应用健康状态正常</p>' >> "$report_file"
    else
        echo '        <p class="error">✗ 应用健康状态异常</p>' >> "$report_file"
    fi
    echo '    </div>' >> "$report_file"
    
    # 添加资源使用情况
    echo '    <div class="section">' >> "$report_file"
    echo '        <h2>资源使用情况</h2>' >> "$report_file"
    if kubectl top pods -n "$NAMESPACE" -l app.kubernetes.io/name=nova-proxy &> /dev/null; then
        echo '        <table>' >> "$report_file"
        echo '            <tr><th>Pod</th><th>CPU</th><th>内存</th></tr>' >> "$report_file"
        kubectl top pods -n "$NAMESPACE" -l app.kubernetes.io/name=nova-proxy --no-headers | while read -r line; do
            local pod_name cpu_usage memory_usage
            read -r pod_name cpu_usage memory_usage <<< "$line"
            echo "            <tr><td>$pod_name</td><td>$cpu_usage</td><td>$memory_usage</td></tr>" >> "$report_file"
        done
        echo '        </table>' >> "$report_file"
    else
        echo '        <p class="warning">无法获取资源使用情况</p>' >> "$report_file"
    fi
    echo '    </div>' >> "$report_file"
    
    # 结束 HTML
    echo '</body></html>' >> "$report_file"
    
    log_success "监控报告已生成: $report_file"
}

# 主函数
main() {
    parse_args "$@"
    check_dependencies
    
    # 创建必要的目录
    mkdir -p "$LOG_DIR" "$REPORT_DIR"
    
    case $COMMAND in
        health)
            check_health
            ;;
        metrics)
            get_metrics
            ;;
        performance)
            run_performance_test
            ;;
        resources)
            check_resources
            ;;
        logs)
            analyze_logs
            ;;
        alerts)
            check_alerts
            ;;
        watch)
            watch_metrics
            ;;
        report)
            generate_report
            ;;
        *)
            log_error "未知命令: $COMMAND"
            show_help
            exit 1
            ;;
    esac
}

# 执行主函数
main "$@"