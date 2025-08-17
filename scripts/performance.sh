#!/bin/bash

# Nova Proxy 性能优化脚本
# 用于分析和优化应用性能

set -euo pipefail

# 脚本配置
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PERF_DIR="$PROJECT_ROOT/performance"
REPORTS_DIR="$PERF_DIR/reports"

# 默认配置
DEFAULT_ENVIRONMENT="development"
DEFAULT_NAMESPACE="nova-proxy"
DEFAULT_DURATION="60s"
DEFAULT_CONCURRENCY="10"
DEFAULT_RPS="100"

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

log_debug() {
    if [[ "${VERBOSE:-false}" == "true" ]]; then
        echo -e "${PURPLE}[DEBUG]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
    fi
}

log_perf() {
    echo -e "${CYAN}[PERF]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
}

# 显示帮助信息
show_help() {
    cat << EOF
Nova Proxy 性能优化脚本

用法: $0 <命令> [选项]

命令:
  benchmark                 运行基准测试
  load-test                 负载测试
  stress-test               压力测试
  profile                   性能分析
  optimize                  性能优化
  monitor                   实时监控
  analyze                   分析性能数据
  compare                   比较测试结果
  report                    生成性能报告
  tune                      自动调优

选项:
  -e, --environment ENV     环境名称 [默认: $DEFAULT_ENVIRONMENT]
  -n, --namespace NS        命名空间 [默认: $DEFAULT_NAMESPACE]
  -d, --duration DURATION   测试持续时间 [默认: $DEFAULT_DURATION]
  -c, --concurrency NUM     并发数 [默认: $DEFAULT_CONCURRENCY]
  -r, --rps NUM             每秒请求数 [默认: $DEFAULT_RPS]
  -u, --url URL             测试 URL
  -o, --output DIR          输出目录 [默认: $REPORTS_DIR]
  -p, --protocol PROTO      协议 (http1, http2, quic) [默认: http2]
  -t, --test-type TYPE      测试类型 (cpu, memory, network, disk)
  -v, --verbose             详细输出
  -h, --help                显示此帮助信息

示例:
  $0 benchmark -e production -d 300s -c 50        # 生产环境基准测试
  $0 load-test -e staging -r 200 -d 120s          # Staging 负载测试
  $0 stress-test -e development -c 100            # 开发环境压力测试
  $0 profile -e production -t cpu                 # CPU 性能分析
  $0 optimize -e staging                          # 自动优化
  $0 compare report1.json report2.json            # 比较测试结果

EOF
}

# 解析命令行参数
parse_args() {
    COMMAND=""
    ENVIRONMENT="$DEFAULT_ENVIRONMENT"
    NAMESPACE="$DEFAULT_NAMESPACE"
    DURATION="$DEFAULT_DURATION"
    CONCURRENCY="$DEFAULT_CONCURRENCY"
    RPS="$DEFAULT_RPS"
    TEST_URL=""
    OUTPUT_DIR="$REPORTS_DIR"
    PROTOCOL="http2"
    TEST_TYPE=""
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
            -d|--duration)
                DURATION="$2"
                shift 2
                ;;
            -c|--concurrency)
                CONCURRENCY="$2"
                shift 2
                ;;
            -r|--rps)
                RPS="$2"
                shift 2
                ;;
            -u|--url)
                TEST_URL="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -p|--protocol)
                PROTOCOL="$2"
                shift 2
                ;;
            -t|--test-type)
                TEST_TYPE="$2"
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
    
    # 检查性能测试工具
    local perf_tools=("hey" "wrk" "ab")
    local found_tool=""
    
    for tool in "${perf_tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            found_tool="$tool"
            break
        fi
    done
    
    if [[ -z "$found_tool" ]]; then
        log_warning "未找到性能测试工具，尝试安装 hey..."
        if command -v go &> /dev/null; then
            go install github.com/rakyll/hey@latest
        else
            log_error "需要安装性能测试工具: hey, wrk, 或 ab"
            missing_deps+=("hey")
        fi
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "缺少以下依赖: ${missing_deps[*]}"
        exit 1
    fi
    
    # 检查 Kubernetes 连接
    if ! kubectl cluster-info &> /dev/null; then
        log_error "无法连接到 Kubernetes 集群"
        exit 1
    fi
}

# 设置性能测试环境
setup_performance_env() {
    local timestamp
    timestamp=$(date +"%Y%m%d_%H%M%S")
    PERF_SESSION_DIR="$OUTPUT_DIR/perf-session-$timestamp"
    
    mkdir -p "$PERF_SESSION_DIR"
    log_info "性能测试会话目录: $PERF_SESSION_DIR"
    
    # 获取测试 URL
    if [[ -z "$TEST_URL" ]]; then
        TEST_URL=$(get_service_url)
    fi
    
    log_info "测试 URL: $TEST_URL"
}

# 获取服务 URL
get_service_url() {
    local service_type
    service_type=$(kubectl get service nova-proxy -n "$NAMESPACE" -o jsonpath='{.spec.type}' 2>/dev/null || echo "")
    
    case $service_type in
        "LoadBalancer")
            local external_ip
            external_ip=$(kubectl get service nova-proxy -n "$NAMESPACE" -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "")
            if [[ -n "$external_ip" ]]; then
                echo "http://$external_ip:8080"
            else
                log_warning "LoadBalancer IP 未就绪，使用端口转发"
                setup_port_forward
                echo "http://localhost:8080"
            fi
            ;;
        "NodePort")
            local node_ip node_port
            node_ip=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="ExternalIP")].address}' 2>/dev/null || \
                     kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
            node_port=$(kubectl get service nova-proxy -n "$NAMESPACE" -o jsonpath='{.spec.ports[0].nodePort}')
            echo "http://$node_ip:$node_port"
            ;;
        *)
            log_info "使用端口转发访问服务"
            setup_port_forward
            echo "http://localhost:8080"
            ;;
    esac
}

# 设置端口转发
setup_port_forward() {
    local pod_name
    pod_name=$(kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name=nova-proxy -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    
    if [[ -n "$pod_name" ]]; then
        log_info "设置端口转发: $pod_name:8080 -> localhost:8080"
        kubectl port-forward -n "$NAMESPACE" "$pod_name" 8080:8080 &
        PORT_FORWARD_PID=$!
        sleep 2
        
        # 注册清理函数
        trap 'cleanup_port_forward' EXIT
    else
        log_error "没有找到可用的 Pod"
        exit 1
    fi
}

# 清理端口转发
cleanup_port_forward() {
    if [[ -n "${PORT_FORWARD_PID:-}" ]]; then
        log_info "清理端口转发进程: $PORT_FORWARD_PID"
        kill $PORT_FORWARD_PID 2>/dev/null || true
    fi
}

# 运行基准测试
run_benchmark() {
    log_info "运行基准测试..."
    
    local test_endpoints=(
        "/health"
        "/metrics"
        "/api/v1/status"
    )
    
    local results_file="$PERF_SESSION_DIR/benchmark-results.json"
    echo '{"tests": []}' > "$results_file"
    
    for endpoint in "${test_endpoints[@]}"; do
        log_info "测试端点: $endpoint"
        
        local url="$TEST_URL$endpoint"
        local output_file="$PERF_SESSION_DIR/benchmark-$endpoint.txt"
        
        # 使用 hey 进行测试
        if command -v hey &> /dev/null; then
            hey -n 1000 -c "$CONCURRENCY" -o csv "$url" > "$output_file" 2>&1
            
            # 解析结果
            local avg_time p95_time p99_time rps_achieved
            avg_time=$(tail -n +2 "$output_file" | awk -F',' '{sum+=$2; count++} END {print sum/count}')
            p95_time=$(tail -n +2 "$output_file" | awk -F',' '{print $2}' | sort -n | awk 'NR==int(NR*0.95)')
            p99_time=$(tail -n +2 "$output_file" | awk -F',' '{print $2}' | sort -n | awk 'NR==int(NR*0.99)')
            rps_achieved=$(echo "1000 / $avg_time" | bc -l)
            
            # 保存结果到 JSON
            local test_result
            test_result=$(jq -n \
                --arg endpoint "$endpoint" \
                --arg avg_time "$avg_time" \
                --arg p95_time "$p95_time" \
                --arg p99_time "$p99_time" \
                --arg rps "$rps_achieved" \
                '{
                    endpoint: $endpoint,
                    avg_response_time: ($avg_time | tonumber),
                    p95_response_time: ($p95_time | tonumber),
                    p99_response_time: ($p99_time | tonumber),
                    requests_per_second: ($rps | tonumber)
                }')
            
            # 添加到结果文件
            jq --argjson test "$test_result" '.tests += [$test]' "$results_file" > "$results_file.tmp" && mv "$results_file.tmp" "$results_file"
            
            log_perf "$endpoint - 平均响应时间: ${avg_time}ms, P95: ${p95_time}ms, P99: ${p99_time}ms, RPS: $rps_achieved"
        fi
    done
    
    log_success "基准测试完成，结果保存到: $results_file"
}

# 负载测试
run_load_test() {
    log_info "运行负载测试..."
    
    local results_file="$PERF_SESSION_DIR/load-test-results.json"
    local output_file="$PERF_SESSION_DIR/load-test-output.txt"
    
    # 预热
    log_info "预热阶段..."
    if command -v hey &> /dev/null; then
        hey -n 100 -c 5 "$TEST_URL/health" > /dev/null 2>&1
    fi
    
    sleep 5
    
    # 开始监控资源使用
    start_resource_monitoring &
    MONITOR_PID=$!
    
    # 运行负载测试
    log_info "开始负载测试 - 持续时间: $DURATION, 并发数: $CONCURRENCY, RPS: $RPS"
    
    if command -v hey &> /dev/null; then
        hey -z "$DURATION" -c "$CONCURRENCY" -q "$RPS" -o csv "$TEST_URL/api/v1/proxy" > "$output_file" 2>&1
    elif command -v wrk &> /dev/null; then
        wrk -t"$CONCURRENCY" -c"$CONCURRENCY" -d"$DURATION" --latency "$TEST_URL/api/v1/proxy" > "$output_file" 2>&1
    fi
    
    # 停止资源监控
    kill $MONITOR_PID 2>/dev/null || true
    
    # 分析结果
    analyze_load_test_results "$output_file" "$results_file"
    
    log_success "负载测试完成，结果保存到: $results_file"
}

# 压力测试
run_stress_test() {
    log_info "运行压力测试..."
    
    local results_file="$PERF_SESSION_DIR/stress-test-results.json"
    local phases=("10" "25" "50" "100" "200")
    
    echo '{"phases": []}' > "$results_file"
    
    for concurrency in "${phases[@]}"; do
        log_info "压力测试阶段 - 并发数: $concurrency"
        
        local phase_output="$PERF_SESSION_DIR/stress-phase-$concurrency.txt"
        
        # 运行测试
        if command -v hey &> /dev/null; then
            hey -n 1000 -c "$concurrency" "$TEST_URL/api/v1/proxy" > "$phase_output" 2>&1
        fi
        
        # 检查错误率
        local error_rate
        error_rate=$(grep -o "Error distribution" -A 10 "$phase_output" | grep -o "[0-9]*" | head -1 || echo "0")
        
        # 如果错误率超过 5%，停止测试
        if [[ "$error_rate" -gt 50 ]]; then
            log_warning "错误率过高 ($error_rate/1000)，停止压力测试"
            break
        fi
        
        # 保存阶段结果
        local phase_result
        phase_result=$(jq -n \
            --arg concurrency "$concurrency" \
            --arg error_rate "$error_rate" \
            '{
                concurrency: ($concurrency | tonumber),
                error_rate: ($error_rate | tonumber),
                timestamp: now
            }')
        
        jq --argjson phase "$phase_result" '.phases += [$phase]' "$results_file" > "$results_file.tmp" && mv "$results_file.tmp" "$results_file"
        
        log_perf "并发数 $concurrency - 错误率: $error_rate/1000"
        
        # 等待系统恢复
        sleep 10
    done
    
    log_success "压力测试完成，结果保存到: $results_file"
}

# 性能分析
run_profiling() {
    log_info "运行性能分析..."
    
    local pod_name
    pod_name=$(kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name=nova-proxy -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    
    if [[ -z "$pod_name" ]]; then
        log_error "没有找到可用的 Pod"
        return 1
    fi
    
    case $TEST_TYPE in
        "cpu")
            profile_cpu "$pod_name"
            ;;
        "memory")
            profile_memory "$pod_name"
            ;;
        "goroutine")
            profile_goroutines "$pod_name"
            ;;
        *)
            log_info "运行所有性能分析..."
            profile_cpu "$pod_name"
            profile_memory "$pod_name"
            profile_goroutines "$pod_name"
            ;;
    esac
}

# CPU 性能分析
profile_cpu() {
    local pod_name="$1"
    log_info "CPU 性能分析..."
    
    # 启动 CPU 分析
    kubectl exec -n "$NAMESPACE" "$pod_name" -- curl -s "http://localhost:6060/debug/pprof/profile?seconds=30" > "$PERF_SESSION_DIR/cpu-profile.pprof"
    
    # 如果有 go tool pprof，生成报告
    if command -v go &> /dev/null; then
        go tool pprof -text "$PERF_SESSION_DIR/cpu-profile.pprof" > "$PERF_SESSION_DIR/cpu-profile.txt" 2>/dev/null || true
        go tool pprof -svg "$PERF_SESSION_DIR/cpu-profile.pprof" > "$PERF_SESSION_DIR/cpu-profile.svg" 2>/dev/null || true
    fi
    
    log_success "CPU 性能分析完成"
}

# 内存性能分析
profile_memory() {
    local pod_name="$1"
    log_info "内存性能分析..."
    
    # 获取堆内存分析
    kubectl exec -n "$NAMESPACE" "$pod_name" -- curl -s "http://localhost:6060/debug/pprof/heap" > "$PERF_SESSION_DIR/heap-profile.pprof"
    
    # 获取内存分配分析
    kubectl exec -n "$NAMESPACE" "$pod_name" -- curl -s "http://localhost:6060/debug/pprof/allocs" > "$PERF_SESSION_DIR/allocs-profile.pprof"
    
    # 生成报告
    if command -v go &> /dev/null; then
        go tool pprof -text "$PERF_SESSION_DIR/heap-profile.pprof" > "$PERF_SESSION_DIR/heap-profile.txt" 2>/dev/null || true
        go tool pprof -text "$PERF_SESSION_DIR/allocs-profile.pprof" > "$PERF_SESSION_DIR/allocs-profile.txt" 2>/dev/null || true
    fi
    
    log_success "内存性能分析完成"
}

# Goroutine 分析
profile_goroutines() {
    local pod_name="$1"
    log_info "Goroutine 分析..."
    
    # 获取 goroutine 信息
    kubectl exec -n "$NAMESPACE" "$pod_name" -- curl -s "http://localhost:6060/debug/pprof/goroutine" > "$PERF_SESSION_DIR/goroutine-profile.pprof"
    
    # 生成报告
    if command -v go &> /dev/null; then
        go tool pprof -text "$PERF_SESSION_DIR/goroutine-profile.pprof" > "$PERF_SESSION_DIR/goroutine-profile.txt" 2>/dev/null || true
    fi
    
    log_success "Goroutine 分析完成"
}

# 资源监控
start_resource_monitoring() {
    local monitor_file="$PERF_SESSION_DIR/resource-usage.csv"
    
    echo "timestamp,cpu_usage,memory_usage,network_rx,network_tx" > "$monitor_file"
    
    while true; do
        local timestamp cpu_usage memory_usage
        timestamp=$(date +%s)
        
        # 获取 Pod 资源使用情况
        if kubectl top pods -n "$NAMESPACE" -l app.kubernetes.io/name=nova-proxy --no-headers &> /dev/null; then
            local resource_data
            resource_data=$(kubectl top pods -n "$NAMESPACE" -l app.kubernetes.io/name=nova-proxy --no-headers | head -1)
            cpu_usage=$(echo "$resource_data" | awk '{print $2}' | sed 's/m//')
            memory_usage=$(echo "$resource_data" | awk '{print $3}' | sed 's/Mi//')
        else
            cpu_usage="0"
            memory_usage="0"
        fi
        
        echo "$timestamp,$cpu_usage,$memory_usage,0,0" >> "$monitor_file"
        sleep 5
    done
}

# 分析负载测试结果
analyze_load_test_results() {
    local output_file="$1"
    local results_file="$2"
    
    if [[ ! -f "$output_file" ]]; then
        log_error "输出文件不存在: $output_file"
        return 1
    fi
    
    # 解析 hey 输出
    if grep -q "Summary:" "$output_file"; then
        local total_requests successful_requests failed_requests
        local avg_time min_time max_time p50_time p95_time p99_time
        local rps_achieved
        
        total_requests=$(grep "Total:" "$output_file" | awk '{print $2}')
        successful_requests=$(grep "Successful:" "$output_file" | awk '{print $2}' || echo "$total_requests")
        failed_requests=$((total_requests - successful_requests))
        
        avg_time=$(grep "Average:" "$output_file" | awk '{print $2}' | sed 's/secs//')
        min_time=$(grep "Fastest:" "$output_file" | awk '{print $2}' | sed 's/secs//')
        max_time=$(grep "Slowest:" "$output_file" | awk '{print $2}' | sed 's/secs//')
        
        rps_achieved=$(grep "Requests/sec:" "$output_file" | awk '{print $2}')
        
        # 创建结果 JSON
        jq -n \
            --arg total "$total_requests" \
            --arg successful "$successful_requests" \
            --arg failed "$failed_requests" \
            --arg avg_time "$avg_time" \
            --arg min_time "$min_time" \
            --arg max_time "$max_time" \
            --arg rps "$rps_achieved" \
            --arg duration "$DURATION" \
            --arg concurrency "$CONCURRENCY" \
            '{
                test_config: {
                    duration: $duration,
                    concurrency: ($concurrency | tonumber),
                    target_rps: '$RPS'
                },
                results: {
                    total_requests: ($total | tonumber),
                    successful_requests: ($successful | tonumber),
                    failed_requests: ($failed | tonumber),
                    success_rate: (($successful | tonumber) / ($total | tonumber) * 100),
                    avg_response_time: ($avg_time | tonumber),
                    min_response_time: ($min_time | tonumber),
                    max_response_time: ($max_time | tonumber),
                    requests_per_second: ($rps | tonumber)
                },
                timestamp: now
            }' > "$results_file"
    fi
}

# 性能优化建议
run_optimization() {
    log_info "分析性能并提供优化建议..."
    
    local recommendations_file="$PERF_SESSION_DIR/optimization-recommendations.json"
    local recommendations=()
    
    # 检查资源使用情况
    if kubectl top pods -n "$NAMESPACE" -l app.kubernetes.io/name=nova-proxy --no-headers &> /dev/null; then
        local resource_data
        resource_data=$(kubectl top pods -n "$NAMESPACE" -l app.kubernetes.io/name=nova-proxy --no-headers | head -1)
        local cpu_usage memory_usage
        cpu_usage=$(echo "$resource_data" | awk '{print $2}' | sed 's/m//')
        memory_usage=$(echo "$resource_data" | awk '{print $3}' | sed 's/Mi//')
        
        # CPU 优化建议
        if [[ "$cpu_usage" -gt 800 ]]; then
            recommendations+=("CPU 使用率过高 (${cpu_usage}m)，建议增加副本数或优化代码")
        elif [[ "$cpu_usage" -lt 100 ]]; then
            recommendations+=("CPU 使用率较低 (${cpu_usage}m)，可以考虑减少资源请求")
        fi
        
        # 内存优化建议
        if [[ "$memory_usage" -gt 1000 ]]; then
            recommendations+=("内存使用率过高 (${memory_usage}Mi)，建议检查内存泄漏或增加内存限制")
        fi
    fi
    
    # 检查副本数
    local current_replicas desired_replicas
    current_replicas=$(kubectl get deployment nova-proxy -n "$NAMESPACE" -o jsonpath='{.status.replicas}' 2>/dev/null || echo "1")
    desired_replicas=$(kubectl get deployment nova-proxy -n "$NAMESPACE" -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "1")
    
    if [[ "$current_replicas" -lt "$desired_replicas" ]]; then
        recommendations+=("当前副本数 ($current_replicas) 少于期望副本数 ($desired_replicas)，检查 Pod 状态")
    fi
    
    # 检查 HPA
    if kubectl get hpa -n "$NAMESPACE" &> /dev/null; then
        recommendations+=("已配置 HPA，监控自动扩缩容行为")
    else
        recommendations+=("建议配置 HPA 以实现自动扩缩容")
    fi
    
    # 生成建议报告
    local recommendations_json
    recommendations_json=$(printf '%s\n' "${recommendations[@]}" | jq -R . | jq -s .)
    
    jq -n \
        --argjson recommendations "$recommendations_json" \
        '{
            timestamp: now,
            recommendations: $recommendations,
            next_steps: [
                "运行负载测试验证性能",
                "监控关键指标",
                "根据建议调整配置",
                "重新测试验证改进"
            ]
        }' > "$recommendations_file"
    
    log_success "优化建议已生成: $recommendations_file"
    
    # 显示建议
    for recommendation in "${recommendations[@]}"; do
        log_perf "建议: $recommendation"
    done
}

# 生成性能报告
generate_performance_report() {
    log_info "生成性能报告..."
    
    local report_file="$OUTPUT_DIR/nova-proxy-performance-report-$(date +%Y%m%d_%H%M%S).html"
    
    # 收集所有测试结果
    local test_files=()
    if [[ -d "$PERF_SESSION_DIR" ]]; then
        mapfile -t test_files < <(find "$PERF_SESSION_DIR" -name "*.json" -type f)
    fi
    
    # 生成 HTML 报告
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Nova Proxy 性能报告</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .metric { display: inline-block; margin: 10px; padding: 10px; background-color: #f9f9f9; border-radius: 3px; }
        .good { color: green; }
        .warning { color: orange; }
        .error { color: red; }
        pre { background-color: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .chart { width: 100%; height: 300px; background-color: #f9f9f9; border: 1px solid #ddd; }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="header">
        <h1>Nova Proxy 性能报告</h1>
        <p>生成时间: $(date)</p>
        <p>环境: $ENVIRONMENT</p>
        <p>命名空间: $NAMESPACE</p>
    </div>
    
    <div class="section">
        <h2>测试概览</h2>
        <div class="metric">
            <strong>测试持续时间:</strong> $DURATION
        </div>
        <div class="metric">
            <strong>并发数:</strong> $CONCURRENCY
        </div>
        <div class="metric">
            <strong>目标 RPS:</strong> $RPS
        </div>
        <div class="metric">
            <strong>协议:</strong> $PROTOCOL
        </div>
    </div>
EOF
    
    # 添加测试结果
    for test_file in "${test_files[@]}"; do
        local test_name
        test_name=$(basename "$test_file" .json)
        
        echo "    <div class=\"section\">" >> "$report_file"
        echo "        <h2>$test_name</h2>" >> "$report_file"
        echo "        <pre>" >> "$report_file"
        jq . "$test_file" >> "$report_file" 2>/dev/null || echo "无法解析测试结果" >> "$report_file"
        echo "        </pre>" >> "$report_file"
        echo "    </div>" >> "$report_file"
    done
    
    # 结束 HTML
    cat >> "$report_file" << EOF
    
    <div class="section">
        <h2>性能建议</h2>
        <ul>
            <li>监控关键性能指标（响应时间、吞吐量、错误率）</li>
            <li>根据负载情况调整副本数和资源限制</li>
            <li>配置 HPA 实现自动扩缩容</li>
            <li>优化数据库查询和缓存策略</li>
            <li>使用连接池和请求复用</li>
            <li>定期进行性能测试和优化</li>
        </ul>
    </div>
</body>
</html>
EOF
    
    log_success "性能报告已生成: $report_file"
}

# 主函数
main() {
    parse_args "$@"
    check_dependencies
    setup_performance_env
    
    case $COMMAND in
        benchmark)
            run_benchmark
            ;;
        load-test)
            run_load_test
            ;;
        stress-test)
            run_stress_test
            ;;
        profile)
            run_profiling
            ;;
        optimize)
            run_optimization
            ;;
        analyze)
            analyze_performance_data
            ;;
        report)
            generate_performance_report
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