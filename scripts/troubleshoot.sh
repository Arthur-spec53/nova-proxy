#!/bin/bash

# Nova Proxy 故障排除脚本
# 用于诊断和解决常见问题

set -euo pipefail

# 脚本配置
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_DIR="$PROJECT_ROOT/logs"
DIAG_DIR="$PROJECT_ROOT/diagnostics"

# 默认配置
DEFAULT_ENVIRONMENT="development"
DEFAULT_NAMESPACE="nova-proxy"

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

log_fix() {
    echo -e "${CYAN}[FIX]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
}

# 显示帮助信息
show_help() {
    cat << EOF
Nova Proxy 故障排除脚本

用法: $0 <命令> [选项]

命令:
  diagnose                  全面诊断
  pods                      Pod 问题诊断
  network                   网络问题诊断
  storage                   存储问题诊断
  performance               性能问题诊断
  logs                      日志问题诊断
  config                    配置问题诊断
  security                  安全问题诊断
  connectivity              连接性测试
  resources                 资源问题诊断
  fix-common                修复常见问题
  collect-info              收集诊断信息
  generate-report           生成诊断报告

选项:
  -e, --environment ENV     环境名称 [默认: $DEFAULT_ENVIRONMENT]
  -n, --namespace NS        命名空间 [默认: $DEFAULT_NAMESPACE]
  -o, --output DIR          输出目录 [默认: $DIAG_DIR]
  -f, --fix                 自动修复问题
  -v, --verbose             详细输出
  -h, --help                显示此帮助信息

示例:
  $0 diagnose -e production                 # 全面诊断生产环境
  $0 pods -e staging -v                     # 详细诊断 staging 环境的 Pod 问题
  $0 network -e production                  # 诊断生产环境网络问题
  $0 fix-common -e development -f           # 自动修复开发环境常见问题
  $0 collect-info -e production -o /tmp     # 收集生产环境诊断信息

EOF
}

# 解析命令行参数
parse_args() {
    COMMAND=""
    ENVIRONMENT="$DEFAULT_ENVIRONMENT"
    NAMESPACE="$DEFAULT_NAMESPACE"
    OUTPUT_DIR="$DIAG_DIR"
    AUTO_FIX=false
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
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -f|--fix)
                AUTO_FIX=true
                shift
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
    local required_commands=("kubectl" "helm" "curl" "jq" "dig")
    
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
}

# 创建诊断目录
setup_diagnostics() {
    local timestamp
    timestamp=$(date +"%Y%m%d_%H%M%S")
    DIAG_SESSION_DIR="$OUTPUT_DIR/nova-proxy-diag-$timestamp"
    
    mkdir -p "$DIAG_SESSION_DIR"
    log_info "诊断会话目录: $DIAG_SESSION_DIR"
}

# 全面诊断
run_full_diagnosis() {
    log_info "开始全面诊断..."
    
    local issues_found=0
    
    # 检查命名空间
    if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log_error "命名空间不存在: $NAMESPACE"
        ((issues_found++))
        
        if [[ "$AUTO_FIX" == "true" ]]; then
            log_fix "创建命名空间: $NAMESPACE"
            kubectl create namespace "$NAMESPACE"
        fi
    else
        log_success "命名空间存在: $NAMESPACE"
    fi
    
    # 诊断各个组件
    diagnose_pods && log_success "Pod 诊断完成" || ((issues_found++))
    diagnose_network && log_success "网络诊断完成" || ((issues_found++))
    diagnose_storage && log_success "存储诊断完成" || ((issues_found++))
    diagnose_config && log_success "配置诊断完成" || ((issues_found++))
    diagnose_resources && log_success "资源诊断完成" || ((issues_found++))
    
    log_info "诊断完成，发现 $issues_found 个问题"
    return $issues_found
}

# Pod 问题诊断
diagnose_pods() {
    log_info "诊断 Pod 问题..."
    
    local pods_json
    pods_json=$(kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name=nova-proxy -o json 2>/dev/null || echo '{"items":[]}')
    local pod_count
    pod_count=$(echo "$pods_json" | jq '.items | length')
    
    if [[ "$pod_count" -eq 0 ]]; then
        log_error "没有找到 Pod"
        
        # 检查 Deployment
        if kubectl get deployment nova-proxy -n "$NAMESPACE" &> /dev/null; then
            log_info "Deployment 存在，检查副本数..."
            local desired_replicas current_replicas
            desired_replicas=$(kubectl get deployment nova-proxy -n "$NAMESPACE" -o jsonpath='{.spec.replicas}')
            current_replicas=$(kubectl get deployment nova-proxy -n "$NAMESPACE" -o jsonpath='{.status.replicas}')
            
            log_info "期望副本数: $desired_replicas, 当前副本数: ${current_replicas:-0}"
            
            if [[ "$AUTO_FIX" == "true" && "${current_replicas:-0}" -eq 0 ]]; then
                log_fix "重启 Deployment"
                kubectl rollout restart deployment nova-proxy -n "$NAMESPACE"
            fi
        else
            log_error "Deployment 不存在"
        fi
        
        return 1
    fi
    
    log_info "找到 $pod_count 个 Pod"
    
    local issues=0
    
    # 检查每个 Pod
    for i in $(seq 0 $((pod_count - 1))); do
        local pod_name phase ready_condition restart_count
        pod_name=$(echo "$pods_json" | jq -r ".items[$i].metadata.name")
        phase=$(echo "$pods_json" | jq -r ".items[$i].status.phase")
        ready_condition=$(echo "$pods_json" | jq -r ".items[$i].status.conditions[] | select(.type==\"Ready\") | .status")
        restart_count=$(echo "$pods_json" | jq -r ".items[$i].status.containerStatuses[0].restartCount")
        
        log_info "检查 Pod: $pod_name"
        log_debug "  Phase: $phase"
        log_debug "  Ready: $ready_condition"
        log_debug "  Restart Count: $restart_count"
        
        # 检查 Pod 状态
        if [[ "$phase" != "Running" ]]; then
            log_error "Pod $pod_name 状态异常: $phase"
            ((issues++))
            
            # 获取 Pod 事件
            log_info "获取 Pod 事件..."
            kubectl describe pod "$pod_name" -n "$NAMESPACE" | grep -A 10 "Events:" || true
            
            # 检查容器状态
            local container_state
            container_state=$(echo "$pods_json" | jq -r ".items[$i].status.containerStatuses[0].state | keys[0]")
            log_debug "  Container State: $container_state"
            
            if [[ "$container_state" == "waiting" ]]; then
                local waiting_reason
                waiting_reason=$(echo "$pods_json" | jq -r ".items[$i].status.containerStatuses[0].state.waiting.reason")
                log_error "容器等待中: $waiting_reason"
                
                case $waiting_reason in
                    "ImagePullBackOff"|"ErrImagePull")
                        log_error "镜像拉取失败"
                        if [[ "$AUTO_FIX" == "true" ]]; then
                            log_fix "删除 Pod 以重新拉取镜像"
                            kubectl delete pod "$pod_name" -n "$NAMESPACE"
                        fi
                        ;;
                    "CrashLoopBackOff")
                        log_error "容器崩溃循环"
                        log_info "查看容器日志..."
                        kubectl logs "$pod_name" -n "$NAMESPACE" --tail=50 || true
                        ;;
                esac
            fi
        elif [[ "$ready_condition" != "True" ]]; then
            log_warning "Pod $pod_name 未就绪"
            ((issues++))
            
            # 检查就绪探针
            log_info "检查就绪探针..."
            kubectl describe pod "$pod_name" -n "$NAMESPACE" | grep -A 5 "Readiness:" || true
        else
            log_success "Pod $pod_name 状态正常"
        fi
        
        # 检查重启次数
        if [[ "$restart_count" -gt 5 ]]; then
            log_warning "Pod $pod_name 重启次数过多: $restart_count"
            ((issues++))
            
            # 查看最近的日志
            log_info "查看最近的重启日志..."
            kubectl logs "$pod_name" -n "$NAMESPACE" --previous --tail=20 2>/dev/null || true
        fi
        
        # 保存 Pod 描述信息
        if [[ -n "${DIAG_SESSION_DIR:-}" ]]; then
            kubectl describe pod "$pod_name" -n "$NAMESPACE" > "$DIAG_SESSION_DIR/pod-$pod_name-describe.txt"
            kubectl logs "$pod_name" -n "$NAMESPACE" --tail=1000 > "$DIAG_SESSION_DIR/pod-$pod_name-logs.txt" 2>/dev/null || true
        fi
    done
    
    return $issues
}

# 网络问题诊断
diagnose_network() {
    log_info "诊断网络问题..."
    
    local issues=0
    
    # 检查服务
    if kubectl get service nova-proxy -n "$NAMESPACE" &> /dev/null; then
        log_success "服务存在: nova-proxy"
        
        # 检查服务端点
        local endpoints
        endpoints=$(kubectl get endpoints nova-proxy -n "$NAMESPACE" -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null || echo "")
        
        if [[ -n "$endpoints" ]]; then
            log_success "服务端点正常: $endpoints"
        else
            log_error "服务没有端点"
            ((issues++))
        fi
        
        # 检查服务端口
        local service_ports
        service_ports=$(kubectl get service nova-proxy -n "$NAMESPACE" -o jsonpath='{.spec.ports[*].port}' 2>/dev/null || echo "")
        log_info "服务端口: $service_ports"
        
    else
        log_error "服务不存在: nova-proxy"
        ((issues++))
    fi
    
    # 检查 Ingress
    if kubectl get ingress -n "$NAMESPACE" &> /dev/null; then
        local ingress_count
        ingress_count=$(kubectl get ingress -n "$NAMESPACE" --no-headers | wc -l)
        log_info "找到 $ingress_count 个 Ingress"
        
        # 检查 Ingress 状态
        kubectl get ingress -n "$NAMESPACE" -o wide
    else
        log_info "没有找到 Ingress"
    fi
    
    # 检查网络策略
    if kubectl get networkpolicy -n "$NAMESPACE" &> /dev/null; then
        local netpol_count
        netpol_count=$(kubectl get networkpolicy -n "$NAMESPACE" --no-headers | wc -l)
        log_info "找到 $netpol_count 个网络策略"
        
        if [[ "$netpol_count" -gt 0 ]]; then
            log_info "网络策略可能影响连接性，请检查规则"
            kubectl get networkpolicy -n "$NAMESPACE" -o wide
        fi
    fi
    
    # DNS 解析测试
    log_info "测试 DNS 解析..."
    local pod_name
    pod_name=$(kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name=nova-proxy -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    
    if [[ -n "$pod_name" ]]; then
        # 测试内部 DNS
        if kubectl exec -n "$NAMESPACE" "$pod_name" -- nslookup kubernetes.default.svc.cluster.local &> /dev/null; then
            log_success "内部 DNS 解析正常"
        else
            log_error "内部 DNS 解析失败"
            ((issues++))
        fi
        
        # 测试外部 DNS
        if kubectl exec -n "$NAMESPACE" "$pod_name" -- nslookup google.com &> /dev/null; then
            log_success "外部 DNS 解析正常"
        else
            log_warning "外部 DNS 解析失败"
        fi
    fi
    
    return $issues
}

# 存储问题诊断
diagnose_storage() {
    log_info "诊断存储问题..."
    
    local issues=0
    
    # 检查 PVC
    local pvc_count
    pvc_count=$(kubectl get pvc -n "$NAMESPACE" --no-headers 2>/dev/null | wc -l || echo "0")
    
    if [[ "$pvc_count" -gt 0 ]]; then
        log_info "找到 $pvc_count 个 PVC"
        
        # 检查 PVC 状态
        while IFS= read -r pvc_line; do
            local pvc_name status volume capacity access_modes storage_class age
            read -r pvc_name status volume capacity access_modes storage_class age <<< "$pvc_line"
            
            if [[ "$status" == "Bound" ]]; then
                log_success "PVC $pvc_name: $status ($capacity)"
            else
                log_error "PVC $pvc_name: $status"
                ((issues++))
                
                # 获取 PVC 事件
                kubectl describe pvc "$pvc_name" -n "$NAMESPACE" | grep -A 10 "Events:" || true
            fi
        done < <(kubectl get pvc -n "$NAMESPACE" --no-headers 2>/dev/null || true)
    else
        log_info "没有找到 PVC"
    fi
    
    # 检查存储类
    log_info "检查可用存储类..."
    kubectl get storageclass
    
    # 检查 Pod 挂载
    local pod_name
    pod_name=$(kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name=nova-proxy -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    
    if [[ -n "$pod_name" ]]; then
        log_info "检查 Pod 存储挂载..."
        kubectl describe pod "$pod_name" -n "$NAMESPACE" | grep -A 10 "Mounts:" || true
        
        # 检查磁盘使用情况
        log_info "检查磁盘使用情况..."
        kubectl exec -n "$NAMESPACE" "$pod_name" -- df -h 2>/dev/null || log_warning "无法获取磁盘使用情况"
    fi
    
    return $issues
}

# 配置问题诊断
diagnose_config() {
    log_info "诊断配置问题..."
    
    local issues=0
    
    # 检查 ConfigMap
    local cm_count
    cm_count=$(kubectl get configmap -n "$NAMESPACE" --no-headers 2>/dev/null | wc -l || echo "0")
    
    if [[ "$cm_count" -gt 0 ]]; then
        log_info "找到 $cm_count 个 ConfigMap"
        kubectl get configmap -n "$NAMESPACE"
    else
        log_warning "没有找到 ConfigMap"
    fi
    
    # 检查 Secret
    local secret_count
    secret_count=$(kubectl get secret -n "$NAMESPACE" --no-headers 2>/dev/null | wc -l || echo "0")
    
    if [[ "$secret_count" -gt 0 ]]; then
        log_info "找到 $secret_count 个 Secret"
        kubectl get secret -n "$NAMESPACE"
    else
        log_warning "没有找到 Secret"
    fi
    
    # 检查环境变量
    local pod_name
    pod_name=$(kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name=nova-proxy -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    
    if [[ -n "$pod_name" ]]; then
        log_info "检查环境变量..."
        kubectl exec -n "$NAMESPACE" "$pod_name" -- env | grep -E "^NOVA_" | head -10 || true
    fi
    
    # 检查 Helm 发布
    if helm list -n "$NAMESPACE" | grep -q nova-proxy; then
        log_success "Helm 发布存在"
        
        # 检查 Helm 状态
        local helm_status
        helm_status=$(helm status nova-proxy -n "$NAMESPACE" -o json | jq -r '.info.status')
        
        if [[ "$helm_status" == "deployed" ]]; then
            log_success "Helm 发布状态: $helm_status"
        else
            log_error "Helm 发布状态异常: $helm_status"
            ((issues++))
        fi
    else
        log_error "Helm 发布不存在"
        ((issues++))
    fi
    
    return $issues
}

# 资源问题诊断
diagnose_resources() {
    log_info "诊断资源问题..."
    
    local issues=0
    
    # 检查节点资源
    if kubectl top nodes &> /dev/null; then
        log_info "节点资源使用情况:"
        kubectl top nodes
    else
        log_warning "无法获取节点资源使用情况（需要 metrics-server）"
    fi
    
    # 检查 Pod 资源
    if kubectl top pods -n "$NAMESPACE" -l app.kubernetes.io/name=nova-proxy &> /dev/null; then
        log_info "Pod 资源使用情况:"
        kubectl top pods -n "$NAMESPACE" -l app.kubernetes.io/name=nova-proxy
        
        # 检查资源限制
        local pod_name
        pod_name=$(kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name=nova-proxy -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
        
        if [[ -n "$pod_name" ]]; then
            log_info "检查资源限制..."
            kubectl describe pod "$pod_name" -n "$NAMESPACE" | grep -A 10 "Limits:" || true
            kubectl describe pod "$pod_name" -n "$NAMESPACE" | grep -A 10 "Requests:" || true
        fi
    else
        log_warning "无法获取 Pod 资源使用情况（需要 metrics-server）"
    fi
    
    # 检查资源配额
    if kubectl get resourcequota -n "$NAMESPACE" &> /dev/null; then
        log_info "资源配额:"
        kubectl describe resourcequota -n "$NAMESPACE"
    fi
    
    # 检查限制范围
    if kubectl get limitrange -n "$NAMESPACE" &> /dev/null; then
        log_info "限制范围:"
        kubectl describe limitrange -n "$NAMESPACE"
    fi
    
    return $issues
}

# 连接性测试
test_connectivity() {
    log_info "测试连接性..."
    
    local pod_name
    pod_name=$(kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name=nova-proxy -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    
    if [[ -z "$pod_name" ]]; then
        log_error "没有找到可用的 Pod 进行连接性测试"
        return 1
    fi
    
    # 测试内部连接
    log_info "测试内部服务连接..."
    if kubectl exec -n "$NAMESPACE" "$pod_name" -- curl -f -s http://localhost:8081/health &> /dev/null; then
        log_success "内部健康检查端点正常"
    else
        log_error "内部健康检查端点异常"
    fi
    
    # 测试服务连接
    log_info "测试服务连接..."
    if kubectl exec -n "$NAMESPACE" "$pod_name" -- curl -f -s http://nova-proxy:8081/health &> /dev/null; then
        log_success "服务连接正常"
    else
        log_error "服务连接异常"
    fi
    
    # 测试外部连接
    log_info "测试外部连接..."
    if kubectl exec -n "$NAMESPACE" "$pod_name" -- curl -f -s --connect-timeout 5 http://httpbin.org/status/200 &> /dev/null; then
        log_success "外部连接正常"
    else
        log_warning "外部连接异常"
    fi
}

# 修复常见问题
fix_common_issues() {
    log_info "修复常见问题..."
    
    local fixes_applied=0
    
    # 重启失败的 Pod
    local failed_pods
    failed_pods=$(kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name=nova-proxy --field-selector=status.phase=Failed -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
    
    if [[ -n "$failed_pods" ]]; then
        log_fix "删除失败的 Pod: $failed_pods"
        kubectl delete pods $failed_pods -n "$NAMESPACE"
        ((fixes_applied++))
    fi
    
    # 重启崩溃循环的 Pod
    local crash_pods
    crash_pods=$(kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name=nova-proxy -o json | jq -r '.items[] | select(.status.containerStatuses[]?.state.waiting?.reason == "CrashLoopBackOff") | .metadata.name' 2>/dev/null || echo "")
    
    if [[ -n "$crash_pods" ]]; then
        log_fix "删除崩溃循环的 Pod: $crash_pods"
        kubectl delete pods $crash_pods -n "$NAMESPACE"
        ((fixes_applied++))
    fi
    
    # 清理已完成的 Job
    local completed_jobs
    completed_jobs=$(kubectl get jobs -n "$NAMESPACE" --field-selector=status.successful=1 -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
    
    if [[ -n "$completed_jobs" ]]; then
        log_fix "清理已完成的 Job: $completed_jobs"
        kubectl delete jobs $completed_jobs -n "$NAMESPACE"
        ((fixes_applied++))
    fi
    
    # 重启 Deployment（如果 Pod 数量为 0）
    local current_replicas
    current_replicas=$(kubectl get deployment nova-proxy -n "$NAMESPACE" -o jsonpath='{.status.replicas}' 2>/dev/null || echo "0")
    
    if [[ "${current_replicas:-0}" -eq 0 ]]; then
        log_fix "重启 Deployment"
        kubectl rollout restart deployment nova-proxy -n "$NAMESPACE"
        ((fixes_applied++))
    fi
    
    log_info "应用了 $fixes_applied 个修复"
}

# 收集诊断信息
collect_diagnostic_info() {
    log_info "收集诊断信息..."
    
    setup_diagnostics
    
    # 收集集群信息
    log_info "收集集群信息..."
    kubectl cluster-info > "$DIAG_SESSION_DIR/cluster-info.txt"
    kubectl version > "$DIAG_SESSION_DIR/version.txt"
    kubectl get nodes -o wide > "$DIAG_SESSION_DIR/nodes.txt"
    
    # 收集命名空间信息
    log_info "收集命名空间信息..."
    kubectl describe namespace "$NAMESPACE" > "$DIAG_SESSION_DIR/namespace.txt"
    kubectl get all -n "$NAMESPACE" -o wide > "$DIAG_SESSION_DIR/resources.txt"
    
    # 收集 Pod 信息
    log_info "收集 Pod 信息..."
    kubectl get pods -n "$NAMESPACE" -o yaml > "$DIAG_SESSION_DIR/pods.yaml"
    
    # 收集日志
    log_info "收集日志..."
    kubectl logs -n "$NAMESPACE" -l app.kubernetes.io/name=nova-proxy --tail=1000 > "$DIAG_SESSION_DIR/application-logs.txt" 2>/dev/null || true
    
    # 收集事件
    log_info "收集事件..."
    kubectl get events -n "$NAMESPACE" --sort-by='.lastTimestamp' > "$DIAG_SESSION_DIR/events.txt"
    
    # 收集 Helm 信息
    if helm list -n "$NAMESPACE" | grep -q nova-proxy; then
        log_info "收集 Helm 信息..."
        helm status nova-proxy -n "$NAMESPACE" > "$DIAG_SESSION_DIR/helm-status.txt"
        helm get all nova-proxy -n "$NAMESPACE" > "$DIAG_SESSION_DIR/helm-release.yaml"
    fi
    
    # 创建摘要
    cat > "$DIAG_SESSION_DIR/summary.txt" << EOF
Nova Proxy 诊断信息摘要
生成时间: $(date)
环境: $ENVIRONMENT
命名空间: $NAMESPACE
Kubernetes 版本: $(kubectl version --short --client)
集群: $(kubectl config current-context)

文件说明:
- cluster-info.txt: 集群基本信息
- nodes.txt: 节点信息
- namespace.txt: 命名空间详情
- resources.txt: 所有资源列表
- pods.yaml: Pod 详细配置
- application-logs.txt: 应用日志
- events.txt: 事件列表
- helm-status.txt: Helm 发布状态
- helm-release.yaml: Helm 发布配置
EOF
    
    log_success "诊断信息已收集到: $DIAG_SESSION_DIR"
}

# 生成诊断报告
generate_diagnostic_report() {
    log_info "生成诊断报告..."
    
    local report_file="$OUTPUT_DIR/nova-proxy-diagnostic-report-$(date +%Y%m%d_%H%M%S).html"
    
    # 运行诊断
    local diagnosis_result
    diagnosis_result=$(run_full_diagnosis 2>&1 || true)
    
    # 生成 HTML 报告
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Nova Proxy 诊断报告</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .success { color: green; }
        .warning { color: orange; }
        .error { color: red; }
        .info { color: blue; }
        pre { background-color: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Nova Proxy 诊断报告</h1>
        <p>生成时间: $(date)</p>
        <p>环境: $ENVIRONMENT</p>
        <p>命名空间: $NAMESPACE</p>
    </div>
    
    <div class="section">
        <h2>诊断结果</h2>
        <pre>$diagnosis_result</pre>
    </div>
    
    <div class="section">
        <h2>建议操作</h2>
        <ul>
            <li>检查 Pod 日志以获取详细错误信息</li>
            <li>验证配置文件和环境变量</li>
            <li>确认网络连接和 DNS 解析</li>
            <li>检查资源限制和配额</li>
            <li>运行连接性测试</li>
        </ul>
    </div>
EOF
    
    # 添加资源信息
    if kubectl get all -n "$NAMESPACE" &> /dev/null; then
        echo '    <div class="section">' >> "$report_file"
        echo '        <h2>资源状态</h2>' >> "$report_file"
        echo '        <pre>' >> "$report_file"
        kubectl get all -n "$NAMESPACE" -o wide >> "$report_file" 2>/dev/null || true
        echo '        </pre>' >> "$report_file"
        echo '    </div>' >> "$report_file"
    fi
    
    # 结束 HTML
    echo '</body></html>' >> "$report_file"
    
    log_success "诊断报告已生成: $report_file"
}

# 主函数
main() {
    parse_args "$@"
    check_dependencies
    
    # 创建输出目录
    mkdir -p "$OUTPUT_DIR"
    
    case $COMMAND in
        diagnose)
            run_full_diagnosis
            ;;
        pods)
            diagnose_pods
            ;;
        network)
            diagnose_network
            ;;
        storage)
            diagnose_storage
            ;;
        config)
            diagnose_config
            ;;
        resources)
            diagnose_resources
            ;;
        connectivity)
            test_connectivity
            ;;
        fix-common)
            fix_common_issues
            ;;
        collect-info)
            collect_diagnostic_info
            ;;
        generate-report)
            generate_diagnostic_report
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