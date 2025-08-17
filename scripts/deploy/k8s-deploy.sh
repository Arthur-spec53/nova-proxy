#!/bin/bash

# Nova Proxy Kubernetes 原生部署脚本
# 使用 kubectl 和 kustomize 进行部署

set -euo pipefail

# 脚本配置
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LOG_FILE="/tmp/nova-proxy-k8s-deploy-$(date +%Y%m%d-%H%M%S).log"

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
Nova Proxy Kubernetes 原生部署脚本

用法: $0 [选项] <环境>

环境:
  development    开发环境
  staging        预发布环境
  production     生产环境

选项:
  -h, --help              显示帮助信息
  -v, --version VERSION   指定版本号 (默认: latest)
  -n, --namespace NS      指定命名空间
  -d, --dry-run          干运行模式
  -f, --force            强制部署
  -w, --wait             等待部署完成
  --prune                删除不再需要的资源
  --validate             验证配置文件
  --diff                 显示配置差异

示例:
  $0 staging -v v1.2.3 --wait
  $0 production --dry-run --diff
  $0 development --validate

EOF
}

# 检查依赖
check_dependencies() {
    log_info "检查依赖工具..."
    
    local deps=("kubectl" "kustomize")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            error_exit "缺少依赖工具: $dep"
        fi
    done
    
    # 检查 kubectl 连接
    if ! kubectl cluster-info &> /dev/null; then
        error_exit "无法连接到 Kubernetes 集群"
    fi
    
    log_success "依赖检查完成"
}

# 验证配置文件
validate_configs() {
    local overlay_dir="$1"
    
    log_info "验证配置文件..."
    
    if [[ ! -d "$overlay_dir" ]]; then
        error_exit "配置目录不存在: $overlay_dir"
    fi
    
    # 验证 kustomization.yaml
    local kustomization_file="${overlay_dir}/kustomization.yaml"
    if [[ ! -f "$kustomization_file" ]]; then
        error_exit "kustomization.yaml 不存在: $kustomization_file"
    fi
    
    # 使用 kustomize 验证配置
    if ! kustomize build "$overlay_dir" > /dev/null; then
        error_exit "配置文件验证失败"
    fi
    
    log_success "配置文件验证通过"
}

# 显示配置差异
show_diff() {
    local overlay_dir="$1"
    local namespace="$2"
    
    log_info "显示配置差异..."
    
    # 生成新配置
    local new_config
    new_config=$(kustomize build "$overlay_dir")
    
    # 获取当前配置
    local current_config
    current_config=$(kubectl get all,configmap,secret,pvc,ingress -n "$namespace" -o yaml 2>/dev/null || echo "")
    
    if [[ -n "$current_config" ]]; then
        # 使用临时文件进行差异比较
        local temp_dir
        temp_dir=$(mktemp -d)
        echo "$current_config" > "${temp_dir}/current.yaml"
        echo "$new_config" > "${temp_dir}/new.yaml"
        
        if command -v diff &> /dev/null; then
            diff -u "${temp_dir}/current.yaml" "${temp_dir}/new.yaml" || true
        else
            log_warn "diff 命令不可用，无法显示差异"
        fi
        
        rm -rf "$temp_dir"
    else
        log_info "当前没有部署，将创建新部署"
    fi
}

# 创建命名空间
create_namespace() {
    local namespace="$1"
    
    log_info "创建命名空间: $namespace"
    
    if kubectl get namespace "$namespace" &> /dev/null; then
        log_info "命名空间 $namespace 已存在"
    else
        kubectl create namespace "$namespace"
        
        # 添加标签
        kubectl label namespace "$namespace" \
            app.kubernetes.io/name=nova-proxy \
            app.kubernetes.io/managed-by=kubectl
        
        log_success "命名空间 $namespace 创建成功"
    fi
}

# 应用配置
apply_configs() {
    local overlay_dir="$1"
    local namespace="$2"
    local dry_run="$3"
    local wait="$4"
    local prune="$5"
    
    log_info "应用配置..."
    
    local kubectl_args=("apply" "-k" "$overlay_dir")
    
    if [[ "$dry_run" == "true" ]]; then
        kubectl_args+=("--dry-run=client")
    fi
    
    if [[ "$prune" == "true" ]]; then
        kubectl_args+=("--prune" "-l" "app.kubernetes.io/name=nova-proxy")
    fi
    
    # 执行应用
    kubectl "${kubectl_args[@]}"
    
    if [[ "$dry_run" != "true" ]]; then
        log_success "配置应用完成"
        
        if [[ "$wait" == "true" ]]; then
            wait_for_deployment "$namespace"
        fi
    else
        log_info "[DRY RUN] 配置应用模拟完成"
    fi
}

# 等待部署完成
wait_for_deployment() {
    local namespace="$1"
    
    log_info "等待部署完成..."
    
    # 等待 Deployment 就绪
    if kubectl get deployment nova-proxy -n "$namespace" &> /dev/null; then
        kubectl rollout status deployment/nova-proxy -n "$namespace" --timeout=600s
        log_success "Deployment 部署完成"
    fi
    
    # 等待 StatefulSet 就绪（如果存在）
    if kubectl get statefulset nova-proxy -n "$namespace" &> /dev/null; then
        kubectl rollout status statefulset/nova-proxy -n "$namespace" --timeout=600s
        log_success "StatefulSet 部署完成"
    fi
    
    # 等待 Pod 就绪
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=nova-proxy -n "$namespace" --timeout=300s
    log_success "Pod 就绪完成"
}

# 部署后验证
post_deploy_verification() {
    local namespace="$1"
    local environment="$2"
    
    log_info "执行部署后验证..."
    
    # 检查 Pod 状态
    log_info "检查 Pod 状态..."
    kubectl get pods -l app.kubernetes.io/name=nova-proxy -n "$namespace"
    
    # 检查服务状态
    log_info "检查服务状态..."
    kubectl get services -l app.kubernetes.io/name=nova-proxy -n "$namespace"
    
    # 检查 Ingress 状态
    if kubectl get ingress nova-proxy -n "$namespace" &> /dev/null; then
        log_info "检查 Ingress 状态..."
        kubectl get ingress nova-proxy -n "$namespace"
    fi
    
    # 检查配置
    log_info "检查配置..."
    kubectl get configmap nova-proxy-config -n "$namespace" -o yaml | head -20
    
    # 执行健康检查
    log_info "执行健康检查..."
    local health_check_passed=false
    local max_retries=10
    local retry=0
    
    while [[ $retry -lt $max_retries ]]; do
        if kubectl exec -n "$namespace" deployment/nova-proxy -- curl -f http://localhost:8080/health &> /dev/null; then
            health_check_passed=true
            break
        fi
        
        retry=$((retry + 1))
        log_warn "健康检查失败，重试 $retry/$max_retries"
        sleep 10
    done
    
    if [[ "$health_check_passed" == "true" ]]; then
        log_success "健康检查通过"
    else
        log_error "健康检查失败"
        
        # 显示 Pod 日志
        log_info "显示 Pod 日志..."
        kubectl logs -l app.kubernetes.io/name=nova-proxy -n "$namespace" --tail=50
        
        return 1
    fi
    
    log_success "部署后验证完成"
}

# 清理资源
cleanup_resources() {
    local namespace="$1"
    
    log_info "清理旧资源..."
    
    # 清理失败的 Pod
    kubectl delete pods --field-selector=status.phase=Failed -n "$namespace" 2>/dev/null || true
    
    # 清理已完成的 Job
    kubectl delete jobs --field-selector=status.conditions[0].type=Complete -n "$namespace" 2>/dev/null || true
    
    log_success "资源清理完成"
}

# 显示部署状态
show_deployment_status() {
    local namespace="$1"
    
    log_info "部署状态概览:"
    
    echo "=== Pods ==="
    kubectl get pods -l app.kubernetes.io/name=nova-proxy -n "$namespace" -o wide
    
    echo "\n=== Services ==="
    kubectl get services -l app.kubernetes.io/name=nova-proxy -n "$namespace"
    
    echo "\n=== Ingress ==="
    kubectl get ingress -n "$namespace" 2>/dev/null || echo "No ingress found"
    
    echo "\n=== ConfigMaps ==="
    kubectl get configmaps -l app.kubernetes.io/name=nova-proxy -n "$namespace"
    
    echo "\n=== Secrets ==="
    kubectl get secrets -l app.kubernetes.io/name=nova-proxy -n "$namespace"
    
    echo "\n=== Events ==="
    kubectl get events -n "$namespace" --sort-by='.lastTimestamp' | tail -10
}

# 主函数
main() {
    # 默认值
    local environment=""
    local version="latest"
    local namespace=""
    local dry_run="false"
    local force="false"
    local wait="false"
    local prune="false"
    local validate="false"
    local show_diff="false"
    
    # 解析命令行参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--version)
                version="$2"
                shift 2
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
            -w|--wait)
                wait="true"
                shift
                ;;
            --prune)
                prune="true"
                shift
                ;;
            --validate)
                validate="true"
                shift
                ;;
            --diff)
                show_diff="true"
                shift
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
    
    # 设置默认命名空间
    if [[ -z "$namespace" ]]; then
        namespace="nova-proxy-$environment"
    fi
    
    # 设置配置目录
    local overlay_dir="${PROJECT_ROOT}/kubernetes/overlays/${environment}"
    
    # 显示部署信息
    log_info "Nova Proxy Kubernetes 部署开始"
    log_info "环境: $environment"
    log_info "版本: $version"
    log_info "命名空间: $namespace"
    log_info "配置目录: $overlay_dir"
    log_info "日志文件: $LOG_FILE"
    
    if [[ "$dry_run" == "true" ]]; then
        log_warn "干运行模式，不会执行实际部署"
    fi
    
    # 执行部署流程
    check_dependencies
    validate_configs "$overlay_dir"
    
    if [[ "$validate" == "true" ]]; then
        log_success "配置验证完成"
        exit 0
    fi
    
    if [[ "$show_diff" == "true" ]]; then
        show_diff "$overlay_dir" "$namespace"
    fi
    
    # 确认部署
    if [[ "$force" != "true" && "$dry_run" != "true" ]]; then
        read -p "确认部署? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "部署已取消"
            exit 0
        fi
    fi
    
    create_namespace "$namespace"
    apply_configs "$overlay_dir" "$namespace" "$dry_run" "$wait" "$prune"
    
    if [[ "$dry_run" != "true" ]]; then
        post_deploy_verification "$namespace" "$environment"
        cleanup_resources "$namespace"
        show_deployment_status "$namespace"
    fi
    
    log_success "Nova Proxy Kubernetes 部署完成!"
    log_info "日志文件: $LOG_FILE"
}

# 执行主函数
main "$@"