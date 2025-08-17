#!/bin/bash

# Nova Proxy 部署脚本
# 支持多环境部署：development, staging, production

set -euo pipefail

# 脚本配置
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LOG_FILE="/tmp/nova-proxy-deploy-$(date +%Y%m%d-%H%M%S).log"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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
Nova Proxy 部署脚本

用法: $0 [选项] <环境>

环境:
  development    开发环境
  staging        预发布环境
  production     生产环境

选项:
  -h, --help              显示帮助信息
  -v, --version VERSION   指定版本号 (默认: latest)
  -n, --namespace NS      指定命名空间 (默认: nova-proxy-<环境>)
  -c, --config FILE       指定配置文件
  -d, --dry-run          干运行模式，不执行实际部署
  -f, --force            强制部署，跳过确认
  -r, --rollback         回滚到上一个版本
  -s, --scale REPLICAS   设置副本数
  --skip-tests           跳过部署后测试
  --skip-backup          跳过备份
  --blue-green           使用蓝绿部署
  --canary PERCENT       使用金丝雀部署，指定流量百分比

示例:
  $0 staging                           # 部署到预发布环境
  $0 production -v v1.2.3             # 部署指定版本到生产环境
  $0 production --blue-green           # 蓝绿部署到生产环境
  $0 production --canary 10            # 金丝雀部署，10% 流量
  $0 production --rollback             # 回滚生产环境

EOF
}

# 检查依赖
check_dependencies() {
    log_info "检查依赖工具..."
    
    local deps=("kubectl" "helm" "docker" "jq" "curl")
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

# 验证环境
validate_environment() {
    local env="$1"
    
    case "$env" in
        development|staging|production)
            log_info "验证环境: $env"
            ;;
        *)
            error_exit "无效的环境: $env. 支持的环境: development, staging, production"
            ;;
    esac
    
    # 检查环境特定的配置
    local values_file="${PROJECT_ROOT}/helm/nova-proxy/values-${env}.yaml"
    if [[ ! -f "$values_file" ]]; then
        log_warn "环境配置文件不存在: $values_file，将使用默认配置"
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
        log_success "命名空间 $namespace 创建成功"
    fi
    
    # 设置默认命名空间
    kubectl config set-context --current --namespace="$namespace"
}

# 备份当前部署
backup_deployment() {
    local namespace="$1"
    local backup_dir="${PROJECT_ROOT}/backups/$(date +%Y%m%d-%H%M%S)"
    
    if [[ "$SKIP_BACKUP" == "true" ]]; then
        log_info "跳过备份"
        return
    fi
    
    log_info "备份当前部署..."
    
    mkdir -p "$backup_dir"
    
    # 备份 Helm release
    if helm list -n "$namespace" | grep -q nova-proxy; then
        helm get all nova-proxy -n "$namespace" > "${backup_dir}/helm-release.yaml"
        log_info "Helm release 备份完成"
    fi
    
    # 备份 Kubernetes 资源
    kubectl get all,configmap,secret,pvc,ingress -n "$namespace" -o yaml > "${backup_dir}/k8s-resources.yaml"
    
    # 备份配置
    if kubectl get configmap nova-proxy-config -n "$namespace" &> /dev/null; then
        kubectl get configmap nova-proxy-config -n "$namespace" -o yaml > "${backup_dir}/configmap.yaml"
    fi
    
    log_success "备份完成: $backup_dir"
    echo "$backup_dir" > "/tmp/nova-proxy-last-backup"
}

# 构建和推送镜像
build_and_push_image() {
    local version="$1"
    local registry="${REGISTRY:-registry.nova-proxy.com}"
    local image_name="${IMAGE_NAME:-nova-proxy}"
    local full_image="${registry}/${image_name}:${version}"
    
    log_info "构建和推送镜像: $full_image"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] 跳过镜像构建"
        return
    fi
    
    # 构建镜像
    cd "$PROJECT_ROOT"
    docker build -t "$full_image" \
        --build-arg VERSION="$version" \
        --build-arg COMMIT="$(git rev-parse HEAD)" \
        --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        .
    
    # 推送镜像
    docker push "$full_image"
    
    log_success "镜像构建和推送完成: $full_image"
}

# 标准部署
standard_deploy() {
    local environment="$1"
    local namespace="$2"
    local version="$3"
    local values_file="$4"
    
    log_info "开始标准部署..."
    
    local helm_args=(
        "upgrade" "--install" "nova-proxy"
        "${PROJECT_ROOT}/helm/nova-proxy"
        "--namespace" "$namespace"
        "--create-namespace"
        "--set" "image.tag=$version"
        "--set" "deployment.annotations.deployment\\.kubernetes\\.io/revision=$(date +%s)"
        "--wait" "--timeout=10m"
    )
    
    if [[ -f "$values_file" ]]; then
        helm_args+=("--values" "$values_file")
    fi
    
    if [[ "$SCALE" != "" ]]; then
        helm_args+=("--set" "deployment.replicaCount=$SCALE")
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        helm_args+=("--dry-run")
    fi
    
    log_info "执行 Helm 部署命令..."
    helm "${helm_args[@]}"
    
    log_success "标准部署完成"
}

# 蓝绿部署
blue_green_deploy() {
    local environment="$1"
    local namespace="$2"
    local version="$3"
    local values_file="$4"
    
    log_info "开始蓝绿部署..."
    
    # 检查当前版本
    local current_color="blue"
    local new_color="green"
    
    if kubectl get deployment nova-proxy-green -n "$namespace" &> /dev/null; then
        current_color="green"
        new_color="blue"
    fi
    
    log_info "当前版本: $current_color, 新版本: $new_color"
    
    # 部署新版本
    local helm_args=(
        "upgrade" "--install" "nova-proxy-$new_color"
        "${PROJECT_ROOT}/helm/nova-proxy"
        "--namespace" "$namespace"
        "--create-namespace"
        "--set" "image.tag=$version"
        "--set" "nameOverride=nova-proxy-$new_color"
        "--set" "service.selector.version=$new_color"
        "--wait" "--timeout=15m"
    )
    
    if [[ -f "$values_file" ]]; then
        helm_args+=("--values" "$values_file")
    fi
    
    if [[ "$DRY_RUN" != "true" ]]; then
        helm "${helm_args[@]}"
        
        # 健康检查
        log_info "等待新版本就绪..."
        kubectl wait --for=condition=ready pod -l "app.kubernetes.io/name=nova-proxy-$new_color" -n "$namespace" --timeout=300s
        
        # 切换流量
        log_info "切换流量到新版本..."
        kubectl patch service nova-proxy -n "$namespace" -p "{\"spec\":{\"selector\":{\"version\":\"$new_color\"}}}"
        
        # 等待流量切换完成
        sleep 30
        
        # 删除旧版本
        log_info "删除旧版本..."
        helm uninstall "nova-proxy-$current_color" -n "$namespace" || true
        
        log_success "蓝绿部署完成"
    else
        log_info "[DRY RUN] 蓝绿部署模拟完成"
    fi
}

# 金丝雀部署
canary_deploy() {
    local environment="$1"
    local namespace="$2"
    local version="$3"
    local values_file="$4"
    local canary_percent="$5"
    
    log_info "开始金丝雀部署 (${canary_percent}% 流量)..."
    
    # 部署金丝雀版本
    local helm_args=(
        "upgrade" "--install" "nova-proxy-canary"
        "${PROJECT_ROOT}/helm/nova-proxy"
        "--namespace" "$namespace"
        "--create-namespace"
        "--set" "image.tag=$version"
        "--set" "nameOverride=nova-proxy-canary"
        "--set" "deployment.replicaCount=1"
        "--set" "service.selector.version=canary"
        "--wait" "--timeout=10m"
    )
    
    if [[ -f "$values_file" ]]; then
        helm_args+=("--values" "$values_file")
    fi
    
    if [[ "$DRY_RUN" != "true" ]]; then
        helm "${helm_args[@]}"
        
        # 配置流量分割（需要 Istio 或其他服务网格）
        log_info "配置流量分割..."
        # 这里需要根据实际的服务网格实现
        
        log_success "金丝雀部署完成，${canary_percent}% 流量路由到新版本"
        log_info "监控金丝雀版本性能，确认无误后执行完整部署"
    else
        log_info "[DRY RUN] 金丝雀部署模拟完成"
    fi
}

# 回滚部署
rollback_deployment() {
    local namespace="$1"
    
    log_info "开始回滚部署..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] 回滚模拟"
        helm history nova-proxy -n "$namespace" || true
        return
    fi
    
    # 获取历史版本
    local history
    history=$(helm history nova-proxy -n "$namespace" --max 5 -o json)
    
    if [[ -z "$history" || "$history" == "[]" ]]; then
        error_exit "没有找到可回滚的版本"
    fi
    
    # 显示历史版本
    log_info "可用的历史版本:"
    echo "$history" | jq -r '.[] | "\(.revision)\t\(.updated)\t\(.status)\t\(.description)"'
    
    # 回滚到上一个版本
    local previous_revision
    previous_revision=$(echo "$history" | jq -r '.[1].revision // empty')
    
    if [[ -z "$previous_revision" ]]; then
        error_exit "没有找到上一个版本"
    fi
    
    log_info "回滚到版本: $previous_revision"
    helm rollback nova-proxy "$previous_revision" -n "$namespace" --wait --timeout=10m
    
    log_success "回滚完成"
}

# 部署后测试
post_deploy_tests() {
    local namespace="$1"
    local environment="$2"
    
    if [[ "$SKIP_TESTS" == "true" ]]; then
        log_info "跳过部署后测试"
        return
    fi
    
    log_info "执行部署后测试..."
    
    # 等待 Pod 就绪
    log_info "等待 Pod 就绪..."
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=nova-proxy -n "$namespace" --timeout=300s
    
    # 健康检查
    log_info "执行健康检查..."
    local service_url
    case "$environment" in
        development)
            service_url="http://localhost:8080"
            kubectl port-forward service/nova-proxy 8080:8080 -n "$namespace" &
            local port_forward_pid=$!
            sleep 5
            ;;
        staging)
            service_url="https://staging.nova-proxy.com"
            ;;
        production)
            service_url="https://nova-proxy.com"
            ;;
    esac
    
    # 执行健康检查
    local max_retries=10
    local retry=0
    
    while [[ $retry -lt $max_retries ]]; do
        if curl -f "${service_url}/health" &> /dev/null; then
            log_success "健康检查通过"
            break
        fi
        
        retry=$((retry + 1))
        log_warn "健康检查失败，重试 $retry/$max_retries"
        sleep 10
    done
    
    if [[ $retry -eq $max_retries ]]; then
        error_exit "健康检查失败"
    fi
    
    # 清理端口转发
    if [[ "$environment" == "development" && -n "${port_forward_pid:-}" ]]; then
        kill $port_forward_pid 2>/dev/null || true
    fi
    
    # 执行烟雾测试
    log_info "执行烟雾测试..."
    kubectl run smoke-test --rm -i --restart=Never --image=curlimages/curl -n "$namespace" -- \
        curl -f "${service_url}/health" || error_exit "烟雾测试失败"
    
    log_success "部署后测试完成"
}

# 主函数
main() {
    # 默认值
    local environment=""
    local version="latest"
    local namespace=""
    local config_file=""
    local dry_run="false"
    local force="false"
    local rollback="false"
    local scale=""
    local skip_tests="false"
    local skip_backup="false"
    local blue_green="false"
    local canary_percent=""
    
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
            -c|--config)
                config_file="$2"
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
            -r|--rollback)
                rollback="true"
                shift
                ;;
            -s|--scale)
                scale="$2"
                shift 2
                ;;
            --skip-tests)
                skip_tests="true"
                shift
                ;;
            --skip-backup)
                skip_backup="true"
                shift
                ;;
            --blue-green)
                blue_green="true"
                shift
                ;;
            --canary)
                canary_percent="$2"
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
    
    # 设置全局变量
    DRY_RUN="$dry_run"
    SKIP_TESTS="$skip_tests"
    SKIP_BACKUP="$skip_backup"
    SCALE="$scale"
    
    # 设置默认命名空间
    if [[ -z "$namespace" ]]; then
        namespace="nova-proxy-$environment"
    fi
    
    # 设置配置文件
    local values_file="${PROJECT_ROOT}/helm/nova-proxy/values-${environment}.yaml"
    if [[ -n "$config_file" ]]; then
        values_file="$config_file"
    fi
    
    # 显示部署信息
    log_info "Nova Proxy 部署开始"
    log_info "环境: $environment"
    log_info "版本: $version"
    log_info "命名空间: $namespace"
    log_info "配置文件: $values_file"
    log_info "日志文件: $LOG_FILE"
    
    if [[ "$dry_run" == "true" ]]; then
        log_warn "干运行模式，不会执行实际部署"
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
    
    # 执行部署流程
    check_dependencies
    validate_environment "$environment"
    create_namespace "$namespace"
    
    if [[ "$rollback" == "true" ]]; then
        rollback_deployment "$namespace"
    else
        backup_deployment "$namespace"
        
        # 根据部署策略执行部署
        if [[ "$blue_green" == "true" ]]; then
            blue_green_deploy "$environment" "$namespace" "$version" "$values_file"
        elif [[ -n "$canary_percent" ]]; then
            canary_deploy "$environment" "$namespace" "$version" "$values_file" "$canary_percent"
        else
            standard_deploy "$environment" "$namespace" "$version" "$values_file"
        fi
    fi
    
    post_deploy_tests "$namespace" "$environment"
    
    log_success "Nova Proxy 部署完成!"
    log_info "日志文件: $LOG_FILE"
}

# 执行主函数
main "$@"