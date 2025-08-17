#!/bin/bash

# Nova Proxy 一键部署脚本
# 支持多环境部署：development, staging, production

set -euo pipefail

# 脚本配置
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
HELM_CHART_DIR="$PROJECT_ROOT/helm/nova-proxy"
DOCKER_DIR="$PROJECT_ROOT/docker"

# 默认配置
DEFAULT_ENVIRONMENT="development"
DEFAULT_NAMESPACE="nova-proxy"
DEFAULT_RELEASE_NAME="nova-proxy"
DEFAULT_IMAGE_TAG="latest"
DEFAULT_REGISTRY="docker.io/nova-proxy"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 显示帮助信息
show_help() {
    cat << EOF
Nova Proxy 部署脚本

用法: $0 [选项]

选项:
  -e, --environment ENV     部署环境 (development|staging|production) [默认: $DEFAULT_ENVIRONMENT]
  -n, --namespace NS        Kubernetes 命名空间 [默认: $DEFAULT_NAMESPACE]
  -r, --release NAME        Helm 发布名称 [默认: $DEFAULT_RELEASE_NAME]
  -t, --tag TAG            Docker 镜像标签 [默认: $DEFAULT_IMAGE_TAG]
  -g, --registry REGISTRY   Docker 镜像仓库 [默认: $DEFAULT_REGISTRY]
  -b, --build              构建 Docker 镜像
  -p, --push               推送 Docker 镜像
  -u, --upgrade            升级现有部署
  -d, --dry-run            干运行模式
  -v, --verbose            详细输出
  -h, --help               显示此帮助信息

示例:
  $0 -e staging -b -p                    # 构建并推送镜像，部署到 staging 环境
  $0 -e production -t v1.0.0 -u          # 使用 v1.0.0 标签升级生产环境
  $0 -e development -d                    # 干运行模式部署到开发环境

EOF
}

# 解析命令行参数
parse_args() {
    ENVIRONMENT="$DEFAULT_ENVIRONMENT"
    NAMESPACE="$DEFAULT_NAMESPACE"
    RELEASE_NAME="$DEFAULT_RELEASE_NAME"
    IMAGE_TAG="$DEFAULT_IMAGE_TAG"
    REGISTRY="$DEFAULT_REGISTRY"
    BUILD_IMAGE=false
    PUSH_IMAGE=false
    UPGRADE_DEPLOYMENT=false
    DRY_RUN=false
    VERBOSE=false

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
            -r|--release)
                RELEASE_NAME="$2"
                shift 2
                ;;
            -t|--tag)
                IMAGE_TAG="$2"
                shift 2
                ;;
            -g|--registry)
                REGISTRY="$2"
                shift 2
                ;;
            -b|--build)
                BUILD_IMAGE=true
                shift
                ;;
            -p|--push)
                PUSH_IMAGE=true
                shift
                ;;
            -u|--upgrade)
                UPGRADE_DEPLOYMENT=true
                shift
                ;;
            -d|--dry-run)
                DRY_RUN=true
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
                log_error "未知参数: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # 验证环境参数
    case $ENVIRONMENT in
        development|staging|production)
            ;;
        *)
            log_error "无效的环境: $ENVIRONMENT"
            log_error "支持的环境: development, staging, production"
            exit 1
            ;;
    esac
}

# 检查依赖
check_dependencies() {
    log_info "检查依赖..."
    
    local missing_deps=()
    
    # 检查必需的命令
    local required_commands=("kubectl" "helm" "docker")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "缺少以下依赖: ${missing_deps[*]}"
        log_error "请安装缺少的依赖后重试"
        exit 1
    fi
    
    # 检查 Kubernetes 连接
    if ! kubectl cluster-info &> /dev/null; then
        log_error "无法连接到 Kubernetes 集群"
        log_error "请检查 kubeconfig 配置"
        exit 1
    fi
    
    # 检查 Helm Chart
    if [[ ! -d "$HELM_CHART_DIR" ]]; then
        log_error "Helm Chart 目录不存在: $HELM_CHART_DIR"
        exit 1
    fi
    
    log_success "依赖检查通过"
}

# 构建 Docker 镜像
build_image() {
    if [[ "$BUILD_IMAGE" == "true" ]]; then
        log_info "构建 Docker 镜像..."
        
        local image_name="$REGISTRY:$IMAGE_TAG"
        local dockerfile="$DOCKER_DIR/Dockerfile"
        
        if [[ ! -f "$dockerfile" ]]; then
            log_error "Dockerfile 不存在: $dockerfile"
            exit 1
        fi
        
        local build_args=()
        if [[ "$VERBOSE" == "true" ]]; then
            build_args+=("--progress=plain")
        fi
        
        if [[ "$DRY_RUN" == "true" ]]; then
            log_info "[DRY RUN] 将构建镜像: $image_name"
        else
            docker build "${build_args[@]}" -t "$image_name" -f "$dockerfile" "$PROJECT_ROOT"
            log_success "镜像构建完成: $image_name"
        fi
    fi
}

# 推送 Docker 镜像
push_image() {
    if [[ "$PUSH_IMAGE" == "true" ]]; then
        log_info "推送 Docker 镜像..."
        
        local image_name="$REGISTRY:$IMAGE_TAG"
        
        if [[ "$DRY_RUN" == "true" ]]; then
            log_info "[DRY RUN] 将推送镜像: $image_name"
        else
            docker push "$image_name"
            log_success "镜像推送完成: $image_name"
        fi
    fi
}

# 创建命名空间
create_namespace() {
    log_info "检查命名空间: $NAMESPACE"
    
    if kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log_info "命名空间已存在: $NAMESPACE"
    else
        if [[ "$DRY_RUN" == "true" ]]; then
            log_info "[DRY RUN] 将创建命名空间: $NAMESPACE"
        else
            kubectl create namespace "$NAMESPACE"
            
            # 添加环境标签
            kubectl label namespace "$NAMESPACE" environment="$ENVIRONMENT" --overwrite
            kubectl label namespace "$NAMESPACE" app.kubernetes.io/name=nova-proxy --overwrite
            kubectl label namespace "$NAMESPACE" app.kubernetes.io/managed-by=helm --overwrite
            
            log_success "命名空间创建完成: $NAMESPACE"
        fi
    fi
}

# 部署应用
deploy_application() {
    log_info "部署 Nova Proxy 到 $ENVIRONMENT 环境..."
    
    local values_file="$HELM_CHART_DIR/values-$ENVIRONMENT.yaml"
    if [[ ! -f "$values_file" ]]; then
        log_warning "环境配置文件不存在: $values_file"
        log_info "使用默认配置文件: $HELM_CHART_DIR/values.yaml"
        values_file="$HELM_CHART_DIR/values.yaml"
    fi
    
    local helm_args=(
        "$RELEASE_NAME"
        "$HELM_CHART_DIR"
        "--namespace" "$NAMESPACE"
        "--values" "$values_file"
        "--set" "image.tag=$IMAGE_TAG"
        "--set" "image.repository=$REGISTRY"
        "--set" "global.environment=$ENVIRONMENT"
        "--create-namespace"
        "--wait"
        "--timeout" "10m"
    )
    
    if [[ "$VERBOSE" == "true" ]]; then
        helm_args+=("--debug")
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        helm_args+=("--dry-run")
        log_info "[DRY RUN] Helm 部署参数:"
        printf '%s\n' "${helm_args[@]}"
    fi
    
    if [[ "$UPGRADE_DEPLOYMENT" == "true" ]] && helm list -n "$NAMESPACE" | grep -q "$RELEASE_NAME"; then
        log_info "升级现有部署..."
        helm upgrade "${helm_args[@]}"
        if [[ "$DRY_RUN" != "true" ]]; then
            log_success "应用升级完成"
        fi
    else
        log_info "安装新部署..."
        helm install "${helm_args[@]}"
        if [[ "$DRY_RUN" != "true" ]]; then
            log_success "应用部署完成"
        fi
    fi
}

# 验证部署
verify_deployment() {
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] 跳过部署验证"
        return
    fi
    
    log_info "验证部署状态..."
    
    # 等待 Pod 就绪
    log_info "等待 Pod 就绪..."
    if kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=nova-proxy -n "$NAMESPACE" --timeout=300s; then
        log_success "Pod 已就绪"
    else
        log_error "Pod 就绪超时"
        kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name=nova-proxy
        exit 1
    fi
    
    # 检查服务状态
    log_info "检查服务状态..."
    kubectl get services -n "$NAMESPACE" -l app.kubernetes.io/name=nova-proxy
    
    # 检查 Ingress 状态
    if kubectl get ingress -n "$NAMESPACE" &> /dev/null; then
        log_info "检查 Ingress 状态..."
        kubectl get ingress -n "$NAMESPACE"
    fi
    
    # 健康检查
    log_info "执行健康检查..."
    local pod_name
    pod_name=$(kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name=nova-proxy -o jsonpath='{.items[0].metadata.name}')
    
    if kubectl exec -n "$NAMESPACE" "$pod_name" -- curl -f http://localhost:8081/health &> /dev/null; then
        log_success "健康检查通过"
    else
        log_warning "健康检查失败，请检查应用日志"
    fi
    
    log_success "部署验证完成"
}

# 显示部署信息
show_deployment_info() {
    if [[ "$DRY_RUN" == "true" ]]; then
        return
    fi
    
    log_info "部署信息:"
    echo "  环境: $ENVIRONMENT"
    echo "  命名空间: $NAMESPACE"
    echo "  发布名称: $RELEASE_NAME"
    echo "  镜像: $REGISTRY:$IMAGE_TAG"
    echo ""
    
    log_info "有用的命令:"
    echo "  查看 Pod 状态: kubectl get pods -n $NAMESPACE"
    echo "  查看服务状态: kubectl get services -n $NAMESPACE"
    echo "  查看日志: kubectl logs -n $NAMESPACE -l app.kubernetes.io/name=nova-proxy -f"
    echo "  端口转发: kubectl port-forward -n $NAMESPACE svc/nova-proxy 8080:8080"
    echo "  删除部署: helm uninstall $RELEASE_NAME -n $NAMESPACE"
    echo ""
    
    # 显示访问信息
    local service_type
    service_type=$(kubectl get service -n "$NAMESPACE" "$RELEASE_NAME" -o jsonpath='{.spec.type}' 2>/dev/null || echo "Unknown")
    
    case $service_type in
        LoadBalancer)
            log_info "获取 LoadBalancer IP..."
            local external_ip
            external_ip=$(kubectl get service -n "$NAMESPACE" "$RELEASE_NAME" -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "Pending")
            if [[ "$external_ip" != "Pending" && -n "$external_ip" ]]; then
                echo "  外部访问地址: https://$external_ip"
            else
                echo "  外部 IP 正在分配中，请稍后查看"
            fi
            ;;
        NodePort)
            local node_port
            node_port=$(kubectl get service -n "$NAMESPACE" "$RELEASE_NAME" -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null || echo "Unknown")
            echo "  NodePort 访问: <节点IP>:$node_port"
            ;;
        ClusterIP)
            echo "  集群内访问: $RELEASE_NAME.$NAMESPACE.svc.cluster.local"
            ;;
    esac
    
    # 显示 Ingress 信息
    if kubectl get ingress -n "$NAMESPACE" &> /dev/null; then
        local ingress_hosts
        ingress_hosts=$(kubectl get ingress -n "$NAMESPACE" -o jsonpath='{.items[*].spec.rules[*].host}' 2>/dev/null || echo "")
        if [[ -n "$ingress_hosts" ]]; then
            echo "  Ingress 访问地址:"
            for host in $ingress_hosts; do
                echo "    https://$host"
            done
        fi
    fi
}

# 清理函数
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_error "部署失败，退出码: $exit_code"
    fi
    exit $exit_code
}

# 主函数
main() {
    # 设置错误处理
    trap cleanup EXIT
    
    log_info "Nova Proxy 部署脚本启动"
    
    # 解析参数
    parse_args "$@"
    
    # 显示配置
    log_info "部署配置:"
    echo "  环境: $ENVIRONMENT"
    echo "  命名空间: $NAMESPACE"
    echo "  发布名称: $RELEASE_NAME"
    echo "  镜像: $REGISTRY:$IMAGE_TAG"
    echo "  构建镜像: $BUILD_IMAGE"
    echo "  推送镜像: $PUSH_IMAGE"
    echo "  升级部署: $UPGRADE_DEPLOYMENT"
    echo "  干运行: $DRY_RUN"
    echo ""
    
    # 执行部署步骤
    check_dependencies
    build_image
    push_image
    create_namespace
    deploy_application
    verify_deployment
    show_deployment_info
    
    log_success "Nova Proxy 部署完成！"
}

# 执行主函数
main "$@"