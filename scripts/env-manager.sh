#!/bin/bash

# Nova Proxy 环境管理脚本
# 用于管理多环境配置、切换和维护

set -euo pipefail

# 脚本配置
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
HELM_CHART_DIR="$PROJECT_ROOT/helm/nova-proxy"
CONFIG_DIR="$PROJECT_ROOT/config"
SECRETS_DIR="$PROJECT_ROOT/secrets"

# 支持的环境
SUPPORTED_ENVIRONMENTS=("development" "staging" "production")

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

log_debug() {
    if [[ "${VERBOSE:-false}" == "true" ]]; then
        echo -e "${PURPLE}[DEBUG]${NC} $1"
    fi
}

# 显示帮助信息
show_help() {
    cat << EOF
Nova Proxy 环境管理脚本

用法: $0 <命令> [选项]

命令:
  list                      列出所有环境
  status [ENV]              显示环境状态
  switch <ENV>              切换到指定环境
  create <ENV>              创建新环境配置
  delete <ENV>              删除环境配置
  backup <ENV>              备份环境配置
  restore <ENV> <BACKUP>    恢复环境配置
  validate <ENV>            验证环境配置
  diff <ENV1> <ENV2>        比较两个环境配置
  sync <SRC_ENV> <DST_ENV>  同步环境配置
  secrets <ENV>             管理环境密钥
  scale <ENV> <REPLICAS>    调整环境副本数
  logs <ENV>                查看环境日志
  exec <ENV> <COMMAND>      在环境中执行命令
  port-forward <ENV>        端口转发
  cleanup <ENV>             清理环境资源

选项:
  -n, --namespace NS        指定命名空间
  -v, --verbose             详细输出
  -f, --force               强制执行
  -d, --dry-run             干运行模式
  -h, --help                显示此帮助信息

示例:
  $0 list                           # 列出所有环境
  $0 status staging                 # 查看 staging 环境状态
  $0 switch production              # 切换到生产环境
  $0 create test                    # 创建测试环境
  $0 backup production              # 备份生产环境配置
  $0 diff staging production        # 比较 staging 和 production 配置
  $0 scale staging 3                # 将 staging 环境扩展到 3 个副本
  $0 logs production -f             # 实时查看生产环境日志

EOF
}

# 解析命令行参数
parse_args() {
    COMMAND=""
    ENVIRONMENT=""
    NAMESPACE=""
    VERBOSE=false
    FORCE=false
    DRY_RUN=false
    EXTRA_ARGS=()

    if [[ $# -eq 0 ]]; then
        show_help
        exit 1
    fi

    COMMAND="$1"
    shift

    while [[ $# -gt 0 ]]; do
        case $1 in
            -n|--namespace)
                NAMESPACE="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -f|--force)
                FORCE=true
                shift
                ;;
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            -*)
                EXTRA_ARGS+=("$1")
                shift
                ;;
            *)
                if [[ -z "$ENVIRONMENT" ]]; then
                    ENVIRONMENT="$1"
                else
                    EXTRA_ARGS+=("$1")
                fi
                shift
                ;;
        esac
    done
}

# 检查依赖
check_dependencies() {
    local missing_deps=()
    local required_commands=("kubectl" "helm" "jq" "yq")
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "缺少以下依赖: ${missing_deps[*]}"
        exit 1
    fi
}

# 验证环境名称
validate_environment() {
    local env="$1"
    
    if [[ -z "$env" ]]; then
        log_error "环境名称不能为空"
        return 1
    fi
    
    # 检查环境名称格式
    if [[ ! "$env" =~ ^[a-z0-9-]+$ ]]; then
        log_error "环境名称只能包含小写字母、数字和连字符"
        return 1
    fi
    
    return 0
}

# 获取环境命名空间
get_namespace() {
    local env="$1"
    
    if [[ -n "$NAMESPACE" ]]; then
        echo "$NAMESPACE"
    else
        echo "nova-proxy-$env"
    fi
}

# 列出所有环境
list_environments() {
    log_info "可用环境:"
    
    echo -e "\n${CYAN}配置文件环境:${NC}"
    for env in "${SUPPORTED_ENVIRONMENTS[@]}"; do
        local values_file="$HELM_CHART_DIR/values-$env.yaml"
        if [[ -f "$values_file" ]]; then
            echo -e "  ${GREEN}✓${NC} $env (配置文件存在)"
        else
            echo -e "  ${RED}✗${NC} $env (配置文件缺失)"
        fi
    done
    
    echo -e "\n${CYAN}Kubernetes 环境:${NC}"
    local namespaces
    namespaces=$(kubectl get namespaces -o name 2>/dev/null | grep "nova-proxy" | sed 's/namespace\///g' || true)
    
    if [[ -n "$namespaces" ]]; then
        while IFS= read -r ns; do
            local env_name="${ns#nova-proxy-}"
            local status
            status=$(kubectl get pods -n "$ns" -l app.kubernetes.io/name=nova-proxy --no-headers 2>/dev/null | wc -l || echo "0")
            echo -e "  ${GREEN}✓${NC} $env_name (命名空间: $ns, Pod 数量: $status)"
        done <<< "$namespaces"
    else
        echo "  没有找到已部署的环境"
    fi
}

# 显示环境状态
show_environment_status() {
    local env="$1"
    local ns
    ns=$(get_namespace "$env")
    
    log_info "环境状态: $env"
    echo "  命名空间: $ns"
    
    # 检查命名空间是否存在
    if ! kubectl get namespace "$ns" &> /dev/null; then
        log_warning "命名空间不存在: $ns"
        return 1
    fi
    
    # 检查 Helm 发布
    local release_name="nova-proxy"
    if helm list -n "$ns" | grep -q "$release_name"; then
        echo -e "  ${GREEN}✓${NC} Helm 发布存在"
        local chart_version
        chart_version=$(helm list -n "$ns" -o json | jq -r ".[] | select(.name==\"$release_name\") | .chart")
        echo "    Chart 版本: $chart_version"
        
        local app_version
        app_version=$(helm list -n "$ns" -o json | jq -r ".[] | select(.name==\"$release_name\") | .app_version")
        echo "    应用版本: $app_version"
    else
        echo -e "  ${RED}✗${NC} Helm 发布不存在"
    fi
    
    # 检查 Pod 状态
    local pods
    pods=$(kubectl get pods -n "$ns" -l app.kubernetes.io/name=nova-proxy --no-headers 2>/dev/null || true)
    
    if [[ -n "$pods" ]]; then
        echo -e "  ${GREEN}✓${NC} Pod 状态:"
        while IFS= read -r pod_line; do
            local pod_name status ready restarts age
            read -r pod_name ready status restarts age <<< "$pod_line"
            echo "    $pod_name: $status ($ready, 重启: $restarts, 运行时间: $age)"
        done <<< "$pods"
    else
        echo -e "  ${RED}✗${NC} 没有找到 Pod"
    fi
    
    # 检查服务状态
    local services
    services=$(kubectl get services -n "$ns" -l app.kubernetes.io/name=nova-proxy --no-headers 2>/dev/null || true)
    
    if [[ -n "$services" ]]; then
        echo -e "  ${GREEN}✓${NC} 服务状态:"
        while IFS= read -r svc_line; do
            local svc_name svc_type cluster_ip external_ip ports age
            read -r svc_name svc_type cluster_ip external_ip ports age <<< "$svc_line"
            echo "    $svc_name: $svc_type ($cluster_ip:$ports)"
        done <<< "$services"
    else
        echo -e "  ${RED}✗${NC} 没有找到服务"
    fi
    
    # 检查 Ingress 状态
    local ingresses
    ingresses=$(kubectl get ingress -n "$ns" --no-headers 2>/dev/null || true)
    
    if [[ -n "$ingresses" ]]; then
        echo -e "  ${GREEN}✓${NC} Ingress 状态:"
        while IFS= read -r ing_line; do
            local ing_name class_name hosts address ports age
            read -r ing_name class_name hosts address ports age <<< "$ing_line"
            echo "    $ing_name: $hosts ($address)"
        done <<< "$ingresses"
    fi
    
    # 检查资源使用情况
    log_info "资源使用情况:"
    kubectl top pods -n "$ns" -l app.kubernetes.io/name=nova-proxy 2>/dev/null || log_warning "无法获取资源使用情况（需要 metrics-server）"
}

# 切换环境
switch_environment() {
    local env="$1"
    local ns
    ns=$(get_namespace "$env")
    
    log_info "切换到环境: $env"
    
    # 设置 kubectl 上下文
    kubectl config set-context --current --namespace="$ns"
    
    # 创建或更新 .env 文件
    cat > "$PROJECT_ROOT/.env" << EOF
# Nova Proxy 当前环境配置
NOVA_ENVIRONMENT=$env
NOVA_NAMESPACE=$ns
NOVA_RELEASE_NAME=nova-proxy
KUBECTL_NAMESPACE=$ns
HELM_NAMESPACE=$ns
EOF
    
    log_success "已切换到环境: $env (命名空间: $ns)"
    log_info "当前 kubectl 默认命名空间已设置为: $ns"
}

# 创建新环境配置
create_environment() {
    local env="$1"
    
    validate_environment "$env" || exit 1
    
    local values_file="$HELM_CHART_DIR/values-$env.yaml"
    
    if [[ -f "$values_file" ]] && [[ "$FORCE" != "true" ]]; then
        log_error "环境配置已存在: $values_file"
        log_info "使用 --force 选项覆盖现有配置"
        exit 1
    fi
    
    log_info "创建环境配置: $env"
    
    # 基于 development 环境创建新配置
    local base_file="$HELM_CHART_DIR/values-development.yaml"
    if [[ ! -f "$base_file" ]]; then
        base_file="$HELM_CHART_DIR/values.yaml"
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] 将创建配置文件: $values_file"
        return
    fi
    
    # 复制基础配置
    cp "$base_file" "$values_file"
    
    # 更新环境特定配置
    yq eval ".global.environment = \"$env\"" -i "$values_file"
    yq eval ".image.tag = \"latest\"" -i "$values_file"
    
    # 根据环境类型调整配置
    case $env in
        *prod*|*production*)
            yq eval '.replicaCount = 3' -i "$values_file"
            yq eval '.resources.requests.memory = "1Gi"' -i "$values_file"
            yq eval '.resources.requests.cpu = "500m"' -i "$values_file"
            yq eval '.autoscaling.enabled = true' -i "$values_file"
            ;;
        *staging*|*stage*)
            yq eval '.replicaCount = 2' -i "$values_file"
            yq eval '.resources.requests.memory = "512Mi"' -i "$values_file"
            yq eval '.resources.requests.cpu = "250m"' -i "$values_file"
            ;;
        *)
            yq eval '.replicaCount = 1' -i "$values_file"
            yq eval '.resources.requests.memory = "256Mi"' -i "$values_file"
            yq eval '.resources.requests.cpu = "100m"' -i "$values_file"
            ;;
    esac
    
    log_success "环境配置创建完成: $values_file"
    log_info "请根据需要编辑配置文件"
}

# 删除环境配置
delete_environment() {
    local env="$1"
    local ns
    ns=$(get_namespace "$env")
    
    if [[ "$FORCE" != "true" ]]; then
        echo -n "确定要删除环境 '$env' 吗？这将删除所有相关资源。[y/N] "
        read -r confirmation
        if [[ "$confirmation" != "y" && "$confirmation" != "Y" ]]; then
            log_info "操作已取消"
            exit 0
        fi
    fi
    
    log_info "删除环境: $env"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] 将删除以下资源:"
        log_info "  - Helm 发布: nova-proxy (命名空间: $ns)"
        log_info "  - 命名空间: $ns"
        log_info "  - 配置文件: $HELM_CHART_DIR/values-$env.yaml"
        return
    fi
    
    # 删除 Helm 发布
    if helm list -n "$ns" | grep -q "nova-proxy"; then
        log_info "删除 Helm 发布..."
        helm uninstall nova-proxy -n "$ns"
    fi
    
    # 删除命名空间
    if kubectl get namespace "$ns" &> /dev/null; then
        log_info "删除命名空间: $ns"
        kubectl delete namespace "$ns" --timeout=300s
    fi
    
    # 删除配置文件
    local values_file="$HELM_CHART_DIR/values-$env.yaml"
    if [[ -f "$values_file" ]]; then
        log_info "删除配置文件: $values_file"
        rm "$values_file"
    fi
    
    log_success "环境删除完成: $env"
}

# 备份环境配置
backup_environment() {
    local env="$1"
    local backup_dir="$PROJECT_ROOT/backups"
    local timestamp
    timestamp=$(date +"%Y%m%d_%H%M%S")
    local backup_file="$backup_dir/${env}_${timestamp}.tar.gz"
    
    log_info "备份环境配置: $env"
    
    mkdir -p "$backup_dir"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] 将创建备份文件: $backup_file"
        return
    fi
    
    # 创建临时目录
    local temp_dir
    temp_dir=$(mktemp -d)
    local backup_content_dir="$temp_dir/$env"
    mkdir -p "$backup_content_dir"
    
    # 备份配置文件
    local values_file="$HELM_CHART_DIR/values-$env.yaml"
    if [[ -f "$values_file" ]]; then
        cp "$values_file" "$backup_content_dir/"
    fi
    
    # 备份 Kubernetes 资源
    local ns
    ns=$(get_namespace "$env")
    
    if kubectl get namespace "$ns" &> /dev/null; then
        log_info "备份 Kubernetes 资源..."
        
        # 备份 Helm 发布信息
        helm get all nova-proxy -n "$ns" > "$backup_content_dir/helm-release.yaml" 2>/dev/null || true
        
        # 备份 ConfigMaps
        kubectl get configmaps -n "$ns" -o yaml > "$backup_content_dir/configmaps.yaml" 2>/dev/null || true
        
        # 备份 Secrets (不包含敏感数据)
        kubectl get secrets -n "$ns" -o yaml | yq eval 'del(.items[].data)' > "$backup_content_dir/secrets-metadata.yaml" 2>/dev/null || true
        
        # 备份其他资源
        kubectl get all -n "$ns" -o yaml > "$backup_content_dir/resources.yaml" 2>/dev/null || true
    fi
    
    # 创建备份元数据
    cat > "$backup_content_dir/metadata.yaml" << EOF
backup:
  environment: $env
  timestamp: $timestamp
  created_by: $(whoami)
  kubernetes_context: $(kubectl config current-context)
  helm_version: $(helm version --short)
  kubectl_version: $(kubectl version --client --short)
EOF
    
    # 创建压缩包
    tar -czf "$backup_file" -C "$temp_dir" "$env"
    
    # 清理临时目录
    rm -rf "$temp_dir"
    
    log_success "备份完成: $backup_file"
}

# 验证环境配置
validate_environment_config() {
    local env="$1"
    local values_file="$HELM_CHART_DIR/values-$env.yaml"
    
    log_info "验证环境配置: $env"
    
    if [[ ! -f "$values_file" ]]; then
        log_error "配置文件不存在: $values_file"
        return 1
    fi
    
    # 验证 YAML 语法
    if ! yq eval '.' "$values_file" > /dev/null 2>&1; then
        log_error "配置文件 YAML 语法错误: $values_file"
        return 1
    fi
    
    log_success "YAML 语法验证通过"
    
    # 使用 Helm 验证配置
    if helm template nova-proxy "$HELM_CHART_DIR" -f "$values_file" > /dev/null 2>&1; then
        log_success "Helm 模板验证通过"
    else
        log_error "Helm 模板验证失败"
        return 1
    fi
    
    # 验证必需字段
    local required_fields=(
        ".image.repository"
        ".image.tag"
        ".service.type"
        ".resources.requests.memory"
        ".resources.requests.cpu"
    )
    
    for field in "${required_fields[@]}"; do
        if ! yq eval "$field" "$values_file" > /dev/null 2>&1; then
            log_warning "缺少必需字段: $field"
        fi
    done
    
    log_success "环境配置验证完成"
}

# 调整环境副本数
scale_environment() {
    local env="$1"
    local replicas="$2"
    local ns
    ns=$(get_namespace "$env")
    
    if [[ ! "$replicas" =~ ^[0-9]+$ ]]; then
        log_error "副本数必须是正整数: $replicas"
        exit 1
    fi
    
    log_info "调整环境副本数: $env -> $replicas"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] 将调整副本数到: $replicas"
        return
    fi
    
    # 使用 kubectl 直接调整
    kubectl scale deployment nova-proxy -n "$ns" --replicas="$replicas"
    
    # 等待调整完成
    kubectl rollout status deployment nova-proxy -n "$ns" --timeout=300s
    
    log_success "副本数调整完成: $replicas"
}

# 查看环境日志
view_environment_logs() {
    local env="$1"
    local ns
    ns=$(get_namespace "$env")
    
    log_info "查看环境日志: $env"
    
    # 传递额外参数给 kubectl logs
    kubectl logs -n "$ns" -l app.kubernetes.io/name=nova-proxy "${EXTRA_ARGS[@]}"
}

# 在环境中执行命令
exec_in_environment() {
    local env="$1"
    local command="${EXTRA_ARGS[*]}"
    local ns
    ns=$(get_namespace "$env")
    
    if [[ -z "$command" ]]; then
        log_error "请指定要执行的命令"
        exit 1
    fi
    
    log_info "在环境 $env 中执行命令: $command"
    
    # 获取第一个可用的 Pod
    local pod_name
    pod_name=$(kubectl get pods -n "$ns" -l app.kubernetes.io/name=nova-proxy -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    
    if [[ -z "$pod_name" ]]; then
        log_error "没有找到可用的 Pod"
        exit 1
    fi
    
    kubectl exec -n "$ns" "$pod_name" -- $command
}

# 端口转发
port_forward() {
    local env="$1"
    local ns
    ns=$(get_namespace "$env")
    
    log_info "设置端口转发: $env"
    
    # 默认端口映射
    local local_port="8080"
    local remote_port="8080"
    
    # 解析额外参数中的端口
    if [[ ${#EXTRA_ARGS[@]} -gt 0 ]]; then
        local_port="${EXTRA_ARGS[0]}"
        if [[ ${#EXTRA_ARGS[@]} -gt 1 ]]; then
            remote_port="${EXTRA_ARGS[1]}"
        fi
    fi
    
    log_info "端口映射: localhost:$local_port -> nova-proxy:$remote_port"
    log_info "按 Ctrl+C 停止端口转发"
    
    kubectl port-forward -n "$ns" service/nova-proxy "$local_port:$remote_port"
}

# 清理环境资源
cleanup_environment() {
    local env="$1"
    local ns
    ns=$(get_namespace "$env")
    
    log_info "清理环境资源: $env"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] 将清理以下资源:"
        kubectl get all -n "$ns" 2>/dev/null || true
        return
    fi
    
    # 清理失败的 Pod
    log_info "清理失败的 Pod..."
    kubectl delete pods -n "$ns" --field-selector=status.phase=Failed 2>/dev/null || true
    
    # 清理已完成的 Job
    log_info "清理已完成的 Job..."
    kubectl delete jobs -n "$ns" --field-selector=status.successful=1 2>/dev/null || true
    
    # 重启部署（如果需要）
    if [[ "$FORCE" == "true" ]]; then
        log_info "重启部署..."
        kubectl rollout restart deployment nova-proxy -n "$ns" 2>/dev/null || true
    fi
    
    log_success "环境资源清理完成"
}

# 主函数
main() {
    parse_args "$@"
    check_dependencies
    
    case $COMMAND in
        list)
            list_environments
            ;;
        status)
            if [[ -z "$ENVIRONMENT" ]]; then
                log_error "请指定环境名称"
                exit 1
            fi
            show_environment_status "$ENVIRONMENT"
            ;;
        switch)
            if [[ -z "$ENVIRONMENT" ]]; then
                log_error "请指定环境名称"
                exit 1
            fi
            switch_environment "$ENVIRONMENT"
            ;;
        create)
            if [[ -z "$ENVIRONMENT" ]]; then
                log_error "请指定环境名称"
                exit 1
            fi
            create_environment "$ENVIRONMENT"
            ;;
        delete)
            if [[ -z "$ENVIRONMENT" ]]; then
                log_error "请指定环境名称"
                exit 1
            fi
            delete_environment "$ENVIRONMENT"
            ;;
        backup)
            if [[ -z "$ENVIRONMENT" ]]; then
                log_error "请指定环境名称"
                exit 1
            fi
            backup_environment "$ENVIRONMENT"
            ;;
        validate)
            if [[ -z "$ENVIRONMENT" ]]; then
                log_error "请指定环境名称"
                exit 1
            fi
            validate_environment_config "$ENVIRONMENT"
            ;;
        scale)
            if [[ -z "$ENVIRONMENT" ]] || [[ ${#EXTRA_ARGS[@]} -eq 0 ]]; then
                log_error "请指定环境名称和副本数"
                exit 1
            fi
            scale_environment "$ENVIRONMENT" "${EXTRA_ARGS[0]}"
            ;;
        logs)
            if [[ -z "$ENVIRONMENT" ]]; then
                log_error "请指定环境名称"
                exit 1
            fi
            view_environment_logs "$ENVIRONMENT"
            ;;
        exec)
            if [[ -z "$ENVIRONMENT" ]]; then
                log_error "请指定环境名称"
                exit 1
            fi
            exec_in_environment "$ENVIRONMENT"
            ;;
        port-forward)
            if [[ -z "$ENVIRONMENT" ]]; then
                log_error "请指定环境名称"
                exit 1
            fi
            port_forward "$ENVIRONMENT"
            ;;
        cleanup)
            if [[ -z "$ENVIRONMENT" ]]; then
                log_error "请指定环境名称"
                exit 1
            fi
            cleanup_environment "$ENVIRONMENT"
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