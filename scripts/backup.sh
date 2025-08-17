#!/bin/bash

# Nova Proxy 备份和恢复脚本
# 用于数据备份和灾难恢复

set -euo pipefail

# 脚本配置
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="$PROJECT_ROOT/backups"

# 默认配置
DEFAULT_ENVIRONMENT="development"
DEFAULT_NAMESPACE="nova-proxy"
DEFAULT_RETENTION_DAYS="30"
DEFAULT_STORAGE_CLASS="standard"

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

log_backup() {
    echo -e "${CYAN}[BACKUP]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
}

# 显示帮助信息
show_help() {
    cat << EOF
Nova Proxy 备份和恢复脚本

用法: $0 <命令> [选项]

命令:
  backup                    创建完整备份
  backup-config             备份配置文件
  backup-data               备份数据
  backup-pvc                备份持久化卷
  restore                   恢复备份
  restore-config            恢复配置
  restore-data              恢复数据
  restore-pvc               恢复持久化卷
  list                      列出备份
  verify                    验证备份
  cleanup                   清理旧备份
  schedule                  设置定时备份
  migrate                   数据迁移

选项:
  -e, --environment ENV     环境名称 [默认: $DEFAULT_ENVIRONMENT]
  -n, --namespace NS        命名空间 [默认: $DEFAULT_NAMESPACE]
  -b, --backup-name NAME    备份名称
  -d, --backup-dir DIR      备份目录 [默认: $BACKUP_DIR]
  -s, --storage-class CLASS 存储类 [默认: $DEFAULT_STORAGE_CLASS]
  -r, --retention DAYS      保留天数 [默认: $DEFAULT_RETENTION_DAYS]
  -c, --compress            压缩备份
  -e, --encrypt             加密备份
  -f, --force               强制执行
  -v, --verbose             详细输出
  -h, --help                显示此帮助信息

示例:
  $0 backup -e production -c -e                   # 创建压缩加密的生产环境备份
  $0 backup-config -e staging                     # 备份 staging 环境配置
  $0 restore -b backup-20240101-120000            # 恢复指定备份
  $0 list -e production                           # 列出生产环境备份
  $0 cleanup -r 7                                 # 清理 7 天前的备份
  $0 schedule -e production --cron "0 2 * * *"    # 设置每日 2 点备份

EOF
}

# 解析命令行参数
parse_args() {
    COMMAND=""
    ENVIRONMENT="$DEFAULT_ENVIRONMENT"
    NAMESPACE="$DEFAULT_NAMESPACE"
    BACKUP_NAME=""
    BACKUP_DIR_OVERRIDE=""
    STORAGE_CLASS="$DEFAULT_STORAGE_CLASS"
    RETENTION_DAYS="$DEFAULT_RETENTION_DAYS"
    COMPRESS=false
    ENCRYPT=false
    FORCE=false
    VERBOSE=false
    CRON_SCHEDULE=""
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
            -b|--backup-name)
                BACKUP_NAME="$2"
                shift 2
                ;;
            -d|--backup-dir)
                BACKUP_DIR_OVERRIDE="$2"
                shift 2
                ;;
            -s|--storage-class)
                STORAGE_CLASS="$2"
                shift 2
                ;;
            -r|--retention)
                RETENTION_DAYS="$2"
                shift 2
                ;;
            -c|--compress)
                COMPRESS=true
                shift
                ;;
            -e|--encrypt)
                ENCRYPT=true
                shift
                ;;
            -f|--force)
                FORCE=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            --cron)
                CRON_SCHEDULE="$2"
                shift 2
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
    
    # 设置备份目录
    if [[ -n "$BACKUP_DIR_OVERRIDE" ]]; then
        BACKUP_DIR="$BACKUP_DIR_OVERRIDE"
    fi
    
    BACKUP_DIR="$BACKUP_DIR/$ENVIRONMENT"
}

# 检查依赖
check_dependencies() {
    local missing_deps=()
    local required_commands=("kubectl" "helm" "tar" "gzip")
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_deps+=("$cmd")
        fi
    done
    
    # 检查加密工具
    if [[ "$ENCRYPT" == "true" ]]; then
        if ! command -v gpg &> /dev/null && ! command -v openssl &> /dev/null; then
            missing_deps+=("gpg or openssl")
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

# 设置备份环境
setup_backup_env() {
    local timestamp
    timestamp=$(date +"%Y%m%d_%H%M%S")
    
    if [[ -z "$BACKUP_NAME" ]]; then
        BACKUP_NAME="nova-proxy-backup-$timestamp"
    fi
    
    BACKUP_SESSION_DIR="$BACKUP_DIR/$BACKUP_NAME"
    mkdir -p "$BACKUP_SESSION_DIR"
    
    log_info "备份会话目录: $BACKUP_SESSION_DIR"
    
    # 创建备份元数据
    cat > "$BACKUP_SESSION_DIR/metadata.json" << EOF
{
    "backup_name": "$BACKUP_NAME",
    "environment": "$ENVIRONMENT",
    "namespace": "$NAMESPACE",
    "timestamp": "$(date -Iseconds)",
    "kubernetes_version": "$(kubectl version --short --client | grep Client | awk '{print $3}')",
    "cluster_context": "$(kubectl config current-context)",
    "compressed": $COMPRESS,
    "encrypted": $ENCRYPT
}
EOF
}

# 创建完整备份
create_full_backup() {
    log_info "创建完整备份..."
    
    # 备份配置
    backup_configurations
    
    # 备份持久化卷
    backup_persistent_volumes
    
    # 备份数据库（如果存在）
    backup_database
    
    # 备份 Helm 发布
    backup_helm_release
    
    # 备份 RBAC 配置
    backup_rbac
    
    # 创建备份清单
    create_backup_manifest
    
    # 压缩和加密
    if [[ "$COMPRESS" == "true" ]] || [[ "$ENCRYPT" == "true" ]]; then
        process_backup_archive
    fi
    
    log_success "完整备份创建完成: $BACKUP_SESSION_DIR"
}

# 备份配置文件
backup_configurations() {
    log_backup "备份配置文件..."
    
    local config_dir="$BACKUP_SESSION_DIR/configs"
    mkdir -p "$config_dir"
    
    # 备份 ConfigMaps
    if kubectl get configmaps -n "$NAMESPACE" &> /dev/null; then
        log_info "备份 ConfigMaps..."
        kubectl get configmaps -n "$NAMESPACE" -o yaml > "$config_dir/configmaps.yaml"
        
        # 单独备份每个 ConfigMap
        local configmaps
        mapfile -t configmaps < <(kubectl get configmaps -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}')
        
        for cm in "${configmaps[@]}"; do
            if [[ -n "$cm" ]]; then
                kubectl get configmap "$cm" -n "$NAMESPACE" -o yaml > "$config_dir/configmap-$cm.yaml"
            fi
        done
    fi
    
    # 备份 Secrets
    if kubectl get secrets -n "$NAMESPACE" &> /dev/null; then
        log_info "备份 Secrets..."
        kubectl get secrets -n "$NAMESPACE" -o yaml > "$config_dir/secrets.yaml"
        
        # 单独备份每个 Secret（不包括系统 Secret）
        local secrets
        mapfile -t secrets < <(kubectl get secrets -n "$NAMESPACE" -o jsonpath='{.items[?(@.type!="kubernetes.io/service-account-token")].metadata.name}')
        
        for secret in "${secrets[@]}"; do
            if [[ -n "$secret" ]]; then
                kubectl get secret "$secret" -n "$NAMESPACE" -o yaml > "$config_dir/secret-$secret.yaml"
            fi
        done
    fi
    
    # 备份服务配置
    if kubectl get services -n "$NAMESPACE" &> /dev/null; then
        log_info "备份服务配置..."
        kubectl get services -n "$NAMESPACE" -o yaml > "$config_dir/services.yaml"
    fi
    
    # 备份 Ingress 配置
    if kubectl get ingress -n "$NAMESPACE" &> /dev/null; then
        log_info "备份 Ingress 配置..."
        kubectl get ingress -n "$NAMESPACE" -o yaml > "$config_dir/ingress.yaml"
    fi
    
    # 备份网络策略
    if kubectl get networkpolicies -n "$NAMESPACE" &> /dev/null; then
        log_info "备份网络策略..."
        kubectl get networkpolicies -n "$NAMESPACE" -o yaml > "$config_dir/networkpolicies.yaml"
    fi
    
    log_success "配置文件备份完成"
}

# 备份持久化卷
backup_persistent_volumes() {
    log_backup "备份持久化卷..."
    
    local pvc_dir="$BACKUP_SESSION_DIR/pvcs"
    mkdir -p "$pvc_dir"
    
    # 获取所有 PVC
    local pvcs
    mapfile -t pvcs < <(kubectl get pvc -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
    
    if [[ ${#pvcs[@]} -eq 0 || -z "${pvcs[0]}" ]]; then
        log_info "没有找到 PVC"
        return 0
    fi
    
    for pvc in "${pvcs[@]}"; do
        if [[ -n "$pvc" ]]; then
            log_info "备份 PVC: $pvc"
            
            # 备份 PVC 配置
            kubectl get pvc "$pvc" -n "$NAMESPACE" -o yaml > "$pvc_dir/pvc-$pvc.yaml"
            
            # 创建备份 Pod 来复制数据
            create_backup_pod "$pvc" "$pvc_dir"
        fi
    done
    
    log_success "持久化卷备份完成"
}

# 创建备份 Pod
create_backup_pod() {
    local pvc_name="$1"
    local output_dir="$2"
    local backup_pod_name="backup-pod-$pvc_name"
    
    # 创建备份 Pod YAML
    cat > "/tmp/$backup_pod_name.yaml" << EOF
apiVersion: v1
kind: Pod
metadata:
  name: $backup_pod_name
  namespace: $NAMESPACE
spec:
  restartPolicy: Never
  containers:
  - name: backup
    image: alpine:latest
    command: ["/bin/sh"]
    args: ["-c", "tar czf /backup/data.tar.gz -C /data . && echo 'Backup completed'"]
    volumeMounts:
    - name: data-volume
      mountPath: /data
    - name: backup-volume
      mountPath: /backup
  volumes:
  - name: data-volume
    persistentVolumeClaim:
      claimName: $pvc_name
  - name: backup-volume
    emptyDir: {}
EOF
    
    # 创建并等待 Pod 完成
    kubectl apply -f "/tmp/$backup_pod_name.yaml"
    
    # 等待 Pod 完成
    log_info "等待备份 Pod 完成..."
    kubectl wait --for=condition=Ready pod/$backup_pod_name -n "$NAMESPACE" --timeout=300s
    
    # 复制备份数据
    kubectl cp "$NAMESPACE/$backup_pod_name:/backup/data.tar.gz" "$output_dir/pvc-$pvc_name-data.tar.gz"
    
    # 清理备份 Pod
    kubectl delete pod "$backup_pod_name" -n "$NAMESPACE"
    rm -f "/tmp/$backup_pod_name.yaml"
    
    log_success "PVC $pvc_name 数据备份完成"
}

# 备份数据库
backup_database() {
    log_backup "备份数据库..."
    
    local db_dir="$BACKUP_SESSION_DIR/database"
    mkdir -p "$db_dir"
    
    # 检查是否有数据库 Pod
    local db_pods
    mapfile -t db_pods < <(kubectl get pods -n "$NAMESPACE" -l app=postgresql -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
    
    if [[ ${#db_pods[@]} -gt 0 && -n "${db_pods[0]}" ]]; then
        for db_pod in "${db_pods[@]}"; do
            if [[ -n "$db_pod" ]]; then
                log_info "备份 PostgreSQL 数据库: $db_pod"
                
                # 创建数据库备份
                kubectl exec -n "$NAMESPACE" "$db_pod" -- pg_dumpall -U postgres > "$db_dir/postgresql-$db_pod.sql"
                
                # 压缩备份
                gzip "$db_dir/postgresql-$db_pod.sql"
            fi
        done
    fi
    
    # 检查 Redis
    local redis_pods
    mapfile -t redis_pods < <(kubectl get pods -n "$NAMESPACE" -l app=redis -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
    
    if [[ ${#redis_pods[@]} -gt 0 && -n "${redis_pods[0]}" ]]; then
        for redis_pod in "${redis_pods[@]}"; do
            if [[ -n "$redis_pod" ]]; then
                log_info "备份 Redis 数据: $redis_pod"
                
                # 创建 Redis 备份
                kubectl exec -n "$NAMESPACE" "$redis_pod" -- redis-cli BGSAVE
                sleep 5
                kubectl cp "$NAMESPACE/$redis_pod:/data/dump.rdb" "$db_dir/redis-$redis_pod.rdb"
            fi
        done
    fi
    
    log_success "数据库备份完成"
}

# 备份 Helm 发布
backup_helm_release() {
    log_backup "备份 Helm 发布..."
    
    local helm_dir="$BACKUP_SESSION_DIR/helm"
    mkdir -p "$helm_dir"
    
    # 检查 Helm 发布
    if helm list -n "$NAMESPACE" | grep -q nova-proxy; then
        log_info "备份 Helm 发布配置..."
        
        # 获取发布信息
        helm get all nova-proxy -n "$NAMESPACE" > "$helm_dir/nova-proxy-release.yaml"
        helm get values nova-proxy -n "$NAMESPACE" > "$helm_dir/nova-proxy-values.yaml"
        helm status nova-proxy -n "$NAMESPACE" > "$helm_dir/nova-proxy-status.txt"
        
        # 备份 Chart
        if [[ -d "$PROJECT_ROOT/helm/nova-proxy" ]]; then
            tar czf "$helm_dir/nova-proxy-chart.tar.gz" -C "$PROJECT_ROOT/helm" nova-proxy
        fi
    else
        log_info "没有找到 Helm 发布"
    fi
    
    log_success "Helm 发布备份完成"
}

# 备份 RBAC 配置
backup_rbac() {
    log_backup "备份 RBAC 配置..."
    
    local rbac_dir="$BACKUP_SESSION_DIR/rbac"
    mkdir -p "$rbac_dir"
    
    # 备份 ServiceAccounts
    if kubectl get serviceaccounts -n "$NAMESPACE" &> /dev/null; then
        kubectl get serviceaccounts -n "$NAMESPACE" -o yaml > "$rbac_dir/serviceaccounts.yaml"
    fi
    
    # 备份 Roles
    if kubectl get roles -n "$NAMESPACE" &> /dev/null; then
        kubectl get roles -n "$NAMESPACE" -o yaml > "$rbac_dir/roles.yaml"
    fi
    
    # 备份 RoleBindings
    if kubectl get rolebindings -n "$NAMESPACE" &> /dev/null; then
        kubectl get rolebindings -n "$NAMESPACE" -o yaml > "$rbac_dir/rolebindings.yaml"
    fi
    
    # 备份 ClusterRoles（如果存在）
    local cluster_roles
    mapfile -t cluster_roles < <(kubectl get clusterroles -o jsonpath='{.items[?(@.metadata.name=="nova-proxy*")].metadata.name}' 2>/dev/null || echo "")
    
    if [[ ${#cluster_roles[@]} -gt 0 && -n "${cluster_roles[0]}" ]]; then
        kubectl get clusterroles "${cluster_roles[@]}" -o yaml > "$rbac_dir/clusterroles.yaml"
    fi
    
    # 备份 ClusterRoleBindings（如果存在）
    local cluster_role_bindings
    mapfile -t cluster_role_bindings < <(kubectl get clusterrolebindings -o jsonpath='{.items[?(@.metadata.name=="nova-proxy*")].metadata.name}' 2>/dev/null || echo "")
    
    if [[ ${#cluster_role_bindings[@]} -gt 0 && -n "${cluster_role_bindings[0]}" ]]; then
        kubectl get clusterrolebindings "${cluster_role_bindings[@]}" -o yaml > "$rbac_dir/clusterrolebindings.yaml"
    fi
    
    log_success "RBAC 配置备份完成"
}

# 创建备份清单
create_backup_manifest() {
    log_info "创建备份清单..."
    
    local manifest_file="$BACKUP_SESSION_DIR/manifest.txt"
    
    cat > "$manifest_file" << EOF
Nova Proxy 备份清单
生成时间: $(date)
备份名称: $BACKUP_NAME
环境: $ENVIRONMENT
命名空间: $NAMESPACE

备份内容:
EOF
    
    # 列出所有备份文件
    find "$BACKUP_SESSION_DIR" -type f -name "*.yaml" -o -name "*.sql" -o -name "*.rdb" -o -name "*.tar.gz" | \
        sed "s|$BACKUP_SESSION_DIR/||" | sort >> "$manifest_file"
    
    # 计算文件大小
    echo "" >> "$manifest_file"
    echo "文件大小统计:" >> "$manifest_file"
    du -sh "$BACKUP_SESSION_DIR"/* >> "$manifest_file" 2>/dev/null || true
    
    # 计算总大小
    local total_size
    total_size=$(du -sh "$BACKUP_SESSION_DIR" | awk '{print $1}')
    echo "" >> "$manifest_file"
    echo "总备份大小: $total_size" >> "$manifest_file"
    
    log_success "备份清单创建完成"
}

# 处理备份归档
process_backup_archive() {
    log_info "处理备份归档..."
    
    local archive_name="$BACKUP_NAME"
    local archive_path="$BACKUP_DIR/$archive_name"
    
    # 压缩
    if [[ "$COMPRESS" == "true" ]]; then
        log_info "压缩备份..."
        tar czf "$archive_path.tar.gz" -C "$BACKUP_DIR" "$BACKUP_NAME"
        
        # 删除原始目录
        rm -rf "$BACKUP_SESSION_DIR"
        archive_path="$archive_path.tar.gz"
        
        log_success "备份压缩完成: $archive_path"
    fi
    
    # 加密
    if [[ "$ENCRYPT" == "true" ]]; then
        log_info "加密备份..."
        
        if command -v gpg &> /dev/null; then
            # 使用 GPG 加密
            gpg --symmetric --cipher-algo AES256 --output "$archive_path.gpg" "$archive_path"
            rm -f "$archive_path"
            archive_path="$archive_path.gpg"
        elif command -v openssl &> /dev/null; then
            # 使用 OpenSSL 加密
            openssl enc -aes-256-cbc -salt -in "$archive_path" -out "$archive_path.enc"
            rm -f "$archive_path"
            archive_path="$archive_path.enc"
        fi
        
        log_success "备份加密完成: $archive_path"
    fi
}

# 恢复备份
restore_backup() {
    log_info "恢复备份: $BACKUP_NAME"
    
    local backup_path="$BACKUP_DIR/$BACKUP_NAME"
    
    # 检查备份是否存在
    if [[ ! -d "$backup_path" && ! -f "$backup_path.tar.gz" && ! -f "$backup_path.gpg" && ! -f "$backup_path.enc" ]]; then
        log_error "备份不存在: $BACKUP_NAME"
        return 1
    fi
    
    # 解密和解压
    prepare_backup_for_restore "$backup_path"
    
    # 确认恢复操作
    if [[ "$FORCE" != "true" ]]; then
        echo -n "确认恢复备份 '$BACKUP_NAME' 到环境 '$ENVIRONMENT'? (y/N): "
        read -r confirmation
        if [[ "$confirmation" != "y" && "$confirmation" != "Y" ]]; then
            log_info "恢复操作已取消"
            return 0
        fi
    fi
    
    # 恢复配置
    restore_configurations
    
    # 恢复持久化卷
    restore_persistent_volumes
    
    # 恢复数据库
    restore_database
    
    # 恢复 Helm 发布
    restore_helm_release
    
    # 恢复 RBAC
    restore_rbac
    
    log_success "备份恢复完成"
}

# 准备备份进行恢复
prepare_backup_for_restore() {
    local backup_path="$1"
    
    # 解密
    if [[ -f "$backup_path.gpg" ]]; then
        log_info "解密备份..."
        gpg --decrypt --output "$backup_path.tar.gz" "$backup_path.gpg"
        backup_path="$backup_path.tar.gz"
    elif [[ -f "$backup_path.enc" ]]; then
        log_info "解密备份..."
        openssl enc -aes-256-cbc -d -in "$backup_path.enc" -out "$backup_path.tar.gz"
        backup_path="$backup_path.tar.gz"
    fi
    
    # 解压
    if [[ -f "$backup_path.tar.gz" ]]; then
        log_info "解压备份..."
        tar xzf "$backup_path.tar.gz" -C "$BACKUP_DIR"
    fi
    
    BACKUP_SESSION_DIR="$BACKUP_DIR/$BACKUP_NAME"
}

# 恢复配置
restore_configurations() {
    log_info "恢复配置..."
    
    local config_dir="$BACKUP_SESSION_DIR/configs"
    
    if [[ ! -d "$config_dir" ]]; then
        log_warning "配置备份目录不存在"
        return 0
    fi
    
    # 恢复 ConfigMaps
    if [[ -f "$config_dir/configmaps.yaml" ]]; then
        log_info "恢复 ConfigMaps..."
        kubectl apply -f "$config_dir/configmaps.yaml"
    fi
    
    # 恢复 Secrets
    if [[ -f "$config_dir/secrets.yaml" ]]; then
        log_info "恢复 Secrets..."
        kubectl apply -f "$config_dir/secrets.yaml"
    fi
    
    # 恢复服务
    if [[ -f "$config_dir/services.yaml" ]]; then
        log_info "恢复服务..."
        kubectl apply -f "$config_dir/services.yaml"
    fi
    
    # 恢复 Ingress
    if [[ -f "$config_dir/ingress.yaml" ]]; then
        log_info "恢复 Ingress..."
        kubectl apply -f "$config_dir/ingress.yaml"
    fi
    
    log_success "配置恢复完成"
}

# 恢复持久化卷
restore_persistent_volumes() {
    log_info "恢复持久化卷..."
    
    local pvc_dir="$BACKUP_SESSION_DIR/pvcs"
    
    if [[ ! -d "$pvc_dir" ]]; then
        log_warning "PVC 备份目录不存在"
        return 0
    fi
    
    # 恢复每个 PVC
    for pvc_file in "$pvc_dir"/pvc-*.yaml; do
        if [[ -f "$pvc_file" ]]; then
            local pvc_name
            pvc_name=$(basename "$pvc_file" .yaml | sed 's/pvc-//')
            
            log_info "恢复 PVC: $pvc_name"
            
            # 创建 PVC
            kubectl apply -f "$pvc_file"
            
            # 恢复数据
            local data_file="$pvc_dir/pvc-$pvc_name-data.tar.gz"
            if [[ -f "$data_file" ]]; then
                restore_pvc_data "$pvc_name" "$data_file"
            fi
        fi
    done
    
    log_success "持久化卷恢复完成"
}

# 恢复 PVC 数据
restore_pvc_data() {
    local pvc_name="$1"
    local data_file="$2"
    local restore_pod_name="restore-pod-$pvc_name"
    
    # 创建恢复 Pod YAML
    cat > "/tmp/$restore_pod_name.yaml" << EOF
apiVersion: v1
kind: Pod
metadata:
  name: $restore_pod_name
  namespace: $NAMESPACE
spec:
  restartPolicy: Never
  containers:
  - name: restore
    image: alpine:latest
    command: ["/bin/sh"]
    args: ["-c", "cd /data && tar xzf /backup/data.tar.gz && echo 'Restore completed'"]
    volumeMounts:
    - name: data-volume
      mountPath: /data
    - name: backup-volume
      mountPath: /backup
  volumes:
  - name: data-volume
    persistentVolumeClaim:
      claimName: $pvc_name
  - name: backup-volume
    emptyDir: {}
EOF
    
    # 创建 Pod
    kubectl apply -f "/tmp/$restore_pod_name.yaml"
    
    # 等待 Pod 就绪
    kubectl wait --for=condition=Ready pod/$restore_pod_name -n "$NAMESPACE" --timeout=300s
    
    # 复制数据到 Pod
    kubectl cp "$data_file" "$NAMESPACE/$restore_pod_name:/backup/data.tar.gz"
    
    # 等待恢复完成
    kubectl wait --for=condition=Succeeded pod/$restore_pod_name -n "$NAMESPACE" --timeout=600s
    
    # 清理
    kubectl delete pod "$restore_pod_name" -n "$NAMESPACE"
    rm -f "/tmp/$restore_pod_name.yaml"
    
    log_success "PVC $pvc_name 数据恢复完成"
}

# 恢复数据库
restore_database() {
    log_info "恢复数据库..."
    
    local db_dir="$BACKUP_SESSION_DIR/database"
    
    if [[ ! -d "$db_dir" ]]; then
        log_warning "数据库备份目录不存在"
        return 0
    fi
    
    # 恢复 PostgreSQL
    for sql_file in "$db_dir"/postgresql-*.sql.gz; do
        if [[ -f "$sql_file" ]]; then
            local pod_name
            pod_name=$(basename "$sql_file" .sql.gz | sed 's/postgresql-//')
            
            log_info "恢复 PostgreSQL 数据库: $pod_name"
            
            # 解压并恢复
            gunzip -c "$sql_file" | kubectl exec -i -n "$NAMESPACE" "$pod_name" -- psql -U postgres
        fi
    done
    
    # 恢复 Redis
    for rdb_file in "$db_dir"/redis-*.rdb; do
        if [[ -f "$rdb_file" ]]; then
            local pod_name
            pod_name=$(basename "$rdb_file" .rdb | sed 's/redis-//')
            
            log_info "恢复 Redis 数据: $pod_name"
            
            # 复制 RDB 文件
            kubectl cp "$rdb_file" "$NAMESPACE/$pod_name:/data/dump.rdb"
            
            # 重启 Redis
            kubectl exec -n "$NAMESPACE" "$pod_name" -- redis-cli SHUTDOWN NOSAVE
            sleep 5
        fi
    done
    
    log_success "数据库恢复完成"
}

# 恢复 Helm 发布
restore_helm_release() {
    log_info "恢复 Helm 发布..."
    
    local helm_dir="$BACKUP_SESSION_DIR/helm"
    
    if [[ ! -d "$helm_dir" ]]; then
        log_warning "Helm 备份目录不存在"
        return 0
    fi
    
    # 恢复 Chart
    if [[ -f "$helm_dir/nova-proxy-chart.tar.gz" ]]; then
        log_info "恢复 Helm Chart..."
        tar xzf "$helm_dir/nova-proxy-chart.tar.gz" -C "$PROJECT_ROOT/helm/"
    fi
    
    # 恢复发布
    if [[ -f "$helm_dir/nova-proxy-values.yaml" ]]; then
        log_info "恢复 Helm 发布..."
        helm upgrade --install nova-proxy "$PROJECT_ROOT/helm/nova-proxy" \
            -n "$NAMESPACE" \
            -f "$helm_dir/nova-proxy-values.yaml"
    fi
    
    log_success "Helm 发布恢复完成"
}

# 恢复 RBAC
restore_rbac() {
    log_info "恢复 RBAC 配置..."
    
    local rbac_dir="$BACKUP_SESSION_DIR/rbac"
    
    if [[ ! -d "$rbac_dir" ]]; then
        log_warning "RBAC 备份目录不存在"
        return 0
    fi
    
    # 恢复各种 RBAC 资源
    for rbac_file in "$rbac_dir"/*.yaml; do
        if [[ -f "$rbac_file" ]]; then
            log_info "恢复 RBAC 文件: $(basename "$rbac_file")"
            kubectl apply -f "$rbac_file"
        fi
    done
    
    log_success "RBAC 配置恢复完成"
}

# 列出备份
list_backups() {
    log_info "列出备份..."
    
    if [[ ! -d "$BACKUP_DIR" ]]; then
        log_info "备份目录不存在: $BACKUP_DIR"
        return 0
    fi
    
    echo "可用备份:"
    echo "========================================"
    
    local backup_count=0
    
    for backup_item in "$BACKUP_DIR"/*; do
        if [[ -d "$backup_item" ]] || [[ -f "$backup_item" ]]; then
            local backup_name
            backup_name=$(basename "$backup_item")
            
            # 跳过非备份文件
            if [[ ! "$backup_name" =~ ^nova-proxy-backup- ]]; then
                continue
            fi
            
            ((backup_count++))
            
            local size timestamp
            size=$(du -sh "$backup_item" 2>/dev/null | awk '{print $1}' || echo "未知")
            
            if [[ -d "$backup_item" ]]; then
                timestamp=$(stat -c %y "$backup_item" 2>/dev/null | cut -d' ' -f1,2 | cut -d'.' -f1 || echo "未知")
                echo "$backup_name (目录) - 大小: $size, 时间: $timestamp"
            else
                timestamp=$(stat -c %y "$backup_item" 2>/dev/null | cut -d' ' -f1,2 | cut -d'.' -f1 || echo "未知")
                local file_type="文件"
                if [[ "$backup_name" =~ \.tar\.gz$ ]]; then
                    file_type="压缩文件"
                elif [[ "$backup_name" =~ \.gpg$ ]] || [[ "$backup_name" =~ \.enc$ ]]; then
                    file_type="加密文件"
                fi
                echo "$backup_name ($file_type) - 大小: $size, 时间: $timestamp"
            fi
        fi
    done
    
    echo "========================================"
    echo "总计: $backup_count 个备份"
}

# 验证备份
verify_backup() {
    log_info "验证备份: $BACKUP_NAME"
    
    local backup_path="$BACKUP_DIR/$BACKUP_NAME"
    local issues=0
    
    # 检查备份是否存在
    if [[ ! -d "$backup_path" && ! -f "$backup_path.tar.gz" && ! -f "$backup_path.gpg" && ! -f "$backup_path.enc" ]]; then
        log_error "备份不存在: $BACKUP_NAME"
        return 1
    fi
    
    # 检查元数据文件
    local metadata_file
    if [[ -d "$backup_path" ]]; then
        metadata_file="$backup_path/metadata.json"
    else
        # 需要临时解压来检查
        log_info "临时解压备份进行验证..."
        local temp_dir
        temp_dir=$(mktemp -d)
        
        if [[ -f "$backup_path.tar.gz" ]]; then
            tar xzf "$backup_path.tar.gz" -C "$temp_dir"
        elif [[ -f "$backup_path.gpg" ]]; then
            gpg --decrypt --output "$temp_dir/backup.tar.gz" "$backup_path.gpg"
            tar xzf "$temp_dir/backup.tar.gz" -C "$temp_dir"
        elif [[ -f "$backup_path.enc" ]]; then
            openssl enc -aes-256-cbc -d -in "$backup_path.enc" -out "$temp_dir/backup.tar.gz"
            tar xzf "$temp_dir/backup.tar.gz" -C "$temp_dir"
        fi
        
        metadata_file="$temp_dir/$BACKUP_NAME/metadata.json"
    fi
    
    if [[ -f "$metadata_file" ]]; then
        log_success "元数据文件存在"
        
        # 验证元数据
        if jq . "$metadata_file" > /dev/null 2>&1; then
            log_success "元数据格式有效"
            
            # 显示备份信息
            local backup_env backup_ns backup_time
            backup_env=$(jq -r '.environment' "$metadata_file")
            backup_ns=$(jq -r '.namespace' "$metadata_file")
            backup_time=$(jq -r '.timestamp' "$metadata_file")
            
            log_info "备份环境: $backup_env"
            log_info "备份命名空间: $backup_ns"
            log_info "备份时间: $backup_time"
        else
            log_error "元数据格式无效"
            ((issues++))
        fi
    else
        log_error "元数据文件不存在"
        ((issues++))
    fi
    
    # 清理临时目录
    if [[ -n "${temp_dir:-}" ]]; then
        rm -rf "$temp_dir"
    fi
    
    if [[ $issues -eq 0 ]]; then
        log_success "备份验证通过"
    else
        log_error "备份验证失败，发现 $issues 个问题"
        return 1
    fi
}

# 清理旧备份
cleanup_old_backups() {
    log_info "清理 $RETENTION_DAYS 天前的备份..."
    
    if [[ ! -d "$BACKUP_DIR" ]]; then
        log_info "备份目录不存在: $BACKUP_DIR"
        return 0
    fi
    
    local deleted_count=0
    
    # 查找并删除旧备份
    find "$BACKUP_DIR" -name "nova-proxy-backup-*" -type d -mtime +"$RETENTION_DAYS" -exec rm -rf {} \; -print | while read -r deleted_backup; do
        log_info "删除旧备份: $(basename "$deleted_backup")"
        ((deleted_count++))
    done
    
    # 查找并删除旧的压缩备份
    find "$BACKUP_DIR" -name "nova-proxy-backup-*.tar.gz" -type f -mtime +"$RETENTION_DAYS" -exec rm -f {} \; -print | while read -r deleted_backup; do
        log_info "删除旧备份: $(basename "$deleted_backup")"
        ((deleted_count++))
    done
    
    # 查找并删除旧的加密备份
    find "$BACKUP_DIR" -name "nova-proxy-backup-*.gpg" -o -name "nova-proxy-backup-*.enc" -type f -mtime +"$RETENTION_DAYS" -exec rm -f {} \; -print | while read -r deleted_backup; do
        log_info "删除旧备份: $(basename "$deleted_backup")"
        ((deleted_count++))
    done
    
    log_success "清理完成，删除了 $deleted_count 个旧备份"
}

# 主函数
main() {
    parse_args "$@"
    check_dependencies
    setup_backup_env
    
    case $COMMAND in
        backup)
            create_full_backup
            ;;
        backup-config)
            backup_configurations
            ;;
        backup-data)
            backup_persistent_volumes
            backup_database
            ;;
        backup-pvc)
            backup_persistent_volumes
            ;;
        restore)
            restore_backup
            ;;
        restore-config)
            restore_configurations
            ;;
        restore-data)
            restore_persistent_volumes
            restore_database
            ;;
        restore-pvc)
            restore_persistent_volumes
            ;;
        list)
            list_backups
            ;;
        verify)
            verify_backup
            ;;
        cleanup)
            cleanup_old_backups
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