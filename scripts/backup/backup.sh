#!/bin/bash

# Nova Proxy 备份脚本
# 备份配置、数据和状态信息

set -euo pipefail

# 脚本配置
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/nova-proxy}"
LOG_FILE="${BACKUP_ROOT}/logs/backup-$(date +%Y%m%d-%H%M%S).log"

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
Nova Proxy 备份脚本

用法: $0 [选项] <类型>

备份类型:
  config      备份配置文件
  data        备份数据
  k8s         备份 Kubernetes 资源
  monitoring  备份监控数据
  full        完整备份 (默认)

选项:
  -h, --help              显示帮助信息
  -n, --namespace NS      指定命名空间
  -o, --output DIR        指定输出目录
  -c, --compress          压缩备份文件
  -e, --encrypt           加密备份文件
  -r, --retention DAYS    设置备份保留天数 (默认: 30)
  -s, --storage TYPE      存储类型 (local/s3/gcs) (默认: local)
  --s3-bucket BUCKET      S3 存储桶名称
  --s3-region REGION      S3 区域
  --gcs-bucket BUCKET     GCS 存储桶名称
  --exclude PATTERN       排除文件模式
  --dry-run              干运行模式
  --verify               验证备份完整性

示例:
  $0 full                           # 完整备份
  $0 config -c -e                  # 压缩加密配置备份
  $0 k8s -n nova-proxy-prod        # 备份生产环境 K8s 资源
  $0 data -s s3 --s3-bucket backups # 备份到 S3

EOF
}

# 检查依赖
check_dependencies() {
    log_info "检查依赖工具..."
    
    local deps=("kubectl" "tar" "gzip")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            error_exit "缺少依赖工具: $dep"
        fi
    done
    
    # 检查可选依赖
    if [[ "$ENCRYPT" == "true" ]] && ! command -v "gpg" &> /dev/null; then
        error_exit "加密功能需要 gpg 工具"
    fi
    
    if [[ "$STORAGE_TYPE" == "s3" ]] && ! command -v "aws" &> /dev/null; then
        error_exit "S3 存储需要 aws cli 工具"
    fi
    
    if [[ "$STORAGE_TYPE" == "gcs" ]] && ! command -v "gsutil" &> /dev/null; then
        error_exit "GCS 存储需要 gsutil 工具"
    fi
    
    log_success "依赖检查完成"
}

# 创建备份目录
create_backup_dirs() {
    local backup_date="$(date +%Y%m%d-%H%M%S)"
    BACKUP_DIR="${BACKUP_ROOT}/${backup_date}"
    
    log_info "创建备份目录: $BACKUP_DIR"
    
    mkdir -p "$BACKUP_DIR"/{config,data,k8s,monitoring,logs}
    mkdir -p "${BACKUP_ROOT}/logs"
    
    # 创建备份元数据
    cat > "${BACKUP_DIR}/metadata.json" << EOF
{
  "backup_date": "$backup_date",
  "backup_type": "$BACKUP_TYPE",
  "namespace": "$NAMESPACE",
  "hostname": "$(hostname)",
  "user": "$(whoami)",
  "script_version": "1.0.0",
  "compress": $COMPRESS,
  "encrypt": $ENCRYPT,
  "storage_type": "$STORAGE_TYPE"
}
EOF
    
    log_success "备份目录创建完成"
}

# 备份配置文件
backup_config() {
    log_info "备份配置文件..."
    
    local config_dir="${BACKUP_DIR}/config"
    
    # 备份项目配置
    if [[ -d "$PROJECT_ROOT" ]]; then
        log_info "备份项目配置..."
        
        # 备份 Kubernetes 配置
        if [[ -d "${PROJECT_ROOT}/kubernetes" ]]; then
            cp -r "${PROJECT_ROOT}/kubernetes" "${config_dir}/"
        fi
        
        # 备份 Helm 配置
        if [[ -d "${PROJECT_ROOT}/helm" ]]; then
            cp -r "${PROJECT_ROOT}/helm" "${config_dir}/"
        fi
        
        # 备份脚本
        if [[ -d "${PROJECT_ROOT}/scripts" ]]; then
            cp -r "${PROJECT_ROOT}/scripts" "${config_dir}/"
        fi
        
        # 备份配置文件
        for config_file in "Dockerfile" "docker-compose.yml" ".env" "config.yaml" "config.toml"; do
            if [[ -f "${PROJECT_ROOT}/${config_file}" ]]; then
                cp "${PROJECT_ROOT}/${config_file}" "${config_dir}/"
            fi
        done
    fi
    
    # 备份系统配置
    log_info "备份系统配置..."
    
    # 备份 systemd 服务文件
    if [[ -f "/etc/systemd/system/nova-proxy.service" ]]; then
        cp "/etc/systemd/system/nova-proxy.service" "${config_dir}/"
    fi
    
    # 备份 nginx 配置
    if [[ -d "/etc/nginx/sites-available" ]]; then
        find /etc/nginx/sites-available -name "*nova-proxy*" -exec cp {} "${config_dir}/" \;
    fi
    
    # 备份证书
    if [[ -d "/etc/ssl/nova-proxy" ]]; then
        cp -r "/etc/ssl/nova-proxy" "${config_dir}/ssl/"
    fi
    
    log_success "配置文件备份完成"
}

# 备份 Kubernetes 资源
backup_k8s() {
    log_info "备份 Kubernetes 资源..."
    
    local k8s_dir="${BACKUP_DIR}/k8s"
    
    if [[ -z "$NAMESPACE" ]]; then
        log_warn "未指定命名空间，跳过 K8s 备份"
        return
    fi
    
    # 检查命名空间是否存在
    if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log_warn "命名空间 $NAMESPACE 不存在，跳过 K8s 备份"
        return
    fi
    
    # 备份所有资源
    log_info "备份命名空间 $NAMESPACE 的所有资源..."
    kubectl get all,configmap,secret,pvc,ingress,networkpolicy,servicemonitor,prometheusrule \
        -n "$NAMESPACE" -o yaml > "${k8s_dir}/all-resources.yaml"
    
    # 备份特定资源
    local resources=("deployment" "service" "configmap" "secret" "ingress" "pvc")
    for resource in "${resources[@]}"; do
        if kubectl get "$resource" -n "$NAMESPACE" &> /dev/null; then
            kubectl get "$resource" -n "$NAMESPACE" -o yaml > "${k8s_dir}/${resource}.yaml"
        fi
    done
    
    # 备份 Helm releases
    if command -v "helm" &> /dev/null; then
        log_info "备份 Helm releases..."
        helm list -n "$NAMESPACE" -o yaml > "${k8s_dir}/helm-releases.yaml"
        
        # 备份每个 release 的详细信息
        helm list -n "$NAMESPACE" -q | while read -r release; do
            if [[ -n "$release" ]]; then
                helm get all "$release" -n "$NAMESPACE" > "${k8s_dir}/helm-${release}.yaml"
            fi
        done
    fi
    
    # 备份集群级别资源
    log_info "备份集群级别资源..."
    kubectl get clusterrole,clusterrolebinding,storageclass,persistentvolume \
        -l app.kubernetes.io/name=nova-proxy -o yaml > "${k8s_dir}/cluster-resources.yaml" 2>/dev/null || true
    
    log_success "Kubernetes 资源备份完成"
}

# 备份数据
backup_data() {
    log_info "备份数据..."
    
    local data_dir="${BACKUP_DIR}/data"
    
    # 备份 Redis 数据
    if kubectl get pod -l app=redis -n "$NAMESPACE" &> /dev/null; then
        log_info "备份 Redis 数据..."
        kubectl exec -n "$NAMESPACE" deployment/redis -- redis-cli BGSAVE
        kubectl cp "$NAMESPACE/$(kubectl get pod -l app=redis -n "$NAMESPACE" -o jsonpath='{.items[0].metadata.name}'):/data/dump.rdb" "${data_dir}/redis-dump.rdb"
    fi
    
    # 备份持久化卷数据
    log_info "备份持久化卷数据..."
    kubectl get pvc -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | while read -r pvc; do
        if [[ -n "$pvc" ]]; then
            log_info "备份 PVC: $pvc"
            
            # 创建临时 Pod 来访问 PVC
            kubectl run backup-pod-"$pvc" --rm -i --restart=Never \
                --image=alpine:latest \
                --overrides='{
                  "spec": {
                    "containers": [{
                      "name": "backup",
                      "image": "alpine:latest",
                      "command": ["tar", "czf", "/backup/'"$pvc"'.tar.gz", "-C", "/data", "."],
                      "volumeMounts": [{
                        "name": "data",
                        "mountPath": "/data"
                      }, {
                        "name": "backup",
                        "mountPath": "/backup"
                      }]
                    }],
                    "volumes": [{
                      "name": "data",
                      "persistentVolumeClaim": {
                        "claimName": "'"$pvc"'"
                      }
                    }, {
                      "name": "backup",
                      "hostPath": {
                        "path": "'"$data_dir"'"
                      }
                    }]
                  }
                }' \
                -n "$NAMESPACE" || log_warn "备份 PVC $pvc 失败"
        fi
    done
    
    log_success "数据备份完成"
}

# 备份监控数据
backup_monitoring() {
    log_info "备份监控数据..."
    
    local monitoring_dir="${BACKUP_DIR}/monitoring"
    local monitoring_namespace="${MONITORING_NAMESPACE:-monitoring}"
    
    # 备份 Prometheus 配置和规则
    if kubectl get namespace "$monitoring_namespace" &> /dev/null; then
        log_info "备份 Prometheus 配置..."
        
        # 备份 Prometheus 配置
        kubectl get configmap prometheus-server -n "$monitoring_namespace" -o yaml > "${monitoring_dir}/prometheus-config.yaml" 2>/dev/null || true
        
        # 备份告警规则
        kubectl get prometheusrule -n "$monitoring_namespace" -o yaml > "${monitoring_dir}/prometheus-rules.yaml" 2>/dev/null || true
        
        # 备份 Grafana 配置
        kubectl get configmap prometheus-grafana -n "$monitoring_namespace" -o yaml > "${monitoring_dir}/grafana-config.yaml" 2>/dev/null || true
        
        # 备份 Grafana 仪表板
        kubectl get configmap -l grafana_dashboard=1 -n "$monitoring_namespace" -o yaml > "${monitoring_dir}/grafana-dashboards.yaml" 2>/dev/null || true
        
        # 备份 Alertmanager 配置
        kubectl get secret alertmanager-prometheus-alertmanager -n "$monitoring_namespace" -o yaml > "${monitoring_dir}/alertmanager-config.yaml" 2>/dev/null || true
    fi
    
    log_success "监控数据备份完成"
}

# 压缩备份
compress_backup() {
    if [[ "$COMPRESS" != "true" ]]; then
        return
    fi
    
    log_info "压缩备份文件..."
    
    local backup_name="$(basename "$BACKUP_DIR")"
    local compressed_file="${BACKUP_ROOT}/${backup_name}.tar.gz"
    
    cd "$(dirname "$BACKUP_DIR")"
    tar czf "$compressed_file" "$backup_name"
    
    # 验证压缩文件
    if tar tzf "$compressed_file" > /dev/null; then
        log_success "备份压缩完成: $compressed_file"
        
        # 删除原始目录
        rm -rf "$BACKUP_DIR"
        BACKUP_FILE="$compressed_file"
    else
        error_exit "备份压缩失败"
    fi
}

# 加密备份
encrypt_backup() {
    if [[ "$ENCRYPT" != "true" ]]; then
        return
    fi
    
    log_info "加密备份文件..."
    
    local source_file="${BACKUP_FILE:-$BACKUP_DIR}"
    local encrypted_file="${source_file}.gpg"
    
    # 使用对称加密
    gpg --symmetric --cipher-algo AES256 --compress-algo 2 --s2k-mode 3 \
        --s2k-digest-algo SHA512 --s2k-count 65536 \
        --output "$encrypted_file" "$source_file"
    
    if [[ -f "$encrypted_file" ]]; then
        log_success "备份加密完成: $encrypted_file"
        
        # 删除原始文件
        rm -rf "$source_file"
        BACKUP_FILE="$encrypted_file"
    else
        error_exit "备份加密失败"
    fi
}

# 上传到云存储
upload_to_cloud() {
    if [[ "$STORAGE_TYPE" == "local" ]]; then
        return
    fi
    
    log_info "上传备份到云存储 ($STORAGE_TYPE)..."
    
    local backup_file="${BACKUP_FILE:-$BACKUP_DIR}"
    local backup_name="$(basename "$backup_file")"
    
    case "$STORAGE_TYPE" in
        s3)
            if [[ -z "$S3_BUCKET" ]]; then
                error_exit "S3 存储桶未指定"
            fi
            
            aws s3 cp "$backup_file" "s3://${S3_BUCKET}/nova-proxy/${backup_name}" \
                ${S3_REGION:+--region $S3_REGION}
            
            log_success "备份上传到 S3 完成: s3://${S3_BUCKET}/nova-proxy/${backup_name}"
            ;;
        
        gcs)
            if [[ -z "$GCS_BUCKET" ]]; then
                error_exit "GCS 存储桶未指定"
            fi
            
            gsutil cp "$backup_file" "gs://${GCS_BUCKET}/nova-proxy/${backup_name}"
            
            log_success "备份上传到 GCS 完成: gs://${GCS_BUCKET}/nova-proxy/${backup_name}"
            ;;
        
        *)
            error_exit "不支持的存储类型: $STORAGE_TYPE"
            ;;
    esac
}

# 验证备份
verify_backup() {
    if [[ "$VERIFY" != "true" ]]; then
        return
    fi
    
    log_info "验证备份完整性..."
    
    local backup_file="${BACKUP_FILE:-$BACKUP_DIR}"
    
    if [[ -f "$backup_file" ]]; then
        # 验证压缩文件
        if [[ "$backup_file" == *.tar.gz ]]; then
            if tar tzf "$backup_file" > /dev/null; then
                log_success "压缩文件验证通过"
            else
                error_exit "压缩文件验证失败"
            fi
        fi
        
        # 验证加密文件
        if [[ "$backup_file" == *.gpg ]]; then
            if gpg --list-packets "$backup_file" > /dev/null 2>&1; then
                log_success "加密文件验证通过"
            else
                error_exit "加密文件验证失败"
            fi
        fi
        
        # 计算校验和
        local checksum
        checksum=$(sha256sum "$backup_file" | cut -d' ' -f1)
        echo "$checksum  $(basename "$backup_file")" > "${backup_file}.sha256"
        
        log_success "备份校验和: $checksum"
    else
        log_info "验证备份目录结构..."
        
        local required_dirs=("config" "k8s" "monitoring")
        for dir in "${required_dirs[@]}"; do
            if [[ ! -d "${backup_file}/${dir}" ]]; then
                log_warn "缺少备份目录: $dir"
            fi
        done
        
        log_success "备份目录验证完成"
    fi
}

# 清理旧备份
cleanup_old_backups() {
    log_info "清理旧备份 (保留 $RETENTION 天)..."
    
    # 清理本地备份
    find "$BACKUP_ROOT" -name "20*" -type d -mtime +"$RETENTION" -exec rm -rf {} + 2>/dev/null || true
    find "$BACKUP_ROOT" -name "*.tar.gz" -mtime +"$RETENTION" -delete 2>/dev/null || true
    find "$BACKUP_ROOT" -name "*.gpg" -mtime +"$RETENTION" -delete 2>/dev/null || true
    
    # 清理云存储备份
    case "$STORAGE_TYPE" in
        s3)
            if [[ -n "$S3_BUCKET" ]]; then
                aws s3 ls "s3://${S3_BUCKET}/nova-proxy/" | \
                    awk -v date="$(date -d "$RETENTION days ago" +%Y-%m-%d)" '$1 < date {print $4}' | \
                    while read -r file; do
                        aws s3 rm "s3://${S3_BUCKET}/nova-proxy/$file"
                    done
            fi
            ;;
        
        gcs)
            if [[ -n "$GCS_BUCKET" ]]; then
                gsutil ls "gs://${GCS_BUCKET}/nova-proxy/" | \
                    while read -r file; do
                        local file_date
                        file_date=$(gsutil stat "$file" | grep "Creation time" | cut -d: -f2- | xargs)
                        if [[ "$(date -d "$file_date" +%s)" -lt "$(date -d "$RETENTION days ago" +%s)" ]]; then
                            gsutil rm "$file"
                        fi
                    done
            fi
            ;;
    esac
    
    log_success "旧备份清理完成"
}

# 生成备份报告
generate_report() {
    log_info "生成备份报告..."
    
    local report_file="${BACKUP_ROOT}/backup-report-$(date +%Y%m%d).txt"
    
    cat > "$report_file" << EOF
Nova Proxy 备份报告
==================

备份时间: $(date)
备份类型: $BACKUP_TYPE
命名空间: ${NAMESPACE:-N/A}
存储类型: $STORAGE_TYPE
压缩: $([ "$COMPRESS" == "true" ] && echo "是" || echo "否")
加密: $([ "$ENCRYPT" == "true" ] && echo "是" || echo "否")

备份位置:
$([ -n "${BACKUP_FILE:-}" ] && echo "文件: $BACKUP_FILE" || echo "目录: $BACKUP_DIR")

备份大小:
$(du -sh "${BACKUP_FILE:-$BACKUP_DIR}" | cut -f1)

备份内容:
$(find "${BACKUP_FILE:-$BACKUP_DIR}" -type f | wc -l) 个文件

日志文件: $LOG_FILE
EOF
    
    log_success "备份报告生成完成: $report_file"
}

# 主函数
main() {
    # 默认值
    local backup_type="full"
    local namespace=""
    local output_dir=""
    local compress="false"
    local encrypt="false"
    local retention="30"
    local storage_type="local"
    local s3_bucket=""
    local s3_region=""
    local gcs_bucket=""
    local exclude_pattern=""
    local dry_run="false"
    local verify="false"
    
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
            -o|--output)
                output_dir="$2"
                shift 2
                ;;
            -c|--compress)
                compress="true"
                shift
                ;;
            -e|--encrypt)
                encrypt="true"
                shift
                ;;
            -r|--retention)
                retention="$2"
                shift 2
                ;;
            -s|--storage)
                storage_type="$2"
                shift 2
                ;;
            --s3-bucket)
                s3_bucket="$2"
                shift 2
                ;;
            --s3-region)
                s3_region="$2"
                shift 2
                ;;
            --gcs-bucket)
                gcs_bucket="$2"
                shift 2
                ;;
            --exclude)
                exclude_pattern="$2"
                shift 2
                ;;
            --dry-run)
                dry_run="true"
                shift
                ;;
            --verify)
                verify="true"
                shift
                ;;
            -*)
                error_exit "未知选项: $1"
                ;;
            *)
                backup_type="$1"
                shift
                ;;
        esac
    done
    
    # 设置全局变量
    BACKUP_TYPE="$backup_type"
    NAMESPACE="$namespace"
    COMPRESS="$compress"
    ENCRYPT="$encrypt"
    RETENTION="$retention"
    STORAGE_TYPE="$storage_type"
    S3_BUCKET="$s3_bucket"
    S3_REGION="$s3_region"
    GCS_BUCKET="$gcs_bucket"
    VERIFY="$verify"
    
    # 设置输出目录
    if [[ -n "$output_dir" ]]; then
        BACKUP_ROOT="$output_dir"
    fi
    
    # 显示备份信息
    log_info "Nova Proxy 备份开始"
    log_info "备份类型: $backup_type"
    log_info "命名空间: ${namespace:-N/A}"
    log_info "输出目录: $BACKUP_ROOT"
    log_info "存储类型: $storage_type"
    log_info "保留天数: $retention"
    log_info "日志文件: $LOG_FILE"
    
    if [[ "$dry_run" == "true" ]]; then
        log_warn "干运行模式，不会执行实际备份"
        exit 0
    fi
    
    # 执行备份流程
    check_dependencies
    create_backup_dirs
    
    # 根据备份类型执行相应的备份
    case "$backup_type" in
        config)
            backup_config
            ;;
        data)
            backup_data
            ;;
        k8s)
            backup_k8s
            ;;
        monitoring)
            backup_monitoring
            ;;
        full)
            backup_config
            backup_k8s
            backup_data
            backup_monitoring
            ;;
        *)
            error_exit "不支持的备份类型: $backup_type"
            ;;
    esac
    
    compress_backup
    encrypt_backup
    verify_backup
    upload_to_cloud
    cleanup_old_backups
    generate_report
    
    log_success "Nova Proxy 备份完成!"
    log_info "备份位置: ${BACKUP_FILE:-$BACKUP_DIR}"
    log_info "日志文件: $LOG_FILE"
}

# 执行主函数
main "$@"