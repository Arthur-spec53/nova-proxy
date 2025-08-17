#!/bin/bash

# Nova Proxy 系统清理脚本
# 清理日志、临时文件、旧镜像等

set -euo pipefail

# 脚本配置
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LOG_FILE="/tmp/nova-proxy-cleanup-$(date +%Y%m%d-%H%M%S).log"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 清理统计
CLEANED_FILES=0
CLEANED_SIZE=0
CLEANED_IMAGES=0
CLEANED_CONTAINERS=0

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

# 显示帮助信息
show_help() {
    cat << EOF
Nova Proxy 系统清理脚本

用法: $0 [选项]

选项:
  -h, --help              显示帮助信息
  -n, --namespace NS      指定命名空间
  -d, --days DAYS         保留天数 (默认: 7)
  -s, --size SIZE         最大日志大小 (默认: 100M)
  --dry-run              干运行模式，不执行实际清理
  -v, --verbose          详细输出
  -q, --quiet            静默模式
  --logs                 清理日志文件
  --temp                 清理临时文件
  --docker               清理 Docker 资源
  --k8s                  清理 Kubernetes 资源
  --cache                清理缓存文件
  --all                  执行所有清理 (默认)
  --force                强制清理，不询问确认

清理类型:
  --logs                 清理应用日志和系统日志
  --temp                 清理临时文件和缓存
  --docker               清理未使用的 Docker 镜像和容器
  --k8s                  清理已完成的 Pod 和 Job
  --cache                清理应用缓存和构建缓存

示例:
  $0                              # 执行所有清理
  $0 --logs -d 3                  # 清理 3 天前的日志
  $0 --docker --dry-run           # 干运行 Docker 清理
  $0 --k8s -n nova-proxy-prod     # 清理生产环境 K8s 资源
  $0 --temp --cache --force       # 强制清理临时文件和缓存

EOF
}

# 获取文件大小（字节）
get_file_size() {
    local file="$1"
    if [[ -f "$file" ]]; then
        stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo 0
    else
        echo 0
    fi
}

# 转换字节为人类可读格式
format_size() {
    local bytes="$1"
    if (( bytes > 1073741824 )); then
        printf "%.2fG" "$(echo "scale=2; $bytes / 1073741824" | bc)"
    elif (( bytes > 1048576 )); then
        printf "%.2fM" "$(echo "scale=2; $bytes / 1048576" | bc)"
    elif (( bytes > 1024 )); then
        printf "%.2fK" "$(echo "scale=2; $bytes / 1024" | bc)"
    else
        printf "%dB" "$bytes"
    fi
}

# 解析大小字符串为字节
parse_size() {
    local size_str="$1"
    local number unit
    
    if [[ "$size_str" =~ ^([0-9]+)([KMGT]?)$ ]]; then
        number="${BASH_REMATCH[1]}"
        unit="${BASH_REMATCH[2]}"
        
        case "$unit" in
            K|k) echo $((number * 1024)) ;;
            M|m) echo $((number * 1048576)) ;;
            G|g) echo $((number * 1073741824)) ;;
            T|t) echo $((number * 1099511627776)) ;;
            *) echo "$number" ;;
        esac
    else
        echo 0
    fi
}

# 清理日志文件
cleanup_logs() {
    local days="$1"
    local max_size="$2"
    local dry_run="$3"
    
    log_info "清理日志文件..."
    
    local log_dirs=(
        "/var/log"
        "/tmp"
        "$HOME/.cache/nova-proxy"
        "$PROJECT_ROOT/logs"
    )
    
    local log_patterns=(
        "*.log"
        "*.log.*"
        "nova-proxy*.log"
        "access.log*"
        "error.log*"
        "audit.log*"
    )
    
    for log_dir in "${log_dirs[@]}"; do
        if [[ ! -d "$log_dir" ]]; then
            continue
        fi
        
        log_info "检查目录: $log_dir"
        
        for pattern in "${log_patterns[@]}"; do
            while IFS= read -r -d '' file; do
                local file_size
                file_size=$(get_file_size "$file")
                local file_age
                file_age=$(find "$file" -mtime +"$days" -print 2>/dev/null | wc -l)
                
                local should_delete=false
                local reason=""
                
                # 检查文件年龄
                if [[ "$file_age" -gt 0 ]]; then
                    should_delete=true
                    reason="超过 $days 天"
                fi
                
                # 检查文件大小
                local max_size_bytes
                max_size_bytes=$(parse_size "$max_size")
                if [[ "$file_size" -gt "$max_size_bytes" ]]; then
                    should_delete=true
                    reason="${reason:+$reason, }超过大小限制 $(format_size $file_size)"
                fi
                
                if [[ "$should_delete" == "true" ]]; then
                    if [[ "$dry_run" == "true" ]]; then
                        log_info "[DRY-RUN] 将删除: $file ($reason)"
                    else
                        log_info "删除日志文件: $file ($reason)"
                        if rm -f "$file"; then
                            CLEANED_FILES=$((CLEANED_FILES + 1))
                            CLEANED_SIZE=$((CLEANED_SIZE + file_size))
                        else
                            log_error "删除失败: $file"
                        fi
                    fi
                fi
            done < <(find "$log_dir" -name "$pattern" -type f -print0 2>/dev/null)
        done
    done
    
    # 清理系统日志
    if command -v journalctl &> /dev/null; then
        log_info "清理系统日志..."
        
        if [[ "$dry_run" == "true" ]]; then
            log_info "[DRY-RUN] 将清理 $days 天前的系统日志"
        else
            if journalctl --vacuum-time="${days}d" &> /dev/null; then
                log_success "系统日志清理完成"
            else
                log_warn "系统日志清理失败"
            fi
        fi
    fi
    
    # 清理 logrotate 压缩文件
    log_info "清理压缩日志文件..."
    local compressed_logs
    compressed_logs=$(find /var/log -name "*.gz" -o -name "*.bz2" -o -name "*.xz" -mtime +"$days" 2>/dev/null | wc -l)
    
    if [[ "$compressed_logs" -gt 0 ]]; then
        if [[ "$dry_run" == "true" ]]; then
            log_info "[DRY-RUN] 将删除 $compressed_logs 个压缩日志文件"
        else
            find /var/log -name "*.gz" -o -name "*.bz2" -o -name "*.xz" -mtime +"$days" -delete 2>/dev/null
            log_success "删除了 $compressed_logs 个压缩日志文件"
            CLEANED_FILES=$((CLEANED_FILES + compressed_logs))
        fi
    fi
}

# 清理临时文件
cleanup_temp() {
    local days="$1"
    local dry_run="$2"
    
    log_info "清理临时文件..."
    
    local temp_dirs=(
        "/tmp"
        "/var/tmp"
        "$HOME/.cache"
        "$HOME/.tmp"
        "$PROJECT_ROOT/tmp"
        "$PROJECT_ROOT/.cache"
    )
    
    local temp_patterns=(
        "nova-proxy-*"
        "*.tmp"
        "*.temp"
        "core.*"
        "*.pid"
        "*.lock"
    )
    
    for temp_dir in "${temp_dirs[@]}"; do
        if [[ ! -d "$temp_dir" ]]; then
            continue
        fi
        
        log_info "检查临时目录: $temp_dir"
        
        for pattern in "${temp_patterns[@]}"; do
            local temp_files
            temp_files=$(find "$temp_dir" -name "$pattern" -mtime +"$days" 2>/dev/null | wc -l)
            
            if [[ "$temp_files" -gt 0 ]]; then
                if [[ "$dry_run" == "true" ]]; then
                    log_info "[DRY-RUN] 将删除 $temp_files 个临时文件 ($pattern)"
                else
                    local deleted_size
                    deleted_size=$(find "$temp_dir" -name "$pattern" -mtime +"$days" -exec stat -f%z {} + 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
                    
                    find "$temp_dir" -name "$pattern" -mtime +"$days" -delete 2>/dev/null
                    log_success "删除了 $temp_files 个临时文件 ($pattern)"
                    
                    CLEANED_FILES=$((CLEANED_FILES + temp_files))
                    CLEANED_SIZE=$((CLEANED_SIZE + deleted_size))
                fi
            fi
        done
    done
    
    # 清理空目录
    log_info "清理空目录..."
    for temp_dir in "${temp_dirs[@]}"; do
        if [[ -d "$temp_dir" ]]; then
            local empty_dirs
            empty_dirs=$(find "$temp_dir" -type d -empty 2>/dev/null | wc -l)
            
            if [[ "$empty_dirs" -gt 0 ]]; then
                if [[ "$dry_run" == "true" ]]; then
                    log_info "[DRY-RUN] 将删除 $empty_dirs 个空目录"
                else
                    find "$temp_dir" -type d -empty -delete 2>/dev/null
                    log_success "删除了 $empty_dirs 个空目录"
                fi
            fi
        fi
    done
}

# 清理 Docker 资源
cleanup_docker() {
    local days="$1"
    local dry_run="$2"
    
    log_info "清理 Docker 资源..."
    
    if ! command -v docker &> /dev/null; then
        log_warn "Docker 未安装，跳过 Docker 清理"
        return
    fi
    
    # 清理停止的容器
    log_info "清理停止的容器..."
    local stopped_containers
    stopped_containers=$(docker ps -aq --filter "status=exited" --filter "status=created" | wc -l)
    
    if [[ "$stopped_containers" -gt 0 ]]; then
        if [[ "$dry_run" == "true" ]]; then
            log_info "[DRY-RUN] 将删除 $stopped_containers 个停止的容器"
        else
            docker container prune -f &> /dev/null
            log_success "删除了 $stopped_containers 个停止的容器"
            CLEANED_CONTAINERS=$((CLEANED_CONTAINERS + stopped_containers))
        fi
    fi
    
    # 清理未使用的镜像
    log_info "清理未使用的镜像..."
    local dangling_images
    dangling_images=$(docker images -f "dangling=true" -q | wc -l)
    
    if [[ "$dangling_images" -gt 0 ]]; then
        if [[ "$dry_run" == "true" ]]; then
            log_info "[DRY-RUN] 将删除 $dangling_images 个悬空镜像"
        else
            docker image prune -f &> /dev/null
            log_success "删除了 $dangling_images 个悬空镜像"
            CLEANED_IMAGES=$((CLEANED_IMAGES + dangling_images))
        fi
    fi
    
    # 清理旧的 Nova Proxy 镜像
    log_info "清理旧的 Nova Proxy 镜像..."
    local old_images
    old_images=$(docker images --format "table {{.Repository}}:{{.Tag}}\t{{.CreatedAt}}" | grep "nova-proxy" | awk -v days="$days" '
        {
            # 解析创建时间
            created = $2 " " $3 " " $4 " " $5 " " $6
            cmd = "date -d \"" created "\" +%s"
            cmd | getline created_timestamp
            close(cmd)
            
            # 获取当前时间戳
            "date +%s" | getline current_timestamp
            close("date +%s")
            
            # 计算天数差
            age_days = (current_timestamp - created_timestamp) / 86400
            
            if (age_days > days) {
                print $1
            }
        }
    ' | wc -l)
    
    if [[ "$old_images" -gt 0 ]]; then
        if [[ "$dry_run" == "true" ]]; then
            log_info "[DRY-RUN] 将删除 $old_images 个旧的 Nova Proxy 镜像"
        else
            docker images --format "table {{.Repository}}:{{.Tag}}\t{{.CreatedAt}}" | grep "nova-proxy" | awk -v days="$days" '
                {
                    created = $2 " " $3 " " $4 " " $5 " " $6
                    cmd = "date -d \"" created "\" +%s"
                    cmd | getline created_timestamp
                    close(cmd)
                    
                    "date +%s" | getline current_timestamp
                    close("date +%s")
                    
                    age_days = (current_timestamp - created_timestamp) / 86400
                    
                    if (age_days > days) {
                        system("docker rmi " $1 " 2>/dev/null")
                    }
                }'
            log_success "删除了 $old_images 个旧的 Nova Proxy 镜像"
            CLEANED_IMAGES=$((CLEANED_IMAGES + old_images))
        fi
    fi
    
    # 清理未使用的网络
    log_info "清理未使用的网络..."
    if [[ "$dry_run" == "true" ]]; then
        log_info "[DRY-RUN] 将清理未使用的 Docker 网络"
    else
        docker network prune -f &> /dev/null
        log_success "清理了未使用的 Docker 网络"
    fi
    
    # 清理未使用的卷
    log_info "清理未使用的卷..."
    if [[ "$dry_run" == "true" ]]; then
        log_info "[DRY-RUN] 将清理未使用的 Docker 卷"
    else
        docker volume prune -f &> /dev/null
        log_success "清理了未使用的 Docker 卷"
    fi
    
    # 清理构建缓存
    log_info "清理构建缓存..."
    if [[ "$dry_run" == "true" ]]; then
        log_info "[DRY-RUN] 将清理 Docker 构建缓存"
    else
        docker builder prune -f &> /dev/null
        log_success "清理了 Docker 构建缓存"
    fi
}

# 清理 Kubernetes 资源
cleanup_k8s() {
    local namespace="$1"
    local days="$2"
    local dry_run="$3"
    
    log_info "清理 Kubernetes 资源..."
    
    if ! command -v kubectl &> /dev/null; then
        log_warn "kubectl 未安装，跳过 K8s 清理"
        return
    fi
    
    # 清理已完成的 Pod
    log_info "清理已完成的 Pod..."
    local completed_pods
    if [[ -n "$namespace" ]]; then
        completed_pods=$(kubectl get pods -n "$namespace" --field-selector=status.phase=Succeeded,status.phase=Failed -o name 2>/dev/null | wc -l)
    else
        completed_pods=$(kubectl get pods --all-namespaces --field-selector=status.phase=Succeeded,status.phase=Failed -o name 2>/dev/null | wc -l)
    fi
    
    if [[ "$completed_pods" -gt 0 ]]; then
        if [[ "$dry_run" == "true" ]]; then
            log_info "[DRY-RUN] 将删除 $completed_pods 个已完成的 Pod"
        else
            if [[ -n "$namespace" ]]; then
                kubectl delete pods -n "$namespace" --field-selector=status.phase=Succeeded,status.phase=Failed &> /dev/null
            else
                kubectl delete pods --all-namespaces --field-selector=status.phase=Succeeded,status.phase=Failed &> /dev/null
            fi
            log_success "删除了 $completed_pods 个已完成的 Pod"
        fi
    fi
    
    # 清理已完成的 Job
    log_info "清理已完成的 Job..."
    local completed_jobs
    if [[ -n "$namespace" ]]; then
        completed_jobs=$(kubectl get jobs -n "$namespace" --field-selector=status.successful=1 -o name 2>/dev/null | wc -l)
    else
        completed_jobs=$(kubectl get jobs --all-namespaces --field-selector=status.successful=1 -o name 2>/dev/null | wc -l)
    fi
    
    if [[ "$completed_jobs" -gt 0 ]]; then
        if [[ "$dry_run" == "true" ]]; then
            log_info "[DRY-RUN] 将删除 $completed_jobs 个已完成的 Job"
        else
            if [[ -n "$namespace" ]]; then
                kubectl delete jobs -n "$namespace" --field-selector=status.successful=1 &> /dev/null
            else
                kubectl delete jobs --all-namespaces --field-selector=status.successful=1 &> /dev/null
            fi
            log_success "删除了 $completed_jobs 个已完成的 Job"
        fi
    fi
    
    # 清理旧的 ReplicaSet
    log_info "清理旧的 ReplicaSet..."
    if [[ -n "$namespace" ]]; then
        local old_replicasets
        old_replicasets=$(kubectl get rs -n "$namespace" -o jsonpath='{.items[?(@.spec.replicas==0)].metadata.name}' | wc -w)
        
        if [[ "$old_replicasets" -gt 0 ]]; then
            if [[ "$dry_run" == "true" ]]; then
                log_info "[DRY-RUN] 将删除 $old_replicasets 个旧的 ReplicaSet"
            else
                kubectl get rs -n "$namespace" -o jsonpath='{.items[?(@.spec.replicas==0)].metadata.name}' | xargs -r kubectl delete rs -n "$namespace" &> /dev/null
                log_success "删除了 $old_replicasets 个旧的 ReplicaSet"
            fi
        fi
    fi
    
    # 清理 Evicted Pod
    log_info "清理被驱逐的 Pod..."
    local evicted_pods
    if [[ -n "$namespace" ]]; then
        evicted_pods=$(kubectl get pods -n "$namespace" --field-selector=status.phase=Failed -o jsonpath='{.items[?(@.status.reason=="Evicted")].metadata.name}' | wc -w)
    else
        evicted_pods=$(kubectl get pods --all-namespaces --field-selector=status.phase=Failed -o jsonpath='{.items[?(@.status.reason=="Evicted")].metadata.name}' | wc -w)
    fi
    
    if [[ "$evicted_pods" -gt 0 ]]; then
        if [[ "$dry_run" == "true" ]]; then
            log_info "[DRY-RUN] 将删除 $evicted_pods 个被驱逐的 Pod"
        else
            if [[ -n "$namespace" ]]; then
                kubectl get pods -n "$namespace" --field-selector=status.phase=Failed -o jsonpath='{.items[?(@.status.reason=="Evicted")].metadata.name}' | xargs -r kubectl delete pod -n "$namespace" &> /dev/null
            else
                kubectl get pods --all-namespaces --field-selector=status.phase=Failed -o jsonpath='{.items[?(@.status.reason=="Evicted")].metadata.name}' | xargs -r kubectl delete pod --all-namespaces &> /dev/null
            fi
            log_success "删除了 $evicted_pods 个被驱逐的 Pod"
        fi
    fi
}

# 清理缓存文件
cleanup_cache() {
    local days="$1"
    local dry_run="$2"
    
    log_info "清理缓存文件..."
    
    local cache_dirs=(
        "$HOME/.cache"
        "$PROJECT_ROOT/.cache"
        "$PROJECT_ROOT/node_modules/.cache"
        "$PROJECT_ROOT/target/debug"
        "$PROJECT_ROOT/target/release"
        "/var/cache"
    )
    
    for cache_dir in "${cache_dirs[@]}"; do
        if [[ ! -d "$cache_dir" ]]; then
            continue
        fi
        
        log_info "检查缓存目录: $cache_dir"
        
        local cache_size
        cache_size=$(du -sb "$cache_dir" 2>/dev/null | cut -f1 || echo 0)
        
        if [[ "$cache_size" -gt 0 ]]; then
            if [[ "$dry_run" == "true" ]]; then
                log_info "[DRY-RUN] 将清理缓存目录 $cache_dir ($(format_size $cache_size))"
            else
                rm -rf "${cache_dir:?}"/* 2>/dev/null || true
                log_success "清理了缓存目录 $cache_dir ($(format_size $cache_size))"
                CLEANED_SIZE=$((CLEANED_SIZE + cache_size))
            fi
        fi
    done
    
    # 清理包管理器缓存
    if command -v npm &> /dev/null; then
        log_info "清理 npm 缓存..."
        if [[ "$dry_run" == "true" ]]; then
            log_info "[DRY-RUN] 将清理 npm 缓存"
        else
            npm cache clean --force &> /dev/null
            log_success "清理了 npm 缓存"
        fi
    fi
    
    if command -v yarn &> /dev/null; then
        log_info "清理 yarn 缓存..."
        if [[ "$dry_run" == "true" ]]; then
            log_info "[DRY-RUN] 将清理 yarn 缓存"
        else
            yarn cache clean &> /dev/null
            log_success "清理了 yarn 缓存"
        fi
    fi
    
    if command -v go &> /dev/null; then
        log_info "清理 Go 模块缓存..."
        if [[ "$dry_run" == "true" ]]; then
            log_info "[DRY-RUN] 将清理 Go 模块缓存"
        else
            go clean -modcache &> /dev/null
            log_success "清理了 Go 模块缓存"
        fi
    fi
}

# 生成清理报告
generate_report() {
    log_info "清理完成统计:"
    echo "清理的文件数: $CLEANED_FILES"
    echo "清理的大小: $(format_size $CLEANED_SIZE)"
    echo "清理的镜像数: $CLEANED_IMAGES"
    echo "清理的容器数: $CLEANED_CONTAINERS"
    echo "日志文件: $LOG_FILE"
}

# 主函数
main() {
    # 默认值
    local namespace=""
    local days="7"
    local max_size="100M"
    local dry_run="false"
    local verbose="false"
    local quiet="false"
    local clean_logs="false"
    local clean_temp="false"
    local clean_docker="false"
    local clean_k8s="false"
    local clean_cache="false"
    local clean_all="true"
    local force="false"
    
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
            -d|--days)
                days="$2"
                shift 2
                ;;
            -s|--size)
                max_size="$2"
                shift 2
                ;;
            --dry-run)
                dry_run="true"
                shift
                ;;
            -v|--verbose)
                verbose="true"
                shift
                ;;
            -q|--quiet)
                quiet="true"
                shift
                ;;
            --logs)
                clean_logs="true"
                clean_all="false"
                shift
                ;;
            --temp)
                clean_temp="true"
                clean_all="false"
                shift
                ;;
            --docker)
                clean_docker="true"
                clean_all="false"
                shift
                ;;
            --k8s)
                clean_k8s="true"
                clean_all="false"
                shift
                ;;
            --cache)
                clean_cache="true"
                clean_all="false"
                shift
                ;;
            --all)
                clean_all="true"
                shift
                ;;
            --force)
                force="true"
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
    
    # 确认清理操作
    if [[ "$force" != "true" && "$dry_run" != "true" ]]; then
        echo "即将执行清理操作:"
        [[ "$clean_all" == "true" || "$clean_logs" == "true" ]] && echo "- 清理 $days 天前的日志文件"
        [[ "$clean_all" == "true" || "$clean_temp" == "true" ]] && echo "- 清理 $days 天前的临时文件"
        [[ "$clean_all" == "true" || "$clean_docker" == "true" ]] && echo "- 清理 Docker 资源"
        [[ "$clean_all" == "true" || "$clean_k8s" == "true" ]] && echo "- 清理 Kubernetes 资源"
        [[ "$clean_all" == "true" || "$clean_cache" == "true" ]] && echo "- 清理缓存文件"
        
        read -p "确认继续? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "清理操作已取消"
            exit 0
        fi
    fi
    
    # 开始清理
    if [[ "$quiet" != "true" ]]; then
        log_info "Nova Proxy 系统清理开始"
        log_info "时间戳: $(date)"
        log_info "日志文件: $LOG_FILE"
        [[ "$dry_run" == "true" ]] && log_info "运行模式: 干运行"
    fi
    
    # 执行清理
    if [[ "$clean_all" == "true" || "$clean_logs" == "true" ]]; then
        cleanup_logs "$days" "$max_size" "$dry_run"
    fi
    
    if [[ "$clean_all" == "true" || "$clean_temp" == "true" ]]; then
        cleanup_temp "$days" "$dry_run"
    fi
    
    if [[ "$clean_all" == "true" || "$clean_docker" == "true" ]]; then
        cleanup_docker "$days" "$dry_run"
    fi
    
    if [[ "$clean_all" == "true" || "$clean_k8s" == "true" ]]; then
        cleanup_k8s "$namespace" "$days" "$dry_run"
    fi
    
    if [[ "$clean_all" == "true" || "$clean_cache" == "true" ]]; then
        cleanup_cache "$days" "$dry_run"
    fi
    
    # 生成报告
    if [[ "$quiet" != "true" ]]; then
        generate_report
    fi
    
    log_success "清理操作完成"
}

# 执行主函数
main "$@"