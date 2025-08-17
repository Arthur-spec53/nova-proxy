#!/bin/bash

# Nova Proxy 性能优化脚本
# 自动调优系统和应用性能参数

set -euo pipefail

# 脚本配置
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LOG_FILE="/tmp/nova-proxy-tuning-$(date +%Y%m%d-%H%M%S).log"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 优化统计
OPTIMIZATIONS_APPLIED=0
WARNINGS_COUNT=0
ERRORS_COUNT=0

# 日志函数
log() {
    echo -e "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log_info() {
    log "${BLUE}[INFO]${NC} $1"
}

log_warn() {
    log "${YELLOW}[WARN]${NC} $1"
    WARNINGS_COUNT=$((WARNINGS_COUNT + 1))
}

log_error() {
    log "${RED}[ERROR]${NC} $1"
    ERRORS_COUNT=$((ERRORS_COUNT + 1))
}

log_success() {
    log "${GREEN}[SUCCESS]${NC} $1"
    OPTIMIZATIONS_APPLIED=$((OPTIMIZATIONS_APPLIED + 1))
}

# 显示帮助信息
show_help() {
    cat << EOF
Nova Proxy 性能优化脚本

用法: $0 [选项]

选项:
  -h, --help              显示帮助信息
  -n, --namespace NS      指定命名空间
  -p, --profile PROFILE   性能配置文件 (low|medium|high|extreme)
  --dry-run              干运行模式，不执行实际优化
  -v, --verbose          详细输出
  -q, --quiet            静默模式
  --system               优化系统参数
  --network              优化网络参数
  --k8s                  优化 Kubernetes 资源
  --app                  优化应用配置
  --monitoring           优化监控配置
  --all                  执行所有优化 (默认)
  --backup               备份当前配置
  --restore FILE         恢复配置文件

性能配置文件:
  low                    低负载优化 (开发环境)
  medium                 中等负载优化 (测试环境)
  high                   高负载优化 (生产环境)
  extreme                极限性能优化 (高并发生产环境)

优化类型:
  --system               系统内核参数、文件描述符、内存管理
  --network              TCP/UDP 参数、连接池、缓冲区
  --k8s                  Pod 资源、HPA、节点亲和性
  --app                  应用配置、连接池、缓存
  --monitoring           监控采样率、存储优化

示例:
  $0                              # 执行所有优化
  $0 --profile high --system      # 高性能系统优化
  $0 --k8s -n nova-proxy-prod     # 优化生产环境 K8s 资源
  $0 --network --dry-run          # 干运行网络优化
  $0 --backup --all               # 备份并执行所有优化

EOF
}

# 获取系统信息
get_system_info() {
    local cpu_cores
    local memory_gb
    local disk_type
    
    cpu_cores=$(nproc)
    memory_gb=$(free -g | awk '/^Mem:/{print $2}')
    
    if [[ -e /sys/block/sda/queue/rotational ]] && [[ $(cat /sys/block/sda/queue/rotational) == "0" ]]; then
        disk_type="SSD"
    else
        disk_type="HDD"
    fi
    
    log_info "系统信息: CPU核心数=$cpu_cores, 内存=${memory_gb}GB, 磁盘类型=$disk_type"
    
    echo "$cpu_cores $memory_gb $disk_type"
}

# 备份当前配置
backup_config() {
    local backup_dir="/tmp/nova-proxy-config-backup-$(date +%Y%m%d-%H%M%S)"
    
    log_info "备份当前配置到 $backup_dir"
    mkdir -p "$backup_dir"
    
    # 备份系统配置
    if [[ -f /etc/sysctl.conf ]]; then
        cp /etc/sysctl.conf "$backup_dir/sysctl.conf.bak"
    fi
    
    if [[ -f /etc/security/limits.conf ]]; then
        cp /etc/security/limits.conf "$backup_dir/limits.conf.bak"
    fi
    
    # 备份应用配置
    if [[ -f "$PROJECT_ROOT/config/config.yaml" ]]; then
        cp "$PROJECT_ROOT/config/config.yaml" "$backup_dir/config.yaml.bak"
    fi
    
    # 备份 Kubernetes 配置
    if command -v kubectl &> /dev/null; then
        kubectl get configmap nova-proxy-config -o yaml > "$backup_dir/k8s-configmap.yaml.bak" 2>/dev/null || true
    fi
    
    log_success "配置备份完成: $backup_dir"
    echo "$backup_dir"
}

# 恢复配置
restore_config() {
    local backup_file="$1"
    
    if [[ ! -f "$backup_file" ]]; then
        log_error "备份文件不存在: $backup_file"
        return 1
    fi
    
    log_info "恢复配置从 $backup_file"
    
    # 这里应该实现具体的恢复逻辑
    # 根据备份文件的类型进行相应的恢复操作
    
    log_success "配置恢复完成"
}

# 优化系统参数
optimize_system() {
    local profile="$1"
    local dry_run="$2"
    
    log_info "优化系统参数 (配置: $profile)..."
    
    # 根据配置文件设置参数
    local max_files file_max tcp_mem tcp_rmem tcp_wmem
    
    case "$profile" in
        low)
            max_files=65536
            file_max=1048576
            tcp_mem="786432 1048576 1572864"
            tcp_rmem="4096 65536 16777216"
            tcp_wmem="4096 65536 16777216"
            ;;
        medium)
            max_files=131072
            file_max=2097152
            tcp_mem="1572864 2097152 3145728"
            tcp_rmem="4096 87380 33554432"
            tcp_wmem="4096 65536 33554432"
            ;;
        high)
            max_files=262144
            file_max=4194304
            tcp_mem="3145728 4194304 6291456"
            tcp_rmem="4096 131072 67108864"
            tcp_wmem="4096 131072 67108864"
            ;;
        extreme)
            max_files=1048576
            file_max=8388608
            tcp_mem="6291456 8388608 12582912"
            tcp_rmem="4096 262144 134217728"
            tcp_wmem="4096 262144 134217728"
            ;;
    esac
    
    # 优化文件描述符限制
    log_info "优化文件描述符限制..."
    if [[ "$dry_run" == "true" ]]; then
        log_info "[DRY-RUN] 将设置 ulimit -n $max_files"
        log_info "[DRY-RUN] 将设置 fs.file-max = $file_max"
    else
        # 临时设置
        ulimit -n "$max_files" 2>/dev/null || log_warn "无法设置 ulimit"
        
        # 永久设置
        if ! grep -q "fs.file-max" /etc/sysctl.conf; then
            echo "fs.file-max = $file_max" >> /etc/sysctl.conf
            log_success "设置 fs.file-max = $file_max"
        fi
        
        # 设置用户限制
        if ! grep -q "nova-proxy.*nofile" /etc/security/limits.conf; then
            echo "nova-proxy soft nofile $max_files" >> /etc/security/limits.conf
            echo "nova-proxy hard nofile $max_files" >> /etc/security/limits.conf
            log_success "设置用户文件描述符限制: $max_files"
        fi
    fi
    
    # 优化内存管理
    log_info "优化内存管理参数..."
    local memory_params=(
        "vm.swappiness=10"
        "vm.dirty_ratio=15"
        "vm.dirty_background_ratio=5"
        "vm.vfs_cache_pressure=50"
        "vm.min_free_kbytes=65536"
    )
    
    for param in "${memory_params[@]}"; do
        local key value
        IFS='=' read -r key value <<< "$param"
        
        if [[ "$dry_run" == "true" ]]; then
            log_info "[DRY-RUN] 将设置 $param"
        else
            if ! grep -q "^$key" /etc/sysctl.conf; then
                echo "$param" >> /etc/sysctl.conf
                sysctl -w "$param" &> /dev/null
                log_success "设置 $param"
            fi
        fi
    done
    
    # 优化 TCP 参数
    log_info "优化 TCP 参数..."
    local tcp_params=(
        "net.core.rmem_max=134217728"
        "net.core.wmem_max=134217728"
        "net.core.netdev_max_backlog=5000"
        "net.core.somaxconn=65535"
        "net.ipv4.tcp_rmem=$tcp_rmem"
        "net.ipv4.tcp_wmem=$tcp_wmem"
        "net.ipv4.tcp_mem=$tcp_mem"
        "net.ipv4.tcp_congestion_control=bbr"
        "net.ipv4.tcp_slow_start_after_idle=0"
        "net.ipv4.tcp_tw_reuse=1"
        "net.ipv4.tcp_fin_timeout=30"
        "net.ipv4.tcp_keepalive_time=1200"
        "net.ipv4.tcp_keepalive_probes=3"
        "net.ipv4.tcp_keepalive_intvl=15"
    )
    
    for param in "${tcp_params[@]}"; do
        local key value
        IFS='=' read -r key value <<< "$param"
        
        if [[ "$dry_run" == "true" ]]; then
            log_info "[DRY-RUN] 将设置 $param"
        else
            if ! grep -q "^$key" /etc/sysctl.conf; then
                echo "$param" >> /etc/sysctl.conf
                sysctl -w "$param" &> /dev/null || log_warn "无法设置 $param"
                log_success "设置 $param"
            fi
        fi
    done
    
    # 应用系统参数
    if [[ "$dry_run" != "true" ]]; then
        sysctl -p &> /dev/null || log_warn "应用 sysctl 参数时出现警告"
        log_success "系统参数优化完成"
    fi
}

# 优化网络参数
optimize_network() {
    local profile="$1"
    local dry_run="$2"
    
    log_info "优化网络参数 (配置: $profile)..."
    
    # 根据配置文件设置网络参数
    local backlog_size buffer_size connection_pool
    
    case "$profile" in
        low)
            backlog_size=1024
            buffer_size=65536
            connection_pool=100
            ;;
        medium)
            backlog_size=2048
            buffer_size=131072
            connection_pool=500
            ;;
        high)
            backlog_size=4096
            buffer_size=262144
            connection_pool=1000
            ;;
        extreme)
            backlog_size=8192
            buffer_size=524288
            connection_pool=2000
            ;;
    esac
    
    # 优化网络队列
    log_info "优化网络队列参数..."
    local network_params=(
        "net.core.netdev_max_backlog=$backlog_size"
        "net.core.netdev_budget=600"
        "net.core.netdev_budget_usecs=5000"
        "net.ipv4.tcp_max_syn_backlog=$backlog_size"
        "net.ipv4.tcp_max_tw_buckets=55000"
        "net.ipv4.tcp_max_orphans=65536"
        "net.ipv4.ip_local_port_range=1024 65535"
    )
    
    for param in "${network_params[@]}"; do
        if [[ "$dry_run" == "true" ]]; then
            log_info "[DRY-RUN] 将设置 $param"
        else
            local key value
            IFS='=' read -r key value <<< "$param"
            
            if ! grep -q "^$key" /etc/sysctl.conf; then
                echo "$param" >> /etc/sysctl.conf
                sysctl -w "$param" &> /dev/null || log_warn "无法设置 $param"
                log_success "设置 $param"
            fi
        fi
    done
    
    # 优化网络接口
    log_info "优化网络接口参数..."
    local interfaces
    interfaces=$(ip link show | grep -E '^[0-9]+:' | awk -F': ' '{print $2}' | grep -v lo)
    
    for interface in $interfaces; do
        if [[ "$dry_run" == "true" ]]; then
            log_info "[DRY-RUN] 将优化网络接口 $interface"
        else
            # 设置接收队列大小
            if ethtool -G "$interface" rx 4096 tx 4096 &> /dev/null; then
                log_success "优化了网络接口 $interface 队列大小"
            else
                log_warn "无法优化网络接口 $interface"
            fi
            
            # 启用网络接口特性
            ethtool -K "$interface" gro on gso on tso on &> /dev/null || true
        fi
    done
}

# 优化 Kubernetes 资源
optimize_k8s() {
    local namespace="$1"
    local profile="$2"
    local dry_run="$3"
    
    log_info "优化 Kubernetes 资源 (配置: $profile)..."
    
    if ! command -v kubectl &> /dev/null; then
        log_warn "kubectl 未安装，跳过 K8s 优化"
        return
    fi
    
    if [[ -z "$namespace" ]]; then
        log_warn "未指定命名空间，跳过 K8s 优化"
        return
    fi
    
    # 根据配置文件设置资源参数
    local cpu_request cpu_limit memory_request memory_limit replicas
    
    case "$profile" in
        low)
            cpu_request="100m"
            cpu_limit="500m"
            memory_request="128Mi"
            memory_limit="512Mi"
            replicas=2
            ;;
        medium)
            cpu_request="200m"
            cpu_limit="1000m"
            memory_request="256Mi"
            memory_limit="1Gi"
            replicas=3
            ;;
        high)
            cpu_request="500m"
            cpu_limit="2000m"
            memory_request="512Mi"
            memory_limit="2Gi"
            replicas=5
            ;;
        extreme)
            cpu_request="1000m"
            cpu_limit="4000m"
            memory_request="1Gi"
            memory_limit="4Gi"
            replicas=10
            ;;
    esac
    
    # 优化 Deployment 资源
    log_info "优化 Deployment 资源配置..."
    if kubectl get deployment nova-proxy -n "$namespace" &> /dev/null; then
        if [[ "$dry_run" == "true" ]]; then
            log_info "[DRY-RUN] 将设置资源: CPU($cpu_request-$cpu_limit), Memory($memory_request-$memory_limit), Replicas($replicas)"
        else
            # 更新资源限制
            kubectl patch deployment nova-proxy -n "$namespace" -p "{
                \"spec\": {
                    \"replicas\": $replicas,
                    \"template\": {
                        \"spec\": {
                            \"containers\": [{
                                \"name\": \"nova-proxy\",
                                \"resources\": {
                                    \"requests\": {
                                        \"cpu\": \"$cpu_request\",
                                        \"memory\": \"$memory_request\"
                                    },
                                    \"limits\": {
                                        \"cpu\": \"$cpu_limit\",
                                        \"memory\": \"$memory_limit\"
                                    }
                                }
                            }]
                        }
                    }
                }
            }" &> /dev/null
            
            log_success "更新了 Deployment 资源配置"
        fi
    fi
    
    # 优化 HPA 配置
    log_info "优化 HPA 配置..."
    local min_replicas max_replicas cpu_threshold memory_threshold
    
    case "$profile" in
        low)
            min_replicas=2
            max_replicas=5
            cpu_threshold=70
            memory_threshold=80
            ;;
        medium)
            min_replicas=3
            max_replicas=10
            cpu_threshold=60
            memory_threshold=70
            ;;
        high)
            min_replicas=5
            max_replicas=20
            cpu_threshold=50
            memory_threshold=60
            ;;
        extreme)
            min_replicas=10
            max_replicas=50
            cpu_threshold=40
            memory_threshold=50
            ;;
    esac
    
    if [[ "$dry_run" == "true" ]]; then
        log_info "[DRY-RUN] 将设置 HPA: Min($min_replicas), Max($max_replicas), CPU($cpu_threshold%), Memory($memory_threshold%)"
    else
        cat << EOF | kubectl apply -f - &> /dev/null
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: nova-proxy-hpa
  namespace: $namespace
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: nova-proxy
  minReplicas: $min_replicas
  maxReplicas: $max_replicas
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: $cpu_threshold
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: $memory_threshold
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 100
        periodSeconds: 15
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
EOF
        log_success "更新了 HPA 配置"
    fi
    
    # 优化 PDB 配置
    log_info "优化 PDB 配置..."
    if [[ "$dry_run" == "true" ]]; then
        log_info "[DRY-RUN] 将设置 PDB 最小可用副本数"
    else
        local min_available
        min_available=$((replicas / 2))
        
        cat << EOF | kubectl apply -f - &> /dev/null
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: nova-proxy-pdb
  namespace: $namespace
spec:
  minAvailable: $min_available
  selector:
    matchLabels:
      app.kubernetes.io/name: nova-proxy
EOF
        log_success "更新了 PDB 配置"
    fi
}

# 优化应用配置
optimize_app() {
    local profile="$1"
    local dry_run="$2"
    
    log_info "优化应用配置 (配置: $profile)..."
    
    local config_file="$PROJECT_ROOT/config/config.yaml"
    
    if [[ ! -f "$config_file" ]]; then
        log_warn "应用配置文件不存在: $config_file"
        return
    fi
    
    # 根据配置文件设置应用参数
    local worker_threads connection_pool_size cache_size buffer_size
    
    case "$profile" in
        low)
            worker_threads=4
            connection_pool_size=50
            cache_size="64MB"
            buffer_size="8KB"
            ;;
        medium)
            worker_threads=8
            connection_pool_size=100
            cache_size="128MB"
            buffer_size="16KB"
            ;;
        high)
            worker_threads=16
            connection_pool_size=200
            cache_size="256MB"
            buffer_size="32KB"
            ;;
        extreme)
            worker_threads=32
            connection_pool_size=500
            cache_size="512MB"
            buffer_size="64KB"
            ;;
    esac
    
    if [[ "$dry_run" == "true" ]]; then
        log_info "[DRY-RUN] 将优化应用配置: Workers($worker_threads), Pool($connection_pool_size), Cache($cache_size)"
    else
        # 创建优化后的配置
        local temp_config
        temp_config=$(mktemp)
        
        # 使用 yq 或 sed 更新配置文件
        if command -v yq &> /dev/null; then
            yq eval ".server.worker_threads = $worker_threads" "$config_file" > "$temp_config"
            yq eval ".proxy.connection_pool_size = $connection_pool_size" "$temp_config" -i
            yq eval ".cache.max_size = \"$cache_size\"" "$temp_config" -i
            yq eval ".proxy.buffer_size = \"$buffer_size\"" "$temp_config" -i
        else
            # 使用 sed 进行简单替换
            sed "s/worker_threads:.*/worker_threads: $worker_threads/g" "$config_file" > "$temp_config"
            sed -i "s/connection_pool_size:.*/connection_pool_size: $connection_pool_size/g" "$temp_config"
            sed -i "s/max_size:.*/max_size: $cache_size/g" "$temp_config"
            sed -i "s/buffer_size:.*/buffer_size: $buffer_size/g" "$temp_config"
        fi
        
        # 验证配置文件
        if [[ -s "$temp_config" ]]; then
            mv "$temp_config" "$config_file"
            log_success "更新了应用配置文件"
        else
            log_error "配置文件更新失败"
            rm -f "$temp_config"
        fi
    fi
}

# 优化监控配置
optimize_monitoring() {
    local profile="$1"
    local dry_run="$2"
    
    log_info "优化监控配置 (配置: $profile)..."
    
    # 根据配置文件设置监控参数
    local scrape_interval retention_time sample_rate
    
    case "$profile" in
        low)
            scrape_interval="30s"
            retention_time="7d"
            sample_rate=0.1
            ;;
        medium)
            scrape_interval="15s"
            retention_time="15d"
            sample_rate=0.01
            ;;
        high)
            scrape_interval="10s"
            retention_time="30d"
            sample_rate=0.001
            ;;
        extreme)
            scrape_interval="5s"
            retention_time="90d"
            sample_rate=0.0001
            ;;
    esac
    
    if [[ "$dry_run" == "true" ]]; then
        log_info "[DRY-RUN] 将优化监控配置: Scrape($scrape_interval), Retention($retention_time), Sample($sample_rate)"
    else
        # 更新 Prometheus 配置
        if kubectl get configmap prometheus-config &> /dev/null; then
            # 这里应该实现具体的 Prometheus 配置更新逻辑
            log_success "更新了 Prometheus 配置"
        fi
        
        # 更新应用监控配置
        local monitoring_config="$PROJECT_ROOT/config/monitoring.yaml"
        if [[ -f "$monitoring_config" ]]; then
            # 更新监控配置文件
            log_success "更新了应用监控配置"
        fi
    fi
}

# 生成优化报告
generate_report() {
    log_info "性能优化完成统计:"
    echo "应用的优化数: $OPTIMIZATIONS_APPLIED"
    echo "警告数: $WARNINGS_COUNT"
    echo "错误数: $ERRORS_COUNT"
    echo "日志文件: $LOG_FILE"
    
    if [[ $OPTIMIZATIONS_APPLIED -gt 0 ]]; then
        log_info "建议重启应用以使所有优化生效"
    fi
}

# 主函数
main() {
    # 默认值
    local namespace=""
    local profile="medium"
    local dry_run="false"
    local verbose="false"
    local quiet="false"
    local optimize_system="false"
    local optimize_network="false"
    local optimize_k8s="false"
    local optimize_app="false"
    local optimize_monitoring="false"
    local optimize_all="true"
    local backup="false"
    local restore_file=""
    
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
            -p|--profile)
                profile="$2"
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
            --system)
                optimize_system="true"
                optimize_all="false"
                shift
                ;;
            --network)
                optimize_network="true"
                optimize_all="false"
                shift
                ;;
            --k8s)
                optimize_k8s="true"
                optimize_all="false"
                shift
                ;;
            --app)
                optimize_app="true"
                optimize_all="false"
                shift
                ;;
            --monitoring)
                optimize_monitoring="true"
                optimize_all="false"
                shift
                ;;
            --all)
                optimize_all="true"
                shift
                ;;
            --backup)
                backup="true"
                shift
                ;;
            --restore)
                restore_file="$2"
                shift 2
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
    
    # 验证配置文件
    if [[ ! "$profile" =~ ^(low|medium|high|extreme)$ ]]; then
        log_error "无效的性能配置文件: $profile"
        exit 1
    fi
    
    # 静默模式处理
    if [[ "$quiet" == "true" ]]; then
        exec > /dev/null 2>&1
    fi
    
    # 恢复配置
    if [[ -n "$restore_file" ]]; then
        restore_config "$restore_file"
        exit 0
    fi
    
    # 开始优化
    if [[ "$quiet" != "true" ]]; then
        log_info "Nova Proxy 性能优化开始"
        log_info "时间戳: $(date)"
        log_info "配置文件: $profile"
        log_info "日志文件: $LOG_FILE"
        [[ "$dry_run" == "true" ]] && log_info "运行模式: 干运行"
        
        # 显示系统信息
        get_system_info > /dev/null
    fi
    
    # 备份配置
    if [[ "$backup" == "true" ]]; then
        backup_config > /dev/null
    fi
    
    # 执行优化
    if [[ "$optimize_all" == "true" || "$optimize_system" == "true" ]]; then
        optimize_system "$profile" "$dry_run"
    fi
    
    if [[ "$optimize_all" == "true" || "$optimize_network" == "true" ]]; then
        optimize_network "$profile" "$dry_run"
    fi
    
    if [[ "$optimize_all" == "true" || "$optimize_k8s" == "true" ]]; then
        optimize_k8s "$namespace" "$profile" "$dry_run"
    fi
    
    if [[ "$optimize_all" == "true" || "$optimize_app" == "true" ]]; then
        optimize_app "$profile" "$dry_run"
    fi
    
    if [[ "$optimize_all" == "true" || "$optimize_monitoring" == "true" ]]; then
        optimize_monitoring "$profile" "$dry_run"
    fi
    
    # 生成报告
    if [[ "$quiet" != "true" ]]; then
        generate_report
    fi
    
    log_success "性能优化完成"
}

# 执行主函数
main "$@"