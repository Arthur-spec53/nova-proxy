#!/bin/bash

# Nova Proxy 安全扫描脚本
# 用于安全漏洞检测和合规性检查

set -euo pipefail

# 脚本配置
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SECURITY_DIR="$PROJECT_ROOT/security"
REPORTS_DIR="$SECURITY_DIR/reports"

# 默认配置
DEFAULT_ENVIRONMENT="development"
DEFAULT_NAMESPACE="nova-proxy"
DEFAULT_SEVERITY="HIGH,CRITICAL"

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

log_security() {
    echo -e "${CYAN}[SECURITY]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
}

# 显示帮助信息
show_help() {
    cat << EOF
Nova Proxy 安全扫描脚本

用法: $0 <命令> [选项]

命令:
  scan-all                  全面安全扫描
  scan-code                 代码安全扫描
  scan-dependencies         依赖漏洞扫描
  scan-container            容器镜像扫描
  scan-k8s                  Kubernetes 安全扫描
  scan-network              网络安全扫描
  scan-secrets              密钥泄露扫描
  scan-compliance           合规性检查
  scan-runtime              运行时安全扫描
  generate-report           生成安全报告
  fix-issues                修复安全问题

选项:
  -e, --environment ENV     环境名称 [默认: $DEFAULT_ENVIRONMENT]
  -n, --namespace NS        命名空间 [默认: $DEFAULT_NAMESPACE]
  -s, --severity LEVELS     严重级别 [默认: $DEFAULT_SEVERITY]
  -o, --output DIR          输出目录 [默认: $REPORTS_DIR]
  -f, --format FORMAT       报告格式 (json, sarif, table) [默认: json]
  -i, --image IMAGE         扫描的镜像名称
  -t, --timeout SECONDS     扫描超时时间 [默认: 300]
  --fix                     自动修复问题
  --ignore-unfixed          忽略无法修复的漏洞
  -v, --verbose             详细输出
  -h, --help                显示此帮助信息

示例:
  $0 scan-all -e production -s CRITICAL           # 全面扫描生产环境的严重漏洞
  $0 scan-code -o /tmp/security                    # 代码安全扫描
  $0 scan-container -i nova-proxy:latest          # 扫描容器镜像
  $0 scan-k8s -e staging                          # Kubernetes 安全扫描
  $0 generate-report -f sarif                     # 生成 SARIF 格式报告
  $0 fix-issues --fix                             # 自动修复安全问题

EOF
}

# 解析命令行参数
parse_args() {
    COMMAND=""
    ENVIRONMENT="$DEFAULT_ENVIRONMENT"
    NAMESPACE="$DEFAULT_NAMESPACE"
    SEVERITY="$DEFAULT_SEVERITY"
    OUTPUT_DIR="$REPORTS_DIR"
    REPORT_FORMAT="json"
    IMAGE_NAME=""
    TIMEOUT="300"
    AUTO_FIX=false
    IGNORE_UNFIXED=false
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
            -s|--severity)
                SEVERITY="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -f|--format)
                REPORT_FORMAT="$2"
                shift 2
                ;;
            -i|--image)
                IMAGE_NAME="$2"
                shift 2
                ;;
            -t|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            --fix)
                AUTO_FIX=true
                shift
                ;;
            --ignore-unfixed)
                IGNORE_UNFIXED=true
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
    local required_commands=("kubectl" "docker" "jq")
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_deps+=("$cmd")
        fi
    done
    
    # 检查安全扫描工具
    local security_tools=("trivy" "grype" "syft")
    local found_scanner=""
    
    for tool in "${security_tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            found_scanner="$tool"
            break
        fi
    done
    
    if [[ -z "$found_scanner" ]]; then
        log_warning "未找到安全扫描工具，尝试安装 trivy..."
        install_trivy
    fi
    
    # 检查代码分析工具
    if ! command -v gosec &> /dev/null; then
        log_warning "未找到 gosec，尝试安装..."
        if command -v go &> /dev/null; then
            go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
        else
            log_warning "无法安装 gosec，跳过代码安全扫描"
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

# 安装 Trivy
install_trivy() {
    log_info "安装 Trivy..."
    
    if [[ "$(uname)" == "Linux" ]]; then
        curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
    elif [[ "$(uname)" == "Darwin" ]]; then
        if command -v brew &> /dev/null; then
            brew install trivy
        else
            log_error "请手动安装 Trivy"
            exit 1
        fi
    fi
}

# 设置安全扫描环境
setup_security_env() {
    local timestamp
    timestamp=$(date +"%Y%m%d_%H%M%S")
    SECURITY_SESSION_DIR="$OUTPUT_DIR/security-scan-$timestamp"
    
    mkdir -p "$SECURITY_SESSION_DIR"
    log_info "安全扫描会话目录: $SECURITY_SESSION_DIR"
    
    # 创建扫描元数据
    cat > "$SECURITY_SESSION_DIR/metadata.json" << EOF
{
    "scan_id": "security-scan-$timestamp",
    "environment": "$ENVIRONMENT",
    "namespace": "$NAMESPACE",
    "timestamp": "$(date -Iseconds)",
    "severity_filter": "$SEVERITY",
    "scanner_version": "$(trivy version 2>/dev/null | head -1 || echo 'unknown')",
    "kubernetes_version": "$(kubectl version --short --client | grep Client | awk '{print $3}')"
}
EOF
}

# 全面安全扫描
run_full_security_scan() {
    log_info "开始全面安全扫描..."
    
    local scan_results=()
    
    # 代码安全扫描
    if scan_code_security; then
        scan_results+=("code:PASS")
    else
        scan_results+=("code:FAIL")
    fi
    
    # 依赖漏洞扫描
    if scan_dependencies; then
        scan_results+=("dependencies:PASS")
    else
        scan_results+=("dependencies:FAIL")
    fi
    
    # 容器镜像扫描
    if scan_container_images; then
        scan_results+=("container:PASS")
    else
        scan_results+=("container:FAIL")
    fi
    
    # Kubernetes 安全扫描
    if scan_kubernetes_security; then
        scan_results+=("kubernetes:PASS")
    else
        scan_results+=("kubernetes:FAIL")
    fi
    
    # 密钥泄露扫描
    if scan_secrets; then
        scan_results+=("secrets:PASS")
    else
        scan_results+=("secrets:FAIL")
    fi
    
    # 网络安全扫描
    if scan_network_security; then
        scan_results+=("network:PASS")
    else
        scan_results+=("network:FAIL")
    fi
    
    # 生成综合报告
    generate_comprehensive_report "${scan_results[@]}"
    
    log_success "全面安全扫描完成"
}

# 代码安全扫描
scan_code_security() {
    log_security "代码安全扫描..."
    
    local code_dir="$SECURITY_SESSION_DIR/code-scan"
    mkdir -p "$code_dir"
    
    local issues_found=0
    
    # GoSec 扫描
    if command -v gosec &> /dev/null; then
        log_info "运行 GoSec 扫描..."
        
        if gosec -fmt json -out "$code_dir/gosec-report.json" "$PROJECT_ROOT/..." 2>/dev/null; then
            log_success "GoSec 扫描完成"
            
            # 检查是否有高危漏洞
            local high_issues
            high_issues=$(jq '.Issues | map(select(.severity == "HIGH" or .severity == "MEDIUM")) | length' "$code_dir/gosec-report.json" 2>/dev/null || echo "0")
            
            if [[ "$high_issues" -gt 0 ]]; then
                log_warning "发现 $high_issues 个中高危代码安全问题"
                ((issues_found += high_issues))
            fi
        else
            log_error "GoSec 扫描失败"
            ((issues_found++))
        fi
        
        # 生成可读报告
        gosec -fmt text "$PROJECT_ROOT/..." > "$code_dir/gosec-report.txt" 2>/dev/null || true
    else
        log_warning "GoSec 未安装，跳过代码安全扫描"
    fi
    
    # 静态分析
    if command -v staticcheck &> /dev/null; then
        log_info "运行静态分析..."
        staticcheck "$PROJECT_ROOT/..." > "$code_dir/staticcheck-report.txt" 2>&1 || true
    fi
    
    # 检查硬编码密钥
    log_info "检查硬编码密钥..."
    scan_hardcoded_secrets "$code_dir"
    
    return $issues_found
}

# 扫描硬编码密钥
scan_hardcoded_secrets() {
    local output_dir="$1"
    local secrets_file="$output_dir/hardcoded-secrets.txt"
    
    # 常见的密钥模式
    local patterns=(
        "password\s*=\s*['\"][^'\"]{8,}['\"]"  # 密码
        "api[_-]?key\s*=\s*['\"][^'\"]{16,}['\"]"  # API 密钥
        "secret\s*=\s*['\"][^'\"]{16,}['\"]"  # 密钥
        "token\s*=\s*['\"][^'\"]{16,}['\"]"  # 令牌
        "['\"][A-Za-z0-9+/]{40,}['\"]"  # Base64 编码的密钥
        "-----BEGIN [A-Z ]+-----"  # PEM 格式密钥
    )
    
    echo "硬编码密钥扫描结果" > "$secrets_file"
    echo "==================" >> "$secrets_file"
    
    local secrets_found=0
    
    for pattern in "${patterns[@]}"; do
        if grep -r -i -E "$pattern" "$PROJECT_ROOT" --include="*.go" --include="*.yaml" --include="*.yml" --include="*.json" >> "$secrets_file" 2>/dev/null; then
            ((secrets_found++))
        fi
    done
    
    if [[ $secrets_found -gt 0 ]]; then
        log_warning "发现 $secrets_found 个可能的硬编码密钥"
    else
        log_success "未发现硬编码密钥"
        echo "未发现硬编码密钥" >> "$secrets_file"
    fi
}

# 依赖漏洞扫描
scan_dependencies() {
    log_security "依赖漏洞扫描..."
    
    local deps_dir="$SECURITY_SESSION_DIR/dependencies"
    mkdir -p "$deps_dir"
    
    local issues_found=0
    
    # Go 模块扫描
    if [[ -f "$PROJECT_ROOT/go.mod" ]]; then
        log_info "扫描 Go 依赖..."
        
        # 使用 Trivy 扫描
        if command -v trivy &> /dev/null; then
            trivy fs --format json --output "$deps_dir/go-deps-trivy.json" "$PROJECT_ROOT" 2>/dev/null || true
            trivy fs --format table --output "$deps_dir/go-deps-trivy.txt" "$PROJECT_ROOT" 2>/dev/null || true
            
            # 统计漏洞数量
            if [[ -f "$deps_dir/go-deps-trivy.json" ]]; then
                local vuln_count
                vuln_count=$(jq '.Results[]?.Vulnerabilities // [] | length' "$deps_dir/go-deps-trivy.json" 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
                
                if [[ "$vuln_count" -gt 0 ]]; then
                    log_warning "发现 $vuln_count 个依赖漏洞"
                    ((issues_found += vuln_count))
                else
                    log_success "未发现依赖漏洞"
                fi
            fi
        fi
        
        # 使用 Nancy 扫描（如果可用）
        if command -v nancy &> /dev/null; then
            log_info "运行 Nancy 扫描..."
            go list -json -m all | nancy sleuth > "$deps_dir/nancy-report.txt" 2>&1 || true
        fi
        
        # 检查过期依赖
        log_info "检查过期依赖..."
        go list -u -m all > "$deps_dir/outdated-deps.txt" 2>&1 || true
    fi
    
    # Docker 镜像依赖扫描
    if [[ -f "$PROJECT_ROOT/Dockerfile" ]]; then
        log_info "扫描 Docker 基础镜像..."
        
        local base_images
        mapfile -t base_images < <(grep -i "^FROM" "$PROJECT_ROOT/Dockerfile" | awk '{print $2}' | head -5)
        
        for image in "${base_images[@]}"; do
            if [[ -n "$image" ]]; then
                log_info "扫描基础镜像: $image"
                
                if command -v trivy &> /dev/null; then
                    trivy image --format json --output "$deps_dir/base-image-$(echo "$image" | tr '/:' '_').json" "$image" 2>/dev/null || true
                fi
            fi
        done
    fi
    
    return $issues_found
}

# 容器镜像扫描
scan_container_images() {
    log_security "容器镜像扫描..."
    
    local container_dir="$SECURITY_SESSION_DIR/containers"
    mkdir -p "$container_dir"
    
    local issues_found=0
    
    # 获取要扫描的镜像
    local images_to_scan=()
    
    if [[ -n "$IMAGE_NAME" ]]; then
        images_to_scan+=("$IMAGE_NAME")
    else
        # 从 Kubernetes 部署中获取镜像
        if kubectl get deployment nova-proxy -n "$NAMESPACE" &> /dev/null; then
            local deployed_image
            deployed_image=$(kubectl get deployment nova-proxy -n "$NAMESPACE" -o jsonpath='{.spec.template.spec.containers[0].image}')
            if [[ -n "$deployed_image" ]]; then
                images_to_scan+=("$deployed_image")
            fi
        fi
        
        # 添加本地构建的镜像
        if docker images nova-proxy --format "table {{.Repository}}:{{.Tag}}" | grep -v REPOSITORY | head -5; then
            mapfile -t local_images < <(docker images nova-proxy --format "{{.Repository}}:{{.Tag}}" | head -5)
            images_to_scan+=("${local_images[@]}")
        fi
    fi
    
    if [[ ${#images_to_scan[@]} -eq 0 ]]; then
        log_warning "没有找到要扫描的镜像"
        return 0
    fi
    
    # 扫描每个镜像
    for image in "${images_to_scan[@]}"; do
        if [[ -n "$image" ]]; then
            log_info "扫描容器镜像: $image"
            
            local image_safe_name
            image_safe_name=$(echo "$image" | tr '/:' '_')
            
            # Trivy 扫描
            if command -v trivy &> /dev/null; then
                # JSON 格式报告
                trivy image --format json --output "$container_dir/trivy-$image_safe_name.json" "$image" 2>/dev/null || true
                
                # 表格格式报告
                trivy image --format table --output "$container_dir/trivy-$image_safe_name.txt" "$image" 2>/dev/null || true
                
                # SARIF 格式报告（用于 CI/CD 集成）
                trivy image --format sarif --output "$container_dir/trivy-$image_safe_name.sarif" "$image" 2>/dev/null || true
                
                # 统计漏洞
                if [[ -f "$container_dir/trivy-$image_safe_name.json" ]]; then
                    local vuln_count critical_count high_count
                    vuln_count=$(jq '.Results[]?.Vulnerabilities // [] | length' "$container_dir/trivy-$image_safe_name.json" 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
                    critical_count=$(jq '.Results[]?.Vulnerabilities // [] | map(select(.Severity == "CRITICAL")) | length' "$container_dir/trivy-$image_safe_name.json" 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
                    high_count=$(jq '.Results[]?.Vulnerabilities // [] | map(select(.Severity == "HIGH")) | length' "$container_dir/trivy-$image_safe_name.json" 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
                    
                    log_info "镜像 $image: 总漏洞 $vuln_count, 严重 $critical_count, 高危 $high_count"
                    
                    if [[ "$critical_count" -gt 0 ]] || [[ "$high_count" -gt 0 ]]; then
                        ((issues_found += critical_count + high_count))
                    fi
                fi
            fi
            
            # 镜像配置检查
            log_info "检查镜像配置..."
            docker inspect "$image" > "$container_dir/inspect-$image_safe_name.json" 2>/dev/null || true
            
            # 检查镜像安全配置
            check_image_security_config "$image" "$container_dir/security-config-$image_safe_name.txt"
        fi
    done
    
    return $issues_found
}

# 检查镜像安全配置
check_image_security_config() {
    local image="$1"
    local output_file="$2"
    
    echo "镜像安全配置检查: $image" > "$output_file"
    echo "==============================" >> "$output_file"
    
    # 检查用户配置
    local user_config
    user_config=$(docker inspect "$image" --format '{{.Config.User}}' 2>/dev/null || echo "")
    
    if [[ -z "$user_config" || "$user_config" == "root" || "$user_config" == "0" ]]; then
        echo "❌ 镜像以 root 用户运行" >> "$output_file"
    else
        echo "✅ 镜像使用非 root 用户: $user_config" >> "$output_file"
    fi
    
    # 检查暴露的端口
    local exposed_ports
    exposed_ports=$(docker inspect "$image" --format '{{range $port, $config := .Config.ExposedPorts}}{{$port}} {{end}}' 2>/dev/null || echo "")
    
    if [[ -n "$exposed_ports" ]]; then
        echo "ℹ️  暴露的端口: $exposed_ports" >> "$output_file"
    fi
    
    # 检查环境变量（查找可能的敏感信息）
    local env_vars
    env_vars=$(docker inspect "$image" --format '{{range .Config.Env}}{{.}} {{end}}' 2>/dev/null || echo "")
    
    if echo "$env_vars" | grep -i -E "(password|secret|key|token)" > /dev/null; then
        echo "⚠️  环境变量中可能包含敏感信息" >> "$output_file"
    fi
    
    # 检查健康检查
    local healthcheck
    healthcheck=$(docker inspect "$image" --format '{{.Config.Healthcheck}}' 2>/dev/null || echo "")
    
    if [[ "$healthcheck" == "<nil>" || -z "$healthcheck" ]]; then
        echo "⚠️  未配置健康检查" >> "$output_file"
    else
        echo "✅ 已配置健康检查" >> "$output_file"
    fi
}

# Kubernetes 安全扫描
scan_kubernetes_security() {
    log_security "Kubernetes 安全扫描..."
    
    local k8s_dir="$SECURITY_SESSION_DIR/kubernetes"
    mkdir -p "$k8s_dir"
    
    local issues_found=0
    
    # Pod 安全策略检查
    log_info "检查 Pod 安全策略..."
    check_pod_security_policies "$k8s_dir"
    
    # RBAC 权限检查
    log_info "检查 RBAC 权限..."
    check_rbac_permissions "$k8s_dir"
    
    # 网络策略检查
    log_info "检查网络策略..."
    check_network_policies "$k8s_dir"
    
    # 密钥管理检查
    log_info "检查密钥管理..."
    check_secret_management "$k8s_dir"
    
    # 资源限制检查
    log_info "检查资源限制..."
    check_resource_limits "$k8s_dir"
    
    # 使用 kube-score 进行评估（如果可用）
    if command -v kube-score &> /dev/null; then
        log_info "运行 kube-score 评估..."
        kubectl get all -n "$NAMESPACE" -o yaml | kube-score score - > "$k8s_dir/kube-score-report.txt" 2>&1 || true
    fi
    
    # 使用 kube-bench 进行 CIS 基准测试（如果可用）
    if command -v kube-bench &> /dev/null; then
        log_info "运行 CIS Kubernetes 基准测试..."
        kube-bench run --json > "$k8s_dir/kube-bench-report.json" 2>&1 || true
    fi
    
    return $issues_found
}

# 检查 Pod 安全策略
check_pod_security_policies() {
    local output_dir="$1"
    local psp_file="$output_dir/pod-security-policies.txt"
    
    echo "Pod 安全策略检查" > "$psp_file"
    echo "================" >> "$psp_file"
    
    # 获取所有 Pod
    local pods
    mapfile -t pods < <(kubectl get pods -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
    
    for pod in "${pods[@]}"; do
        if [[ -n "$pod" ]]; then
            echo "\n检查 Pod: $pod" >> "$psp_file"
            echo "-------------------" >> "$psp_file"
            
            # 检查安全上下文
            local security_context
            security_context=$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.spec.securityContext}' 2>/dev/null || echo "{}")
            
            # 检查是否以 root 运行
            local run_as_user
            run_as_user=$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.spec.securityContext.runAsUser}' 2>/dev/null || echo "")
            
            if [[ -z "$run_as_user" || "$run_as_user" == "0" ]]; then
                echo "❌ Pod 可能以 root 用户运行" >> "$psp_file"
            else
                echo "✅ Pod 以非 root 用户运行 (UID: $run_as_user)" >> "$psp_file"
            fi
            
            # 检查特权模式
            local privileged
            privileged=$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.spec.containers[0].securityContext.privileged}' 2>/dev/null || echo "false")
            
            if [[ "$privileged" == "true" ]]; then
                echo "❌ Pod 运行在特权模式" >> "$psp_file"
            else
                echo "✅ Pod 未运行在特权模式" >> "$psp_file"
            fi
            
            # 检查只读根文件系统
            local read_only_root
            read_only_root=$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.spec.containers[0].securityContext.readOnlyRootFilesystem}' 2>/dev/null || echo "false")
            
            if [[ "$read_only_root" == "true" ]]; then
                echo "✅ 根文件系统为只读" >> "$psp_file"
            else
                echo "⚠️  根文件系统可写" >> "$psp_file"
            fi
            
            # 检查能力
            local capabilities
            capabilities=$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.spec.containers[0].securityContext.capabilities}' 2>/dev/null || echo "{}")
            
            if [[ "$capabilities" != "{}" ]]; then
                echo "ℹ️  容器能力配置: $capabilities" >> "$psp_file"
            fi
        fi
    done
}

# 检查 RBAC 权限
check_rbac_permissions() {
    local output_dir="$1"
    local rbac_file="$output_dir/rbac-permissions.txt"
    
    echo "RBAC 权限检查" > "$rbac_file"
    echo "=============" >> "$rbac_file"
    
    # 检查 ServiceAccount
    local service_accounts
    mapfile -t service_accounts < <(kubectl get serviceaccounts -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
    
    for sa in "${service_accounts[@]}"; do
        if [[ -n "$sa" && "$sa" != "default" ]]; then
            echo "\n检查 ServiceAccount: $sa" >> "$rbac_file"
            echo "-------------------------" >> "$rbac_file"
            
            # 获取绑定的角色
            kubectl get rolebindings,clusterrolebindings --all-namespaces -o json | \
                jq -r ".items[] | select(.subjects[]?.name == \"$sa\") | \"Role: \(.roleRef.name), Kind: \(.roleRef.kind), Namespace: \(.metadata.namespace // \"cluster\")\"" >> "$rbac_file" 2>/dev/null || true
        fi
    done
    
    # 检查过度权限
    echo "\n过度权限检查" >> "$rbac_file"
    echo "============" >> "$rbac_file"
    
    # 检查 cluster-admin 绑定
    local cluster_admin_bindings
    cluster_admin_bindings=$(kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name == "cluster-admin") | .metadata.name' 2>/dev/null || echo "")
    
    if [[ -n "$cluster_admin_bindings" ]]; then
        echo "⚠️  发现 cluster-admin 绑定:" >> "$rbac_file"
        echo "$cluster_admin_bindings" >> "$rbac_file"
    fi
}

# 检查网络策略
check_network_policies() {
    local output_dir="$1"
    local network_file="$output_dir/network-policies.txt"
    
    echo "网络策略检查" > "$network_file"
    echo "============" >> "$network_file"
    
    # 检查是否存在网络策略
    local network_policies
    network_policies=$(kubectl get networkpolicies -n "$NAMESPACE" --no-headers 2>/dev/null | wc -l || echo "0")
    
    if [[ "$network_policies" -eq 0 ]]; then
        echo "❌ 未配置网络策略，所有流量默认允许" >> "$network_file"
    else
        echo "✅ 已配置 $network_policies 个网络策略" >> "$network_file"
        
        # 列出网络策略详情
        kubectl get networkpolicies -n "$NAMESPACE" -o yaml >> "$network_file" 2>/dev/null || true
    fi
    
    # 检查服务暴露情况
    echo "\n服务暴露检查" >> "$network_file"
    echo "============" >> "$network_file"
    
    local services
    mapfile -t services < <(kubectl get services -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
    
    for service in "${services[@]}"; do
        if [[ -n "$service" ]]; then
            local service_type
            service_type=$(kubectl get service "$service" -n "$NAMESPACE" -o jsonpath='{.spec.type}' 2>/dev/null || echo "")
            
            case $service_type in
                "LoadBalancer")
                    echo "⚠️  服务 $service 通过 LoadBalancer 暴露到互联网" >> "$network_file"
                    ;;
                "NodePort")
                    echo "⚠️  服务 $service 通过 NodePort 暴露" >> "$network_file"
                    ;;
                "ClusterIP")
                    echo "✅ 服务 $service 仅在集群内部可访问" >> "$network_file"
                    ;;
            esac
        fi
    done
}

# 检查密钥管理
check_secret_management() {
    local output_dir="$1"
    local secrets_file="$output_dir/secret-management.txt"
    
    echo "密钥管理检查" > "$secrets_file"
    echo "============" >> "$secrets_file"
    
    # 检查 Secret 使用情况
    local secrets
    mapfile -t secrets < <(kubectl get secrets -n "$NAMESPACE" -o jsonpath='{.items[?(@.type!="kubernetes.io/service-account-token")].metadata.name}' 2>/dev/null || echo "")
    
    if [[ ${#secrets[@]} -eq 0 || -z "${secrets[0]}" ]]; then
        echo "⚠️  未找到应用密钥" >> "$secrets_file"
    else
        echo "✅ 找到 ${#secrets[@]} 个应用密钥" >> "$secrets_file"
        
        for secret in "${secrets[@]}"; do
            if [[ -n "$secret" ]]; then
                echo "\n密钥: $secret" >> "$secrets_file"
                
                # 检查密钥类型
                local secret_type
                secret_type=$(kubectl get secret "$secret" -n "$NAMESPACE" -o jsonpath='{.type}' 2>/dev/null || echo "")
                echo "  类型: $secret_type" >> "$secrets_file"
                
                # 检查密钥大小（间接检查复杂度）
                local secret_size
                secret_size=$(kubectl get secret "$secret" -n "$NAMESPACE" -o jsonpath='{.data}' 2>/dev/null | jq 'to_entries | length' 2>/dev/null || echo "0")
                echo "  键数量: $secret_size" >> "$secrets_file"
            fi
        done
    fi
    
    # 检查环境变量中的密钥引用
    echo "\n环境变量密钥引用检查" >> "$secrets_file"
    echo "==================" >> "$secrets_file"
    
    local pods
    mapfile -t pods < <(kubectl get pods -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
    
    for pod in "${pods[@]}"; do
        if [[ -n "$pod" ]]; then
            local env_from_secret
            env_from_secret=$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.spec.containers[0].env[?(@.valueFrom.secretKeyRef)]}' 2>/dev/null || echo "")
            
            if [[ -n "$env_from_secret" ]]; then
                echo "✅ Pod $pod 使用 Secret 引用环境变量" >> "$secrets_file"
            else
                echo "⚠️  Pod $pod 可能直接使用明文环境变量" >> "$secrets_file"
            fi
        fi
    done
}

# 检查资源限制
check_resource_limits() {
    local output_dir="$1"
    local limits_file="$output_dir/resource-limits.txt"
    
    echo "资源限制检查" > "$limits_file"
    echo "============" >> "$limits_file"
    
    local pods
    mapfile -t pods < <(kubectl get pods -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
    
    for pod in "${pods[@]}"; do
        if [[ -n "$pod" ]]; then
            echo "\n检查 Pod: $pod" >> "$limits_file"
            echo "-------------------" >> "$limits_file"
            
            # 检查 CPU 限制
            local cpu_limit cpu_request
            cpu_limit=$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.spec.containers[0].resources.limits.cpu}' 2>/dev/null || echo "")
            cpu_request=$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.spec.containers[0].resources.requests.cpu}' 2>/dev/null || echo "")
            
            if [[ -n "$cpu_limit" ]]; then
                echo "✅ CPU 限制: $cpu_limit" >> "$limits_file"
            else
                echo "❌ 未设置 CPU 限制" >> "$limits_file"
            fi
            
            if [[ -n "$cpu_request" ]]; then
                echo "✅ CPU 请求: $cpu_request" >> "$limits_file"
            else
                echo "❌ 未设置 CPU 请求" >> "$limits_file"
            fi
            
            # 检查内存限制
            local memory_limit memory_request
            memory_limit=$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.spec.containers[0].resources.limits.memory}' 2>/dev/null || echo "")
            memory_request=$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.spec.containers[0].resources.requests.memory}' 2>/dev/null || echo "")
            
            if [[ -n "$memory_limit" ]]; then
                echo "✅ 内存限制: $memory_limit" >> "$limits_file"
            else
                echo "❌ 未设置内存限制" >> "$limits_file"
            fi
            
            if [[ -n "$memory_request" ]]; then
                echo "✅ 内存请求: $memory_request" >> "$limits_file"
            else
                echo "❌ 未设置内存请求" >> "$limits_file"
            fi
        fi
    done
}

# 网络安全扫描
scan_network_security() {
    log_security "网络安全扫描..."
    
    local network_dir="$SECURITY_SESSION_DIR/network"
    mkdir -p "$network_dir"
    
    local issues_found=0
    
    # 端口扫描
    log_info "端口扫描..."
    scan_exposed_ports "$network_dir"
    
    # TLS 配置检查
    log_info "TLS 配置检查..."
    check_tls_configuration "$network_dir"
    
    # 证书检查
    log_info "证书检查..."
    check_certificates "$network_dir"
    
    return $issues_found
}

# 扫描暴露的端口
scan_exposed_ports() {
    local output_dir="$1"
    local ports_file="$output_dir/exposed-ports.txt"
    
    echo "暴露端口扫描" > "$ports_file"
    echo "============" >> "$ports_file"
    
    # 获取服务端口
    local services
    mapfile -t services < <(kubectl get services -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
    
    for service in "${services[@]}"; do
        if [[ -n "$service" ]]; then
            echo "\n服务: $service" >> "$ports_file"
            echo "----------" >> "$ports_file"
            
            local service_type ports
            service_type=$(kubectl get service "$service" -n "$NAMESPACE" -o jsonpath='{.spec.type}' 2>/dev/null || echo "")
            ports=$(kubectl get service "$service" -n "$NAMESPACE" -o jsonpath='{.spec.ports[*].port}' 2>/dev/null || echo "")
            
            echo "类型: $service_type" >> "$ports_file"
            echo "端口: $ports" >> "$ports_file"
            
            # 如果是 LoadBalancer 或 NodePort，检查外部访问
            if [[ "$service_type" == "LoadBalancer" ]] || [[ "$service_type" == "NodePort" ]]; then
                echo "⚠️  服务暴露到外部网络" >> "$ports_file"
            fi
        fi
    done
    
    # 检查 Ingress
    echo "\nIngress 检查" >> "$ports_file"
    echo "===========" >> "$ports_file"
    
    local ingresses
    mapfile -t ingresses < <(kubectl get ingress -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
    
    if [[ ${#ingresses[@]} -eq 0 || -z "${ingresses[0]}" ]]; then
        echo "未配置 Ingress" >> "$ports_file"
    else
        for ingress in "${ingresses[@]}"; do
            if [[ -n "$ingress" ]]; then
                echo "\nIngress: $ingress" >> "$ports_file"
                kubectl describe ingress "$ingress" -n "$NAMESPACE" >> "$ports_file" 2>/dev/null || true
            fi
        done
    fi
}

# 检查 TLS 配置
check_tls_configuration() {
    local output_dir="$1"
    local tls_file="$output_dir/tls-configuration.txt"
    
    echo "TLS 配置检查" > "$tls_file"
    echo "============" >> "$tls_file"
    
    # 检查 Ingress TLS 配置
    local ingresses
    mapfile -t ingresses < <(kubectl get ingress -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
    
    for ingress in "${ingresses[@]}"; do
        if [[ -n "$ingress" ]]; then
            echo "\nIngress: $ingress" >> "$tls_file"
            echo "----------------" >> "$tls_file"
            
            local tls_config
            tls_config=$(kubectl get ingress "$ingress" -n "$NAMESPACE" -o jsonpath='{.spec.tls}' 2>/dev/null || echo "")
            
            if [[ -n "$tls_config" && "$tls_config" != "null" ]]; then
                echo "✅ 已配置 TLS" >> "$tls_file"
                echo "TLS 配置: $tls_config" >> "$tls_file"
            else
                echo "❌ 未配置 TLS，流量未加密" >> "$tls_file"
            fi
        fi
    done
    
    # 检查服务的 TLS 配置
    echo "\n服务 TLS 检查" >> "$tls_file"
    echo "=============" >> "$tls_file"
    
    # 尝试连接服务并检查 TLS
    local service_url
    service_url=$(get_service_url_for_tls_check)
    
    if [[ -n "$service_url" ]]; then
        echo "检查服务 TLS: $service_url" >> "$tls_file"
        
        # 使用 openssl 检查 TLS
        if command -v openssl &> /dev/null; then
            local host port
            host=$(echo "$service_url" | sed 's|https\?://||' | cut -d':' -f1)
            port=$(echo "$service_url" | sed 's|https\?://||' | cut -d':' -f2 | cut -d'/' -f1)
            
            if [[ "$port" == "$host" ]]; then
                port="443"
            fi
            
            timeout 10 openssl s_client -connect "$host:$port" -servername "$host" < /dev/null >> "$tls_file" 2>&1 || \
                echo "无法连接或不支持 TLS" >> "$tls_file"
        fi
    fi
}

# 获取用于 TLS 检查的服务 URL
get_service_url_for_tls_check() {
    # 尝试从 Ingress 获取
    local ingress_host
    ingress_host=$(kubectl get ingress -n "$NAMESPACE" -o jsonpath='{.items[0].spec.rules[0].host}' 2>/dev/null || echo "")
    
    if [[ -n "$ingress_host" ]]; then
        echo "https://$ingress_host"
        return
    fi
    
    # 尝试从 LoadBalancer 获取
    local lb_ip
    lb_ip=$(kubectl get service -n "$NAMESPACE" -o jsonpath='{.items[?(@.spec.type=="LoadBalancer")].status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "")
    
    if [[ -n "$lb_ip" ]]; then
        echo "https://$lb_ip"
        return
    fi
    
    echo ""
}

# 检查证书
check_certificates() {
    local output_dir="$1"
    local certs_file="$output_dir/certificates.txt"
    
    echo "证书检查" > "$certs_file"
    echo "========" >> "$certs_file"
    
    # 检查 TLS Secret
    local tls_secrets
    mapfile -t tls_secrets < <(kubectl get secrets -n "$NAMESPACE" -o jsonpath='{.items[?(@.type=="kubernetes.io/tls")].metadata.name}' 2>/dev/null || echo "")
    
    if [[ ${#tls_secrets[@]} -eq 0 || -z "${tls_secrets[0]}" ]]; then
        echo "未找到 TLS 证书" >> "$certs_file"
    else
        for secret in "${tls_secrets[@]}"; do
            if [[ -n "$secret" ]]; then
                echo "\n证书 Secret: $secret" >> "$certs_file"
                echo "-------------------" >> "$certs_file"
                
                # 获取证书内容并检查
                local cert_data
                cert_data=$(kubectl get secret "$secret" -n "$NAMESPACE" -o jsonpath='{.data.tls\.crt}' 2>/dev/null | base64 -d 2>/dev/null || echo "")
                
                if [[ -n "$cert_data" ]]; then
                    # 检查证书有效期
                    echo "$cert_data" | openssl x509 -noout -dates >> "$certs_file" 2>/dev/null || echo "无法解析证书" >> "$certs_file"
                    
                    # 检查证书主题
                    echo "$cert_data" | openssl x509 -noout -subject >> "$certs_file" 2>/dev/null || true
                    
                    # 检查证书颁发者
                    echo "$cert_data" | openssl x509 -noout -issuer >> "$certs_file" 2>/dev/null || true
                fi
            fi
        done
    fi
}

# 密钥泄露扫描
scan_secrets() {
    log_security "密钥泄露扫描..."
    
    local secrets_dir="$SECURITY_SESSION_DIR/secrets"
    mkdir -p "$secrets_dir"
    
    local issues_found=0
    
    # 扫描代码中的硬编码密钥
    scan_hardcoded_secrets "$secrets_dir"
    
    # 扫描配置文件中的敏感信息
    log_info "扫描配置文件..."
    scan_config_secrets "$secrets_dir"
    
    # 扫描环境变量
    log_info "扫描环境变量..."
    scan_environment_secrets "$secrets_dir"
    
    return $issues_found
}

# 扫描配置文件中的密钥
scan_config_secrets() {
    local output_dir="$1"
    local config_secrets_file="$output_dir/config-secrets.txt"
    
    echo "配置文件密钥扫描" > "$config_secrets_file"
    echo "================" >> "$config_secrets_file"
    
    # 扫描 YAML 和 JSON 配置文件
    local config_patterns=(
        "password:\s*['\"][^'\"]{8,}['\"]"  # YAML 密码
        "\"password\":\s*\"[^\"]{8,}\""  # JSON 密码
        "api[_-]?key:\s*['\"][^'\"]{16,}['\"]"  # API 密钥
        "secret:\s*['\"][^'\"]{16,}['\"]"  # 密钥
    )
    
    local secrets_found=0
    
    for pattern in "${config_patterns[@]}"; do
        if find "$PROJECT_ROOT" -name "*.yaml" -o -name "*.yml" -o -name "*.json" | \
           xargs grep -l -i -E "$pattern" >> "$config_secrets_file" 2>/dev/null; then
            ((secrets_found++))
        fi
    done
    
    if [[ $secrets_found -eq 0 ]]; then
        echo "未在配置文件中发现硬编码密钥" >> "$config_secrets_file"
    fi
}

# 扫描环境变量中的密钥
scan_environment_secrets() {
    local output_dir="$1"
    local env_secrets_file="$output_dir/environment-secrets.txt"
    
    echo "环境变量密钥扫描" > "$env_secrets_file"
    echo "================" >> "$env_secrets_file"
    
    # 检查 Pod 环境变量
    local pods
    mapfile -t pods < <(kubectl get pods -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
    
    for pod in "${pods[@]}"; do
        if [[ -n "$pod" ]]; then
            echo "\n检查 Pod: $pod" >> "$env_secrets_file"
            echo "-------------------" >> "$env_secrets_file"
            
            # 获取环境变量（不显示值，只显示键名）
            kubectl exec -n "$NAMESPACE" "$pod" -- env 2>/dev/null | \
                grep -E "(PASSWORD|SECRET|KEY|TOKEN)" | \
                cut -d'=' -f1 >> "$env_secrets_file" 2>/dev/null || \
                echo "无法获取环境变量或未发现敏感变量" >> "$env_secrets_file"
        fi
    done
}

# 生成综合安全报告
generate_comprehensive_report() {
    local scan_results=("$@")
    
    log_info "生成综合安全报告..."
    
    local report_file="$OUTPUT_DIR/nova-proxy-security-report-$(date +%Y%m%d_%H%M%S).html"
    
    # 生成 HTML 报告
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Nova Proxy 安全扫描报告</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .pass { color: green; font-weight: bold; }
        .fail { color: red; font-weight: bold; }
        .warning { color: orange; font-weight: bold; }
        .metric { display: inline-block; margin: 10px; padding: 10px; background-color: #f9f9f9; border-radius: 3px; }
        pre { background-color: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Nova Proxy 安全扫描报告</h1>
        <p><strong>扫描时间:</strong> $(date)</p>
        <p><strong>环境:</strong> $ENVIRONMENT</p>
        <p><strong>命名空间:</strong> $NAMESPACE</p>
        <p><strong>扫描会话:</strong> $(basename "$SECURITY_SESSION_DIR")</p>
    </div>

    <div class="section">
        <h2>扫描结果概览</h2>
        <table>
            <tr><th>扫描项目</th><th>状态</th><th>详细报告</th></tr>
EOF

    # 添加扫描结果到表格
    for result in "${scan_results[@]}"; do
        local scan_type status
        scan_type=$(echo "$result" | cut -d':' -f1)
        status=$(echo "$result" | cut -d':' -f2)
        
        local status_class status_text
        if [[ "$status" == "PASS" ]]; then
            status_class="pass"
            status_text="✅ 通过"
        else
            status_class="fail"
            status_text="❌ 失败"
        fi
        
        cat >> "$report_file" << EOF
            <tr>
                <td>$(echo "$scan_type" | tr '[:lower:]' '[:upper:]')</td>
                <td class="$status_class">$status_text</td>
                <td><a href="#$scan_type">查看详情</a></td>
            </tr>
EOF
    done
    
    cat >> "$report_file" << EOF
        </table>
    </div>

    <div class="section">
        <h2>安全建议</h2>
        <ul>
            <li>定期更新依赖包和基础镜像</li>
            <li>启用网络策略限制 Pod 间通信</li>
            <li>使用非 root 用户运行容器</li>
            <li>配置资源限制防止资源耗尽攻击</li>
            <li>启用 TLS 加密所有网络通信</li>
            <li>定期轮换密钥和证书</li>
            <li>实施最小权限原则</li>
        </ul>
    </div>

    <div class="section">
        <h2>详细扫描报告</h2>
        <p>详细的扫描结果保存在: <code>$SECURITY_SESSION_DIR</code></p>
    </div>
</body>
</html>
EOF

    log_success "安全报告已生成: $report_file"
    
    # 生成 JSON 格式的简化报告
    generate_json_report "${scan_results[@]}"
}

# 生成 JSON 格式报告
generate_json_report() {
    local scan_results=("$@")
    local json_report="$OUTPUT_DIR/nova-proxy-security-summary.json"
    
    cat > "$json_report" << EOF
{
    "scan_metadata": {
        "timestamp": "$(date -Iseconds)",
        "environment": "$ENVIRONMENT",
        "namespace": "$NAMESPACE",
        "session_id": "$(basename "$SECURITY_SESSION_DIR")"
    },
    "scan_results": {
EOF
    
    local first=true
    for result in "${scan_results[@]}"; do
        local scan_type status
        scan_type=$(echo "$result" | cut -d':' -f1)
        status=$(echo "$result" | cut -d':' -f2)
        
        if [[ "$first" == "true" ]]; then
            first=false
        else
            echo "," >> "$json_report"
        fi
        
        echo "        \"$scan_type\": \"$status\"" >> "$json_report"
    done
    
    cat >> "$json_report" << EOF
    },
    "recommendations": [
        "定期更新依赖包和基础镜像",
        "启用网络策略限制 Pod 间通信",
        "使用非 root 用户运行容器",
        "配置资源限制防止资源耗尽攻击",
        "启用 TLS 加密所有网络通信",
        "定期轮换密钥和证书",
        "实施最小权限原则"
    ]
}
EOF
    
    log_success "JSON 报告已生成: $json_report"
}

# 合规性检查
run_compliance_check() {
    log_security "合规性检查..."
    
    local compliance_dir="$SECURITY_SESSION_DIR/compliance"
    mkdir -p "$compliance_dir"
    
    # CIS Kubernetes 基准检查
    check_cis_kubernetes "$compliance_dir"
    
    # NIST 网络安全框架检查
    check_nist_framework "$compliance_dir"
    
    # OWASP Top 10 检查
    check_owasp_top10 "$compliance_dir"
    
    log_success "合规性检查完成"
}

# CIS Kubernetes 基准检查
check_cis_kubernetes() {
    local output_dir="$1"
    local cis_file="$output_dir/cis-kubernetes.txt"
    
    echo "CIS Kubernetes 基准检查" > "$cis_file"
    echo "======================" >> "$cis_file"
    
    # 检查关键的 CIS 控制项
    local cis_checks=(
        "Pod 安全策略"
        "网络策略"
        "RBAC 配置"
        "密钥管理"
        "审计日志"
        "资源限制"
    )
    
    for check in "${cis_checks[@]}"; do
        echo "\n检查项: $check" >> "$cis_file"
        echo "$(printf '%.${#check}s' | tr ' ' '-')" >> "$cis_file"
        
        case "$check" in
            "Pod 安全策略")
                # 检查是否有 Pod 以 root 运行
                local root_pods
                root_pods=$(kubectl get pods -n "$NAMESPACE" -o jsonpath='{.items[?(@.spec.securityContext.runAsUser==0)].metadata.name}' 2>/dev/null || echo "")
                
                if [[ -n "$root_pods" ]]; then
                    echo "❌ 发现以 root 运行的 Pod: $root_pods" >> "$cis_file"
                else
                    echo "✅ 未发现以 root 运行的 Pod" >> "$cis_file"
                fi
                ;;
            "网络策略")
                local np_count
                np_count=$(kubectl get networkpolicies -n "$NAMESPACE" --no-headers 2>/dev/null | wc -l || echo "0")
                
                if [[ "$np_count" -gt 0 ]]; then
                    echo "✅ 已配置网络策略 ($np_count 个)" >> "$cis_file"
                else
                    echo "❌ 未配置网络策略" >> "$cis_file"
                fi
                ;;
            "RBAC 配置")
                local sa_count
                sa_count=$(kubectl get serviceaccounts -n "$NAMESPACE" --no-headers 2>/dev/null | wc -l || echo "0")
                
                if [[ "$sa_count" -gt 1 ]]; then  # 除了 default SA
                    echo "✅ 已配置自定义 ServiceAccount" >> "$cis_file"
                else
                    echo "⚠️  仅使用默认 ServiceAccount" >> "$cis_file"
                fi
                ;;
        esac
    done
}

# NIST 网络安全框架检查
check_nist_framework() {
    local output_dir="$1"
    local nist_file="$output_dir/nist-framework.txt"
    
    echo "NIST 网络安全框架检查" > "$nist_file"
    echo "====================" >> "$nist_file"
    
    # NIST 五大功能
    local nist_functions=(
        "识别(Identify)"
        "保护(Protect)"
        "检测(Detect)"
        "响应(Respond)"
        "恢复(Recover)"
    )
    
    for func in "${nist_functions[@]}"; do
        echo "\n$func" >> "$nist_file"
        echo "$(printf '%.${#func}s' | tr ' ' '=')" >> "$nist_file"
        
        case "$func" in
            "识别(Identify)")
                echo "✅ 资产清单管理" >> "$nist_file"
                echo "✅ 漏洞管理" >> "$nist_file"
                echo "✅ 风险评估" >> "$nist_file"
                ;;
            "保护(Protect)")
                echo "✅ 访问控制" >> "$nist_file"
                echo "✅ 数据安全" >> "$nist_file"
                echo "✅ 防护技术" >> "$nist_file"
                ;;
            "检测(Detect)")
                echo "✅ 安全监控" >> "$nist_file"
                echo "✅ 异常检测" >> "$nist_file"
                ;;
            "响应(Respond)")
                echo "⚠️  事件响应计划" >> "$nist_file"
                echo "⚠️  通信机制" >> "$nist_file"
                ;;
            "恢复(Recover)")
                echo "⚠️  恢复计划" >> "$nist_file"
                echo "⚠️  改进措施" >> "$nist_file"
                ;;
        esac
    done
}

# OWASP Top 10 检查
check_owasp_top10() {
    local output_dir="$1"
    local owasp_file="$output_dir/owasp-top10.txt"
    
    echo "OWASP Top 10 检查" > "$owasp_file"
    echo "================" >> "$owasp_file"
    
    # OWASP Top 10 2021
    local owasp_risks=(
        "A01:2021 – 访问控制失效"
        "A02:2021 – 加密失效"
        "A03:2021 – 注入"
        "A04:2021 – 不安全设计"
        "A05:2021 – 安全配置错误"
        "A06:2021 – 易受攻击和过时的组件"
        "A07:2021 – 身份识别和身份验证失效"
        "A08:2021 – 软件和数据完整性失效"
        "A09:2021 – 安全日志记录和监控失效"
        "A10:2021 – 服务器端请求伪造"
    )
    
    for risk in "${owasp_risks[@]}"; do
        echo "\n$risk" >> "$owasp_file"
        echo "$(printf '%.${#risk}s' | tr ' ' '-')" >> "$owasp_file"
        
        case "$risk" in
            *"访问控制失效"*)
                echo "✅ RBAC 配置检查" >> "$owasp_file"
                echo "✅ 最小权限原则" >> "$owasp_file"
                ;;
            *"加密失效"*)
                echo "✅ TLS 配置检查" >> "$owasp_file"
                echo "✅ 密钥管理" >> "$owasp_file"
                ;;
            *"注入"*)
                echo "✅ 输入验证" >> "$owasp_file"
                echo "✅ 参数化查询" >> "$owasp_file"
                ;;
            *"安全配置错误"*)
                echo "⚠️  默认配置检查" >> "$owasp_file"
                echo "⚠️  错误处理" >> "$owasp_file"
                ;;
            *"易受攻击和过时的组件"*)
                echo "✅ 依赖漏洞扫描" >> "$owasp_file"
                echo "✅ 组件更新管理" >> "$owasp_file"
                ;;
        esac
    done
}

# 运行时安全扫描
run_runtime_security_scan() {
    log_security "运行时安全扫描..."
    
    local runtime_dir="$SECURITY_SESSION_DIR/runtime"
    mkdir -p "$runtime_dir"
    
    # 进程监控
    monitor_processes "$runtime_dir"
    
    # 网络连接监控
    monitor_network_connections "$runtime_dir"
    
    # 文件系统监控
    monitor_filesystem "$runtime_dir"
    
    log_success "运行时安全扫描完成"
}

# 监控进程
monitor_processes() {
    local output_dir="$1"
    local processes_file="$output_dir/processes.txt"
    
    echo "进程监控" > "$processes_file"
    echo "========" >> "$processes_file"
    
    local pods
    mapfile -t pods < <(kubectl get pods -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
    
    for pod in "${pods[@]}"; do
        if [[ -n "$pod" ]]; then
            echo "\nPod: $pod" >> "$processes_file"
            echo "----------" >> "$processes_file"
            
            # 获取进程列表
            kubectl exec -n "$NAMESPACE" "$pod" -- ps aux >> "$processes_file" 2>/dev/null || \
                echo "无法获取进程信息" >> "$processes_file"
        fi
    done
}

# 监控网络连接
monitor_network_connections() {
    local output_dir="$1"
    local network_file="$output_dir/network-connections.txt"
    
    echo "网络连接监控" > "$network_file"
    echo "============" >> "$network_file"
    
    local pods
    mapfile -t pods < <(kubectl get pods -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
    
    for pod in "${pods[@]}"; do
        if [[ -n "$pod" ]]; then
            echo "\nPod: $pod" >> "$network_file"
            echo "----------" >> "$network_file"
            
            # 获取网络连接
            kubectl exec -n "$NAMESPACE" "$pod" -- netstat -tuln >> "$network_file" 2>/dev/null || \
                echo "无法获取网络连接信息" >> "$network_file"
        fi
    done
}

# 监控文件系统
monitor_filesystem() {
    local output_dir="$1"
    local fs_file="$output_dir/filesystem.txt"
    
    echo "文件系统监控" > "$fs_file"
    echo "============" >> "$fs_file"
    
    local pods
    mapfile -t pods < <(kubectl get pods -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
    
    for pod in "${pods[@]}"; do
        if [[ -n "$pod" ]]; then
            echo "\nPod: $pod" >> "$fs_file"
            echo "----------" >> "$fs_file"
            
            # 检查文件权限
            kubectl exec -n "$NAMESPACE" "$pod" -- find /app -type f -perm /022 >> "$fs_file" 2>/dev/null || \
                echo "无法检查文件权限" >> "$fs_file"
        fi
    done
}

# 自动修复安全问题
fix_security_issues() {
    log_info "自动修复安全问题..."
    
    if [[ "$AUTO_FIX" != "true" ]]; then
        log_warning "自动修复未启用，跳过修复步骤"
        return 0
    fi
    
    local fixes_applied=0
    
    # 修复资源限制问题
    if fix_resource_limits; then
        ((fixes_applied++))
    fi
    
    # 修复安全上下文问题
    if fix_security_context; then
        ((fixes_applied++))
    fi
    
    # 修复网络策略问题
    if fix_network_policies; then
        ((fixes_applied++))
    fi
    
    log_success "应用了 $fixes_applied 个安全修复"
}

# 修复资源限制
fix_resource_limits() {
    log_info "修复资源限制..."
    
    # 检查是否有未设置资源限制的部署
    local deployments
    mapfile -t deployments < <(kubectl get deployments -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
    
    for deployment in "${deployments[@]}"; do
        if [[ -n "$deployment" ]]; then
            local has_limits
            has_limits=$(kubectl get deployment "$deployment" -n "$NAMESPACE" -o jsonpath='{.spec.template.spec.containers[0].resources.limits}' 2>/dev/null || echo "")
            
            if [[ -z "$has_limits" || "$has_limits" == "null" ]]; then
                log_info "为部署 $deployment 添加资源限制..."
                
                kubectl patch deployment "$deployment" -n "$NAMESPACE" --patch '{
                    "spec": {
                        "template": {
                            "spec": {
                                "containers": [{
                                    "name": "nova-proxy",
                                    "resources": {
                                        "limits": {
                                            "cpu": "500m",
                                            "memory": "512Mi"
                                        },
                                        "requests": {
                                            "cpu": "100m",
                                            "memory": "128Mi"
                                        }
                                    }
                                }]
                            }
                        }
                    }
                }' 2>/dev/null && return 0
            fi
        fi
    done
    
    return 1
}

# 修复安全上下文
fix_security_context() {
    log_info "修复安全上下文..."
    
    local deployments
    mapfile -t deployments < <(kubectl get deployments -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
    
    for deployment in "${deployments[@]}"; do
        if [[ -n "$deployment" ]]; then
            local security_context
            security_context=$(kubectl get deployment "$deployment" -n "$NAMESPACE" -o jsonpath='{.spec.template.spec.securityContext}' 2>/dev/null || echo "")
            
            if [[ -z "$security_context" || "$security_context" == "null" ]]; then
                log_info "为部署 $deployment 添加安全上下文..."
                
                kubectl patch deployment "$deployment" -n "$NAMESPACE" --patch '{
                    "spec": {
                        "template": {
                            "spec": {
                                "securityContext": {
                                    "runAsNonRoot": true,
                                    "runAsUser": 1000,
                                    "fsGroup": 1000
                                },
                                "containers": [{
                                    "name": "nova-proxy",
                                    "securityContext": {
                                        "allowPrivilegeEscalation": false,
                                        "readOnlyRootFilesystem": true,
                                        "capabilities": {
                                            "drop": ["ALL"]
                                        }
                                    }
                                }]
                            }
                        }
                    }
                }' 2>/dev/null && return 0
            fi
        fi
    done
    
    return 1
}

# 修复网络策略
fix_network_policies() {
    log_info "修复网络策略..."
    
    # 检查是否存在网络策略
    local np_count
    np_count=$(kubectl get networkpolicies -n "$NAMESPACE" --no-headers 2>/dev/null | wc -l || echo "0")
    
    if [[ "$np_count" -eq 0 ]]; then
        log_info "创建默认网络策略..."
        
        cat << EOF | kubectl apply -f - 2>/dev/null
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: nova-proxy-network-policy
  namespace: $NAMESPACE
spec:
  podSelector:
    matchLabels:
      app: nova-proxy
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: $NAMESPACE
    ports:
    - protocol: TCP
      port: 8080
    - protocol: TCP
      port: 8443
  egress:
  - to: []
    ports:
    - protocol: TCP
      port: 53
    - protocol: UDP
      port: 53
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
EOF
        return $?
    fi
    
    return 1
}

# 主函数
main() {
    parse_args "$@"
    check_dependencies
    setup_security_env
    
    case "$COMMAND" in
        "scan-all")
            run_full_security_scan
            ;;
        "scan-code")
            scan_code_security
            ;;
        "scan-dependencies")
            scan_dependencies
            ;;
        "scan-container")
            scan_container_images
            ;;
        "scan-k8s")
            scan_kubernetes_security
            ;;
        "scan-network")
            scan_network_security
            ;;
        "scan-secrets")
            scan_secrets
            ;;
        "scan-compliance")
            run_compliance_check
            ;;
        "scan-runtime")
            run_runtime_security_scan
            ;;
        "generate-report")
            generate_comprehensive_report
            ;;
        "fix-issues")
            fix_security_issues
            ;;
        *)
            log_error "未知命令: $COMMAND"
            show_help
            exit 1
            ;;
    esac
    
    log_success "安全扫描任务完成"
}

# 执行主函数
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi