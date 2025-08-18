#!/bin/bash

# Nova Proxy 系统资源检查脚本
# 帮助用户评估系统配置并推荐合适的部署方案

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 打印带颜色的消息
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "\n${BLUE}=== $1 ===${NC}"
}

# 检查命令是否存在
check_command() {
    if ! command -v "$1" &> /dev/null; then
        print_error "命令 '$1' 未找到，请先安装"
        return 1
    fi
    return 0
}

# 获取系统信息
get_system_info() {
    print_header "系统信息检查"
    
    # 操作系统
    if [ -f /etc/os-release ]; then
        OS=$(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)
        print_info "操作系统: $OS"
    fi
    
    # 内核版本
    KERNEL=$(uname -r)
    print_info "内核版本: $KERNEL"
    
    # 架构
    ARCH=$(uname -m)
    print_info "系统架构: $ARCH"
}

# 检查内存
check_memory() {
    print_header "内存检查"
    
    # 总内存 (MB)
    TOTAL_MEM=$(free -m | awk 'NR==2{printf "%.0f", $2}')
    # 可用内存 (MB)
    AVAILABLE_MEM=$(free -m | awk 'NR==2{printf "%.0f", $7}')
    # 内存使用率
    MEM_USAGE=$(free | awk 'NR==2{printf "%.1f", ($3/$2)*100}')
    
    print_info "总内存: ${TOTAL_MEM}MB"
    print_info "可用内存: ${AVAILABLE_MEM}MB"
    print_info "内存使用率: ${MEM_USAGE}%"
    
    # 内存建议
    if [ "$TOTAL_MEM" -ge 4096 ]; then
        print_success "内存充足，推荐完整部署"
        MEMORY_SCORE=3
    elif [ "$TOTAL_MEM" -ge 2048 ]; then
        print_warning "内存适中，推荐轻量级部署或选择性启用监控"
        MEMORY_SCORE=2
    else
        print_error "内存不足，强烈推荐轻量级部署"
        MEMORY_SCORE=1
    fi
}

# 检查CPU
check_cpu() {
    print_header "CPU检查"
    
    # CPU核心数
    CPU_CORES=$(nproc)
    # CPU型号
    CPU_MODEL=$(grep "model name" /proc/cpuinfo | head -1 | cut -d':' -f2 | xargs)
    # 平均负载
    LOAD_AVG=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
    
    print_info "CPU核心数: $CPU_CORES"
    print_info "CPU型号: $CPU_MODEL"
    print_info "平均负载: $LOAD_AVG"
    
    # CPU建议
    if [ "$CPU_CORES" -ge 4 ]; then
        print_success "CPU性能充足，推荐完整部署"
        CPU_SCORE=3
    elif [ "$CPU_CORES" -ge 2 ]; then
        print_warning "CPU性能适中，推荐轻量级部署"
        CPU_SCORE=2
    else
        print_error "CPU性能不足，强烈推荐轻量级部署"
        CPU_SCORE=1
    fi
}

# 检查磁盘空间
check_disk() {
    print_header "磁盘空间检查"
    
    # 当前目录磁盘使用情况
    DISK_INFO=$(df -h . | tail -1)
    DISK_USAGE=$(echo $DISK_INFO | awk '{print $5}' | sed 's/%//')
    DISK_AVAILABLE=$(echo $DISK_INFO | awk '{print $4}')
    
    print_info "磁盘使用率: ${DISK_USAGE}%"
    print_info "可用空间: $DISK_AVAILABLE"
    
    # 磁盘建议
    if [ "$DISK_USAGE" -lt 70 ]; then
        print_success "磁盘空间充足"
        DISK_SCORE=3
    elif [ "$DISK_USAGE" -lt 85 ]; then
        print_warning "磁盘空间适中，建议定期清理"
        DISK_SCORE=2
    else
        print_error "磁盘空间不足，请清理后再部署"
        DISK_SCORE=1
    fi
}

# 检查Docker
check_docker() {
    print_header "Docker环境检查"
    
    if ! check_command "docker"; then
        print_error "Docker未安装，请先安装Docker"
        DOCKER_SCORE=0
        return
    fi
    
    # Docker版本
    DOCKER_VERSION=$(docker --version | awk '{print $3}' | sed 's/,//')
    print_info "Docker版本: $DOCKER_VERSION"
    
    # Docker Compose
    if check_command "docker-compose" || docker compose version &>/dev/null; then
        if command -v docker-compose &> /dev/null; then
            COMPOSE_VERSION=$(docker-compose --version | awk '{print $3}' | sed 's/,//')
        else
            COMPOSE_VERSION=$(docker compose version --short)
        fi
        print_info "Docker Compose版本: $COMPOSE_VERSION"
        print_success "Docker环境正常"
        DOCKER_SCORE=3
    else
        print_error "Docker Compose未安装"
        DOCKER_SCORE=1
    fi
}

# 检查网络端口
check_ports() {
    print_header "端口检查"
    
    PORTS=("8080" "8443" "8081" "9090" "9091" "3000" "16686" "6379" "80" "443")
    OCCUPIED_PORTS=()
    
    for port in "${PORTS[@]}"; do
        if netstat -tuln 2>/dev/null | grep -q ":$port " || ss -tuln 2>/dev/null | grep -q ":$port "; then
            OCCUPIED_PORTS+=("$port")
        fi
    done
    
    if [ ${#OCCUPIED_PORTS[@]} -eq 0 ]; then
        print_success "所有必需端口都可用"
        PORT_SCORE=3
    else
        print_warning "以下端口已被占用: ${OCCUPIED_PORTS[*]}"
        print_info "请检查是否有冲突的服务"
        PORT_SCORE=2
    fi
}

# 生成部署建议
generate_recommendation() {
    print_header "部署建议"
    
    # 计算总分
    TOTAL_SCORE=$((MEMORY_SCORE + CPU_SCORE + DISK_SCORE + DOCKER_SCORE))
    MAX_SCORE=12
    
    print_info "系统评分: $TOTAL_SCORE/$MAX_SCORE"
    
    if [ "$TOTAL_SCORE" -ge 10 ]; then
        print_success "🚀 推荐使用完整部署 (docker-compose.yml)"
        echo -e "\n${GREEN}部署命令:${NC}"
        echo "cp .env.example .env"
        echo "docker compose up -d"
        
    elif [ "$TOTAL_SCORE" -ge 7 ]; then
        print_warning "💡 推荐使用轻量级部署 (docker-compose.minimal.yml)"
        echo -e "\n${YELLOW}部署命令:${NC}"
        echo "cp .env.minimal .env"
        echo "docker compose -f docker-compose.minimal.yml up -d"
        echo "# 可选：启用监控"
        echo "docker compose -f docker-compose.minimal.yml --profile monitoring up -d"
        
    else
        print_error "⚠️  系统配置较低，建议仅运行核心服务"
        echo -e "\n${RED}部署命令:${NC}"
        echo "cp .env.minimal .env"
        echo "docker compose -f docker-compose.minimal.yml up -d nova-server"
    fi
    
    # 优化建议
    echo -e "\n${BLUE}优化建议:${NC}"
    
    if [ "$MEMORY_SCORE" -lt 3 ]; then
        echo "• 考虑增加内存或使用swap"
        echo "• 设置 METRICS_ENABLED=false 禁用指标收集"
        echo "• 调整 GOGC=200 减少GC频率"
    fi
    
    if [ "$CPU_SCORE" -lt 3 ]; then
        echo "• 设置 GOMAXPROCS=1 限制CPU使用"
        echo "• 延长健康检查间隔"
        echo "• 使用 LOG_LEVEL=warn 减少日志输出"
    fi
    
    if [ "$DISK_SCORE" -lt 3 ]; then
        echo "• 定期清理Docker镜像和容器"
        echo "• 减少日志保留时间"
        echo "• 限制Prometheus数据存储大小"
    fi
}

# 主函数
main() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                Nova Proxy 系统资源检查工具                    ║"
    echo "║              帮助您选择最适合的部署方案                        ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}\n"
    
    # 初始化评分
    MEMORY_SCORE=0
    CPU_SCORE=0
    DISK_SCORE=0
    DOCKER_SCORE=0
    PORT_SCORE=0
    
    # 执行检查
    get_system_info
    check_memory
    check_cpu
    check_disk
    check_docker
    check_ports
    
    # 生成建议
    generate_recommendation
    
    echo -e "\n${BLUE}检查完成！${NC}"
    echo "如需更多帮助，请查看 DEPLOYMENT_GUIDE.md"
}

# 运行主函数
main "$@"