#!/bin/bash

# Nova Proxy 管理脚本
# 提供完整的服务部署、管理和配置功能

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# 项目根目录
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

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

log_header() {
    echo -e "\n${CYAN}=== $1 ===${NC}\n"
}

# 检查依赖
check_dependencies() {
    local missing_deps=()
    
    if ! command -v docker &> /dev/null; then
        missing_deps+=("docker")
    fi
    
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        missing_deps+=("docker-compose")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "缺少以下依赖: ${missing_deps[*]}"
        log_info "请先安装 Docker 和 Docker Compose"
        exit 1
    fi
}

# 获取 Docker Compose 命令
get_compose_cmd() {
    if docker compose version &> /dev/null; then
        echo "docker compose"
    else
        echo "docker-compose"
    fi
}

# 显示主菜单
show_main_menu() {
    clear
    echo -e "${PURPLE}"
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║                    Nova Proxy 管理工具                        ║
║                     v1.0.0 - 2024                           ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    echo -e "${WHITE}请选择操作:${NC}"
    echo -e "${CYAN}┌─ 部署管理 ─────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} 1) 系统检查和部署建议"
    echo -e "${CYAN}│${NC} 2) 核心服务部署 (最小资源)"
    echo -e "${CYAN}│${NC} 3) 轻量级部署 (含可选监控)"
    echo -e "${CYAN}│${NC} 4) 完整部署 (全套监控)"
    echo -e "${CYAN}│${NC} 5) 开发环境部署"
    echo -e "${CYAN}└───────────────────────────────────────────────────────────┘${NC}"
    
    echo -e "${CYAN}┌─ 服务管理 ─────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} 6) 查看服务状态"
    echo -e "${CYAN}│${NC} 7) 启动服务"
    echo -e "${CYAN}│${NC} 8) 停止服务"
    echo -e "${CYAN}│${NC} 9) 重启服务"
    echo -e "${CYAN}│${NC} 10) 查看服务日志"
    echo -e "${CYAN}└───────────────────────────────────────────────────────────┘${NC}"
    
    echo -e "${CYAN}┌─ 监控管理 ─────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} 11) 启用监控组件"
    echo -e "${CYAN}│${NC} 12) 禁用监控组件"
    echo -e "${CYAN}│${NC} 13) 监控面板访问地址"
    echo -e "${CYAN}│${NC} 14) 资源使用监控"
    echo -e "${CYAN}└───────────────────────────────────────────────────────────┘${NC}"
    
    echo -e "${CYAN}┌─ 配置管理 ─────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} 15) 查看当前配置"
    echo -e "${CYAN}│${NC} 16) 修改环境变量"
    echo -e "${CYAN}│${NC} 17) 备份配置"
    echo -e "${CYAN}│${NC} 18) 恢复配置"
    echo -e "${CYAN}└───────────────────────────────────────────────────────────┘${NC}"
    
    echo -e "${CYAN}┌─ 维护工具 ─────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} 19) 性能测试"
    echo -e "${CYAN}│${NC} 20) 清理数据"
    echo -e "${CYAN}│${NC} 21) 更新镜像"
    echo -e "${CYAN}│${NC} 22) 故障排除"
    echo -e "${CYAN}│${NC} 23) ${RED}完全卸载服务${NC}"
    echo -e "${CYAN}└───────────────────────────────────────────────────────────┘${NC}"
    
    echo -e "${RED}0) 退出${NC}"
    echo
}

# 系统检查
system_check() {
    log_header "系统资源检查"
    
    if [ -f "scripts/system-check.sh" ]; then
        chmod +x scripts/system-check.sh
        ./scripts/system-check.sh
    else
        log_error "系统检查脚本不存在"
    fi
    
    echo
    read -p "按回车键继续..."
}

# 部署服务
deploy_service() {
    local deployment_type=$1
    local compose_file=""
    local env_file=""
    
    case $deployment_type in
        "core")
            log_header "核心服务部署 (最小资源)"
            compose_file="docker-compose.yml"
            env_file=".env.minimal"
            ;;
        "minimal")
            log_header "轻量级部署"
            compose_file="docker-compose.yml"
            env_file=".env.minimal"
            ;;
        "full")
            log_header "完整部署"
            compose_file="docker-compose.yml"
            env_file=".env"
            ;;
        "dev")
            log_header "开发环境部署"
            compose_file="docker-compose.dev.yml"
            env_file=".env"
            ;;
    esac
    
    # 检查配置文件
    if [ ! -f "$compose_file" ]; then
        log_error "Docker Compose 文件不存在: $compose_file"
        return 1
    fi
    
    if [ ! -f "$env_file" ]; then
        log_warning "环境文件不存在: $env_file，使用默认配置"
        if [ -f ".env.example" ]; then
            cp .env.example .env
            log_info "已从 .env.example 创建 .env 文件"
        fi
    fi
    
    # 设置环境文件
    if [ "$env_file" != ".env" ] && [ -f "$env_file" ]; then
        cp "$env_file" .env
        log_info "已应用环境配置: $env_file"
    fi
    
    local compose_cmd=$(get_compose_cmd)
    
    log_info "开始部署服务..."
    
    # 构建镜像
    log_info "构建 Docker 镜像..."
    $compose_cmd -f "$compose_file" build
    
    # 启动服务
    log_info "启动服务..."
    if [ "$deployment_type" = "core" ]; then
        # 仅启动核心服务
        $compose_cmd -f "$compose_file" up -d nova-server
    else
        $compose_cmd -f "$compose_file" up -d
    fi
    
    # 等待服务启动
    log_info "等待服务启动..."
    sleep 10
    
    # 检查服务状态
    log_info "检查服务状态..."
    $compose_cmd -f "$compose_file" ps
    
    log_success "部署完成！"
    
    # 显示访问信息
    show_access_info "$deployment_type"
    
    echo
    read -p "按回车键继续..."
}

# 显示访问信息
show_access_info() {
    local deployment_type=$1
    
    log_header "服务访问信息"
    
    echo -e "${GREEN}Nova Proxy 服务:${NC}"
    echo -e "  - HTTP: http://localhost:8080"
    echo -e "  - HTTPS: https://localhost:8443"
    echo -e "  - 管理接口: http://localhost:8081/admin"
    
    if [ "$deployment_type" != "core" ]; then
        echo -e "\n${GREEN}监控服务:${NC}"
        echo -e "  - Prometheus: http://localhost:9090"
        echo -e "  - Grafana: http://localhost:3000"
        echo -e "    用户名: admin"
        echo -e "    密码: admin123"
        
        if [ "$deployment_type" = "full" ]; then
            echo -e "  - Jaeger: http://localhost:16686"
        fi
    fi
}

# 查看服务状态
show_service_status() {
    log_header "服务状态"
    
    local compose_cmd=$(get_compose_cmd)
    
    # 检查哪个 compose 文件在使用
    local compose_file="docker-compose.yml"
    if $compose_cmd -f docker-compose.dev.yml ps &> /dev/null; then
        compose_file="docker-compose.dev.yml"
    fi
    
    log_info "当前使用的配置文件: $compose_file"
    echo
    
    # 显示服务状态
    $compose_cmd -f "$compose_file" ps
    
    echo
    log_info "Docker 容器资源使用情况:"
    docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}"
    
    echo
    read -p "按回车键继续..."
}

# 服务管理
manage_service() {
    local action=$1
    local compose_cmd=$(get_compose_cmd)
    
    # 检测使用的 compose 文件
    local compose_file="docker-compose.yml"
    if $compose_cmd -f docker-compose.dev.yml ps &> /dev/null; then
        compose_file="docker-compose.dev.yml"
    fi
    
    case $action in
        "start")
            log_header "启动服务"
            log_info "启动所有服务..."
            $compose_cmd -f "$compose_file" start
            ;;
        "stop")
            log_header "停止服务"
            log_info "停止所有服务..."
            $compose_cmd -f "$compose_file" stop
            ;;
        "restart")
            log_header "重启服务"
            log_info "重启所有服务..."
            $compose_cmd -f "$compose_file" restart
            ;;
    esac
    
    log_success "操作完成！"
    
    # 显示服务状态
    echo
    $compose_cmd -f "$compose_file" ps
    
    echo
    read -p "按回车键继续..."
}

# 查看日志
view_logs() {
    log_header "服务日志"
    
    local compose_cmd=$(get_compose_cmd)
    local compose_file="docker-compose.yml"
    
    if $compose_cmd -f docker-compose.dev.yml ps &> /dev/null; then
        compose_file="docker-compose.dev.yml"
    fi
    
    echo -e "${WHITE}请选择要查看的服务日志:${NC}"
    echo "1) Nova Server"
    echo "2) Prometheus"
    echo "3) Grafana"
    echo "4) Jaeger"
    echo "5) 所有服务"
    echo "0) 返回"
    echo
    
    read -p "请输入选择 [0-5]: " choice
    
    case $choice in
        1)
            log_info "显示 Nova Server 日志 (按 Ctrl+C 退出):"
            $compose_cmd -f "$compose_file" logs -f nova-server
            ;;
        2)
            log_info "显示 Prometheus 日志 (按 Ctrl+C 退出):"
            $compose_cmd -f "$compose_file" logs -f prometheus
            ;;
        3)
            log_info "显示 Grafana 日志 (按 Ctrl+C 退出):"
            $compose_cmd -f "$compose_file" logs -f grafana
            ;;
        4)
            log_info "显示 Jaeger 日志 (按 Ctrl+C 退出):"
            $compose_cmd -f "$compose_file" logs -f jaeger
            ;;
        5)
            log_info "显示所有服务日志 (按 Ctrl+C 退出):"
            $compose_cmd -f "$compose_file" logs -f
            ;;
        0)
            return
            ;;
        *)
            log_error "无效选择"
            ;;
    esac
}

# 监控管理
manage_monitoring() {
    local action=$1
    local compose_cmd=$(get_compose_cmd)
    local compose_file="docker-compose.yml"
    
    case $action in
        "enable")
            log_header "启用监控组件"
            log_info "启动监控服务..."
            $compose_cmd -f "$compose_file" up -d prometheus grafana
            log_success "监控组件已启用"
            show_access_info "minimal"
            ;;
        "disable")
            log_header "禁用监控组件"
            log_info "停止监控服务..."
            $compose_cmd -f "$compose_file" stop prometheus grafana jaeger
            log_success "监控组件已禁用"
            ;;
        "access")
            log_header "监控面板访问地址"
            show_access_info "full"
            ;;
        "resource")
            log_header "资源使用监控"
            log_info "实时资源使用情况 (按 Ctrl+C 退出):"
            while true; do
                clear
                echo -e "${CYAN}=== 系统资源监控 ===${NC}"
                echo
                
                # 系统资源
                echo -e "${GREEN}系统资源:${NC}"
                echo "内存使用: $(free -h | awk 'NR==2{printf "%.1f%%", $3*100/$2 }')"
                echo "CPU 使用: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)%"
                echo "磁盘使用: $(df -h / | awk 'NR==2{print $5}')"
                echo
                
                # Docker 容器资源
                echo -e "${GREEN}容器资源:${NC}"
                docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}"
                
                sleep 5
            done
            ;;
    esac
    
    echo
    read -p "按回车键继续..."
}

# 配置管理
manage_config() {
    local action=$1
    
    case $action in
        "view")
            log_header "当前配置"
            
            if [ -f ".env" ]; then
                log_info "环境变量配置 (.env):"
                echo -e "${YELLOW}"
                cat .env | grep -v '^#' | grep -v '^$'
                echo -e "${NC}"
            else
                log_warning "未找到 .env 文件"
            fi
            
            echo
            log_info "Docker Compose 配置:"
            if [ -f "docker-compose.yml" ]; then
                echo "- docker-compose.yml (主配置)"
            fi
            if [ -f "docker-compose.dev.yml" ]; then
                echo "- docker-compose.dev.yml (开发环境)"
            fi
            if [ -f ".env.minimal" ]; then
                echo "- .env.minimal (轻量级配置)"
            fi
            ;;
        "edit")
            log_header "修改环境变量"
            
            if [ ! -f ".env" ]; then
                if [ -f ".env.example" ]; then
                    cp .env.example .env
                    log_info "已从 .env.example 创建 .env 文件"
                else
                    log_error "未找到 .env.example 文件"
                    return 1
                fi
            fi
            
            echo -e "${WHITE}请选择要修改的配置:${NC}"
            echo "1) 日志级别"
            echo "2) 服务端口"
            echo "3) 资源限制"
            echo "4) 监控配置"
            echo "5) 直接编辑 .env 文件"
            echo "0) 返回"
            echo
            
            read -p "请输入选择 [0-5]: " choice
            
            case $choice in
                1)
                    edit_log_level
                    ;;
                2)
                    edit_service_ports
                    ;;
                3)
                    edit_resource_limits
                    ;;
                4)
                    edit_monitoring_config
                    ;;
                5)
                    if command -v nano &> /dev/null; then
                        nano .env
                    elif command -v vi &> /dev/null; then
                        vi .env
                    else
                        log_error "未找到文本编辑器"
                    fi
                    ;;
                0)
                    return
                    ;;
                *)
                    log_error "无效选择"
                    ;;
            esac
            ;;
        "backup")
            log_header "备份配置"
            
            local backup_dir="backups/$(date +%Y%m%d_%H%M%S)"
            mkdir -p "$backup_dir"
            
            # 备份配置文件
            if [ -f ".env" ]; then
                cp .env "$backup_dir/"
                log_info "已备份 .env"
            fi
            
            if [ -f "docker-compose.yml" ]; then
                cp docker-compose.yml "$backup_dir/"
                log_info "已备份 docker-compose.yml"
            fi
            
            # 备份配置目录
            if [ -d "configs" ]; then
                cp -r configs "$backup_dir/"
                log_info "已备份 configs 目录"
            fi
            
            log_success "配置已备份到: $backup_dir"
            ;;
        "restore")
            log_header "恢复配置"
            
            if [ ! -d "backups" ]; then
                log_error "未找到备份目录"
                return 1
            fi
            
            echo -e "${WHITE}可用的备份:${NC}"
            ls -1 backups/ | nl
            echo
            
            read -p "请输入要恢复的备份编号: " backup_num
            
            local backup_name=$(ls -1 backups/ | sed -n "${backup_num}p")
            if [ -z "$backup_name" ]; then
                log_error "无效的备份编号"
                return 1
            fi
            
            local backup_path="backups/$backup_name"
            
            # 恢复配置文件
            if [ -f "$backup_path/.env" ]; then
                cp "$backup_path/.env" .
                log_info "已恢复 .env"
            fi
            
            if [ -f "$backup_path/docker-compose.yml" ]; then
                cp "$backup_path/docker-compose.yml" .
                log_info "已恢复 docker-compose.yml"
            fi
            
            if [ -d "$backup_path/configs" ]; then
                cp -r "$backup_path/configs" .
                log_info "已恢复 configs 目录"
            fi
            
            log_success "配置已从备份恢复: $backup_name"
            ;;
    esac
    
    echo
    read -p "按回车键继续..."
}

# 编辑日志级别
edit_log_level() {
    echo -e "${WHITE}选择日志级别:${NC}"
    echo "1) debug (详细调试信息)"
    echo "2) info (一般信息)"
    echo "3) warn (警告信息)"
    echo "4) error (仅错误信息)"
    echo
    
    read -p "请输入选择 [1-4]: " level_choice
    
    local log_level
    case $level_choice in
        1) log_level="debug" ;;
        2) log_level="info" ;;
        3) log_level="warn" ;;
        4) log_level="error" ;;
        *) log_error "无效选择"; return ;;
    esac
    
    # 更新 .env 文件
    if grep -q "^LOG_LEVEL=" .env; then
        sed -i "s/^LOG_LEVEL=.*/LOG_LEVEL=$log_level/" .env
    else
        echo "LOG_LEVEL=$log_level" >> .env
    fi
    
    log_success "日志级别已设置为: $log_level"
}

# 编辑服务端口
edit_service_ports() {
    echo -e "${WHITE}当前端口配置:${NC}"
    grep -E "^(HTTP_PORT|HTTPS_PORT|ADMIN_PORT)=" .env 2>/dev/null || echo "未找到端口配置"
    echo
    
    read -p "HTTP 端口 (默认 8080): " http_port
    read -p "HTTPS 端口 (默认 8443): " https_port
    read -p "管理端口 (默认 8081): " admin_port
    
    # 设置默认值
    http_port=${http_port:-8080}
    https_port=${https_port:-8443}
    admin_port=${admin_port:-8081}
    
    # 更新 .env 文件
    for port_var in "HTTP_PORT=$http_port" "HTTPS_PORT=$https_port" "ADMIN_PORT=$admin_port"; do
        local var_name=$(echo $port_var | cut -d'=' -f1)
        local var_value=$(echo $port_var | cut -d'=' -f2)
        
        if grep -q "^$var_name=" .env; then
            sed -i "s/^$var_name=.*/$var_name=$var_value/" .env
        else
            echo "$var_name=$var_value" >> .env
        fi
    done
    
    log_success "端口配置已更新"
}

# 编辑资源限制
edit_resource_limits() {
    echo -e "${WHITE}当前资源限制:${NC}"
    grep -E "^(NOVA_.*_(MEMORY|CPU))=" .env 2>/dev/null || echo "未找到资源限制配置"
    echo
    
    read -p "Nova Server 内存限制 (如: 256m, 512m, 1g): " nova_memory
    read -p "Nova Server CPU 限制 (如: 0.5, 1, 2): " nova_cpu
    
    if [ -n "$nova_memory" ]; then
        if grep -q "^NOVA_SERVER_MEMORY=" .env; then
            sed -i "s/^NOVA_SERVER_MEMORY=.*/NOVA_SERVER_MEMORY=$nova_memory/" .env
        else
            echo "NOVA_SERVER_MEMORY=$nova_memory" >> .env
        fi
    fi
    
    if [ -n "$nova_cpu" ]; then
        if grep -q "^NOVA_SERVER_CPU=" .env; then
            sed -i "s/^NOVA_SERVER_CPU=.*/NOVA_SERVER_CPU=$nova_cpu/" .env
        else
            echo "NOVA_SERVER_CPU=$nova_cpu" >> .env
        fi
    fi
    
    log_success "资源限制已更新"
}

# 编辑监控配置
edit_monitoring_config() {
    echo -e "${WHITE}监控配置:${NC}"
    echo "1) 启用指标收集"
    echo "2) 禁用指标收集"
    echo "3) 设置 Prometheus 数据保留期"
    echo
    
    read -p "请输入选择 [1-3]: " mon_choice
    
    case $mon_choice in
        1)
            if grep -q "^METRICS_ENABLED=" .env; then
                sed -i "s/^METRICS_ENABLED=.*/METRICS_ENABLED=true/" .env
            else
                echo "METRICS_ENABLED=true" >> .env
            fi
            log_success "指标收集已启用"
            ;;
        2)
            if grep -q "^METRICS_ENABLED=" .env; then
                sed -i "s/^METRICS_ENABLED=.*/METRICS_ENABLED=false/" .env
            else
                echo "METRICS_ENABLED=false" >> .env
            fi
            log_success "指标收集已禁用"
            ;;
        3)
            read -p "数据保留期 (如: 7d, 30d, 90d): " retention
            if [ -n "$retention" ]; then
                if grep -q "^PROMETHEUS_RETENTION=" .env; then
                    sed -i "s/^PROMETHEUS_RETENTION=.*/PROMETHEUS_RETENTION=$retention/" .env
                else
                    echo "PROMETHEUS_RETENTION=$retention" >> .env
                fi
                log_success "数据保留期已设置为: $retention"
            fi
            ;;
        *)
            log_error "无效选择"
            ;;
    esac
}

# 性能测试
performance_test() {
    log_header "性能测试"
    
    if [ -f "scripts/performance.sh" ]; then
        chmod +x scripts/performance.sh
        ./scripts/performance.sh
    else
        log_info "运行简单的性能测试..."
        
        # 检查服务是否运行
        if ! curl -s http://localhost:8080/health > /dev/null; then
            log_error "Nova Server 未运行或不可访问"
            return 1
        fi
        
        log_info "测试 HTTP 连接性能..."
        
        # 使用 curl 进行简单的性能测试
        echo "连接测试:"
        for i in {1..5}; do
            response_time=$(curl -o /dev/null -s -w "%{time_total}" http://localhost:8080/health)
            echo "  请求 $i: ${response_time}s"
        done
        
        log_success "性能测试完成"
    fi
    
    echo
    read -p "按回车键继续..."
}

# 清理数据
clean_data() {
    log_header "清理数据"
    
    echo -e "${WHITE}请选择清理选项:${NC}"
    echo "1) 清理 Docker 镜像和容器"
    echo "2) 清理监控数据"
    echo "3) 清理日志文件"
    echo "4) 完全清理 (包括数据卷)"
    echo "0) 返回"
    echo
    
    read -p "请输入选择 [0-4]: " clean_choice
    
    case $clean_choice in
        1)
            log_info "清理 Docker 镜像和容器..."
            docker system prune -f
            log_success "Docker 清理完成"
            ;;
        2)
            log_info "清理监控数据..."
            docker volume rm nova-proxy_prometheus_data nova-proxy_grafana_data 2>/dev/null || true
            log_success "监控数据清理完成"
            ;;
        3)
            log_info "清理日志文件..."
            find . -name "*.log" -type f -delete 2>/dev/null || true
            docker system prune --volumes -f
            log_success "日志文件清理完成"
            ;;
        4)
            log_warning "这将删除所有数据，包括监控历史数据！"
            read -p "确认继续？(y/N): " confirm
            if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
                local compose_cmd=$(get_compose_cmd)
                $compose_cmd down -v
                docker system prune -a -f --volumes
                log_success "完全清理完成"
            else
                log_info "操作已取消"
            fi
            ;;
        0)
            return
            ;;
        *)
            log_error "无效选择"
            ;;
    esac
    
    echo
    read -p "按回车键继续..."
}

# 更新镜像
update_images() {
    log_header "更新镜像"
    
    local compose_cmd=$(get_compose_cmd)
    local compose_file="docker-compose.yml"
    
    log_info "拉取最新镜像..."
    $compose_cmd -f "$compose_file" pull
    
    log_info "重新构建本地镜像..."
    $compose_cmd -f "$compose_file" build --no-cache
    
    log_info "重启服务以使用新镜像..."
    $compose_cmd -f "$compose_file" up -d
    
    log_success "镜像更新完成"
    
    echo
    read -p "按回车键继续..."
}

# 完全卸载服务
uninstall_service() {
    log_header "完全卸载 Nova Proxy 服务"
    
    echo -e "${RED}警告: 此操作将完全删除所有 Nova Proxy 相关的服务、数据和配置！${NC}"
    echo -e "${YELLOW}包括:${NC}"
    echo -e "  • 停止并删除所有容器"
    echo -e "  • 删除所有相关 Docker 镜像"
    echo -e "  • 删除所有数据卷"
    echo -e "  • 清理网络配置"
    echo -e "  • 删除备份文件 (可选)"
    echo
    
    read -p "确定要继续吗？输入 'YES' 确认: " confirm
    if [ "$confirm" != "YES" ]; then
        log_info "操作已取消"
        echo
        read -p "按回车键继续..."
        return
    fi
    
    local compose_cmd=$(get_compose_cmd)
    
    # 1. 停止所有服务
    log_info "正在停止所有服务..."
    for compose_file in docker-compose.yml docker-compose.dev.yml docker-compose.prod.yml; do
        if [ -f "$compose_file" ]; then
            $compose_cmd -f "$compose_file" down --remove-orphans 2>/dev/null || true
        fi
    done
    
    # 2. 删除所有相关容器
    log_info "正在删除相关容器..."
    docker ps -a --format "{{.Names}}" | grep -E "(nova|proxy|prometheus|grafana|jaeger|nginx|traefik)" | xargs -r docker rm -f 2>/dev/null || true
    
    # 3. 删除相关镜像
    log_info "正在删除相关镜像..."
    docker images --format "{{.Repository}}:{{.Tag}}" | grep -E "(nova|proxy)" | xargs -r docker rmi -f 2>/dev/null || true
    
    # 删除常用监控镜像 (可选)
    echo
    read -p "是否同时删除监控相关镜像 (prometheus, grafana, jaeger)? [y/N]: " delete_monitoring
    if [[ "$delete_monitoring" =~ ^[Yy]$ ]]; then
        docker images --format "{{.Repository}}:{{.Tag}}" | grep -E "(prometheus|grafana|jaeger|prom/)" | xargs -r docker rmi -f 2>/dev/null || true
    fi
    
    # 4. 删除数据卷
    log_info "正在删除数据卷..."
    docker volume ls --format "{{.Name}}" | grep -E "(nova|proxy|prometheus|grafana|jaeger)" | xargs -r docker volume rm -f 2>/dev/null || true
    
    # 5. 清理网络
    log_info "正在清理网络配置..."
    docker network ls --format "{{.Name}}" | grep -E "(nova|proxy)" | xargs -r docker network rm 2>/dev/null || true
    
    # 6. 清理配置文件 (可选)
    echo
    read -p "是否删除生成的配置文件 (.env, logs/)? [y/N]: " delete_configs
    if [[ "$delete_configs" =~ ^[Yy]$ ]]; then
        log_info "正在清理配置文件..."
        [ -f ".env" ] && rm -f .env && log_info "已删除 .env 文件"
        [ -d "logs" ] && rm -rf logs && log_info "已删除 logs 目录"
        [ -d "data" ] && rm -rf data && log_info "已删除 data 目录"
    fi
    
    # 7. 清理备份文件 (可选)
    if [ -d "backups" ]; then
        echo
        read -p "是否删除配置备份文件 (backups/)? [y/N]: " delete_backups
        if [[ "$delete_backups" =~ ^[Yy]$ ]]; then
            rm -rf backups
            log_info "已删除备份目录"
        fi
    fi
    
    # 8. Docker 系统清理
    echo
    read -p "是否执行 Docker 系统清理 (清理未使用的镜像、容器、网络)? [y/N]: " docker_prune
    if [[ "$docker_prune" =~ ^[Yy]$ ]]; then
        log_info "正在执行 Docker 系统清理..."
        docker system prune -f
        docker volume prune -f
    fi
    
    log_success "Nova Proxy 服务卸载完成！"
    
    echo -e "\n${GREEN}卸载摘要:${NC}"
    echo -e "  ✓ 已停止并删除所有容器"
    echo -e "  ✓ 已删除相关 Docker 镜像"
    echo -e "  ✓ 已清理数据卷和网络"
    if [[ "$delete_configs" =~ ^[Yy]$ ]]; then
        echo -e "  ✓ 已删除配置文件"
    fi
    if [[ "$delete_backups" =~ ^[Yy]$ ]]; then
        echo -e "  ✓ 已删除备份文件"
    fi
    
    echo -e "\n${YELLOW}注意:${NC}"
    echo -e "  • 项目源代码文件未被删除"
    echo -e "  • 如需重新部署，请重新运行此管理脚本"
    echo -e "  • 建议重启后再进行新的部署操作"
    
    echo
    read -p "按回车键继续..."
}

# 故障排除
troubleshoot() {
    log_header "故障排除"
    
    if [ -f "scripts/troubleshoot.sh" ]; then
        chmod +x scripts/troubleshoot.sh
        ./scripts/troubleshoot.sh
    else
        log_info "运行基本故障排除检查..."
        
        echo -e "${GREEN}1. 检查 Docker 服务状态:${NC}"
        systemctl is-active docker || echo "Docker 服务未运行"
        
        echo -e "\n${GREEN}2. 检查端口占用:${NC}"
        netstat -tlnp | grep -E ':(8080|8443|8081|9090|3000)' || echo "相关端口未被占用"
        
        echo -e "\n${GREEN}3. 检查容器状态:${NC}"
        docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
        
        echo -e "\n${GREEN}4. 检查磁盘空间:${NC}"
        df -h
        
        echo -e "\n${GREEN}5. 检查内存使用:${NC}"
        free -h
        
        echo -e "\n${GREEN}6. 最近的容器日志错误:${NC}"
        docker logs --tail 10 $(docker ps -q) 2>&1 | grep -i error || echo "未发现明显错误"
    fi
    
    echo
    read -p "按回车键继续..."
}

# 主程序循环
main() {
    # 检查依赖
    check_dependencies
    
    while true; do
        show_main_menu
        read -p "请输入选择 [0-23]: " choice
        
        case $choice in
            1) system_check ;;
            2) deploy_service "core" ;;
            3) deploy_service "minimal" ;;
            4) deploy_service "full" ;;
            5) deploy_service "dev" ;;
            6) show_service_status ;;
            7) manage_service "start" ;;
            8) manage_service "stop" ;;
            9) manage_service "restart" ;;
            10) view_logs ;;
            11) manage_monitoring "enable" ;;
            12) manage_monitoring "disable" ;;
            13) manage_monitoring "access" ;;
            14) manage_monitoring "resource" ;;
            15) manage_config "view" ;;
            16) manage_config "edit" ;;
            17) manage_config "backup" ;;
            18) manage_config "restore" ;;
            19) performance_test ;;
            20) clean_data ;;
            21) update_images ;;
            22) troubleshoot ;;
            23) uninstall_service ;;
            0)
                log_info "感谢使用 Nova Proxy 管理工具！"
                exit 0
                ;;
            *)
                log_error "无效选择，请重新输入"
                sleep 2
                ;;
        esac
    done
}

# 运行主程序
main "$@"