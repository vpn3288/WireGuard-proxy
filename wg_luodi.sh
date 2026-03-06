#!/bin/bash
# ============================================================
# wg_luodi.sh v2.0 — 落地机 WireGuard 一键部署脚本
# 功能：在落地机上配置 WireGuard 客户端，连接到 CN2GIA 中转机
# 特性：
#   - 动态 WAN 接口检测（不硬编码 eth0）
#   - 甲骨文云检测与提示
#   - KEY=VALUE 格式摘要，供 wg_duijie.sh 读取
#   - 支持重新运行（幂等性）
# 用法：bash <(curl -s https://raw.githubusercontent.com/vpn3288/proxy/main/wg_luodi.sh)
# ============================================================

set -uo pipefail

# ── 颜色 ────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; PURPLE='\033[0;35m'; CYAN='\033[0;36m'; NC='\033[0m'

ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }
info() { echo -e "${BLUE}[i]${NC} $1"; }
step() { echo -e "${CYAN}[→]${NC} $1"; }
hr()   { echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }

[[ $EUID -ne 0 ]] && err "请使用 root 权限运行"

WORK_DIR="/opt/relay-wg"
CONFIG_DIR="$WORK_DIR/config"
SUMMARY_FILE="$CONFIG_DIR/peer-summary.txt"
WG_CONF="/etc/wireguard/wg0.conf"
mkdir -p "$CONFIG_DIR"

# ── 工具函数 ─────────────────────────────────────────────────
get_wan_iface() {
    ip route show default 2>/dev/null | awk '/default/{print $5; exit}' \
    || ip link show 2>/dev/null | awk -F': ' '/^[0-9]+: [^lo]/{print $2; exit}' \
    || echo "eth0"
}

validate_ip() {
    local ip=$1
    [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS='.'; read -ra p <<< "$ip"
    for x in "${p[@]}"; do (( x >= 0 && x <= 255 )) || return 1; done
    return 0
}

validate_port() {
    [[ $1 =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 ))
}

validate_wg_key() {
    # WireGuard 密钥：44字符 Base64，以 = 结尾
    local key=$1
    [[ ${#key} -eq 44 && $key =~ ^[A-Za-z0-9+/]{43}=$ ]]
}

validate_wg_ip() {
    # 接受 10.0.0.x 或 10.0.0.x/32
    local addr="${1%/*}"
    [[ $addr =~ ^10\.0\.0\.[0-9]+$ ]] || return 1
    local last="${addr##*.}"
    (( last >= 2 && last <= 254 ))
}

# ── 甲骨文云检测 ─────────────────────────────────────────────
detect_oracle() {
    ORACLE_CLOUD=false
    if [[ -f /etc/oracle-cloud-agent/agent.conf ]] || \
       curl -s --max-time 2 -H "Authorization: Bearer Oracle" \
           http://169.254.169.254/opc/v2/instance/ &>/dev/null; then
        ORACLE_CLOUD=true
    fi
}

# ── Banner ────────────────────────────────────────────────────
print_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║            落地机 WireGuard 一键部署工具  v2.0                 ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ──────────────────────────────────────────────────────────────
# 检测是否已部署（幂等性）
# ──────────────────────────────────────────────────────────────
check_existing() {
    if [[ -f "$WG_CONF" && -f "$SUMMARY_FILE" ]]; then
        echo ""
        ok "检测到已有 WireGuard 配置"
        echo ""
        echo -e "${YELLOW}选择操作：${NC}"
        echo -e "  ${CYAN}[1]${NC} 重新配置（覆盖现有配置）"
        echo -e "  ${CYAN}[2]${NC} 查看当前配置"
        echo -e "  ${CYAN}[3]${NC} 退出"
        echo ""
        read -rp "选择 [默认2]: " ch
        case "${ch:-2}" in
            1) return ;;
            2) echo ""; cat "$SUMMARY_FILE"; echo ""; wg show 2>/dev/null; exit 0 ;;
            3) exit 0 ;;
        esac
    fi
}

# ──────────────────────────────────────────────────────────────
# 步骤1：收集配置信息
# ──────────────────────────────────────────────────────────────
collect_info() {
    hr; echo -e "${PURPLE}步骤 1/5: 收集配置信息${NC}"; hr
    echo ""
    info "请从中转机的 relay-info 或 /opt/relay-wg/config/summary.txt 获取以下参数"
    echo ""

    # 甲骨文云提示
    if [[ "$ORACLE_CLOUD" == "true" ]]; then
        echo -e "${YELLOW}┌─────────────────────────────────────────────────────────┐${NC}"
        echo -e "${YELLOW}│  ⚠ 检测到甲骨文云环境                                  │${NC}"
        echo -e "${YELLOW}│  注意：甲骨文默认禁用密码 SSH，请务必在安全组中          │${NC}"
        echo -e "${YELLOW}│  放行 WireGuard UDP 端口（在 VCN 安全列表中添加规则）   │${NC}"
        echo -e "${YELLOW}└─────────────────────────────────────────────────────────┘${NC}"
        echo ""
    fi

    # 落地机名称
    read -rp "此落地机名称（如 phoenix，与中转机一致）: " PEER_NAME
    [[ -z "$PEER_NAME" ]] && err "名称不能为空"

    echo ""

    # 中转机公网 IP
    while true; do
        read -rp "中转机公网 IP: " RELAY_IP
        validate_ip "$RELAY_IP" && break
        warn "IP 格式不正确，请重新输入"
    done

    # WireGuard 端口
    while true; do
        read -rp "中转机 WireGuard 端口 [51820]: " WG_PORT
        WG_PORT="${WG_PORT:-51820}"
        validate_port "$WG_PORT" && break
        warn "端口无效，请重新输入"
    done

    # 中转机 WireGuard 公钥
    echo ""
    info "中转机公钥在中转机运行 relay-info 查看（RELAY_WG_PUBKEY 字段）"
    while true; do
        read -rp "中转机 WireGuard 公钥: " RELAY_PUBKEY
        validate_wg_key "$RELAY_PUBKEY" && break
        warn "密钥格式不正确（应为44字符Base64，以=结尾），请重新输入"
    done

    # 本机 WireGuard 私钥
    echo ""
    info "私钥在中转机的 /opt/relay-wg/config/peer-configs/${PEER_NAME}-wg.conf 中"
    info "或中转机 relay-info 输出的 PEER_x_WG_PRIVKEY 字段"
    while true; do
        read -rp "本机 WireGuard 私钥: " WG_PRIVKEY
        if [[ "$WG_PRIVKEY" == "$RELAY_PUBKEY" ]]; then
            warn "私钥与中转机公钥相同！你可能填反了，请重新输入"
            continue
        fi
        validate_wg_key "$WG_PRIVKEY" && break
        warn "私钥格式不正确，请重新输入"
    done

    # 本机 WireGuard 虚拟 IP
    echo ""
    info "虚拟 IP 在中转机 relay-info 输出的 PEER_x_WG_IP 字段（如 10.0.0.2）"
    while true; do
        read -rp "本机 WireGuard 虚拟 IP（如 10.0.0.2）: " _raw_ip
        # 自动补全 /32
        _raw_ip="${_raw_ip%/*}"
        validate_wg_ip "$_raw_ip" && { WG_ADDRESS="${_raw_ip}/32"; break; }
        warn "格式不正确，应为 10.0.0.2 ~ 10.0.0.254"
    done

    ok "配置信息收集完毕"
    echo ""
    echo -e "${YELLOW}── 确认信息 ──${NC}"
    echo -e "  落地机名称    : $PEER_NAME"
    echo -e "  中转机 IP     : $RELAY_IP"
    echo -e "  WireGuard 端口: $WG_PORT"
    echo -e "  本机虚拟 IP   : $WG_ADDRESS"
    echo ""
    read -rp "确认以上信息正确？[Y/n]: " confirm
    [[ "${confirm,,}" == "n" ]] && { info "重新输入"; collect_info; return; }

    echo ""; read -rp "[按Enter继续...]"
}

# ──────────────────────────────────────────────────────────────
# 步骤2：安装依赖
# ──────────────────────────────────────────────────────────────
install_deps() {
    hr; echo -e "${PURPLE}步骤 2/5: 安装依赖${NC}"; hr
    echo ""

    step "更新软件包列表..."
    apt-get update -qq 2>/dev/null || apt-get update -qq --allow-releaseinfo-change 2>/dev/null || true

    local pkgs="wireguard wireguard-tools curl wget net-tools iptables"

    local ores
    ores=$(apt-cache policy openresolv 2>/dev/null | grep 'Candidate:' | awk '{print $2}')
    if [[ -n "$ores" && "$ores" != "(none)" ]]; then
        pkgs="$pkgs openresolv"
    fi

    step "安装: $pkgs ..."
    # shellcheck disable=SC2086
    apt-get install -y -qq $pkgs

    # iptables-legacy
    if command -v update-alternatives &>/dev/null; then
        update-alternatives --set iptables  /usr/sbin/iptables-legacy  &>/dev/null || true
        update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy &>/dev/null || true
    fi

    # 禁用 nftables/ufw
    for svc in nftables ufw; do
        systemctl stop    "$svc" &>/dev/null || true
        systemctl disable "$svc" &>/dev/null || true
        systemctl mask    "$svc" &>/dev/null || true
    done
    command -v nft &>/dev/null && nft flush ruleset 2>/dev/null || true

    # iptables-persistent
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections 2>/dev/null || true
    apt-get install -y -qq iptables-persistent netfilter-persistent 2>/dev/null || true

    # 检测内核模块
    if ! modprobe wireguard 2>/dev/null; then
        warn "内核无 WireGuard 模块，安装 wireguard-go..."
        apt-get install -y wireguard-go
    fi

    # sysctl
    cat > /etc/sysctl.d/98-landing-wg.conf << 'EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF
    sysctl -p /etc/sysctl.d/98-landing-wg.conf &>/dev/null || true
    ok "依赖安装完成"

    echo ""; read -rp "[按Enter继续...]"
}

# ──────────────────────────────────────────────────────────────
# 步骤3：配置 WireGuard
# ──────────────────────────────────────────────────────────────
setup_wireguard() {
    hr; echo -e "${PURPLE}步骤 3/5: 配置 WireGuard${NC}"; hr
    echo ""

    mkdir -p /etc/wireguard
    chmod 700 /etc/wireguard

    # ★ 动态检测 WAN 接口（修复 eth0 硬编码问题）
    WAN_IFACE=$(get_wan_iface)
    info "检测到 WAN 接口: $WAN_IFACE"

    # 检测 systemd-resolved（决定是否写 DNS 行）
    local dns_line=""
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        dns_line="DNS = 8.8.8.8, 1.1.1.1"
        info "检测到 systemd-resolved，启用 DNS 配置"
    else
        warn "systemd-resolved 未运行，跳过 DNS 配置"
    fi

    step "生成 wg0.conf..."

    # 注意：落地机 AllowedIPs 只路由 WG 子网（10.0.0.0/24）
    # 不写 0.0.0.0/0，保证落地机自己的互联网流量走正常路由
    cat > "$WG_CONF" << EOF
[Interface]
Address = $WG_ADDRESS
PrivateKey = $WG_PRIVKEY
${dns_line}

PostUp   = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o ${WAN_IFACE} -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o ${WAN_IFACE} -j MASQUERADE

[Peer]
PublicKey = $RELAY_PUBKEY
Endpoint = $RELAY_IP:$WG_PORT
AllowedIPs = 10.0.0.0/24
PersistentKeepalive = 25
EOF

    # 清理空行（DNS 行为空时）
    sed -i '/^[[:space:]]*$/d' "$WG_CONF"
    # 恢复 Peer 前的空行
    sed -i '/^\[Peer\]/i\\' "$WG_CONF"

    chmod 600 "$WG_CONF"
    ok "wg0.conf 已生成（WAN接口: $WAN_IFACE）"

    echo ""; read -rp "[按Enter继续...]"
}

# ──────────────────────────────────────────────────────────────
# 步骤4：启动 WireGuard，验证连通性
# ──────────────────────────────────────────────────────────────
start_wg() {
    hr; echo -e "${PURPLE}步骤 4/5: 启动 WireGuard${NC}"; hr
    echo ""

    systemctl enable wg-quick@wg0 &>/dev/null || true

    if systemctl is-active --quiet wg-quick@wg0; then
        step "WireGuard 已运行，重启以应用新配置..."
        systemctl restart wg-quick@wg0
    else
        step "启动 WireGuard..."
        systemctl start wg-quick@wg0
    fi

    sleep 3

    if ! wg show wg0 &>/dev/null; then
        err "WireGuard 启动失败，请查看日志: journalctl -u wg-quick@wg0 -n 30"
    fi
    ok "WireGuard 已启动"
    echo ""
    wg show wg0
    echo ""

    # 验证与中转机隧道连通性
    step "验证 WireGuard 隧道连通性（ping 10.0.0.1）..."
    local ping_ok=false
    for _ in 1 2 3; do
        if ping -c 1 -W 3 10.0.0.1 &>/dev/null; then
            ping_ok=true; break
        fi
        sleep 2
    done

    if $ping_ok; then
        ok "隧道连通！可以 ping 通 10.0.0.1（中转机）"
    else
        warn "无法 ping 通 10.0.0.1，可能是中转机端防火墙未放行，或中转机还未配置此落地机的 Peer"
        warn "请在中转机检查: wg show | iptables -L INPUT -n"
        echo ""
        read -rp "是否继续？[y/N]: " cn
        [[ "${cn,,}" == "y" ]] || exit 1
    fi

    # 获取本机公网 IP（验证出口 IP 正确）
    step "获取本机公网出口 IP..."
    PUBLIC_IP=$(
        curl -s4 --max-time 5 https://api.ipify.org    2>/dev/null ||
        curl -s4 --max-time 5 https://ifconfig.me      2>/dev/null ||
        curl -s4 --max-time 5 https://icanhazip.com    2>/dev/null ||
        echo "获取失败"
    )
    PUBLIC_IP=$(echo "$PUBLIC_IP" | tr -d '[:space:]')
    ok "本机公网出口 IP: $PUBLIC_IP"
    info "（此 IP 应为落地机自身的 IP，不应是中转机 IP）"

    echo ""; read -rp "[按Enter继续...]"
}

# ──────────────────────────────────────────────────────────────
# 步骤5：保存摘要，配置防火墙
# ──────────────────────────────────────────────────────────────
save_and_finish() {
    hr; echo -e "${PURPLE}步骤 5/5: 保存信息${NC}"; hr
    echo ""

    local wg_ip_plain="${WG_ADDRESS%/*}"

    # 写摘要（KEY=VALUE 格式，供 wg_duijie.sh 读取）
    cat > "$SUMMARY_FILE" << EOF
============================================================
  落地机部署信息
  更新时间: $(date '+%Y-%m-%d %H:%M:%S')
============================================================

LUODI_NAME=$PEER_NAME
LUODI_WG_IP=${wg_ip_plain}
LUODI_WG_ADDRESS=$WG_ADDRESS
LUODI_PUBLIC_IP=${PUBLIC_IP:-unknown}
LUODI_WAN_IFACE=$WAN_IFACE

RELAY_PUBLIC_IP=$RELAY_IP
RELAY_WG_PORT=$WG_PORT
RELAY_WG_PUBKEY=$RELAY_PUBKEY
RELAY_WG_IP=10.0.0.1
RELAY_WG_SUBNET=10.0.0.0/24
EOF
    chmod 600 "$SUMMARY_FILE"
    ok "摘要已保存: $SUMMARY_FILE"

    # 防火墙基础规则（落地机只需放行代理端口和 WG 转发）
    step "配置落地机基础防火墙..."
    local SSH_PORT
    SSH_PORT=$(ss -tlnp 2>/dev/null | grep sshd | grep -oE ':[0-9]+' | grep -oE '[0-9]+' | head -1 || echo 22)

    iptables -P INPUT DROP    2>/dev/null || true
    iptables -P FORWARD DROP  2>/dev/null || true
    iptables -P OUTPUT ACCEPT 2>/dev/null || true
    iptables -F 2>/dev/null || true
    iptables -X 2>/dev/null || true
    iptables -t nat -F 2>/dev/null || true
    iptables -t nat -X 2>/dev/null || true

    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 10/sec -j ACCEPT

    # SSH 防暴力
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -m conntrack --ctstate NEW \
        -m recent --name SSH_BF --set
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -m conntrack --ctstate NEW \
        -m recent --name SSH_BF --update --seconds 60 --hitcount 6 -j DROP
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT

    # 代理常用端口（80/443）
    iptables -A INPUT -p tcp --dport 80  -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    iptables -A INPUT -p udp --dport 443 -j ACCEPT

    # WireGuard FORWARD
    iptables -A FORWARD -i wg0 -j ACCEPT
    iptables -A FORWARD -o wg0 -j ACCEPT
    iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -m conntrack --ctstate DNAT -j ACCEPT

    iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "[FW-DROP] " --log-level 4
    iptables -A INPUT -j DROP

    # 持久化
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    command -v netfilter-persistent &>/dev/null && \
        netfilter-persistent save &>/dev/null || true
    systemctl enable netfilter-persistent &>/dev/null || true
    ok "防火墙规则已配置并持久化"

    # 安装 relay-info
    cat > /usr/local/bin/relay-info << 'CMEOF'
#!/bin/bash
CYAN='\033[0;36m' GREEN='\033[0;32m' YELLOW='\033[1;33m' NC='\033[0m'
SUMMARY=/opt/relay-wg/config/peer-summary.txt
echo -e "${CYAN}"
echo "╔════════════════════════════════════════════════════╗"
echo "║            落地机信息速查 (relay-info)              ║"
echo "╚════════════════════════════════════════════════════╝"
echo -e "${NC}"
[[ -f "$SUMMARY" ]] && cat "$SUMMARY" || echo -e "${YELLOW}摘要不存在${NC}"
echo ""
echo -e "${GREEN}▸ WireGuard：${NC}"; wg show 2>/dev/null || echo "  (未运行)"
echo ""
echo -e "${GREEN}▸ 本机出口 IP：${NC}"
curl -s4 --max-time 5 https://api.ipify.org 2>/dev/null || echo "  获取失败"
echo ""
echo -e "${GREEN}▸ 中转机隧道 (ping 10.0.0.1)：${NC}"
ping -c 2 -W 2 10.0.0.1 2>/dev/null | tail -2 || echo "  不通"
CMEOF
    chmod +x /usr/local/bin/relay-info
    ok "relay-info 命令已安装"
}

# ── 最终展示 ─────────────────────────────────────────────────
print_result() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║           ★ 落地机 WireGuard 部署完成！                        ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}【本机信息】${NC}"
    echo -e "  落地机名称   → ${GREEN}$PEER_NAME${NC}"
    echo -e "  WG 虚拟 IP   → ${GREEN}$WG_ADDRESS${NC}"
    echo -e "  本机出口 IP  → ${GREEN}${PUBLIC_IP:-未知}${NC}"
    echo -e "  WAN 接口     → ${GREEN}$WAN_IFACE${NC}"
    echo ""
    echo -e "${YELLOW}【中转机信息】${NC}"
    echo -e "  中转机 IP    → ${GREEN}$RELAY_IP${NC}"
    echo -e "  WG 端口      → ${GREEN}$WG_PORT/UDP${NC}"
    echo ""
    echo -e "${YELLOW}【下一步】${NC}"
    echo -e "  在本机运行: ${CYAN}bash wg_duijie.sh${NC}"
    echo -e "  脚本会自动检测代理节点，并在中转机添加 DNAT 转发规则"
    echo ""

    if [[ "$ORACLE_CLOUD" == "true" ]]; then
        echo -e "${YELLOW}【甲骨文云提醒】${NC}"
        echo -e "  ★ 请在甲骨文控制台的 VCN → 安全列表中："
        echo -e "     - 已放行：代理端口（TCP，出入站）"
        echo -e "     - 已放行：443/TCP、443/UDP（出入站）"
        echo -e "  甲骨文实例防火墙（iptables）已由本脚本配置"
        echo ""
    fi

    echo -e "${YELLOW}【常用命令】${NC}"
    echo -e "  查看信息    → ${CYAN}relay-info${NC}"
    echo -e "  WG 状态     → ${CYAN}wg show${NC}"
    echo -e "  重启 WG     → ${CYAN}systemctl restart wg-quick@wg0${NC}"
    echo -e "  防火墙状态  → ${CYAN}iptables -L -n${NC}"
    echo -e "  添加代理端口→ ${CYAN}iptables -I INPUT -p tcp --dport <端口> -j ACCEPT${NC}"
    echo ""
}

# ──────────────────────────────────────────────────────────────
# 主流程
# ──────────────────────────────────────────────────────────────
main() {
    print_banner
    detect_oracle
    check_existing
    collect_info
    install_deps
    setup_wireguard
    start_wg
    save_and_finish
    print_result
}

main "$@"
