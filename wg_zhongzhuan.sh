#!/bin/bash
# ============================================================
# wg_zhongzhuan.sh v2.0 — CN2GIA 中转机 WireGuard 一键部署
# 功能：在中转机上安装 WireGuard，生成密钥，创建落地机配置
# 特性：
#   - 幂等性：重复运行时支持追加新落地机，不覆盖已有密钥
#   - 动态 WAN 接口：自动检测而非硬编码 eth0
#   - KEY=VALUE 格式摘要，供 wg_luodi.sh / wg_duijie.sh 读取
#   - 支持热加载（wg addconf），无需重启 WireGuard 服务
# 用法：bash <(curl -s https://raw.githubusercontent.com/vpn3288/proxy/main/wg_zhongzhuan.sh)
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

# ── 全局路径 ────────────────────────────────────────────────
WORK_DIR="/opt/relay-wg"
CONFIG_DIR="$WORK_DIR/config"
PEER_DIR="$CONFIG_DIR/peer-configs"
SUMMARY_FILE="$CONFIG_DIR/summary.txt"
WG_CONF="/etc/wireguard/wg0.conf"
WG_KEY_DIR="/etc/wireguard"

mkdir -p "$CONFIG_DIR" "$PEER_DIR"
chmod 700 "$WG_KEY_DIR" 2>/dev/null || true

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

# ── 打印 banner ───────────────────────────────────────────────
print_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║        CN2GIA 中转机 WireGuard 一键部署工具  v2.0             ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ──────────────────────────────────────────────────────────────
# 检测是否已部署（幂等性核心）
# ──────────────────────────────────────────────────────────────
check_existing() {
    if [[ -f "$WG_CONF" && -f "$SUMMARY_FILE" ]]; then
        echo ""
        ok "检测到已有 WireGuard 部署"
        echo ""
        echo -e "${YELLOW}请选择操作：${NC}"
        echo -e "  ${CYAN}[1]${NC} 追加新落地机（保留现有配置和密钥）"
        echo -e "  ${CYAN}[2]${NC} 查看当前部署信息"
        echo -e "  ${CYAN}[3]${NC} 全新部署（★危险：将重新生成密钥，所有已对接节点失效）"
        echo -e "  ${CYAN}[4]${NC} 退出"
        echo ""
        read -rp "选择 [默认1]: " choice
        choice="${choice:-1}"
        case "$choice" in
            1) MODE="append" ;;
            2) show_info; exit 0 ;;
            3)
                echo -e "${RED}警告：这将销毁所有已有 WireGuard 配置！${NC}"
                read -rp "确认全新部署？输入 YES 继续: " confirm
                [[ "$confirm" == "YES" ]] || { info "已取消"; exit 0; }
                MODE="fresh"
                ;;
            4) exit 0 ;;
            *) MODE="append" ;;
        esac
    else
        MODE="fresh"
    fi
}

show_info() {
    echo ""
    hr
    echo -e "${CYAN}  中转机部署信息${NC}"
    hr
    [[ -f "$SUMMARY_FILE" ]] && cat "$SUMMARY_FILE" || warn "摘要文件不存在"
    echo ""
    echo -e "${GREEN}▸ WireGuard 状态：${NC}"
    wg show 2>/dev/null || echo "  (未运行)"
    echo ""
    echo -e "${GREEN}▸ 已配置的 DNAT 规则：${NC}"
    iptables -t nat -L PREROUTING -n 2>/dev/null \
        | grep DNAT \
        | awk '{print "  •", $0}' \
        || echo "  无"
    hr
}

# ──────────────────────────────────────────────────────────────
# 读取现有配置（追加模式）
# ──────────────────────────────────────────────────────────────
load_existing_config() {
    step "读取现有配置..."
    while IFS='=' read -r key val; do
        val=$(echo "$val" | tr -d '\r' | sed 's/^[[:space:]]*//')
        case "$key" in
            RELAY_PUBLIC_IP)  RELAY_IP="$val"      ;;
            RELAY_WG_PORT)    WG_PORT="$val"        ;;
            RELAY_WG_PUBKEY)  RELAY_PUB="$val"      ;;
            RELAY_WG_PRIVKEY) RELAY_PRIV="$val"     ;;
            RELAY_WG_IP)      RELAY_WG_IP="$val"    ;;
            PEER_COUNT)       EXISTING_PEER_COUNT="$val" ;;
        esac
    done < "$SUMMARY_FILE"

    # 读取私钥（可能在密钥文件中）
    if [[ -z "${RELAY_PRIV:-}" ]]; then
        [[ -f "$WG_KEY_DIR/relay_privatekey" ]] && \
            RELAY_PRIV=$(cat "$WG_KEY_DIR/relay_privatekey")
    fi

    ok "已读取现有配置：IP=$RELAY_IP  WG端口=$WG_PORT"
}

# ──────────────────────────────────────────────────────────────
# 步骤1：收集基本信息（全新部署）
# ──────────────────────────────────────────────────────────────
collect_info_fresh() {
    hr; echo -e "${PURPLE}步骤 1/6: 基本信息${NC}"; hr

    # 中转机公网 IP
    echo ""
    info "正在自动获取公网 IP..."
    RELAY_IP=$(
        curl -s4 --max-time 5 https://api.ipify.org    2>/dev/null ||
        curl -s4 --max-time 5 https://ifconfig.me      2>/dev/null ||
        curl -s4 --max-time 5 https://icanhazip.com    2>/dev/null ||
        echo ""
    )
    RELAY_IP=$(echo "$RELAY_IP" | tr -d '[:space:]')

    if [[ -n "$RELAY_IP" ]]; then
        read -rp "中转机公网 IP [${RELAY_IP}]: " i
        [[ -n "$i" ]] && RELAY_IP="$i"
    else
        while true; do
            read -rp "中转机公网 IP: " RELAY_IP
            validate_ip "$RELAY_IP" && break
            warn "IP 格式不正确，请重新输入"
        done
    fi
    validate_ip "$RELAY_IP" || err "IP 格式不正确: $RELAY_IP"
    ok "中转机 IP: $RELAY_IP"

    # WireGuard 端口
    echo ""
    while true; do
        read -rp "WireGuard 监听端口 [51820]: " WG_PORT
        WG_PORT="${WG_PORT:-51820}"
        validate_port "$WG_PORT" && break
        warn "端口号无效，请重新输入"
    done
    ok "WireGuard 端口: $WG_PORT/UDP"

    # 落地机数量
    echo ""
    while true; do
        read -rp "本次需要配置几台落地机 (1-20) [1]: " PEER_COUNT
        PEER_COUNT="${PEER_COUNT:-1}"
        [[ "$PEER_COUNT" =~ ^[0-9]+$ ]] && (( PEER_COUNT >= 1 && PEER_COUNT <= 20 )) && break
        warn "请输入 1-20 之间的数字"
    done
    ok "落地机数量: $PEER_COUNT"

    EXISTING_PEER_COUNT=0
    RELAY_WG_IP="10.0.0.1"

    echo ""; read -rp "[按Enter继续...]"
}

collect_info_append() {
    hr; echo -e "${PURPLE}追加模式：添加新落地机${NC}"; hr
    echo ""
    info "已有配置：IP=$RELAY_IP  WG端口=$WG_PORT  已有${EXISTING_PEER_COUNT:-0}台落地机"
    echo ""
    while true; do
        read -rp "本次追加几台落地机 (1-10) [1]: " PEER_COUNT
        PEER_COUNT="${PEER_COUNT:-1}"
        [[ "$PEER_COUNT" =~ ^[0-9]+$ ]] && (( PEER_COUNT >= 1 && PEER_COUNT <= 10 )) && break
        warn "请输入 1-10 之间的数字"
    done
    ok "追加落地机: $PEER_COUNT 台"
    echo ""; read -rp "[按Enter继续...]"
}

# ──────────────────────────────────────────────────────────────
# 步骤2：安装依赖
# ──────────────────────────────────────────────────────────────
install_deps() {
    hr; echo -e "${PURPLE}步骤 2/6: 安装依赖${NC}"; hr
    echo ""

    step "更新软件包列表..."
    apt-get update -qq 2>/dev/null || apt-get update -qq --allow-releaseinfo-change 2>/dev/null || true

    local pkgs="wireguard wireguard-tools curl wget net-tools iptables"

    # 检测 openresolv
    local ores
    ores=$(apt-cache policy openresolv 2>/dev/null | grep 'Candidate:' | awk '{print $2}')
    if [[ -n "$ores" && "$ores" != "(none)" ]]; then
        pkgs="$pkgs openresolv"
        info "检测到 openresolv 可安装"
    else
        info "系统无 openresolv（Ubuntu 22.04+ 正常）"
    fi

    step "安装: $pkgs ..."
    # shellcheck disable=SC2086
    apt-get install -y -qq $pkgs

    # iptables-legacy
    if command -v update-alternatives &>/dev/null; then
        update-alternatives --set iptables  /usr/sbin/iptables-legacy  &>/dev/null || true
        update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy &>/dev/null || true
        ok "切换 iptables → legacy 模式"
    fi

    # 禁用 nftables
    for svc in nftables ufw firewalld; do
        systemctl stop    "$svc" &>/dev/null || true
        systemctl disable "$svc" &>/dev/null || true
        systemctl mask    "$svc" &>/dev/null || true
    done
    command -v nft &>/dev/null && nft flush ruleset 2>/dev/null || true
    ok "nftables/ufw/firewalld 已禁用"

    # iptables-persistent
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections 2>/dev/null || true
    apt-get install -y -qq iptables-persistent netfilter-persistent 2>/dev/null || true

    # 检测 WireGuard 内核模块
    if ! modprobe wireguard 2>/dev/null; then
        warn "内核无 WireGuard 模块（内核: $(uname -r)），安装 wireguard-go..."
        apt-get install -y wireguard-go
        ok "wireguard-go 已安装"
    else
        ok "WireGuard 内核模块可用"
    fi

    # sysctl
    cat > /etc/sysctl.d/98-relay-wg.conf << 'EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
EOF
    sysctl -p /etc/sysctl.d/98-relay-wg.conf &>/dev/null || true
    ok "依赖安装完成"

    echo ""; read -rp "[按Enter继续...]"
}

# ──────────────────────────────────────────────────────────────
# 步骤3：生成/加载密钥，创建落地机配置
# ──────────────────────────────────────────────────────────────
generate_keys() {
    hr; echo -e "${PURPLE}步骤 3/6: 生成密钥${NC}"; hr
    echo ""
    mkdir -p "$WG_KEY_DIR"; chmod 700 "$WG_KEY_DIR"

    if [[ "$MODE" == "fresh" ]]; then
        step "生成中转机 WireGuard 密钥..."
        wg genkey | tee "$WG_KEY_DIR/relay_privatekey" | wg pubkey > "$WG_KEY_DIR/relay_publickey"
        chmod 600 "$WG_KEY_DIR/relay_privatekey" "$WG_KEY_DIR/relay_publickey"
        RELAY_PRIV=$(cat "$WG_KEY_DIR/relay_privatekey")
        RELAY_PUB=$(cat "$WG_KEY_DIR/relay_publickey")
        ok "中转机密钥已生成"
    else
        # 追加模式：从文件读取已有密钥
        [[ -f "$WG_KEY_DIR/relay_privatekey" ]] || err "找不到中转机私钥: $WG_KEY_DIR/relay_privatekey"
        [[ -f "$WG_KEY_DIR/relay_publickey"  ]] || wg pubkey < "$WG_KEY_DIR/relay_privatekey" > "$WG_KEY_DIR/relay_publickey"
        RELAY_PRIV=$(cat "$WG_KEY_DIR/relay_privatekey")
        RELAY_PUB=$(cat "$WG_KEY_DIR/relay_publickey")
        ok "使用现有中转机密钥"
    fi

    info "中转机 WireGuard 公钥: $RELAY_PUB"
    echo ""

    # 确定起始 peer 序号（追加时续号）
    local start_idx=$(( ${EXISTING_PEER_COUNT:-0} + 1 ))

    declare -ag NEW_PEER_NAMES=()
    declare -ag NEW_PEER_PRIVKEYS=()
    declare -ag NEW_PEER_PUBKEYS=()
    declare -ag NEW_PEER_IPS=()

    # 读取已有 peer 名称（避免重复）
    declare -a EXISTING_NAMES=()
    for f in "$PEER_DIR"/*-wg.conf; do
        [[ -f "$f" ]] || continue
        local n; n=$(basename "$f" -wg.conf)
        EXISTING_NAMES+=("$n")
    done

    local peer_rel=0
    while (( peer_rel < PEER_COUNT )); do
        local idx=$(( start_idx + peer_rel ))
        local ip_last=$(( idx + 1 ))    # 10.0.0.2, 10.0.0.3, ...
        [[ $ip_last -gt 254 ]] && err "已达到最大 WireGuard 地址 (10.0.0.254)"

        # 输入落地机名称
        local pname=""
        while true; do
            read -rp "第 $((peer_rel+1)) 台落地机名称（如 phoenix, tokyo）: " pname
            [[ -z "$pname" ]] && warn "名称不能为空" && continue
            # 检查重复
            local dup=false
            for n in "${EXISTING_NAMES[@]:-}" "${NEW_PEER_NAMES[@]:-}"; do
                [[ "$n" == "$pname" ]] && dup=true && break
            done
            $dup && warn "名称 '$pname' 已存在，请换一个" && continue
            break
        done

        # 生成密钥对
        local priv pub keyfile_priv keyfile_pub
        keyfile_priv="$WG_KEY_DIR/peer${idx}_privatekey"
        keyfile_pub="$WG_KEY_DIR/peer${idx}_publickey"
        wg genkey | tee "$keyfile_priv" | wg pubkey > "$keyfile_pub"
        chmod 600 "$keyfile_priv" "$keyfile_pub"
        priv=$(cat "$keyfile_priv")
        pub=$(cat "$keyfile_pub")

        NEW_PEER_NAMES+=("$pname")
        NEW_PEER_PRIVKEYS+=("$priv")
        NEW_PEER_PUBKEYS+=("$pub")
        NEW_PEER_IPS+=("10.0.0.${ip_last}")

        ok "[$pname] 密钥已生成，WireGuard IP: 10.0.0.${ip_last}"
        (( peer_rel++ ))
    done

    echo ""; read -rp "[按Enter继续...]"
}

# ──────────────────────────────────────────────────────────────
# 步骤4：写入 WireGuard 配置
# ──────────────────────────────────────────────────────────────
write_wg_config() {
    hr; echo -e "${PURPLE}步骤 4/6: 配置 WireGuard${NC}"; hr
    echo ""

    local WAN_IFACE
    WAN_IFACE=$(get_wan_iface)
    info "检测到 WAN 接口: $WAN_IFACE"

    if [[ "$MODE" == "fresh" ]]; then
        step "生成中转机 wg0.conf..."
        cat > "$WG_CONF" << EOF
[Interface]
Address = ${RELAY_WG_IP:-10.0.0.1}/24
ListenPort = $WG_PORT
PrivateKey = $RELAY_PRIV

PostUp   = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o ${WAN_IFACE} -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -s 10.0.0.0/24 -o ${WAN_IFACE} -j MASQUERADE

EOF
        ok "中转机基础配置已写入"
    fi

    # 追加新 Peer 段（全新模式也走这里）
    for (( i=0; i<${#NEW_PEER_NAMES[@]}; i++ )); do
        local name="${NEW_PEER_NAMES[$i]}"
        local pub="${NEW_PEER_PUBKEYS[$i]}"
        local ip="${NEW_PEER_IPS[$i]}"

        # 检查是否已存在该 Peer（避免重复）
        if grep -q "^PublicKey = $pub" "$WG_CONF" 2>/dev/null; then
            warn "[$name] Peer 已存在于 wg0.conf，跳过"
            continue
        fi

        cat >> "$WG_CONF" << EOF
[Peer]
# $name
PublicKey = $pub
AllowedIPs = ${ip}/32
PersistentKeepalive = 25

EOF
        ok "[$name] Peer 已追加到 wg0.conf"

        # 生成落地机 wg0.conf（供 wg_luodi.sh 参考）
        local priv="${NEW_PEER_PRIVKEYS[$i]}"
        cat > "$PEER_DIR/${name}-wg.conf" << EOF
# ============================================================
# 落地机 ${name} WireGuard 配置
# 由 wg_zhongzhuan.sh 在中转机生成，复制到落地机使用
# 也可直接在落地机运行 wg_luodi.sh 手动输入参数
# ============================================================
[Interface]
Address = ${ip}/32
PrivateKey = $priv
# DNS = 8.8.8.8  # 按需开启

# !! 注意：PostUp/PostDown 中的 eth0 需替换为落地机实际 WAN 网卡 !!
# 落地机运行 wg_luodi.sh 会自动检测并填写正确的网卡名称
PostUp   = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT

[Peer]
PublicKey = $RELAY_PUB
Endpoint = $RELAY_IP:$WG_PORT
AllowedIPs = 10.0.0.0/24
PersistentKeepalive = 25
EOF
        ok "[$name] 落地机配置模板已生成: $PEER_DIR/${name}-wg.conf"
    done

    chmod 600 "$WG_CONF"
    ok "WireGuard 配置文件权限已设置"

    echo ""; read -rp "[按Enter继续...]"
}

# ──────────────────────────────────────────────────────────────
# 步骤5：启动/热加载 WireGuard
# ──────────────────────────────────────────────────────────────
start_wg() {
    hr; echo -e "${PURPLE}步骤 5/6: 启动 WireGuard${NC}"; hr
    echo ""

    systemctl enable wg-quick@wg0 &>/dev/null || true

    if wg show wg0 &>/dev/null 2>&1; then
        if [[ "$MODE" == "append" ]]; then
            step "WireGuard 运行中，热加载新 Peer..."
            # 构建临时配置追加新 Peer
            local tmp_conf
            tmp_conf=$(mktemp)
            for (( i=0; i<${#NEW_PEER_NAMES[@]}; i++ )); do
                cat >> "$tmp_conf" << EOF
[Peer]
# ${NEW_PEER_NAMES[$i]}
PublicKey = ${NEW_PEER_PUBKEYS[$i]}
AllowedIPs = ${NEW_PEER_IPS[$i]}/32
PersistentKeepalive = 25
EOF
            done
            wg addconf wg0 "$tmp_conf" 2>/dev/null && ok "热加载成功（不影响现有连接）" \
                || { warn "热加载失败，尝试重启..."; systemctl restart wg-quick@wg0; }
            rm -f "$tmp_conf"
            # 补充路由：wg addconf 不自动注入内核路由，需手动添加
            for (( i=0; i<${#NEW_PEER_IPS[@]}; i++ )); do
                ip route add "${NEW_PEER_IPS[$i]}/32" dev wg0 2>/dev/null || true
                ok "路由已注入: ${NEW_PEER_IPS[$i]}/32 dev wg0"
            done
        else
            step "重启 WireGuard..."
            systemctl restart wg-quick@wg0
        fi
    else
        step "启动 WireGuard..."
        systemctl start wg-quick@wg0
    fi

    sleep 2

    if wg show wg0 &>/dev/null; then
        ok "WireGuard 运行正常"
        wg show wg0
    else
        err "WireGuard 启动失败，请查看日志: journalctl -u wg-quick@wg0 -n 30"
    fi

    # 开放 WireGuard UDP 端口
    iptables -C INPUT -p udp --dport "$WG_PORT" -j ACCEPT &>/dev/null \
        || iptables -I INPUT -p udp --dport "$WG_PORT" -j ACCEPT
    # 确保 FORWARD 和 MASQUERADE（wg0 启动时 PostUp 会添加，这里兜底）
    iptables -C FORWARD -i wg0 -j ACCEPT &>/dev/null \
        || iptables -A FORWARD -i wg0 -j ACCEPT
    iptables -C FORWARD -o wg0 -j ACCEPT &>/dev/null \
        || iptables -A FORWARD -o wg0 -j ACCEPT

    # 持久化防火墙规则
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    command -v netfilter-persistent &>/dev/null && \
        netfilter-persistent save &>/dev/null || true
    ok "防火墙规则已持久化"

    echo ""; read -rp "[按Enter继续...]"
}

# ──────────────────────────────────────────────────────────────
# 步骤6：保存摘要，安装 relay-info
# ──────────────────────────────────────────────────────────────
save_summary() {
    hr; echo -e "${PURPLE}步骤 6/6: 保存信息${NC}"; hr
    echo ""

    # 计算新的总 Peer 数
    local total_peers
    total_peers=$(grep -c '^\[Peer\]' "$WG_CONF" 2>/dev/null || echo 0)

    # 写 summary.txt（完整重写，包含所有 Peer）
    {
        echo "============================================================"
        echo "  CN2GIA 中转机部署信息"
        echo "  更新时间: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "============================================================"
        echo ""
        echo "RELAY_PUBLIC_IP=$RELAY_IP"
        echo "RELAY_WG_PORT=$WG_PORT"
        echo "RELAY_WG_PUBKEY=$RELAY_PUB"
        echo "RELAY_WG_IP=10.0.0.1"
        echo "RELAY_WG_SUBNET=10.0.0.0/24"
        echo "PEER_COUNT=$total_peers"
        echo ""
        echo "# ── 每台落地机信息（供 wg_luodi.sh 使用）──"
        echo ""

        # 从 peer-configs 目录读取所有落地机信息
        local idx=0
        for f in "$PEER_DIR"/*-wg.conf; do
            [[ -f "$f" ]] || continue
            (( idx++ ))
            local fname; fname=$(basename "$f" -wg.conf)
            local peer_priv; peer_priv=$(grep '^PrivateKey' "$f" | awk '{print $3}')
            local peer_ip;   peer_ip=$(grep '^Address'    "$f" | awk '{print $3}' | cut -d'/' -f1)
            # 从 relay wg0.conf 找到对应公钥
            local peer_pub=""
            peer_pub=$(awk -v name="# $fname" '
                /^\[Peer\]/{found=0} $0==name{found=1} found && /^PublicKey/{print $3; exit}
            ' "$WG_CONF" 2>/dev/null || true)

            echo "PEER_${idx}_NAME=$fname"
            echo "PEER_${idx}_WG_IP=$peer_ip"
            echo "PEER_${idx}_WG_PRIVKEY=$peer_priv"
            [[ -n "$peer_pub" ]] && echo "PEER_${idx}_WG_PUBKEY=$peer_pub"
            echo "PEER_${idx}_WG_CONF=peer-configs/${fname}-wg.conf"
            echo ""
        done
    } > "$SUMMARY_FILE"
    chmod 600 "$SUMMARY_FILE"
    ok "摘要已保存: $SUMMARY_FILE"

    # 安装 relay-info 快捷命令
    cat > /usr/local/bin/relay-info << 'CMEOF'
#!/bin/bash
CYAN='\033[0;36m' GREEN='\033[0;32m' YELLOW='\033[1;33m' NC='\033[0m'
SUMMARY=/opt/relay-wg/config/summary.txt

echo -e "${CYAN}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║              中转机信息速查 (relay-info)                        ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

[[ -f "$SUMMARY" ]] && cat "$SUMMARY" || echo -e "${YELLOW}摘要文件不存在${NC}"

echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━ 实时状态 ━━━━━━━━━━━━━━━━━━━━━━${NC}"

echo -e "${GREEN}▸ WireGuard：${NC}"
wg show 2>/dev/null || echo "  (未运行)"

echo ""
echo -e "${GREEN}▸ DNAT 端口转发规则：${NC}"
iptables -t nat -L PREROUTING -n 2>/dev/null \
    | awk '/DNAT/{printf "  • 端口 %-6s → %s\n", $7, $9}' \
    | sed 's/dpt://' | sed 's/to://' \
    || echo "  无"

echo ""
echo -e "${GREEN}▸ 本机公网 IP：${NC}"
curl -s4 --max-time 5 https://api.ipify.org 2>/dev/null \
    || curl -s4 --max-time 5 https://ifconfig.me 2>/dev/null \
    || echo "  获取失败"
echo ""
CMEOF
    chmod +x /usr/local/bin/relay-info
    ok "relay-info 命令已安装"
}

# ──────────────────────────────────────────────────────────────
# 最终展示
# ──────────────────────────────────────────────────────────────
print_result() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║           ★ 中转机部署完成！                                   ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    echo -e "${YELLOW}【中转机基本信息】${NC}"
    echo -e "  公网 IP         → ${GREEN}$RELAY_IP${NC}"
    echo -e "  WireGuard 端口  → ${GREEN}$WG_PORT/UDP${NC}"
    echo -e "  WireGuard 公钥  → ${GREEN}$RELAY_PUB${NC}"
    echo ""

    echo -e "${YELLOW}【新增落地机配置】${NC}"
    for (( i=0; i<${#NEW_PEER_NAMES[@]}; i++ )); do
        echo -e "  ${CYAN}┌── 落地机: ${NEW_PEER_NAMES[$i]}${NC}"
        echo -e "  │  WireGuard IP  → ${GREEN}${NEW_PEER_IPS[$i]}/32${NC}"
        echo -e "  │  WireGuard 私钥 → ${GREEN}${NEW_PEER_PRIVKEYS[$i]}${NC}"
        echo -e "  │  WireGuard 公钥 → ${GREEN}${NEW_PEER_PUBKEYS[$i]}${NC}"
        echo -e "  │  配置模板      → ${CYAN}$PEER_DIR/${NEW_PEER_NAMES[$i]}-wg.conf${NC}"
        echo -e "  ${CYAN}└────────────────────────────────────${NC}"
        echo ""
    done

    echo -e "${YELLOW}【下一步】${NC}"
    echo -e "  1. 在每台落地机上运行: ${CYAN}bash wg_luodi.sh${NC}（输入上面的私钥和 IP）"
    echo -e "  2. 在落地机上运行: ${CYAN}bash wg_duijie.sh${NC}（自动对接代理节点）"
    echo ""
    echo -e "${YELLOW}【常用命令】${NC}"
    echo -e "  查看全部信息  → ${CYAN}relay-info${NC}"
    echo -e "  查看 WG 状态  → ${CYAN}wg show${NC}"
    echo -e "  查看端口转发  → ${CYAN}iptables -t nat -L PREROUTING -n${NC}"
    echo -e "  添加转发规则  → ${CYAN}bash $WORK_DIR/wg_port.sh --add-relay-port${NC}"
    echo -e "  防火墙状态    → ${CYAN}bash $WORK_DIR/wg_port.sh --status${NC}"
    echo ""
}

# ──────────────────────────────────────────────────────────────
# 主流程
# ──────────────────────────────────────────────────────────────
main() {
    print_banner
    check_existing      # 决定 MODE: fresh / append

    if [[ "$MODE" == "fresh" ]]; then
        collect_info_fresh
        install_deps
        generate_keys
        write_wg_config
        start_wg
        save_summary
    else
        load_existing_config
        collect_info_append
        generate_keys
        write_wg_config
        start_wg
        save_summary
    fi

    print_result
}

main "$@"
