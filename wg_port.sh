#!/bin/bash
# ============================================================
# wg_port.sh v5.3 — iptables 防火墙管理脚本
# 适用：Xray / Sing-box / V2Ray / Hysteria2 等代理服务
# 支持：Ubuntu 22/24, Debian 11/12
# 角色：中转机 (relay) | 落地机 (landing)
# 新增 v5.3：
#   --list-relay-ports   列出中转机所有 DNAT 端口转发规则
#   --add-relay-port     交互式添加 DNAT+SNAT 转发规则（SNAT→10.0.0.1）
#   --remove-relay-port  删除指定端口的 DNAT+SNAT 规则
# ============================================================
set -uo pipefail

R="\033[31m" Y="\033[33m" G="\033[32m" C="\033[36m" B="\033[34m" W="\033[0m"
ok()   { echo -e "${G}✓ $*${W}"; }
warn() { echo -e "${Y}⚠ $*${W}"; }
err()  { echo -e "${R}✗ $*${W}"; exit 1; }
info() { echo -e "${C}→ $*${W}"; }
hr()   { echo -e "${B}──────────────────────────────────────────${W}"; }

[[ $(id -u) -eq 0 ]] || err "需要 root 权限"

VERSION="5.3"
SSH_PORT=""
OPEN_PORTS=()
HOP_RULES=()
DRY_RUN=false
ROLE="auto"
RELAY_WG_PORT=""
RELAY_WG_SUBNET=""
WG_IFACE="wg0"

EXCLUDE_PROCS="cloudflared|chronyd|dnsmasq|systemd-resolve|named|unbound|ntpd|avahi"
BLACKLIST_PORTS=(23 25 53 69 111 135 137 138 139 445 514 631
    110 143 465 587 993 995
    1433 1521 3306 5432 6379 27017
    3389 5900 5901 5902 323 2049
    8181 9090 3000 3001 8000 8001 54321 62789
    10080 10081 10082 10083 10084 10085 10086)

# ── 参数解析 ────────────────────────────────────────────────
_status=0 _reset=0 _addhop=0 _listrelay=0 _addrelay=0 _removerelay=0
REMOVE_PORT_ARG=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)           DRY_RUN=true ;;
        --status)            _status=1 ;;
        --reset)             _reset=1 ;;
        --add-hop)           _addhop=1 ;;
        --list-relay-ports)  _listrelay=1 ;;
        --add-relay-port)    _addrelay=1 ;;
        --remove-relay-port) _removerelay=1; [[ $# -gt 1 ]] && { shift; REMOVE_PORT_ARG="$1"; } ;;
        --relay)             ROLE="relay" ;;
        --landing)           ROLE="landing" ;;
        --wg-port)           shift; RELAY_WG_PORT="$1" ;;
        --wg-subnet)         shift; RELAY_WG_SUBNET="$1" ;;
        --wg-iface)          shift; WG_IFACE="$1" ;;
        --help|-h)
            echo "用法: bash wg_port.sh [选项]"
            echo ""
            echo "  (无参数)               交互式完整配置"
            echo "  --relay                中转机模式"
            echo "  --landing              落地机模式"
            echo "  --status               查看当前规则和端口"
            echo "  --reset                清空所有规则（全部放行）"
            echo "  --add-hop              手动添加端口跳跃规则"
            echo ""
            echo "  中转机端口转发管理："
            echo "  --list-relay-ports     列出所有 DNAT 端口转发规则"
            echo "  --add-relay-port       添加新的 DNAT+SNAT 转发规则"
            echo "  --remove-relay-port [PORT]  删除指定端口的转发规则"
            echo ""
            echo "  其他："
            echo "  --wg-port PORT         指定 WireGuard 端口"
            echo "  --wg-subnet CIDR       指定 WireGuard 内网段（默认 10.0.0.0/24）"
            echo "  --wg-iface IFACE       指定 WireGuard 网卡（默认 wg0）"
            echo "  --dry-run              预览模式，不实际修改"
            exit 0 ;;
        *) err "未知参数: $1（运行 --help 查看帮助）" ;;
    esac
    shift
done

# ── 工具函数 ─────────────────────────────────────────────────
get_default_iface() {
    ip route show default 2>/dev/null | awk '/default/ {print $5; exit}' \
        || ip link show 2>/dev/null | awk -F': ' '/^[0-9]+: [^lo]/{print $2; exit}' \
        || echo "eth0"
}

get_public_ports() {
    ss -tulnp 2>/dev/null \
        | grep -vE '[[:space:]](127\.|::1)[^[:space:]]' \
        | grep -vE "($EXCLUDE_PROCS)" \
        | grep -oE '(\*|0\.0\.0\.0|\[?::\]?):[0-9]+' \
        | grep -oE '[0-9]+$' \
        | while read -r p; do [[ "$p" -lt 32768 ]] && echo "$p" || true; done \
        | sort -un || true
}

parse_hop() {
    local rule=$1
    HOP_S=$(echo "$rule" | cut -d'-' -f1)
    HOP_E=$(echo "$rule" | cut -d'-' -f2 | cut -d'>' -f1 | tr -d '>')
    HOP_T=$(echo "$rule" | grep -oE '[0-9]+$')
}

is_blacklisted() {
    local p=$1
    [[ "$p" == "$SSH_PORT" ]] && return 0
    for b in "${BLACKLIST_PORTS[@]}"; do [[ "$p" == "$b" ]] && return 0; done
    return 1
}

add_port() {
    local p=$1
    [[ "$p" =~ ^[0-9]+$ ]]             || return 0
    [[ "$p" -ge 1 && "$p" -le 65535 ]] || return 0
    is_blacklisted "$p"                 && return 0
    [[ " ${OPEN_PORTS[*]:-} " =~ " $p " ]] && return 0
    OPEN_PORTS+=("$p")
}

# ── 初始化依赖 ───────────────────────────────────────────────
install_deps() {
    info "检查依赖..."

    # 禁用 nftables
    systemctl stop    nftables &>/dev/null || true
    systemctl disable nftables &>/dev/null || true
    systemctl mask    nftables &>/dev/null || true
    command -v nft &>/dev/null && nft flush ruleset 2>/dev/null || true
    [[ -f /etc/nftables.conf ]] && > /etc/nftables.conf
    ok "nftables 已禁用"

    for svc in ufw firewalld; do
        if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}\.service"; then
            systemctl stop    "$svc" &>/dev/null || true
            systemctl disable "$svc" &>/dev/null || true
            systemctl mask    "$svc" &>/dev/null || true
        fi
    done

    # 安装 iptables
    local pkgs=()
    command -v iptables      &>/dev/null || pkgs+=(iptables)
    command -v ss            &>/dev/null || pkgs+=(iproute2)
    if [[ ${#pkgs[@]} -gt 0 ]]; then
        apt-get install -y -qq "${pkgs[@]}" 2>/dev/null || \
        yum install -y iptables iproute 2>/dev/null || true
    fi
    command -v iptables &>/dev/null || err "iptables 安装失败"

    # iptables-legacy
    if command -v update-alternatives &>/dev/null; then
        update-alternatives --set iptables  /usr/sbin/iptables-legacy  &>/dev/null || true
        update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy &>/dev/null || true
        ok "iptables 已切换为 legacy 模式"
    fi

    # sysctl
    cat > /etc/sysctl.d/98-iptables-fw.conf << 'EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.tcp_timestamps=0
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
EOF
    sysctl -p /etc/sysctl.d/98-iptables-fw.conf &>/dev/null || true
    ok "依赖检查完成"
}

detect_ssh() {
    SSH_PORT=$(ss -tlnp 2>/dev/null | grep sshd | grep -oE ':[0-9]+' | grep -oE '[0-9]+' | head -1 || true)
    [[ -z "$SSH_PORT" ]] && SSH_PORT=$(awk '/^Port /{print $2;exit}' /etc/ssh/sshd_config 2>/dev/null || true)
    [[ -z "$SSH_PORT" ]] && SSH_PORT=22
    ok "SSH 端口: $SSH_PORT"
}

# ── 角色检测 ─────────────────────────────────────────────────
detect_role() {
    [[ "$ROLE" != "auto" ]] && { ok "角色已指定: $ROLE"; return; }

    if [[ -d /etc/v2ray-agent/xray/conf || -d /etc/v2ray-agent/sing-box/conf \
        || -f /etc/sing-box/config.json || -f /etc/x-ui/x-ui.db ]]; then
        ROLE="landing"
        ok "自动检测角色: 落地机 (landing)"
        return
    fi

    if [[ -f /etc/wireguard/wg0.conf ]]; then
        local peer_count has_listen
        peer_count=$(grep -c '^\[Peer\]' /etc/wireguard/wg0.conf 2>/dev/null || echo 0)
        has_listen=$(grep -c '^ListenPort' /etc/wireguard/wg0.conf 2>/dev/null || echo 0)
        if [[ "$has_listen" -gt 0 && "$peer_count" -gt 1 ]]; then
            ROLE="relay"
            ok "自动检测角色: 中转机 (relay) — $peer_count 个 Peer"
        else
            ROLE="landing"
            ok "自动检测角色: 落地机 (landing)"
        fi
        return
    fi

    ROLE="landing"
    ok "自动检测角色: 落地机 (landing)（默认）"
}

# ── 中转机参数检测 ────────────────────────────────────────────
detect_relay_params() {
    local wg_conf=/etc/wireguard/wg0.conf
    [[ -z "$RELAY_WG_PORT" && -f "$wg_conf" ]] && \
        RELAY_WG_PORT=$(grep -E '^\s*ListenPort' "$wg_conf" | grep -oE '[0-9]+' | head -1 || true)
    [[ -z "$RELAY_WG_SUBNET" && -f "$wg_conf" ]] && \
        RELAY_WG_SUBNET=$(grep -E '^\s*Address' "$wg_conf" \
            | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | head -1 | \
            sed 's/\.[0-9]*\//.0\//' || true)

    RELAY_WG_PORT="${RELAY_WG_PORT:-51820}"
    RELAY_WG_SUBNET="${RELAY_WG_SUBNET:-10.0.0.0/24}"
    ok "中转机参数 — WG端口: $RELAY_WG_PORT  WG内网: $RELAY_WG_SUBNET"
}

# ── 端口跳跃检测 ─────────────────────────────────────────────
detect_existing_hop_rules() {
    while IFS= read -r line; do
        [[ "$line" == *DNAT* ]] || continue
        local range target
        range=$(echo "$line" | grep -oE 'dpts:[0-9]+:[0-9]+' | grep -oE '[0-9]+:[0-9]+' | tr ':' '-')
        target=$(echo "$line" | grep -oE 'to::[0-9]+' | grep -oE '[0-9]+$')
        [[ -n "$range" && -n "$target" ]] || continue
        local rule="${range}->${target}"
        [[ " ${HOP_RULES[*]:-} " =~ " ${rule} " ]] || HOP_RULES+=("$rule")
    done < <(iptables -t nat -L PREROUTING -n 2>/dev/null || true)
}

detect_hysteria_hop() {
    local dirs=(/etc/hysteria /etc/hysteria2 /usr/local/etc/hysteria)
    for d in "${dirs[@]}"; do
        [[ -d "$d" ]] || continue
        for ext in json yaml yml; do
            local f="${d}/config.${ext}"
            [[ -f "$f" ]] || continue
            local listen_port="" hop_range=""
            if [[ "$ext" == "json" ]]; then
                listen_port=$(grep -oE '"listen"[^:]*:[^"]*":[0-9]+"' "$f" 2>/dev/null \
                    | grep -oE ':[0-9]+' | grep -oE '[0-9]+' | head -1 || true)
                hop_range=$(grep -oE '"(portHopping|portRange)"[^:]*:"[0-9]+-[0-9]+"' "$f" 2>/dev/null \
                    | grep -oE '[0-9]+-[0-9]+' | head -1 || true)
            else
                listen_port=$(grep -E '^\s*listen\s*:' "$f" 2>/dev/null \
                    | grep -oE ':[0-9]+' | grep -oE '[0-9]+' | head -1 || true)
                hop_range=$(grep -E '^\s*(portHopping|portRange)\s*:' "$f" 2>/dev/null \
                    | grep -oE '[0-9]+-[0-9]+' | head -1 || true)
            fi
            if [[ -n "$listen_port" && -n "$hop_range" ]]; then
                local rule="${hop_range}->${listen_port}"
                [[ " ${HOP_RULES[*]:-} " =~ " ${rule} " ]] \
                    || { HOP_RULES+=("$rule"); ok "检测到 Hysteria2 跳跃: $hop_range → $listen_port"; }
            fi
        done
    done
}

detect_ports() {
    info "扫描公网监听端口..."
    while read -r port; do add_port "$port"; done < <(get_public_ports)

    local py_parser="/tmp/_fw_ports.py"
    cat > "$py_parser" << 'PYEOF'
import json, sys
def extract(data):
    ports, LOCAL = [], ('127.','::1','localhost')
    is_local = lambda v: any(str(v or '').startswith(x) for x in LOCAL)
    for inb in (data.get('inbounds') or []):
        if not isinstance(inb, dict): continue
        for key in ('port','listen_port'):
            p = inb.get(key)
            if isinstance(p,int) and 1<=p<=65535 and not is_local(inb.get('listen','')):
                ports.append(p)
    return sorted(set(ports))
for f in sys.argv[1:]:
    try:
        with open(f) as fp: [print(p) for p in extract(json.load(fp))]
    except: pass
PYEOF

    local cfg_files=()
    local cfg_dirs=(
        /usr/local/etc/xray /etc/xray
        /usr/local/etc/v2ray /etc/v2ray
        /etc/sing-box /opt/sing-box /usr/local/etc/sing-box
        /etc/v2ray-agent/xray/conf /etc/v2ray-agent/sing-box/conf
        /etc/hysteria /etc/hysteria2 /etc/tuic /etc/trojan
    )
    for d in "${cfg_dirs[@]}"; do
        [[ -d "$d" ]] || continue
        for f in "$d"/config.json "$d"/*.json "$d"/conf/*.json; do
            [[ -f "$f" ]] && cfg_files+=("$f")
        done
    done

    if [[ ${#cfg_files[@]} -gt 0 ]]; then
        while read -r port; do add_port "$port"
        done < <(python3 "$py_parser" "${cfg_files[@]}" 2>/dev/null | sort -un || true)
    fi
}

# ── 端口跳跃 ─────────────────────────────────────────────────
apply_hop() {
    local s=$1 e=$2 t=$3
    local nums
    nums=$(iptables -t nat -L PREROUTING -n --line-numbers 2>/dev/null \
        | grep "dpts:${s}:${e}" | awk '{print $1}' | sort -rn || true)
    for n in $nums; do iptables -t nat -D PREROUTING "$n" 2>/dev/null || true; done
    iptables -t nat -A PREROUTING -p udp --dport "${s}:${e}" -j DNAT --to-destination ":${t}"
    iptables -t nat -A PREROUTING -p tcp --dport "${s}:${e}" -j DNAT --to-destination ":${t}"
    iptables -C INPUT -p udp --dport "${s}:${e}" -j ACCEPT 2>/dev/null \
        || iptables -A INPUT -p udp --dport "${s}:${e}" -j ACCEPT
    iptables -C INPUT -p tcp --dport "${s}:${e}" -j ACCEPT 2>/dev/null \
        || iptables -A INPUT -p tcp --dport "${s}:${e}" -j ACCEPT
}

# ── 清空规则 ─────────────────────────────────────────────────
flush_rules() {
    info "清理旧规则..."
    iptables  -P INPUT   ACCEPT 2>/dev/null || true
    iptables  -P FORWARD ACCEPT 2>/dev/null || true
    iptables  -P OUTPUT  ACCEPT 2>/dev/null || true
    iptables  -F 2>/dev/null || true; iptables  -X 2>/dev/null || true
    iptables  -t nat    -F 2>/dev/null || true; iptables  -t nat    -X 2>/dev/null || true
    iptables  -t mangle -F 2>/dev/null || true; iptables  -t raw    -F 2>/dev/null || true
    ip6tables -P INPUT   ACCEPT 2>/dev/null || true
    ip6tables -P FORWARD ACCEPT 2>/dev/null || true
    ip6tables -F 2>/dev/null || true; ip6tables -t nat -F 2>/dev/null || true
}

# ── 应用规则 ─────────────────────────────────────────────────
apply_rules() {
    local wan_iface
    wan_iface=$(get_default_iface)
    info "出口网卡: $wan_iface"

    if [[ "$DRY_RUN" == true ]]; then
        hr; info "[预览模式] 以下规则不会实际应用"
        info "角色: $ROLE  SSH: $SSH_PORT"
        if [[ "$ROLE" == "relay" ]]; then
            info "WG端口: $RELAY_WG_PORT/UDP  WG内网: $RELAY_WG_SUBNET"
        else
            info "开放端口: ${OPEN_PORTS[*]:-无}"
            for rule in "${HOP_RULES[@]:-}"; do
                [[ -z "$rule" ]] && continue
                parse_hop "$rule"; info "端口跳跃: ${HOP_S}-${HOP_E} → ${HOP_T}"
            done
        fi
        hr; return 0
    fi

    flush_rules

    # 默认策略
    iptables -P INPUT   DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT  ACCEPT

    # 基础
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 10/sec --limit-burst 20 -j ACCEPT
    iptables -A INPUT -p icmp -j DROP

    # SSH 防暴力
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -m conntrack --ctstate NEW \
        -m recent --name SSH_BF --set
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -m conntrack --ctstate NEW \
        -m recent --name SSH_BF --update --seconds 60 --hitcount 6 -j DROP
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT

    if [[ "$ROLE" == "relay" ]]; then
        # ════════════════════════════════════════════════════
        # 中转机规则
        # ════════════════════════════════════════════════════
        iptables -A INPUT -p udp --dport "$RELAY_WG_PORT" -j ACCEPT
        ok "放行 WireGuard: UDP $RELAY_WG_PORT"

        iptables -A FORWARD -i "$WG_IFACE" -j ACCEPT
        iptables -A FORWARD -o "$WG_IFACE" -j ACCEPT
        iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        # 放行 DNAT 转发
        iptables -A FORWARD -m conntrack --ctstate DNAT -j ACCEPT
        ok "放行 FORWARD: $WG_IFACE 双向 + DNAT"

        # MASQUERADE（WireGuard 内网 → WAN）
        iptables -t nat -A POSTROUTING -s "$RELAY_WG_SUBNET" -o "$wan_iface" -j MASQUERADE
        ok "NAT MASQUERADE: $RELAY_WG_SUBNET → $wan_iface"

        # 如果本机也有代理服务，放行
        if [[ ${#OPEN_PORTS[@]} -gt 0 ]]; then
            for port in "${OPEN_PORTS[@]}"; do
                [[ -z "$port" ]] && continue
                iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
                iptables -A INPUT -p udp --dport "$port" -j ACCEPT
            done
            ok "额外代理端口: ${OPEN_PORTS[*]}"
        fi

    else
        # ════════════════════════════════════════════════════
        # 落地机规则
        # ════════════════════════════════════════════════════
        for port in "${OPEN_PORTS[@]:-}"; do
            [[ -z "$port" ]] && continue
            iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
            iptables -A INPUT -p udp --dport "$port" -j ACCEPT
        done
        ok "开放代理端口: ${OPEN_PORTS[*]:-无}"

        if ip link show "$WG_IFACE" &>/dev/null 2>&1; then
            iptables -A FORWARD -i "$WG_IFACE" -j ACCEPT
            iptables -A FORWARD -o "$WG_IFACE" -j ACCEPT
            ok "WireGuard FORWARD: $WG_IFACE 双向"
        fi

        iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        iptables -A FORWARD -m conntrack --ctstate DNAT -j ACCEPT
        iptables -t nat -A POSTROUTING -o "$wan_iface" -j MASQUERADE
        ok "NAT MASQUERADE → $wan_iface"

        for rule in "${HOP_RULES[@]:-}"; do
            [[ -z "$rule" ]] && continue
            parse_hop "$rule"
            [[ -z "${HOP_S:-}" || -z "${HOP_E:-}" || -z "${HOP_T:-}" ]] && continue
            apply_hop "$HOP_S" "$HOP_E" "$HOP_T"
            ok "端口跳跃: ${HOP_S}-${HOP_E} → ${HOP_T}"
        done
    fi

    iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "[FW-DROP] " --log-level 4
    iptables -A INPUT -j DROP
    ok "iptables 规则已应用"
}

# ── 持久化 ───────────────────────────────────────────────────
save_rules() {
    [[ "$DRY_RUN" == true ]] && return 0
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save &>/dev/null || true
        ok "规则已通过 netfilter-persistent 保存"
        return 0
    fi
    cat > /etc/systemd/system/iptables-restore.service << 'SVC'
[Unit]
Description=Restore iptables rules
Before=network-pre.target
Wants=network-pre.target
DefaultDependencies=no

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore /etc/iptables/rules.v4
ExecReload=/sbin/iptables-restore /etc/iptables/rules.v4
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SVC
    systemctl daemon-reload  &>/dev/null || true
    systemctl enable iptables-restore.service &>/dev/null || true
    ok "规则已保存: /etc/iptables/rules.v4（开机自动恢复）"
}

# ════════════════════════════════════════════════════════════
# ★ 新增：中转机端口转发管理
# ════════════════════════════════════════════════════════════

# 列出所有 DNAT 端口转发规则（中转机专用）
list_relay_ports() {
    hr
    echo -e "${C}中转机 DNAT 端口转发规则${W}"
    hr
    echo ""

    local count=0
    local num=0
    while IFS= read -r line; do
        [[ "$line" == *"DNAT"* ]] || continue
        (( num++ ))
        # 解析入站端口和目标 IP:Port
        local dport target
        # 支持 dpt:PORT 和 dpts:START:END
        dport=$(echo "$line" | grep -oE 'dpts?:[0-9:]+' | sed 's/dpts\?://' | tr ':' '-')
        target=$(echo "$line" | grep -oE 'to:[^ ]+' | sed 's/to://')
        local proto
        proto=$(echo "$line" | awk 'NR==1{print $1}')
        printf "  ${C}[%d]${W} %-5s 入站端口: ${G}%-20s${W} → 目标: ${G}%s${W}\n" \
            "$num" "$proto" "$dport" "$target"
        (( count++ ))
    done < <(iptables -t nat -L PREROUTING -n 2>/dev/null || true)

    echo ""
    [[ $count -eq 0 ]] && echo "  无 DNAT 规则" || echo "  共 $count 条规则"
    echo ""

    # 同时显示对应的 SNAT 规则
    echo -e "${C}SNAT 规则（确保回程走 WireGuard）${W}"
    hr
    local snat_count=0
    while IFS= read -r line; do
        [[ "$line" == *"SNAT"* ]] || continue
        local dst src to_src proto
        proto=$(echo "$line" | awk 'NR==1{print $1}')
        dst=$(echo "$line"    | awk '{print $5}')
        to_src=$(echo "$line" | grep -oE 'to:[^ ]+' | sed 's/to://')
        printf "  %-5s 目标: ${G}%-25s${W} → 来源改为: ${G}%s${W}\n" \
            "$proto" "$dst" "$to_src"
        (( snat_count++ ))
    done < <(iptables -t nat -L POSTROUTING -n 2>/dev/null || true)
    echo ""
    [[ $snat_count -eq 0 ]] && echo "  无 SNAT 规则（注意：缺少 SNAT 会导致非对称路由）"
    hr
}

# 交互式添加 DNAT+SNAT 规则
add_relay_port_interactive() {
    hr; echo -e "${C}添加中转机 DNAT+SNAT 端口转发规则${W}"; hr
    echo ""
    echo -e "  说明：DNAT 将入站流量转发到落地机 WireGuard IP"
    echo -e "        SNAT 将来源改为 10.0.0.1，确保回程走 WireGuard 隧道"
    echo ""

    # 落地机 WireGuard IP
    local landing_ip=""
    while true; do
        read -rp "落地机 WireGuard IP（如 10.0.0.2）: " landing_ip
        [[ "$landing_ip" =~ ^10\.0\.0\.[0-9]+$ ]] && break
        warn "格式不正确，应为 10.0.0.2 ~ 10.0.0.254"
    done

    # 端口（支持单端口或多个）
    echo ""
    info "输入要转发的端口（可多个，空格分隔，如：443 8443 2083）"
    read -rp "端口: " _ports_input

    local ports_to_add=()
    for p in $_ports_input; do
        if [[ "$p" =~ ^[0-9]+$ ]] && (( p >= 1 && p <= 65535 )); then
            ports_to_add+=("$p")
        else
            warn "无效端口: $p，跳过"
        fi
    done

    [[ ${#ports_to_add[@]} -eq 0 ]] && err "没有有效端口"

    echo ""
    echo -e "${Y}确认添加以下规则：${W}"
    for p in "${ports_to_add[@]}"; do
        echo -e "  DNAT: *:${G}${p}${W} → ${G}${landing_ip}:${p}${W}"
        echo -e "  SNAT: 来源 → ${G}10.0.0.1${W}"
    done
    echo ""
    read -rp "确认？[y/N]: " confirm
    [[ "${confirm,,}" == "y" ]] || { info "已取消"; return; }

    for p in "${ports_to_add[@]}"; do
        # 删除旧规则（幂等）
        iptables -t nat -D PREROUTING -p tcp --dport "$p" -j DNAT --to-destination "${landing_ip}:${p}" 2>/dev/null || true
        iptables -t nat -D PREROUTING -p udp --dport "$p" -j DNAT --to-destination "${landing_ip}:${p}" 2>/dev/null || true
        iptables -t nat -D POSTROUTING -d "${landing_ip}" -p tcp --dport "$p" -j SNAT --to-source 10.0.0.1 2>/dev/null || true
        iptables -t nat -D POSTROUTING -d "${landing_ip}" -p udp --dport "$p" -j SNAT --to-source 10.0.0.1 2>/dev/null || true
        iptables -D FORWARD -d "${landing_ip}" -p tcp --dport "$p" -j ACCEPT 2>/dev/null || true
        iptables -D FORWARD -d "${landing_ip}" -p udp --dport "$p" -j ACCEPT 2>/dev/null || true
        iptables -D INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || true
        iptables -D INPUT -p udp --dport "$p" -j ACCEPT 2>/dev/null || true
        # 添加新规则
        iptables -t nat -A PREROUTING -p tcp --dport "$p" -j DNAT --to-destination "${landing_ip}:${p}"
        iptables -t nat -A PREROUTING -p udp --dport "$p" -j DNAT --to-destination "${landing_ip}:${p}"
        iptables -t nat -A POSTROUTING -d "${landing_ip}" -p tcp --dport "$p" -j SNAT --to-source 10.0.0.1
        iptables -t nat -A POSTROUTING -d "${landing_ip}" -p udp --dport "$p" -j SNAT --to-source 10.0.0.1
        iptables -A FORWARD -d "${landing_ip}" -p tcp --dport "$p" -j ACCEPT
        iptables -A FORWARD -d "${landing_ip}" -p udp --dport "$p" -j ACCEPT
        iptables -I INPUT -p tcp --dport "$p" -j ACCEPT
        iptables -I INPUT -p udp --dport "$p" -j ACCEPT
        ok "端口 $p DNAT+SNAT 规则已添加 (→ ${landing_ip})"
    done

    save_rules
    echo ""
    ok "所有规则已添加并持久化"
    echo ""
    echo -e "${Y}查看所有规则：${W} bash wg_port.sh --list-relay-ports"
}

# 删除指定端口的 DNAT+SNAT 规则
remove_relay_port() {
    local target_port="${REMOVE_PORT_ARG:-}"
    if [[ -z "$target_port" ]]; then
        hr; echo -e "${C}删除 DNAT+SNAT 端口转发规则${W}"; hr
        echo ""
        list_relay_ports
        read -rp "输入要删除的端口号: " target_port
    fi

    [[ "$target_port" =~ ^[0-9]+$ ]] || err "端口格式错误: $target_port"

    echo ""
    echo -e "${Y}即将删除端口 ${G}${target_port}${Y} 的所有 DNAT+SNAT 规则${W}"
    read -rp "确认？[y/N]: " confirm
    [[ "${confirm,,}" == "y" ]] || { info "已取消"; return; }

    local removed=0

    # 删除 PREROUTING DNAT
    while true; do
        local line_num
        line_num=$(iptables -t nat -L PREROUTING -n --line-numbers 2>/dev/null \
            | awk -v p="$target_port" '/DNAT/ && $0 ~ "dpt[s]?:"p"($|[^0-9])"' | awk 'NR==1{print $1}')
        [[ -z "$line_num" ]] && break
        iptables -t nat -D PREROUTING "$line_num" 2>/dev/null && (( removed++ )) || break
    done

    # 删除 POSTROUTING SNAT
    while true; do
        local line_num
        line_num=$(iptables -t nat -L POSTROUTING -n --line-numbers 2>/dev/null \
            | awk -v p="$target_port" '/SNAT/ && $0 ~ "dpt[s]?:"p"($|[^0-9])"' | awk 'NR==1{print $1}')
        [[ -z "$line_num" ]] && break
        iptables -t nat -D POSTROUTING "$line_num" 2>/dev/null && (( removed++ )) || break
    done

    # 删除 FORWARD
    while true; do
        local line_num
        line_num=$(iptables -L FORWARD -n --line-numbers 2>/dev/null \
            | awk -v p="$target_port" '/ACCEPT/ && $0 ~ "dpt[s]?:"p"($|[^0-9])"' | awk 'NR==1{print $1}')
        [[ -z "$line_num" ]] && break
        iptables -D FORWARD "$line_num" 2>/dev/null && (( removed++ )) || break
    done

    # 删除 INPUT
    iptables -D INPUT -p tcp --dport "$target_port" -j ACCEPT 2>/dev/null && (( removed++ )) || true
    iptables -D INPUT -p udp --dport "$target_port" -j ACCEPT 2>/dev/null && (( removed++ )) || true

    if [[ $removed -gt 0 ]]; then
        save_rules
        ok "端口 $target_port 的 $removed 条规则已删除"
    else
        warn "未找到端口 $target_port 的转发规则"
    fi
}

# ── 手动添加端口跳跃 ─────────────────────────────────────────
add_hop_interactive() {
    detect_ssh
    hr; echo -e "${C}手动添加端口跳跃规则${W}"; hr
    read -rp "$(echo -e "${Y}端口范围（如 20000-50000）: ${W}")" hop_range
    read -rp "$(echo -e "${Y}目标端口（代理实际监听端口）: ${W}")" target_port
    [[ "$hop_range"   =~ ^[0-9]+-[0-9]+$ ]] || err "范围格式错误，示例: 20000-50000"
    [[ "$target_port" =~ ^[0-9]+$         ]] || err "目标端口格式错误"
    local s e
    s=$(echo "$hop_range" | cut -d- -f1)
    e=$(echo "$hop_range" | cut -d- -f2)
    [[ "$s" -ge "$e" ]] && err "起始端口须小于结束端口"
    apply_hop "$s" "$e" "$target_port"
    save_rules
    ok "端口跳跃 ${hop_range} → ${target_port} 已添加"
}

# ── 显示状态 ─────────────────────────────────────────────────
show_status() {
    hr; echo -e "${C}防火墙当前状态${W}"; hr

    detect_role 2>/dev/null || true
    echo -e "\n${G}▸ 角色:${W} $ROLE"

    echo -e "\n${G}▸ 开放端口 (INPUT ACCEPT):${W}"
    iptables -L INPUT -n 2>/dev/null | grep ACCEPT \
        | grep -oE 'dpts?:[0-9:]+' | sort -u \
        | sed 's/dpts\?:/  • /' || echo "  无"

    echo -e "\n${G}▸ DNAT 端口转发 (PREROUTING):${W}"
    local has_nat=0
    while IFS= read -r line; do
        [[ "$line" == *DNAT* ]] || continue
        local dport target
        dport=$(echo "$line"  | grep -oE 'dpts?:[0-9:]+' | sed 's/dpts\?://' | tr ':' '-')
        target=$(echo "$line" | grep -oE 'to:[^ ]+' | sed 's/to://')
        echo "  • :${dport} → ${target}"
        has_nat=1
    done < <(iptables -t nat -L PREROUTING -n 2>/dev/null || true)
    [[ $has_nat -eq 0 ]] && echo "  无"

    echo -e "\n${G}▸ SNAT / MASQUERADE (POSTROUTING):${W}"
    iptables -t nat -L POSTROUTING -n 2>/dev/null | grep -v '^target\|^Chain\|^$' \
        | sed 's/^/  • /' || echo "  无"

    echo -e "\n${G}▸ FORWARD 规则:${W}"
    iptables -L FORWARD -n 2>/dev/null | grep ACCEPT | sed 's/^/  • /' || echo "  无"

    echo -e "\n${G}▸ 公网监听端口:${W}"
    get_public_ports | while read -r p; do
        local proc
        proc=$(ss -tulnp 2>/dev/null | grep ":${p}[^0-9]" \
            | grep -oE '"[^"]+"' | head -1 | tr -d '"' || true)
        printf "  • %-6s %s\n" "$p" "${proc:-(未知)}"
    done

    echo -e "\n${G}▸ WireGuard:${W}"
    wg show 2>/dev/null | head -10 || echo "  未运行"

    echo -e "\n${G}▸ nftables 状态（应为禁用）:${W}"
    systemctl is-active nftables &>/dev/null \
        && warn "nftables 仍在运行！" \
        || ok "nftables 已禁用"

    hr
}

# ── 重置 ─────────────────────────────────────────────────────
do_reset() {
    echo -e "${R}⚠ 清除所有规则并全部放行，确认？[y/N]${W}"
    read -r ans
    [[ "${ans,,}" == y ]] || { info "已取消"; exit 0; }
    iptables -P INPUT ACCEPT; iptables -P FORWARD ACCEPT; iptables -P OUTPUT ACCEPT
    iptables -F; iptables -X
    iptables -t nat -F; iptables -t nat -X
    iptables -t mangle -F; iptables -t mangle -X
    ip6tables -P INPUT ACCEPT 2>/dev/null || true
    ip6tables -P FORWARD ACCEPT 2>/dev/null || true
    ip6tables -F 2>/dev/null || true
    save_rules
    ok "防火墙已重置，所有流量放行"
}

# ── 摘要展示 ─────────────────────────────────────────────────
show_summary() {
    hr; echo -e "${G}✓ 防火墙配置完成！(角色: $ROLE)${W}"; hr
    echo -e "${C}角色:${W} $ROLE  ${C}SSH:${W} $SSH_PORT  ${C}WAN:${W} $(get_default_iface)"
    if [[ "$ROLE" == "relay" ]]; then
        echo -e "${C}WG端口:${W} $RELAY_WG_PORT/UDP  ${C}WG内网:${W} $RELAY_WG_SUBNET"
    else
        echo -e "${C}开放端口:${W} ${OPEN_PORTS[*]:-无}"
        for rule in "${HOP_RULES[@]:-}"; do
            [[ -z "$rule" ]] && continue
            parse_hop "$rule"
            echo -e "  ${G}•${W} 跳跃: ${HOP_S}-${HOP_E} → ${HOP_T}"
        done
    fi
    hr
    echo -e "${Y}常用命令:${W}"
    echo "  查看状态          : bash wg_port.sh --status"
    echo "  添加端口跳跃      : bash wg_port.sh --add-hop"
    echo "  列出DNAT规则      : bash wg_port.sh --list-relay-ports"
    echo "  添加DNAT规则      : bash wg_port.sh --add-relay-port"
    echo "  删除DNAT规则      : bash wg_port.sh --remove-relay-port <PORT>"
    echo "  重置防火墙        : bash wg_port.sh --reset"
    hr
}

# ──────────────────────────────────────────────────────────────
# 主流程
# ──────────────────────────────────────────────────────────────
main() {
    trap 'echo -e "\n${R}已中断${W}"; exit 130' INT TERM
    hr
    echo -e "${G}  iptables 防火墙管理脚本 v${VERSION}${W}"
    hr

    [[ $_status    -eq 1 ]] && { detect_ssh; show_status;              exit 0; }
    [[ $_reset     -eq 1 ]] && { detect_ssh; do_reset;                 exit 0; }
    [[ $_addhop    -eq 1 ]] && { add_hop_interactive;                  exit 0; }
    [[ $_listrelay -eq 1 ]] && { list_relay_ports;                     exit 0; }
    [[ $_addrelay  -eq 1 ]] && { add_relay_port_interactive;           exit 0; }
    [[ $_removerelay -eq 1 ]] && { remove_relay_port;                  exit 0; }

    install_deps
    detect_ssh
    detect_role

    if [[ "$ROLE" == "relay" ]]; then
        detect_relay_params
        detect_existing_hop_rules
        detect_ports
        mapfile -t OPEN_PORTS < <(printf '%s\n' "${OPEN_PORTS[@]:-}" | sort -un) || true
        echo ""
        info "角色: 中转机  WG端口: $RELAY_WG_PORT/UDP  WG内网: $RELAY_WG_SUBNET"
        [[ ${#OPEN_PORTS[@]} -gt 0 ]] && info "本机代理端口: ${OPEN_PORTS[*]}"
    else
        detect_existing_hop_rules
        detect_hysteria_hop
        detect_ports
        add_port 80; add_port 443
        mapfile -t OPEN_PORTS < <(printf '%s\n' "${OPEN_PORTS[@]:-}" | sort -un) || true
        echo ""
        info "角色: 落地机  SSH: $SSH_PORT  代理端口: ${OPEN_PORTS[*]:-无}"
        for rule in "${HOP_RULES[@]:-}"; do
            [[ -z "$rule" ]] && continue
            parse_hop "$rule"; info "端口跳跃: ${HOP_S}-${HOP_E} → ${HOP_T}"
        done
        [[ ${#HOP_RULES[@]} -eq 0 ]] && warn "未检测到端口跳跃 → 按需添加: bash wg_port.sh --add-hop"
    fi

    echo ""
    read -rp "$(echo -e "${Y}确认应用以上配置？[y/N]: ${W}")" ans
    [[ "${ans,,}" == y ]] || { info "已取消"; exit 0; }

    apply_rules
    save_rules
    show_summary
}

main "$@"
