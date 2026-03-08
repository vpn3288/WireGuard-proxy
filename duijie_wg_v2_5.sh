#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════════╗
# ║  duijie.sh  v2.5  —  CN2GIA中转 ↔ 落地机  WireGuard对接            ║
# ║  在落地机执行，SSH连接中转机，完成双端WireGuard + iptables DNAT配置  ║
# ║                                                                      ║
# ║  bash duijie.sh              交互模式                                ║
# ║  bash duijie.sh --auto       全自动模式（须已运行过交互模式）         ║
# ║  bash duijie.sh --manage     节点管理模式                            ║
# ╠══════════════════════════════════════════════════════════════════════╣
# ║  流量链路（WireGuard版，单次解密，消除双重加密开销）                  ║
# ║                                                                      ║
# ║  客户端 ──[VLESS+Reality]──▶ 中转机:RELAY_PORT                      ║
# ║           ──[iptables PREROUTING DNAT]──▶                            ║
# ║           ──[WireGuard wg0 MTU=1380]──▶ 落地机:LUODI_PORT            ║
# ║  落地机 Xray 完成 Reality 握手，以干净IP出口访问互联网               ║
# ║                                                                      ║
# ║  设计要点                                                            ║
# ║  · 中转机不处理 VLESS 协议层，仅做 TCP/UDP 透明转发                  ║
# ║  · Reality 握手、UUID 验证全部由落地机 Xray 完成                     ║
# ║  · 节点链接使用落地机的 UUID 和 公钥（非中转机）                     ║
# ╠══════════════════════════════════════════════════════════════════════╣
# ║  LINK_ID = MD5(落地IP:落地端口)[:8]  节点唯一指纹（幂等键）         ║
# ║  WG网段   10.100.0.0/24  MTU=1380  TCPMSS=1280                      ║
# ║  中转机   wg0 = 10.100.0.1（固定）                                  ║
# ║  落地机   wg0 = 10.100.0.N（N从2起，duijie.sh自动分配）             ║
# ╠══════════════════════════════════════════════════════════════════════╣
# ║  函数命名规范：_模块::函数()                                          ║
# ║  _ssh  _info  _local  _wg  _fw  _port  _out  _check  _mgr           ║
# ╚══════════════════════════════════════════════════════════════════════╝
#
# ── v2.5 修复 & 新增清单 ────────────────────────────────────────────────
#
#  继承 v2.4 全部修复（Bug 1-10, Issue 9-11），新增：
#
#  [C1] _port::allocate()
#        旧版曾引用 netstat（net-tools），Debian 11/12 默认未安装会假阴性
#        → 全部改用 ss（iproute2，现代 Linux 标准），并补充注释说明原因
#
#  [C2] _info::_ensure_xray_listen() + _info::_auto_fix_xray_listen()
#        原版仅告警，用户不知道如何修改
#        → 脚本自动定位 Xray 配置文件（支持 mack-a/标准安装/conf.d多文件目录）
#          自动将 listen 改为 ""（全监听），自动重启 Xray，重启后二次验证
#          仅当自动定位失败时才交互提示
#
#  [C3] _wg::add_peer() / _wg::setup_local()
#        明确不调用 wg-quick save（若 wg0 由原生 ip link 启动则会报错）
#        → 持久化全部通过直接写 wg0.conf 实现，与启动方式无关
#
#  [S1] _fw::dnat_add()
#        UFW/Firewalld 可能在 PREROUTING/FORWARD 之上叠加默认 DROP 策略
#        → 在 iptables 规则写入后额外调用 ufw allow / firewall-cmd，
#          静默执行（|| true），不影响无宿主防火墙的主流程
#
#  [P1] _out::node_link() / _print_result() / _out::save()
#        新增 Xray JSON outbound 配置块输出，供不支持 VLESS 链接的客户端使用
#        订阅注释行标注 MTU=1380/TCPMSS=1280，方便排查掉速问题

set -euo pipefail

# ══════════════════════════════════════════════════════════════════
# §0  颜色 & 日志
# ══════════════════════════════════════════════════════════════════
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log_info()  { echo -e "${GREEN}[✓]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
log_error() { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }
log_step()  { echo -e "${CYAN}[→]${NC} $*"; }
log_sep()   { echo -e "${CYAN}$(printf '─%.0s' {1..64})${NC}"; }

[[ $EUID -ne 0 ]] && log_error "请使用 root 权限运行"
command -v python3 &>/dev/null || log_error "python3 未找到，请安装: apt-get install -y python3"

# ══════════════════════════════════════════════════════════════════
# §1  全局变量
# ══════════════════════════════════════════════════════════════════

# 本地文件路径
LOCAL_INFO="/root/xray_luodi_info.txt"
EXPORT_JSON="/tmp/luodi_export.json"
SUB_FILE="/root/xray_relay_subscription.txt"

# 落地机参数（由 luodi.sh 生成，此处读取）
LUODI_IP="" LUODI_PORT="" LUODI_UUID="" LUODI_PUBKEY=""
LUODI_SHORTID="" LUODI_SNI="" LUODI_NETWORK="tcp"
LUODI_XHTTP_PATH="/" LUODI_XHTTP_HOST="" LUODI_XHTTP_MODE="auto"
LUODI_WS_PATH="/"  LUODI_WS_HOST="" LUODI_GRPC_SERVICE=""
LUODI_WG_PUBKEY="" LUODI_WG_PRIVKEY=""

# 中转机参数（由 zhongzhuan.sh 生成，SSH读取）
RELAY_IP="" RELAY_SSH_PORT="22" RELAY_SSH_USER="root" RELAY_SSH_PASS=""
# [v2.4 Bug-8] SSH_OPTS 数组，防止含空格选项时 word-split
SSH_OPTS=()
AUTH_TYPE=""
RELAY_PUBKEY="" RELAY_SHORT_ID="" RELAY_SNI="" RELAY_DEST=""
RELAY_START_PORT="16888"
RELAY_NODES="/usr/local/etc/xray-relay/nodes.json"
RELAY_WG_PUBKEY="" RELAY_WG_PORT="51820"

# 对接结果
LINK_ID="" RELAY_ASSIGNED_PORT=""
LUODI_WG_ASSIGNED_IP=""
NODE_LABEL="" NODE_LINK="" NODE_JSON=""

# 历史暂存（幂等重对接时保留上次中转机连接信息）
_SAVED_RELAY_IP="" _SAVED_RELAY_SSH_PORT="" _SAVED_RELAY_SSH_USER=""

# 运行模式
AUTO_MODE="false"
[[ "${1:-}" == "--auto" ]] && AUTO_MODE="true"

# ══════════════════════════════════════════════════════════════════
# §2  工具函数
# ══════════════════════════════════════════════════════════════════

url_encode() {
    local s="$1" out="" i c
    for (( i=0; i<${#s}; i++ )); do
        c="${s:$i:1}"
        case "$c" in
            [a-zA-Z0-9.~_-]) out+="$c" ;;
            *) printf -v _h '%%%02X' "'$c"; out+="$_h" ;;
        esac
    done
    echo "$out"
}

# IPv6 地址加方括号（用于 URL/endpoint）；IPv4 直接返回
ip_for_url() {
    local ip="$1"
    [[ "$ip" == *:* ]] && echo "[${ip//[\[\]]/}]" || echo "$ip"
}

# IPv6 地址去方括号（用于 JSON address 字段）
ip_for_json() {
    local ip="$1"
    echo "${ip//[\[\]]/}"
}

_gen_link_id() {
    [[ -z "$LUODI_IP" || -z "$LUODI_PORT" ]] && log_error "生成LINK_ID失败：落地IP或端口为空"
    # md5sum 优先；fallback 到 python3（通过 sys.argv 传参，避免特殊字符注入）
    LINK_ID=$(echo -n "${LUODI_IP}:${LUODI_PORT}" \
        | md5sum 2>/dev/null | cut -c1-8 \
        || python3 -c "import hashlib,sys; print(hashlib.md5(sys.argv[1].encode()).hexdigest()[:8])" \
           "${LUODI_IP}:${LUODI_PORT}")
    [[ -z "$LINK_ID" ]] && log_error "LINK_ID 生成失败（md5sum 和 python3 均不可用）"
    log_info "LINK_ID: ${LINK_ID}  (${LUODI_IP}:${LUODI_PORT})"
}

# ══════════════════════════════════════════════════════════════════
# §3  MODULE: ssh
#     _ssh::setup()   — 交互式 SSH 认证（密码 / 免密密钥自动探测）
#     _ssh::run()     — 在中转机执行单行命令，返回 stdout
#     _ssh::pipe()    — 将 stdin 脚本管道到中转机 bash 执行
#     _ssh::pipe_py() — 将 stdin 脚本管道到中转机 python3 执行
# ══════════════════════════════════════════════════════════════════

_ssh::setup() {
    echo ""
    echo -e "${YELLOW}── 中转机 SSH 连接 ──${NC}"

    # 从本地 info 文件恢复上次连接信息作为默认值
    [[ -z "$RELAY_IP"           && -n "$_SAVED_RELAY_IP"        ]] && RELAY_IP="$_SAVED_RELAY_IP"
    [[ "$RELAY_SSH_PORT" == "22" && -n "$_SAVED_RELAY_SSH_PORT" ]] && RELAY_SSH_PORT="$_SAVED_RELAY_SSH_PORT"
    [[ "$RELAY_SSH_USER" == "root" && -n "$_SAVED_RELAY_SSH_USER" ]] && RELAY_SSH_USER="$_SAVED_RELAY_SSH_USER"

    if [[ "$AUTO_MODE" == "true" ]]; then
        [[ -z "$RELAY_IP" ]] && log_error "--auto 模式下未找到中转机IP，请先运行一次交互模式"
        log_info "自动模式：中转机 ${RELAY_IP}:${RELAY_SSH_PORT:-22}"
    else
        local i
        read -rp "中转机公网IP [${RELAY_IP:-待输入}]: "   i || true; [[ -n "$i" ]] && RELAY_IP="$i"
        [[ -z "$RELAY_IP" ]] && log_error "中转机IP不能为空"
        read -rp "SSH端口 [${RELAY_SSH_PORT:-22}]: "      i || true; RELAY_SSH_PORT="${i:-${RELAY_SSH_PORT:-22}}"
        read -rp "SSH用户 [${RELAY_SSH_USER:-root}]: "    i || true; RELAY_SSH_USER="${i:-${RELAY_SSH_USER:-root}}"
    fi

    # ConnectTimeout=10：防止中转机断网时 ssh 卡死数分钟
    SSH_OPTS=(-o StrictHostKeyChecking=no -o ConnectTimeout=10 -p "${RELAY_SSH_PORT}")

    # 优先尝试免密密钥登录
    log_step "尝试静默密钥登录 ${RELAY_SSH_USER}@${RELAY_IP}..."
    if ssh -q "${SSH_OPTS[@]}" -o BatchMode=yes "${RELAY_SSH_USER}@${RELAY_IP}" "exit" 2>/dev/null; then
        AUTH_TYPE="key"
        SSH_OPTS+=(-o BatchMode=yes)
        log_info "密钥登录验证通过 ✓"
        return 0
    fi

    [[ "$AUTO_MODE" == "true" ]] && \
        log_error "--auto 模式下SSH免密登录失败，请配置免密或设置 RELAY_SSH_PASS 环境变量"

    # 安装 sshpass 并使用密码认证
    if ! command -v sshpass &>/dev/null; then
        log_step "安装 sshpass..."
        apt-get install -y -qq sshpass 2>/dev/null \
            || yum install -y -q sshpass 2>/dev/null \
            || log_error "sshpass 安装失败，请手动安装后重试"
    fi

    read -rsp "SSH密码 (${RELAY_SSH_USER}@${RELAY_IP}): " RELAY_SSH_PASS; echo ""
    [[ -z "$RELAY_SSH_PASS" ]] && log_error "SSH密码不能为空"
    sshpass -p "$RELAY_SSH_PASS" ssh -q "${SSH_OPTS[@]}" "${RELAY_SSH_USER}@${RELAY_IP}" "exit" 2>/dev/null \
        || log_error "SSH密码验证失败，请检查密码或防火墙"
    AUTH_TYPE="password"
    log_info "SSH密码验证通过 ✓"
}

_ssh::run() {
    case "$AUTH_TYPE" in
        key)      ssh      -q "${SSH_OPTS[@]}"                          "${RELAY_SSH_USER}@${RELAY_IP}" "$1" ;;
        password) sshpass -p "$RELAY_SSH_PASS" ssh -q "${SSH_OPTS[@]}" "${RELAY_SSH_USER}@${RELAY_IP}" "$1" ;;
    esac
}

_ssh::pipe() {
    case "$AUTH_TYPE" in
        key)      ssh      -q "${SSH_OPTS[@]}"                          "${RELAY_SSH_USER}@${RELAY_IP}" "bash" ;;
        password) sshpass -p "$RELAY_SSH_PASS" ssh -q "${SSH_OPTS[@]}" "${RELAY_SSH_USER}@${RELAY_IP}" "bash" ;;
    esac
}

_ssh::pipe_py() {
    case "$AUTH_TYPE" in
        key)      ssh      -q "${SSH_OPTS[@]}"                          "${RELAY_SSH_USER}@${RELAY_IP}" "python3" ;;
        password) sshpass -p "$RELAY_SSH_PASS" ssh -q "${SSH_OPTS[@]}" "${RELAY_SSH_USER}@${RELAY_IP}" "python3" ;;
    esac
}

# ══════════════════════════════════════════════════════════════════
# §4  MODULE: info
#     _info::read_luodi()            — 读取落地机配置
#     _info::_ensure_xray_listen()   — 检测+自动修复 Xray 监听地址
#     _info::_auto_fix_xray_listen() — 定位配置文件并修改 listen 字段
#     _info::read_relay()            — SSH 读取中转机配置
# ══════════════════════════════════════════════════════════════════

_info::read_luodi() {
    log_step "读取落地机配置..."

    # ── 从 export.json 读取（最高优先级）────────────────────────
    if [[ -f "$EXPORT_JSON" ]]; then
        local ep
        ep=$(python3 - << 'PYEOF'
import json, sys
try:
    d = json.load(open("/tmp/luodi_export.json"))
    nodes = d.get("nodes", [])
    if not nodes:
        sys.exit(1)
    n = nodes[0]
    fields = ["ip","port","uuid","pubkey","sni","shortid","network",
              "xhttp_path","xhttp_host","xhttp_mode",
              "ws_path","ws_host","grpc_service",
              "wg_pubkey","wg_ip"]
    for k in fields:
        print(f"{k.upper()}={n.get(k,'')}")
except Exception:
    sys.exit(1)
PYEOF
) && {
            while IFS='=' read -r k v; do
                case "$k" in
                    IP)           LUODI_IP="$v" ;;
                    PORT)         LUODI_PORT="$v" ;;
                    UUID)         LUODI_UUID="$v" ;;
                    PUBKEY)       LUODI_PUBKEY="$v" ;;
                    SNI)          LUODI_SNI="$v" ;;
                    SHORTID)      LUODI_SHORTID="$v" ;;
                    NETWORK)      LUODI_NETWORK="${v:-tcp}" ;;
                    XHTTP_PATH)   LUODI_XHTTP_PATH="${v:-/}" ;;
                    XHTTP_HOST)   LUODI_XHTTP_HOST="$v" ;;
                    XHTTP_MODE)   LUODI_XHTTP_MODE="${v:-auto}" ;;
                    WS_PATH)      LUODI_WS_PATH="${v:-/}" ;;
                    WS_HOST)      LUODI_WS_HOST="$v" ;;
                    GRPC_SERVICE) LUODI_GRPC_SERVICE="$v" ;;
                    WG_PUBKEY)    LUODI_WG_PUBKEY="$v" ;;
                    WG_IP)        true ;; # IP 由 duijie.sh 分配，忽略旧值
                esac
            done <<< "$ep"
            log_info "已从 export.json 读取落地机配置"
        } || log_warn "export.json 解析失败，尝试读取 info.txt"
    fi

    # ── 从 info.txt 补全空字段（回退/补充）──────────────────────
    if [[ -f "$LOCAL_INFO" ]]; then
        _kv() { grep -m1 "^${1}=" "$LOCAL_INFO" 2>/dev/null | cut -d= -f2- | tr -d '\r'; }
        [[ -z "$LUODI_IP"       ]] && LUODI_IP="$(_kv LUODI_IP)"
        [[ -z "$LUODI_PORT"     ]] && LUODI_PORT="$(_kv LUODI_PORT)"
        [[ -z "$LUODI_UUID"     ]] && LUODI_UUID="$(_kv LUODI_UUID)"
        [[ -z "$LUODI_PUBKEY"   ]] && LUODI_PUBKEY="$(_kv LUODI_PUBKEY)"
        [[ -z "$LUODI_SNI"      ]] && LUODI_SNI="$(_kv LUODI_SNI)"
        [[ -z "$LUODI_SHORTID"  ]] && {
            LUODI_SHORTID="$(_kv LUODI_SHORTID)"
            [[ -z "$LUODI_SHORTID" ]] && LUODI_SHORTID="$(_kv LUODI_SHORT_ID)"
        }
        [[ "$LUODI_NETWORK" == "tcp" ]] && {
            local _n; _n="$(_kv LUODI_NETWORK)"
            [[ -n "$_n" ]] && LUODI_NETWORK="$_n"
        }
        [[ -z "$LUODI_WG_PUBKEY" ]] && LUODI_WG_PUBKEY="$(_kv LUODI_WG_PUBKEY)"
        LUODI_WG_PRIVKEY="$(_kv LUODI_WG_PRIVKEY)"
        _SAVED_RELAY_IP="$(_kv RELAY_IP)"
        _SAVED_RELAY_SSH_PORT="$(_kv RELAY_SSH_PORT)"
        _SAVED_RELAY_SSH_USER="$(_kv RELAY_SSH_USER)"
    fi

    # ── 交互补全空字段 ────────────────────────────────────────────
    local i
    _ask() {
        local label="$1" var="$2"
        if [[ "$AUTO_MODE" == "true" ]]; then
            [[ -z "${!var}" ]] && log_error "--auto 模式下 ${label} 为空，请先运行 luodi.sh"
            return
        fi
        read -rp "${label} [${!var:-待输入}]: " i || true
        [[ -n "$i" ]] && printf -v "$var" '%s' "$i"
        [[ -z "${!var}" ]] && log_error "${label} 不能为空"
    }

    _ask "落地机公网IP"          LUODI_IP
    _ask "落地机Xray端口"        LUODI_PORT
    _ask "落地机UUID"            LUODI_UUID
    _ask "落地机Reality公钥"     LUODI_PUBKEY
    _ask "落地机ShortID"         LUODI_SHORTID
    _ask "落地机SNI"             LUODI_SNI
    _ask "落地机WireGuard公钥"   LUODI_WG_PUBKEY

    [[ -z "$LUODI_WG_PRIVKEY" && "$AUTO_MODE" != "true" ]] && {
        read -rp "落地机WireGuard私钥（用于配置本机 wg0）: " i || true
        [[ -n "$i" ]] && LUODI_WG_PRIVKEY="$i"
    }
    [[ -z "$LUODI_WG_PRIVKEY" ]] && log_error "落地机WireGuard私钥为空，请重新运行 luodi.sh"

    _gen_link_id
    _local::clean_block_by_link_id "$LINK_ID"

    # [C2] 自动检测并修复 Xray 监听地址（取代原来只告警的版本）
    _info::_ensure_xray_listen
}

# ══════════════════════════════════════════════════════════════════
# _info::_ensure_xray_listen
#   [C2] 检测落地机 Xray 是否监听在可被 DNAT 到达的地址上。
#   · 若监听 0.0.0.0 / :: / * → 直接通过
#   · 若监听 127.0.0.1 或其他特定 IP → 自动定位配置文件并修改
#   · 自动修复后重启 Xray，再次验证；失败则交互询问
# ══════════════════════════════════════════════════════════════════

_info::_ensure_xray_listen() {
    log_step "检测落地机 Xray 监听地址..."
    local listen_addr listen_ip

    # 同时检测 TCP 和 UDP，兼容 IPv4/IPv6
    listen_addr=$(ss -tlnp 2>/dev/null \
        | awk -v p=":${LUODI_PORT}" '$4 ~ p"$" {print $4; exit}' || true)
    if [[ -z "$listen_addr" ]]; then
        listen_addr=$(ss -ulnp 2>/dev/null \
            | awk -v p=":${LUODI_PORT}" '$4 ~ p"$" {print $4; exit}' || true)
    fi

    if [[ -z "$listen_addr" ]]; then
        log_warn "ss 未检测到 Xray 在端口 ${LUODI_PORT} 监听（Xray 可能未运行，继续对接）"
        return 0
    fi

    # 解析监听 IP，兼容 IPv4（0.0.0.0:443）和 IPv6（[::]:443 / :::443）
    local raw_host
    raw_host=$(echo "$listen_addr" | sed 's/:[0-9]*$//' | tr -d '[]')
    if [[ -z "$raw_host" || "$raw_host" == "::" || "$raw_host" == "*" || "$raw_host" == "0.0.0.0" ]]; then
        listen_ip="0.0.0.0"
    else
        listen_ip="$raw_host"
    fi

    if [[ "$listen_ip" == "0.0.0.0" ]]; then
        log_info "落地机 Xray 监听 ${listen_addr} ✓（全监听，DNAT 可到达）"
        return 0
    fi

    # 监听在非全局地址，需要修复
    echo ""
    echo -e "  ${YELLOW}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "  ${YELLOW}║  ⚠  Xray 监听 ${listen_addr}，DNAT 到 WG 虚拟IP后将无法到达  ║${NC}"
    echo -e "  ${YELLOW}║  正在自动修复：将 listen 改为空（等效 0.0.0.0 全监听）...  ║${NC}"
    echo -e "  ${YELLOW}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    _info::_auto_fix_xray_listen

    # 修复并重启后二次验证
    sleep 2
    local new_addr new_host
    new_addr=$(ss -tlnp 2>/dev/null \
        | awk -v p=":${LUODI_PORT}" '$4 ~ p"$" {print $4; exit}' || true)
    new_host=$(echo "$new_addr" | sed 's/:[0-9]*$//' | tr -d '[]')
    if [[ -z "$new_host" || "$new_host" == "::" || "$new_host" == "*" || "$new_host" == "0.0.0.0" ]]; then
        log_info "✓ Xray 现已全局监听 ${new_addr:-0.0.0.0:${LUODI_PORT}}"
    else
        log_warn "Xray 仍监听在 ${new_addr}，若隧道建立后无法连接请手动检查"
    fi
}

# ══════════════════════════════════════════════════════════════════
# _info::_auto_fix_xray_listen
#   [C2] 自动定位 Xray JSON 配置文件并修改 listen 字段。
#   支持：标准单文件 / mack-a / conf.d 多文件目录
#   不支持自动修复：x-ui 面板（SQLite，交互提示手动操作）
# ══════════════════════════════════════════════════════════════════

_info::_auto_fix_xray_listen() {
    local target_port="$LUODI_PORT"
    local config_file=""
    local config_dir=""

    # ── Step1: 尝试从运行中进程命令行提取配置路径 ─────────────────
    local proc_config proc_confdir
    proc_config=$(cat /proc/*/cmdline 2>/dev/null \
        | tr '\0' ' ' \
        | grep -oE '\-config[= ][^ ]+\.json' \
        | grep -oE '[^ ]+\.json' \
        | head -1 || true)
    proc_confdir=$(cat /proc/*/cmdline 2>/dev/null \
        | tr '\0' ' ' \
        | grep -oE '\-confdir[= ][^ ]+' \
        | grep -oE '[^ /]+(/[^ ]+)*' \
        | grep -v confdir \
        | head -1 || true)

    if [[ -n "$proc_config" && -f "$proc_config" ]]; then
        config_file="$proc_config"
        log_step "从进程命令行定位配置: ${config_file}"
    elif [[ -n "$proc_confdir" && -d "$proc_confdir" ]]; then
        config_dir="$proc_confdir"
        log_step "从进程命令行定位 confdir: ${config_dir}"
    fi

    # ── Step2: 常见静态路径探测 ──────────────────────────────────
    if [[ -z "$config_file" && -z "$config_dir" ]]; then
        local try_paths=(
            "/usr/local/etc/xray/config.json"
            "/usr/local/etc/xray-reality/config.json"
            "/etc/xray/config.json"
            "/usr/local/etc/xray-mack/config.json"
        )
        for p in "${try_paths[@]}"; do
            if [[ -f "$p" ]]; then
                config_file="$p"
                log_step "在常用路径找到配置: ${config_file}"
                break
            fi
        done

        # confdir 探测
        if [[ -z "$config_file" ]]; then
            local try_dirs=(
                "/usr/local/etc/xray"
                "/usr/local/etc/xray-reality"
                "/etc/xray"
            )
            for d in "${try_dirs[@]}"; do
                if [[ -d "$d" ]] && ls "$d"/*.json &>/dev/null 2>&1; then
                    config_dir="$d"
                    log_step "找到 confdir: ${config_dir}"
                    break
                fi
            done
        fi
    fi

    # ── Step3: find 兜底 ──────────────────────────────────────────
    if [[ -z "$config_file" && -z "$config_dir" ]]; then
        config_file=$(find /usr/local/etc /etc -maxdepth 4 \
            -name "config.json" -path "*/xray*" 2>/dev/null | head -1 || true)
        [[ -n "$config_file" ]] && log_step "find 兜底找到配置: ${config_file}"
    fi

    # ── Step4: 完全未找到，交互提示 ──────────────────────────────
    if [[ -z "$config_file" && -z "$config_dir" ]]; then
        echo ""
        echo -e "  ${RED}╔════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "  ${RED}║  ✗ 未能自动找到 Xray 配置文件                                  ║${NC}"
        echo -e "  ${RED}║                                                                  ║${NC}"
        echo -e "  ${RED}║  若使用 x-ui 面板：登录面板 → 入站列表 → 编辑对应入站            ║${NC}"
        echo -e "  ${RED}║  将「监听IP」字段清空（即 0.0.0.0），保存后点击「重启Xray」      ║${NC}"
        echo -e "  ${RED}║                                                                  ║${NC}"
        echo -e "  ${RED}║  若使用手动 config.json：将 inbound 的 \"listen\" 改为 \"\"         ║${NC}"
        echo -e "  ${RED}║  然后执行: systemctl restart xray                               ║${NC}"
        echo -e "  ${RED}╚════════════════════════════════════════════════════════════════╝${NC}"
        if [[ "$AUTO_MODE" != "true" ]]; then
            local c
            read -rp "已手动修改并重启 Xray？继续执行？[y/N]: " c || true
            [[ "${c,,}" != "y" ]] && log_error "请修改 Xray 监听地址后重新运行脚本"
        else
            log_warn "--auto 模式：无法自动修复，跳过（可能导致连接失败）"
        fi
        return 0
    fi

    # ── Step5: 构建待修改的文件列表 ──────────────────────────────
    local files_to_check=()
    if [[ -n "$config_file" ]]; then
        files_to_check+=("$config_file")
    else
        while IFS= read -r f; do
            files_to_check+=("$f")
        done < <(find "$config_dir" -maxdepth 1 -name "*.json" 2>/dev/null | sort)
    fi

    # ── Step6: Python 解析并修改所有相关文件 ─────────────────────
    local any_fixed=false
    for f in "${files_to_check[@]}"; do
        [[ ! -f "$f" ]] && continue
        local result
        result=$(python3 - << PYEOF
import json, sys

config_file  = "${f}"
target_port  = int("${target_port}")

try:
    with open(config_file, 'r', encoding='utf-8') as fh:
        config = json.load(fh)
except Exception as e:
    print(f"ERROR:{e}")
    sys.exit(0)

inbounds = config.get('inbounds', [])
fixed = False
for ib in inbounds:
    try:
        port_val = int(ib.get('port', 0))
    except (ValueError, TypeError):
        continue
    if port_val == target_port:
        listen = ib.get('listen', '')
        if listen not in ('', '0.0.0.0', '::'):
            ib['listen'] = ''  # 改为全监听（等效 0.0.0.0）
            fixed = True
        else:
            print(f"ALREADY_OK:{listen}")

if fixed:
    try:
        with open(config_file, 'w', encoding='utf-8') as fh:
            json.dump(config, fh, indent=2, ensure_ascii=False)
        print(f"FIXED:{config_file}")
    except Exception as e:
        print(f"WRITE_ERROR:{e}")
PYEOF
)
        if echo "$result" | grep -q "^FIXED:"; then
            log_info "已修改配置文件 listen → \"\"（全监听）: ${f}"
            any_fixed=true
        elif echo "$result" | grep -q "^ALREADY_OK:"; then
            log_info "配置文件 listen 字段无需修改: ${f}"
        elif echo "$result" | grep -q "^ERROR:\|^WRITE_ERROR:"; then
            log_warn "配置文件处理失败 (${f}): $(echo "$result" | cut -d: -f2-)"
        fi
    done

    # ── Step7: 重启 Xray ────────────────────────────────────────
    if [[ "$any_fixed" == "true" ]]; then
        log_step "重启 Xray 以使配置生效..."
        local restarted=false
        # 按常见服务名逐一尝试重启
        for svc in xray xray-reality xray@reality xray-mack; do
            if systemctl is-active --quiet "$svc" 2>/dev/null; then
                if systemctl restart "$svc" 2>/dev/null; then
                    log_info "Xray 已重启（服务: ${svc}）✓"
                    restarted=true
                    break
                fi
            fi
        done
        if [[ "$restarted" == "false" ]]; then
            # 最后尝试找第一个运行中的 xray 进程并发 SIGHUP
            local xray_pid
            xray_pid=$(pgrep -x xray 2>/dev/null | head -1 || true)
            if [[ -n "$xray_pid" ]]; then
                kill -HUP "$xray_pid" 2>/dev/null && \
                    log_info "已向 Xray 进程 (PID:${xray_pid}) 发送 SIGHUP 重载" && restarted=true
            fi
        fi
        if [[ "$restarted" == "false" ]]; then
            log_warn "Xray 自动重启失败，请手动执行: systemctl restart xray"
            if [[ "$AUTO_MODE" != "true" ]]; then
                read -rp "请手动重启 Xray 后按 [Enter] 继续: " || true
            fi
        fi
    fi
}

_info::read_relay() {
    log_step "读取中转机配置..."
    local info
    info=$(_ssh::run "cat /root/xray_zhongzhuan_info.txt 2>/dev/null || echo ERROR") \
        || log_error "SSH读取中转机配置失败"
    [[ "$info" == "ERROR" ]] && log_error "中转机未找到 xray_zhongzhuan_info.txt，请先运行 zhongzhuan.sh"

    _rkv() { echo "$info" | grep -m1 "^${1}=" | cut -d= -f2- | tr -d '\r'; }

    RELAY_PUBKEY="$(_rkv ZHONGZHUAN_PUBKEY)"
    RELAY_SHORT_ID="$(_rkv ZHONGZHUAN_SHORT_ID)"
    RELAY_SNI="$(_rkv ZHONGZHUAN_SNI)"
    RELAY_DEST="$(_rkv ZHONGZHUAN_DEST)"
    RELAY_START_PORT="$(_rkv ZHONGZHUAN_START_PORT)"
    RELAY_NODES="$(_rkv ZHONGZHUAN_NODES)"
    RELAY_NODES="${RELAY_NODES:-/usr/local/etc/xray-relay/nodes.json}"
    RELAY_WG_PUBKEY="$(_rkv ZHONGZHUAN_WG_PUBKEY)"
    RELAY_WG_PORT="$(_rkv ZHONGZHUAN_WG_PORT)"
    RELAY_WG_PORT="${RELAY_WG_PORT:-51820}"

    [[ -z "$RELAY_PUBKEY"    ]] && log_error "中转机Reality公钥为空，请重新运行 zhongzhuan.sh"
    [[ -z "$RELAY_WG_PUBKEY" ]] && log_error "中转机WireGuard公钥为空，请重新运行 zhongzhuan.sh"

    # 确认中转机内核 IP 转发已开启（iptables DNAT 的前提条件）
    _ssh::run "sed -i '/net\.ipv4\.ip_forward/d' /etc/sysctl.conf && \
        echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf && \
        sysctl -q -p /etc/sysctl.conf" 2>/dev/null || \
        _ssh::run "sysctl -q -w net.ipv4.ip_forward=1" 2>/dev/null || true

    log_info "中转机配置读取完成（SNI: ${RELAY_SNI}, WG端口: ${RELAY_WG_PORT}）"
}

# ══════════════════════════════════════════════════════════════════
# §4.5  MODULE: local
#       _local::clean_block_by_link_id()
#       从本地 LOCAL_INFO / SUB_FILE 中清理指定 LINK_ID 的段落和链接行。
#       复用于：_info::read_luodi（幂等重对接清理）和 _mgr::clean（删除节点）
# ══════════════════════════════════════════════════════════════════

_local::clean_block_by_link_id() {
    local link_id="$1"
    [[ -z "$link_id" ]] && return 0

    if [[ -f "$LOCAL_INFO" ]] && grep -q "LINK_ID=${link_id}" "$LOCAL_INFO" 2>/dev/null; then
        log_info "清理本地旧记录 (LINK_ID: ${link_id})"
        python3 - << PYEOF
link_id = "${link_id}"
fp      = "${LOCAL_INFO}"
lines   = open(fp, encoding="utf-8", errors="replace").readlines()
result, i = [], 0
while i < len(lines):
    if lines[i].startswith("── 对接节点") and "────" in lines[i]:
        block, j = [lines[i]], i+1
        while j < len(lines) and not (lines[j].startswith("── 对接节点") and "────" in lines[j]):
            block.append(lines[j]); j += 1
        if f"LINK_ID={link_id}" not in "".join(block):
            result.extend(block)
        i = j
    else:
        result.append(lines[i]); i += 1
content = "".join(result).rstrip("\n")
open(fp, "w", encoding="utf-8").write(content + "\n" if content else "")
PYEOF
    fi

    if [[ -f "$SUB_FILE" ]]; then
        local tmp_sub
        tmp_sub=$(mktemp 2>/dev/null) || { log_warn "mktemp 失败，跳过订阅文件清理"; return 0; }
        trap 'rm -f "$tmp_sub"' RETURN
        grep -v "LINK_ID=${link_id}" "$SUB_FILE" > "$tmp_sub" 2>/dev/null || true
        mv "$tmp_sub" "$SUB_FILE"
        trap - RETURN
    fi
}

# ══════════════════════════════════════════════════════════════════
# §5  MODULE: wg
#     _wg::allocate_ip()  — 在中转机分配 10.100.0.N，检查冲突
#     _wg::add_peer()     — 中转机热添加落地机 WG Peer + 直接写 wg0.conf
#                           [C3] 不调用 wg-quick save，与启动方式无关
#     _wg::remove_peer()  — 按 LINK_ID 从中转机移除 WG Peer
#     _wg::setup_local()  — 落地机配置 wg0（本地执行）
# ══════════════════════════════════════════════════════════════════

_wg::allocate_ip() {
    log_step "分配WireGuard虚拟IP..."
    local nodes_path="$RELAY_NODES"
    local link_id="$LINK_ID"

    local script
    script=$(python3 - << PYEOF
import json
nodes_path = $(python3 -c "import json; print(json.dumps('${nodes_path}'))")
link_id    = $(python3 -c "import json; print(json.dumps('${link_id}'))")

remote = f"""
import json, subprocess, re, sys

nodes_path = {json.dumps(nodes_path)}
link_id    = {json.dumps(link_id)}
used = {{1}}  # 中转机自身占用 .1

# 从 nodes.json 收集已用 IP
try:
    nd = json.load(open(nodes_path))
    for nid, n in nd.get("nodes", {{}}).items():
        if nid == link_id:
            continue
        ip = n.get("wg_ip", "")
        m = re.search("10\\\\.100\\\\.0\\\\.(\\\\d+)", ip)
        if m:
            used.add(int(m.group(1)))
except Exception:
    pass

# [v2.4 Bug-9 Fix] 正则转义修正：从 wg show 双保险收集已用 IP
try:
    out = subprocess.check_output(["wg", "show", "wg0", "allowed-ips"],
                                   text=True, timeout=5)
    for line in out.splitlines():
        m = re.search("10\\\\.100\\\\.0\\\\.(\\\\d+)/32", line)
        if m:
            used.add(int(m.group(1)))
except Exception:
    pass

for n in range(2, 254):
    if n not in used:
        print(f"10.100.0.{{n}}")
        sys.exit(0)

print("ERROR: WireGuard地址空间耗尽 (10.100.0.2-253 已全部占用)", file=sys.stderr)
sys.exit(1)
"""
print(remote)
PYEOF
)
    LUODI_WG_ASSIGNED_IP=$(echo "$script" | _ssh::pipe_py | tr -d '[:space:]') \
        || log_error "WireGuard IP分配失败"
    [[ "$LUODI_WG_ASSIGNED_IP" =~ ^10\.100\.0\.[0-9]+$ ]] \
        || log_error "分配到无效WG IP: ${LUODI_WG_ASSIGNED_IP}"
    log_info "落地机WireGuard虚拟IP: ${LUODI_WG_ASSIGNED_IP}"
}

_wg::add_peer() {
    log_step "配置中转机WireGuard Peer（落地机: ${LUODI_WG_ASSIGNED_IP}）..."
    local wg_pubkey="$LUODI_WG_PUBKEY"
    local link_id="$LINK_ID"
    local wg_ip="$LUODI_WG_ASSIGNED_IP"

    # SHEOF 不加引号 → bash 在本地展开变量；内层 PYEOF2/PYEOF 同理
    # [C3] 持久化通过直接写 wg0.conf 实现，不调用 wg-quick save，
    #      与中转机 wg0 的启动方式（wg-quick / ip link）无关
    _ssh::pipe << SHEOF
set -e
LUODI_PUBKEY="${wg_pubkey}"
LUODI_WG_IP="${wg_ip}"
LINK_ID="${link_id}"

# 移除运行中 wg0 上的旧 Peer（按 AllowedIP 匹配）
OLD_PK=\$(wg show wg0 dump 2>/dev/null \
    | awk -v ip="\${LUODI_WG_IP}/32" '\$4==ip{print \$1}' || true)
[ -n "\$OLD_PK" ] && wg set wg0 peer "\$OLD_PK" remove 2>/dev/null \
    && echo "[✓] 已移除旧WG Peer（旧IP匹配）" || true

# 移除同公钥的旧 Peer
wg show wg0 peers 2>/dev/null | grep -q "^\${LUODI_PUBKEY}\$" \
    && wg set wg0 peer "\${LUODI_PUBKEY}" remove 2>/dev/null || true

# 热添加新 Peer
wg set wg0 peer "\${LUODI_PUBKEY}" allowed-ips "\${LUODI_WG_IP}/32"
ip link set wg0 mtu 1380 2>/dev/null || true
echo "[✓] WG Peer已热添加: \${LUODI_WG_IP}"

# 同步写入 wg0.conf [Interface] MTU=1380（重启持久化）
python3 - << PYEOF2
conf = "/etc/wireguard/wg0.conf"
try:
    lines = open(conf).readlines()
except FileNotFoundError:
    exit(0)

in_iface = mtu_found = False
for line in lines:
    stripped = line.strip()
    if stripped == "[Interface]":   in_iface = True
    elif stripped.startswith("["): in_iface = False
    if in_iface and stripped.upper().startswith("MTU"):
        mtu_found = True; break

if mtu_found:
    import re
    content = "".join(lines)
    content = re.sub(r'(?m)^MTU\s*=\s*\d+', 'MTU = 1380', content)
    open(conf, "w").write(content)
    print("[✓] wg0.conf MTU 已更新为 1380")
else:
    result = []; in_iface = inserted = False
    for line in lines:
        stripped = line.strip()
        if stripped == "[Interface]": in_iface = True
        if in_iface and not inserted and (stripped == "" or (stripped.startswith("[") and stripped != "[Interface]")):
            result.append("MTU = 1380\n"); inserted = True; in_iface = False
        result.append(line)
    if not inserted: result.append("MTU = 1380\n")
    open(conf, "w").writelines(result)
    print("[✓] wg0.conf [Interface] 已补写 MTU = 1380")
PYEOF2

# 清理 wg0.conf 中同 LINK_ID 或同 IP 的旧 Peer 块，追加新块
python3 - << PYEOF
conf      = "/etc/wireguard/wg0.conf"
link_id   = "${link_id}"
wg_ip     = "${wg_ip}"
wg_pubkey = "${wg_pubkey}"

try:
    lines = open(conf).readlines()
except FileNotFoundError:
    lines = []

result = []; i = 0
while i < len(lines):
    if lines[i].strip() == "[Peer]":
        block = [lines[i]]; j = i + 1
        while j < len(lines) and lines[j].strip() not in ("", "[Peer]", "[Interface]"):
            block.append(lines[j]); j += 1
        block_txt = "".join(block)
        if f"luodi-peer-{link_id}" in block_txt or wg_ip + "/32" in block_txt:
            i = j; continue
        result.extend(block)
        if j < len(lines) and lines[j].strip() == "":
            result.append("\n"); j += 1
        i = j
    else:
        result.append(lines[i]); i += 1

content = "".join(result).rstrip("\n")
content += f"\n\n[Peer]\n# luodi-peer-{link_id}\nPublicKey = {wg_pubkey}\nAllowedIPs = {wg_ip}/32\n"
open(conf, "w").write(content)
print(f"[✓] wg0.conf 已写入新Peer: {wg_ip}")
PYEOF
SHEOF
    log_info "中转机WireGuard Peer配置完成"
}

_wg::remove_peer() {
    local del_lid="$1" del_wg_ip="$2"
    log_step "移除中转机WG Peer（LINK_ID: ${del_lid}, WG IP: ${del_wg_ip}）..."

    _ssh::pipe << SHEOF
set -e
DEL_LID="${del_lid}"
DEL_WG_IP="${del_wg_ip}"

OLD_PK=\$(wg show wg0 dump 2>/dev/null \
    | awk -v ip="\${DEL_WG_IP}/32" '\$4==ip{print \$1}' || true)
if [ -n "\$OLD_PK" ]; then
    wg set wg0 peer "\$OLD_PK" remove 2>/dev/null && echo "[✓] 已移除WG Peer"
else
    echo "[!] 运行中 wg0 未找到对应Peer（可能已移除）"
fi

python3 - << PYEOF
conf    = "/etc/wireguard/wg0.conf"
lid     = "${del_lid}"
wg_ip   = "${del_wg_ip}"
try:    lines = open(conf).readlines()
except: print("[!] wg0.conf 不存在，跳过"); exit(0)

result = []; removed = False; i = 0
while i < len(lines):
    if lines[i].strip() == "[Peer]":
        block = [lines[i]]; j = i + 1
        while j < len(lines) and lines[j].strip() not in ("", "[Peer]", "[Interface]"):
            block.append(lines[j]); j += 1
        block_txt = "".join(block)
        if f"luodi-peer-{lid}" in block_txt or wg_ip + "/32" in block_txt:
            removed = True; i = j; continue
        result.extend(block)
        if j < len(lines) and lines[j].strip() == "":
            result.append("\n"); j += 1
        i = j
    else:
        result.append(lines[i]); i += 1
open(conf, "w").writelines(result)
print(f"[✓] wg0.conf Peer块已{'移除' if removed else '确认不存在'}")
PYEOF
SHEOF
    log_info "中转机WG Peer已处理"
}

_wg::setup_local() {
    log_step "配置落地机WireGuard（本机 wg0 = ${LUODI_WG_ASSIGNED_IP}）..."

    if ! command -v wg &>/dev/null; then
        log_step "安装 WireGuard..."
        apt-get install -y -qq wireguard wireguard-tools 2>/dev/null \
            || yum install -y -q wireguard-tools 2>/dev/null \
            || log_error "WireGuard安装失败，请手动安装"
    fi
    modprobe wireguard 2>/dev/null || true

    # [v2.4 Issue-9] 检测落地机 wg0 ListenPort 51820 是否已被其他进程占用
    if ss -ulnp 2>/dev/null | awk '$4 ~ /:51820$/ {found=1} END{exit !found}'; then
        local lp_owner
        lp_owner=$(ss -ulnp 2>/dev/null | awk '$4 ~ /:51820$/ {print $6}' | head -1 || echo "未知进程")
        log_warn "落地机 UDP:51820 已被占用（${lp_owner}），wg0 将共享该端口"
        log_warn "若出现路由混乱，请在 /etc/wireguard/wg0.conf 中修改 ListenPort"
    fi

    local wg_conf="/etc/wireguard/wg0.conf"
    local assigned_ip="$LUODI_WG_ASSIGNED_IP"
    local relay_wg_pubkey="$RELAY_WG_PUBKEY"
    local relay_ip="$RELAY_IP"
    local relay_wg_port="$RELAY_WG_PORT"
    local luodi_wg_privkey="$LUODI_WG_PRIVKEY"
    local link_id="$LINK_ID"

    python3 - << PYEOF
import subprocess, os, re

conf     = "${wg_conf}"
wg_ip    = "${assigned_ip}"
relay_pk = "${relay_wg_pubkey}"
relay_ep = "${relay_ip}:${relay_wg_port}"
privkey  = "${luodi_wg_privkey}"
link_id  = "${link_id}"

def read_conf():
    try: return open(conf).read()
    except: return ""

content = read_conf()

if "[Interface]" not in content:
    content = f"""[Interface]
Address = {wg_ip}/24
PrivateKey = {privkey}
ListenPort = 51820
MTU = 1380

"""
else:
    content = re.sub(r'(Address\s*=\s*)[\d./]+', rf'\g<1>{wg_ip}/24', content)
    if "MTU" not in content:
        content = re.sub(
            r'(\[Interface\][^\[]*?)(ListenPort\s*=\s*\d+)',
            r'\g<1>\g<2>\nMTU = 1380',
            content, flags=re.DOTALL)

# 清理同 LINK_ID 或同中转机公钥的旧 Peer 块
lines = content.splitlines(keepends=True)
result, i = [], 0
while i < len(lines):
    if lines[i].strip() == "[Peer]":
        block = [lines[i]]; j = i + 1
        while j < len(lines) and lines[j].strip() not in ("", "[Peer]", "[Interface]"):
            block.append(lines[j]); j += 1
        block_txt = "".join(block)
        if f"zhongzhuan-peer-{link_id}" in block_txt or relay_pk in block_txt:
            i = j; continue
        result.extend(block)
        if j < len(lines) and lines[j].strip() == "":
            result.append("\n"); j += 1
        i = j
    else:
        result.append(lines[i]); i += 1

content = "".join(result).rstrip("\n")
content += f"""

[Peer]
# zhongzhuan-peer-{link_id}
PublicKey = {relay_pk}
Endpoint = {relay_ep}
AllowedIPs = 10.100.0.1/32
PersistentKeepalive = 25
"""

os.makedirs("/etc/wireguard", exist_ok=True)
open(conf, "w").write(content)
os.chmod(conf, 0o600)
print(f"[✓] 落地机 wg0.conf 已更新（{wg_ip}）")
PYEOF

    if ip link show wg0 &>/dev/null; then
        local current_ip
        current_ip=$(ip addr show wg0 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d/ -f1 || true)
        if [[ "$current_ip" != "$assigned_ip" ]]; then
            [[ -n "$current_ip" ]] && ip addr del "${current_ip}/24" dev wg0 2>/dev/null || true
            ip addr add "${assigned_ip}/24" dev wg0
        fi
        wg show wg0 peers 2>/dev/null | grep -q "^${relay_wg_pubkey}$" \
            && wg set wg0 peer "$relay_wg_pubkey" remove 2>/dev/null || true

        # [v2.4 Bug-6] WG 私钥用 tmpfile 替代 <(echo ...)，避免 /proc/fd 暴露
        local _wg_key_tmp
        _wg_key_tmp=$(mktemp 2>/dev/null) || _wg_key_tmp="/tmp/.wg_key_$$"
        chmod 600 "$_wg_key_tmp"
        echo "$luodi_wg_privkey" > "$_wg_key_tmp"
        wg set wg0 private-key "$_wg_key_tmp" 2>/dev/null || true
        rm -f "$_wg_key_tmp"

        wg set wg0 peer "$relay_wg_pubkey" \
            endpoint "${relay_ip}:${relay_wg_port}" \
            allowed-ips "10.100.0.1/32" \
            persistent-keepalive 25
        ip link set wg0 mtu 1380 2>/dev/null || true
        ip link set wg0 up
        log_info "落地机 wg0 已热更新"
    else
        wg-quick up wg0 2>/dev/null || {
            ip link add wg0 type wireguard
            wg setconf wg0 "$wg_conf"
            ip addr add "${assigned_ip}/24" dev wg0
            ip link set wg0 mtu 1380 2>/dev/null || true
            ip link set wg0 up
        }
        log_info "落地机 wg0 已启动"
    fi

    systemctl enable wg-quick@wg0 2>/dev/null || true
    log_info "落地机WireGuard配置完成（${assigned_ip} ←→ 中转机 10.100.0.1）"
}

# ══════════════════════════════════════════════════════════════════
# §6  MODULE: fw
#     _fw::dnat_add()    — 中转机配置 iptables DNAT + MASQUERADE
#                          + TCPMSS 双重钳制 + FORWARD + IPv6泄漏防护
#                          + [S1] UFW/Firewalld 兼容放行
#                          + 持久化（netfilter-persistent / iptables-save）
#     _fw::dnat_remove() — 按 LINK_ID 精准删除全部规则
# ══════════════════════════════════════════════════════════════════

_fw::dnat_add() {
    log_step "配置中转机 iptables DNAT（:${RELAY_ASSIGNED_PORT} → ${LUODI_WG_ASSIGNED_IP}:${LUODI_PORT}）..."
    local link_id="$LINK_ID"
    local relay_port="$RELAY_ASSIGNED_PORT"
    local wg_ip="$LUODI_WG_ASSIGNED_IP"
    local luodi_port="$LUODI_PORT"

    _ssh::pipe << SHEOF
set -e
LINK_ID="${link_id}"
RELAY_PORT="${relay_port}"
WG_IP="${wg_ip}"
LUODI_PORT="${luodi_port}"
COMMENT="luodi-dnat-\${LINK_ID}"

# 开启内核 IP 转发
sed -i '/net\.ipv4\.ip_forward/d' /etc/sysctl.conf
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -q -p /etc/sysctl.conf 2>/dev/null || sysctl -q -w net.ipv4.ip_forward=1

# ── 精准删除同 LINK_ID 的旧规则（幂等，不影响第三方规则）───────
# bash -c 重新解析引号，解决 --comment 含空格的 word-split 问题
_del_rules_by_comment() {
    local table="\$1" chain="\$2"
    iptables -t "\${table}" -S "\${chain}" 2>/dev/null \
        | grep -- "\""\${COMMENT}"\"" \
        | sed 's/^-A /-D /' \
        | while IFS= read -r spec; do
            bash -c "iptables -t \${table} \${spec}" 2>/dev/null || true
          done
}
_del_rules_by_comment nat    PREROUTING
_del_rules_by_comment nat    POSTROUTING
_del_rules_by_comment filter FORWARD
_del_rules_by_comment mangle FORWARD

# ── PREROUTING DNAT TCP ─────────────────────────────────────────
iptables -t nat -A PREROUTING \
    -p tcp --dport "\${RELAY_PORT}" \
    -m comment --comment "\${COMMENT}" \
    -j DNAT --to-destination "\${WG_IP}:\${LUODI_PORT}"

# ── PREROUTING DNAT UDP ─────────────────────────────────────────
iptables -t nat -A PREROUTING \
    -p udp --dport "\${RELAY_PORT}" \
    -m comment --comment "\${COMMENT}" \
    -j DNAT --to-destination "\${WG_IP}:\${LUODI_PORT}"

# ── POSTROUTING MASQUERADE ──────────────────────────────────────
# -d WG_IP/32 精确范围，避免意外影响其他 wg0 流量
iptables -t nat -A POSTROUTING \
    -d "\${WG_IP}/32" -o wg0 \
    -m comment --comment "\${COMMENT}" \
    -j MASQUERADE

# ── FORWARD TCPMSS 双重钳制（防大包丢失）────────────────────────
# 规则1：clamp-to-pmtu（动态跟随路径MTU，依赖 ICMP type3/code4）
# 规则2：set-mss 1280（硬编码保守值，覆盖 CN2 GIA 屏蔽 ICMP 场景）
iptables -t mangle -A FORWARD \
    -p tcp --tcp-flags SYN,RST SYN -o wg0 \
    -m comment --comment "\${COMMENT}" \
    -j TCPMSS --clamp-mss-to-pmtu

iptables -t mangle -A FORWARD \
    -p tcp --tcp-flags SYN,RST SYN -o wg0 \
    -m tcpmss --mss 1281:65535 \
    -m comment --comment "\${COMMENT}" \
    -j TCPMSS --set-mss 1280

# ── FORWARD ACCEPT（TCP / UDP）──────────────────────────────────
iptables -A FORWARD \
    -o wg0 -p tcp --dport "\${LUODI_PORT}" \
    -m comment --comment "\${COMMENT}" \
    -j ACCEPT

iptables -A FORWARD \
    -o wg0 -p udp --dport "\${LUODI_PORT}" \
    -m comment --comment "\${COMMENT}" \
    -j ACCEPT

# ── FORWARD 回包（状态跟踪，TCP + UDP）──────────────────────────
iptables -A FORWARD \
    -i wg0 -m state --state RELATED,ESTABLISHED \
    -m comment --comment "\${COMMENT}" \
    -j ACCEPT

echo "[✓] PREROUTING  DNAT  TCP :${relay_port} → ${wg_ip}:${luodi_port}"
echo "[✓] PREROUTING  DNAT  UDP :${relay_port} → ${wg_ip}:${luodi_port}"
echo "[✓] POSTROUTING MASQUERADE -d ${wg_ip}/32"
echo "[✓] mangle TCPMSS clamp-to-pmtu + set-mss 1280 双重钳制"
echo "[✓] FORWARD TCP/UDP + 回包 ESTABLISHED 规则已配置"

# ── [S1] UFW/Firewalld 兼容处理 ─────────────────────────────────
# UFW/Firewalld 的默认 FORWARD DROP 策略可能覆盖上方手动规则
# 主动放行入站端口（静默执行，失败不影响主流程）
if command -v ufw &>/dev/null; then
    _UFW_ST=\$(ufw status 2>/dev/null | head -1)
    if echo "\${_UFW_ST}" | grep -qi "active"; then
        ufw allow "\${RELAY_PORT}/tcp" 2>/dev/null \
            && echo "[✓] UFW 已放行 TCP:\${RELAY_PORT}" || true
        ufw allow "\${RELAY_PORT}/udp" 2>/dev/null \
            && echo "[✓] UFW 已放行 UDP:\${RELAY_PORT}" || true
    fi
fi

if command -v firewall-cmd &>/dev/null; then
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        firewall-cmd --permanent --add-port="\${RELAY_PORT}/tcp" 2>/dev/null \
            && echo "[✓] Firewalld 已放行 TCP:\${RELAY_PORT}" || true
        firewall-cmd --permanent --add-port="\${RELAY_PORT}/udp" 2>/dev/null \
            && echo "[✓] Firewalld 已放行 UDP:\${RELAY_PORT}" || true
        firewall-cmd --reload 2>/dev/null || true
    fi
fi

# ── IPv6 泄漏防护 ─────────────────────────────────────────────────
if command -v ip6tables &>/dev/null; then
    ip6tables -C FORWARD -p tcp --dport "\${RELAY_PORT}" \
        -m comment --comment "\${COMMENT}" -j DROP 2>/dev/null || \
    ip6tables -A FORWARD -p tcp --dport "\${RELAY_PORT}" \
        -m comment --comment "\${COMMENT}" -j DROP 2>/dev/null || true
    ip6tables -C FORWARD -p udp --dport "\${RELAY_PORT}" \
        -m comment --comment "\${COMMENT}" -j DROP 2>/dev/null || \
    ip6tables -A FORWARD -p udp --dport "\${RELAY_PORT}" \
        -m comment --comment "\${COMMENT}" -j DROP 2>/dev/null || true
    echo "[✓] ip6tables FORWARD DROP :${relay_port}（IPv6泄漏防护）"
else
    echo "[!] ip6tables 不可用，如有 IPv6 请手动确认不会泄漏"
fi

# ── 持久化 ──────────────────────────────────────────────────────
if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save 2>/dev/null \
        && echo "[✓] iptables 已持久化 (netfilter-persistent)" || true
else
    echo "[→] 尝试安装 iptables-persistent..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        iptables-persistent netfilter-persistent 2>/dev/null \
    || yum install -y -q iptables-services 2>/dev/null \
    || true

    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save 2>/dev/null \
            && echo "[✓] iptables 已持久化 (netfilter-persistent 安装后保存)" || true
    elif command -v iptables-save &>/dev/null; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        if [[ ! -f /etc/systemd/system/iptables-restore-custom.service ]]; then
            cat > /etc/systemd/system/iptables-restore-custom.service << 'SVCEOF'
[Unit]
Description=Restore iptables rules (duijie.sh)
After=network.target
Before=network-online.target

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore /etc/iptables/rules.v4
ExecStart=/sbin/ip6tables-restore /etc/iptables/rules.v6
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SVCEOF
            systemctl daemon-reload 2>/dev/null || true
            systemctl enable iptables-restore-custom.service 2>/dev/null || true
            echo "[✓] iptables 已持久化 (rules.v4 + systemd restore 服务)"
        else
            iptables-save  > /etc/iptables/rules.v4 2>/dev/null || true
            ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
            echo "[✓] iptables 已持久化 (rules.v4 已更新)"
        fi
    fi
fi
SHEOF
    log_info "中转机 iptables DNAT 配置完成"
}

_fw::dnat_remove() {
    local del_lid="$1"
    log_step "移除中转机 iptables 规则（LINK_ID: ${del_lid}）..."

    _ssh::pipe << SHEOF
set -e
COMMENT="luodi-dnat-${del_lid}"

_del_rules_by_comment() {
    local table="\$1" chain="\$2"
    iptables -t "\${table}" -S "\${chain}" 2>/dev/null \
        | grep -- "\""\${COMMENT}"\"" \
        | sed 's/^-A /-D /' \
        | while IFS= read -r spec; do
            bash -c "iptables -t \${table} \${spec}" 2>/dev/null || true
          done
}
_del_rules_by_comment nat    PREROUTING
_del_rules_by_comment nat    POSTROUTING
_del_rules_by_comment filter FORWARD
_del_rules_by_comment mangle FORWARD
echo "[✓] iptables 规则已精准删除 (LINK_ID: ${del_lid})"

if command -v ip6tables &>/dev/null; then
    _del_ip6_by_comment() {
        local chain="\$1"
        ip6tables -S "\${chain}" 2>/dev/null \
            | grep -- "\""\${COMMENT}"\"" \
            | sed 's/^-A /-D /' \
            | while IFS= read -r spec; do
                bash -c "ip6tables \${spec}" 2>/dev/null || true
              done
    }
    _del_ip6_by_comment FORWARD
    echo "[✓] ip6tables 规则已清理"
fi

if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save 2>/dev/null || true
elif command -v iptables-save &>/dev/null; then
    mkdir -p /etc/iptables
    iptables-save  > /etc/iptables/rules.v4 2>/dev/null || true
    ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
fi
SHEOF
    log_info "中转机 iptables 规则已清理"
}

# ══════════════════════════════════════════════════════════════════
# §7  MODULE: port
#     _port::allocate() — 在中转机分配可用入站端口
#     [C1] 端口占用检测：
#          · 从 nodes.json 收集本项目已用端口
#          · 从 iptables PREROUTING 收集已用端口（双保险）
#          · 用 ss（非 netstat）扫描 OS 级已占用 TCP+UDP 端口
#            原因：Debian 11/12 最小化安装默认无 net-tools(netstat)，
#            ss 是 iproute2 的组成部分，现代 Linux 均预装
# ══════════════════════════════════════════════════════════════════

_port::allocate() {
    log_step "在中转机分配用户入站端口..."
    local start="${RELAY_START_PORT:-16888}"
    local nodes_path="$RELAY_NODES"
    local link_id="$LINK_ID"
    local luodi_ip="$LUODI_IP"
    local luodi_port="$LUODI_PORT"

    local script
    script=$(python3 - << PYEOF
import json
start      = int("${start}")
nodes_path = $(python3 -c "import json; print(json.dumps('${nodes_path}'))")
link_id    = $(python3 -c "import json; print(json.dumps('${link_id}'))")
luodi_ip   = $(python3 -c "import json; print(json.dumps('${luodi_ip}'))")
luodi_port = $(python3 -c "import json; print(json.dumps('${luodi_port}'))")

remote = f"""
import json, subprocess, re, sys

start      = {start}
nodes_path = {json.dumps(nodes_path)}
link_id    = {json.dumps(link_id)}
luodi_ip   = {json.dumps(luodi_ip)}
luodi_port = {json.dumps(luodi_port)}

try:
    nd = json.load(open(nodes_path))
except Exception:
    nd = {{"nodes": {{}}}}
nodes = nd.get("nodes", {{}})

# ── 冲突检测：同一 LUODI_IP:PORT 禁止不同 LINK_ID 重复对接 ────
for nid, n in nodes.items():
    if nid == link_id:
        continue
    if n.get("luodi_ip") == luodi_ip and str(n.get("luodi_port","")) == str(luodi_port):
        print(f"CONFLICT:{{nid}}")
        sys.exit(0)

# ── 收集已用端口 ──────────────────────────────────────────────
used = set()
for nid, n in nodes.items():
    if nid == link_id: continue
    p = n.get("relay_port")
    if p: used.add(int(p))

# iptables PREROUTING（双保险）
try:
    out = subprocess.check_output(
        ["iptables", "-t", "nat", "-S", "PREROUTING"], text=True, timeout=5)
    for m in re.finditer(r'--dport (\\d+)', out):
        try: used.add(int(m.group(1)))
        except: pass
except Exception:
    pass

# [C1] ss 扫描 OS 级占用端口（TCP + UDP）
# 使用 ss 而非 netstat：Debian 11/12 最小化安装无 net-tools
for flag in ["-tlnp", "-ulnp"]:
    try:
        out = subprocess.check_output(["ss", flag], text=True, timeout=5)
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                addr = parts[4]
                port_str = addr.rsplit(":", 1)[-1].strip("[]")
                try: used.add(int(port_str))
                except ValueError: pass
    except Exception:
        pass

p = start
while p in used:
    p += 1
    if p > 65535:
        print("ERROR: 无可用端口", file=sys.stderr)
        sys.exit(1)
print(p)
"""
print(remote)
PYEOF
)

    local out
    out=$(echo "$script" | _ssh::pipe_py 2>&1) || log_error "中转机端口分配执行失败"

    if echo "$out" | grep -q "^CONFLICT:"; then
        local cid; cid=$(echo "$out" | grep "^CONFLICT:" | cut -d: -f2)
        log_error "冲突：${LUODI_IP}:${LUODI_PORT} 已被 LINK_ID=${cid} 对接，禁止重复对接同一落地机地址"
    fi

    RELAY_ASSIGNED_PORT=$(echo "$out" | grep -E '^[0-9]+$' | head -1 | tr -d '[:space:]')
    [[ "$RELAY_ASSIGNED_PORT" =~ ^[0-9]+$ ]] || log_error "端口分配返回无效值: ${out}"
    log_info "用户入站端口: ${RELAY_ASSIGNED_PORT}"
}

# ══════════════════════════════════════════════════════════════════
# §8  MODULE: out
#     _out::node_link()    — 生成 VLESS 节点链接 + [P1] Xray JSON 配置块
#     _out::subscription() — 生成 Base64 订阅字符串
#     _out::save()         — 写入中转机 nodes.json + 更新本地订阅文件
#                           [P1] 订阅注释行标注 MTU=1380/TCPMSS=1280
# ══════════════════════════════════════════════════════════════════

_out::node_link() {
    log_step "生成节点链接..."

    # ╔══════════════════════════════════════════════════════════════╗
    # ║  节点链接必须使用落地机的 UUID 和 Reality 公钥               ║
    # ║  中转机仅做 iptables DNAT，不处理任何 VLESS/Reality 协议     ║
    # ╚══════════════════════════════════════════════════════════════╝

    [[ -z "$LUODI_UUID"   ]] && log_error "落地机UUID为空"
    [[ -z "$LUODI_PUBKEY" ]] && log_error "落地机Reality公钥为空"

    local rh; rh=$(ip_for_url "$RELAY_IP")
    local label="${NODE_LABEL:-落地-${LUODI_IP}}"
    NODE_LABEL="$label"
    local encoded_label; encoded_label=$(url_encode "$label")

    NODE_LINK="vless://${LUODI_UUID}@${rh}:${RELAY_ASSIGNED_PORT}"
    NODE_LINK+="?encryption=none&flow=xtls-rprx-vision"
    NODE_LINK+="&security=reality&sni=${LUODI_SNI}"
    NODE_LINK+="&fp=chrome&pbk=${LUODI_PUBKEY}"
    NODE_LINK+="&sid=${LUODI_SHORTID}"
    NODE_LINK+="&type=${LUODI_NETWORK}&headerType=none"

    case "$LUODI_NETWORK" in
        xhttp)
            NODE_LINK+="&path=$(url_encode "${LUODI_XHTTP_PATH:-/}")"
            [[ -n "$LUODI_XHTTP_HOST" ]] && NODE_LINK+="&host=$(url_encode "$LUODI_XHTTP_HOST")"
            [[ "$LUODI_XHTTP_MODE" != "auto" && -n "$LUODI_XHTTP_MODE" ]] \
                && NODE_LINK+="&mode=$(url_encode "$LUODI_XHTTP_MODE")"
            ;;
        ws)
            NODE_LINK+="&path=$(url_encode "${LUODI_WS_PATH:-/}")"
            [[ -n "$LUODI_WS_HOST" ]] && NODE_LINK+="&host=$(url_encode "$LUODI_WS_HOST")"
            ;;
        grpc)
            [[ -n "$LUODI_GRPC_SERVICE" ]] \
                && NODE_LINK+="&serviceName=$(url_encode "$LUODI_GRPC_SERVICE")"
            ;;
    esac

    NODE_LINK+="#${encoded_label}"

    # [P1] 生成 Xray JSON outbound 配置块
    # 供不支持 VLESS 分享链接的客户端（旧版小火箭 / 路由器插件）使用
    # ip_for_json 去掉方括号（JSON address 字段不含方括号）
    local json_addr; json_addr=$(ip_for_json "$RELAY_IP")
    local network_settings="null"
    case "$LUODI_NETWORK" in
        xhttp)
            network_settings=$(python3 -c "
import json,sys
print(json.dumps({'path':sys.argv[1],'host':sys.argv[2],'mode':sys.argv[3]},ensure_ascii=False))" \
                "${LUODI_XHTTP_PATH:-/}" "${LUODI_XHTTP_HOST:-}" "${LUODI_XHTTP_MODE:-auto}")
            ;;
        ws)
            network_settings=$(python3 -c "
import json,sys
print(json.dumps({'path':sys.argv[1],'headers':{'Host':sys.argv[2]}},ensure_ascii=False))" \
                "${LUODI_WS_PATH:-/}" "${LUODI_WS_HOST:-}")
            ;;
        grpc)
            network_settings=$(python3 -c "
import json,sys
print(json.dumps({'serviceName':sys.argv[1]},ensure_ascii=False))" \
                "${LUODI_GRPC_SERVICE:-}")
            ;;
    esac

    NODE_JSON=$(python3 - << PYEOF
import json, sys

relay_ip      = sys.argv[1]
relay_port    = int(sys.argv[2])
uuid          = sys.argv[3]
sni           = sys.argv[4]
pubkey        = sys.argv[5]
shortid       = sys.argv[6]
network       = sys.argv[7]
net_settings  = json.loads(sys.argv[8]) if sys.argv[8] != "null" else {}
label         = sys.argv[9]

stream = {
    "network": network,
    "security": "reality",
    "realitySettings": {
        "serverName": sni,
        "fingerprint": "chrome",
        "publicKey": pubkey,
        "shortId": shortid,
        "show": False
    }
}

# 附加传输层设置
if network == "xhttp" and net_settings:
    stream["xhttpSettings"] = net_settings
elif network == "ws" and net_settings:
    stream["wsSettings"] = net_settings
elif network == "grpc" and net_settings:
    stream["grpcSettings"] = net_settings
elif network == "tcp":
    stream["tcpSettings"] = {}

config = {
    "// MTU-Note": "WireGuard MTU=1380, TCPMSS=1280. 若遇掉速可调低客户端MTU",
    "tag": label,
    "protocol": "vless",
    "settings": {
        "vnext": [{
            "address": relay_ip,
            "port": relay_port,
            "users": [{
                "id": uuid,
                "flow": "xtls-rprx-vision",
                "encryption": "none",
                "level": 0
            }]
        }]
    },
    "streamSettings": stream
}
print(json.dumps(config, indent=2, ensure_ascii=False))
PYEOF
    "$json_addr" "$RELAY_ASSIGNED_PORT" "$LUODI_UUID" \
    "$LUODI_SNI" "$LUODI_PUBKEY" "$LUODI_SHORTID" \
    "$LUODI_NETWORK" "$network_settings" "$NODE_LABEL")

    log_info "节点链接已生成（落地UUID: ${LUODI_UUID:0:8}... 落地公钥: ${LUODI_PUBKEY:0:10}...）"
}

_out::subscription() {
    touch "$SUB_FILE"
    local all b64
    all=$(grep -v '^#' "$SUB_FILE" | grep -v '^$' || true)
    b64=$(echo "$all" | base64 -w 0 2>/dev/null \
        || echo "$all" | python3 -c \
            "import sys,base64; print(base64.b64encode(sys.stdin.buffer.read()).decode())")
    echo "$b64"
}

_out::save() {
    log_step "保存节点信息..."

    # ── 在中转机更新 nodes.json ─────────────────────────────────
    local nodes_path="$RELAY_NODES"
    local link_id="$LINK_ID"
    local relay_ip="$RELAY_IP"
    local relay_port="$RELAY_ASSIGNED_PORT"
    local luodi_ip="$LUODI_IP"
    local luodi_port="$LUODI_PORT"
    local wg_ip="$LUODI_WG_ASSIGNED_IP"
    local wg_pubkey="$LUODI_WG_PUBKEY"
    local node_label="$NODE_LABEL"

    # [v2.4 Bug-1] node_label 通过 sys.argv 传入，彻底避免特殊字符 Python 注入
    local script
    script=$(python3 - << PYEOF
import json, sys

nodes_path = $(python3 -c "import json; print(json.dumps('${nodes_path}'))")
link_id    = $(python3 -c "import json; print(json.dumps('${link_id}'))")
entry_json = $(python3 -c "
import json, sys
print(json.dumps(json.dumps({
    'relay_ip':   sys.argv[1],
    'relay_port': int(sys.argv[2]),
    'luodi_ip':   sys.argv[3],
    'luodi_port': int(sys.argv[4]),
    'wg_ip':      sys.argv[5],
    'wg_pubkey':  sys.argv[6],
    'node_label': sys.argv[7],
    'link_id':    sys.argv[8],
})))" "${relay_ip}" "${relay_port}" "${luodi_ip}" "${luodi_port}" \
     "${wg_ip}" "${wg_pubkey}" "${node_label}" "${link_id}")

remote = f"""
import json, os

nodes_path = {json.dumps(nodes_path)}
link_id    = {json.dumps(link_id)}
entry      = json.loads({json.dumps(entry_json)})

try:    nd = json.load(open(nodes_path))
except: nd = {{"nodes": {{}}}}

nd.setdefault("nodes", {{}})[link_id] = entry
os.makedirs(os.path.dirname(nodes_path), exist_ok=True)
with open(nodes_path, "w") as f:
    json.dump(nd, f, indent=2, ensure_ascii=False)
print(f"[OK] nodes.json 已更新: {{link_id}}")
"""
print(remote)
PYEOF
)
    echo "$script" | _ssh::pipe_py || log_warn "nodes.json 更新失败，请手动检查中转机"

    # ── 更新本地订阅文件 ───────────────────────────────────────
    # [v2.4 Bug-7/10] mktemp 失败检测 + trap 确保临时文件清理
    touch "$SUB_FILE"
    local tmp
    tmp=$(mktemp 2>/dev/null) || { log_warn "mktemp 失败，跳过本地订阅更新"; tmp=""; }
    if [[ -n "$tmp" ]]; then
        trap 'rm -f "$tmp"' RETURN ERR
        grep -v "LINK_ID=${LINK_ID}" "$SUB_FILE" > "$tmp" 2>/dev/null || true
        # [P1] 订阅注释行标注 MTU/TCPMSS，方便高级用户排查掉速问题
        { echo "# LINK_ID=${LINK_ID}  label=${NODE_LABEL}  $(date '+%Y-%m-%d')  MTU=1380/TCPMSS=1280"
          echo "$NODE_LINK"; } >> "$tmp"
        mv "$tmp" "$SUB_FILE"
        trap - RETURN ERR
    fi

    # ── 追加到本地 info 文件 ───────────────────────────────────
    { echo ""
      echo "── 对接节点 $(date '+%Y-%m-%d %H:%M:%S') ────────────────────────"
      echo "RELAY_IP=${RELAY_IP}"
      echo "RELAY_SSH_PORT=${RELAY_SSH_PORT:-22}"
      echo "RELAY_SSH_USER=${RELAY_SSH_USER:-root}"
      echo "RELAY_PORT=${RELAY_ASSIGNED_PORT}"
      echo "LINK_ID=${LINK_ID}"
      echo "LUODI_NETWORK=${LUODI_NETWORK}"
      echo "LUODI_WG_IP=${LUODI_WG_ASSIGNED_IP}"
      echo "NODE_LABEL=${NODE_LABEL}"
      echo "NODE_LINK=${NODE_LINK}"
      echo "────────────────────────────────────────────────────────────"
    } >> "$LOCAL_INFO"

    log_info "节点信息已写入: ${LOCAL_INFO}"

    local cnt b64
    cnt=$(grep -v '^#' "$SUB_FILE" | grep -vc '^$' || echo "?")
    b64=$(_out::subscription)
    echo ""
    echo -e "  ${BOLD}订阅 Base64（共 ${cnt} 个节点）：${NC}"
    echo -e "  ${GREEN}${b64}${NC}"
}

# ══════════════════════════════════════════════════════════════════
# §9  连通性验证
# ══════════════════════════════════════════════════════════════════

_check::connectivity() {
    log_step "连通性验证..."

    # [v2.4 Bug-5] 带重试的握手等待（跨国链路首次握手最多需 10 秒）
    log_step "等待 WireGuard 首次握手（最多 10 秒）..."
    local wg_ok=false wg_rtt="?"
    local attempt
    for attempt in 1 2 3 4 5; do
        sleep 2
        local ping_raw
        ping_raw=$(_ssh::run "ping -c 2 -W 2 ${LUODI_WG_ASSIGNED_IP} 2>&1" 2>/dev/null || true)
        if echo "$ping_raw" | grep -q "bytes from"; then
            # [v2.4 Bug-3] -oE 替代 -oP（BusyBox/Alpine 无 PCRE）
            wg_rtt=$(echo "$ping_raw" \
                | grep -oE '[0-9]+\.[0-9]+/[0-9]+\.[0-9]+/[0-9]+\.[0-9]+' \
                | head -1 || echo "?")
            wg_ok=true; break
        fi
        log_warn "第 ${attempt}/5 次握手等待...（已等待 $((attempt * 2))s）"
    done

    if [[ "$wg_ok" == "true" ]]; then
        log_info "中转机 → 落地机 WG隧道 ✓  RTT: ${wg_rtt} ms"
    else
        log_warn "WireGuard隧道 ping 不通（请检查落地机防火墙 UDP:${RELAY_WG_PORT}）"
    fi

    # 验证 iptables 规则
    local dnat_tcp dnat_udp tcpmss
    dnat_tcp=$(_ssh::run \
        "iptables -t nat -S PREROUTING 2>/dev/null | grep 'luodi-dnat-${LINK_ID}' | grep -- '-p tcp' | head -1") || true
    dnat_udp=$(_ssh::run \
        "iptables -t nat -S PREROUTING 2>/dev/null | grep 'luodi-dnat-${LINK_ID}' | grep -- '-p udp' | head -1") || true
    tcpmss=$(_ssh::run \
        "iptables -t mangle -S FORWARD 2>/dev/null | grep 'luodi-dnat-${LINK_ID}' | head -1") || true

    [[ -n "$dnat_tcp" ]] && log_info "iptables DNAT TCP ✓" \
                         || log_warn "iptables DNAT TCP 规则未找到，请检查中转机防火墙"
    [[ -n "$dnat_udp" ]] && log_info "iptables DNAT UDP ✓" \
                         || log_warn "iptables DNAT UDP 规则未找到"
    [[ -n "$tcpmss"   ]] && log_info "iptables TCPMSS clamp ✓" \
                         || log_warn "iptables mangle TCPMSS 规则未找到"
}

# ══════════════════════════════════════════════════════════════════
# §10 MODULE: mgr
#     _mgr::list()   — 打印已对接节点列表
#     _mgr::delete() — 交互式删除节点（含确认保护）
#     _mgr::clean()  — 按 LINK_ID 清理：WG Peer + iptables + nodes.json
# ══════════════════════════════════════════════════════════════════

_mgr::list() {
    local nodes_json="$1"
    echo ""
    echo -e "${BOLD}已对接节点列表：${NC}"
    echo ""
    echo "$nodes_json" | python3 - << 'PYEOF'
import json, sys
d = json.load(sys.stdin)
nodes = d.get("nodes", {})
if not nodes:
    print("  （暂无已对接节点）")
else:
    for i, (lid, n) in enumerate(nodes.items(), 1):
        print(f"  [{i}] LINK_ID   : {lid}")
        print(f"      落地机    : {n.get('luodi_ip','?')}:{n.get('luodi_port','?')}")
        print(f"      入站端口  : {n.get('relay_port','?')}")
        print(f"      WG虚拟IP  : {n.get('wg_ip','?')}")
        print(f"      节点标签  : {n.get('node_label','?')}")
        print()
PYEOF
}

_mgr::delete() {
    local nodes_json="$1"
    local node_count
    node_count=$(echo "$nodes_json" | python3 -c \
        "import json,sys; d=json.load(sys.stdin); print(len(d.get('nodes',{})))" 2>/dev/null || echo 0)

    [[ "$node_count" == "0" ]] && { log_warn "无节点可删除"; return 0; }

    local idx
    read -rp "输入要删除的节点序号（1-${node_count}）: " idx || true
    [[ -z "$idx" ]] && { log_warn "已取消"; return 0; }
    [[ ! "$idx" =~ ^[0-9]+$ ]] && { log_warn "请输入有效数字"; return 0; }

    local del_link_id del_wg_ip
    del_link_id=$(echo "$nodes_json" | python3 -c "
import json, sys
d = json.load(sys.stdin)
nodes = list(d.get('nodes', {}).items())
try:    print(nodes[${idx} - 1][0])
except: print('')
" 2>/dev/null || echo "")

    del_wg_ip=$(echo "$nodes_json" | python3 -c "
import json, sys
d = json.load(sys.stdin)
nodes = list(d.get('nodes', {}).items())
try:    print(nodes[${idx} - 1][1].get('wg_ip',''))
except: print('')
" 2>/dev/null || echo "")

    [[ -z "$del_link_id" ]] && { log_error "无效序号: ${idx}"; return 1; }

    echo ""
    log_warn "即将删除节点 LINK_ID=${del_link_id}（WG IP: ${del_wg_ip}）"
    log_warn "此操作将清理：WG Peer + iptables 规则 + nodes.json 记录"
    local confirm
    read -rp "确认删除？[y/N]: " confirm || true
    [[ "${confirm,,}" != "y" ]] && { log_info "已取消"; return 0; }

    _mgr::clean "$del_link_id" "$del_wg_ip"
}

_mgr::clean() {
    local del_lid="$1" del_wg_ip="$2"
    log_step "清理节点 ${del_lid}（WG IP: ${del_wg_ip}）..."

    _wg::remove_peer "$del_lid" "$del_wg_ip"
    _fw::dnat_remove "$del_lid"

    local nodes_path="$RELAY_NODES"
    local script
    script=$(python3 - << PYEOF
import json
del_lid    = $(python3 -c "import json; print(json.dumps('${del_lid}'))")
nodes_path = $(python3 -c "import json; print(json.dumps('${nodes_path}'))")

remote = f"""
import json

del_lid    = {json.dumps(del_lid)}
nodes_path = {json.dumps(nodes_path)}

try:
    nd = json.load(open(nodes_path))
    nd.get("nodes", {{}}).pop(del_lid, None)
    with open(nodes_path, "w") as f:
        json.dump(nd, f, indent=2, ensure_ascii=False)
    print(f"[OK] nodes.json 已移除: {{del_lid}}")
except Exception as e:
    print(f"[!] 清理 nodes.json 失败: {{e}}")
"""
print(remote)
PYEOF
)
    echo "$script" | _ssh::pipe_py || log_warn "nodes.json 远端清理失败，请手动检查"

    # [v2.4 Issue-10] 本地清理复用共用函数
    _local::clean_block_by_link_id "$del_lid"

    log_info "节点 ${del_lid} 清理完成"
}

# ══════════════════════════════════════════════════════════════════
# §11 打印结果摘要
# ══════════════════════════════════════════════════════════════════

_print_result() {
    echo ""
    log_sep
    echo -e "${CYAN}${BOLD}  ✓ 对接完成  duijie.sh v2.5  (WireGuard版，单次解密)${NC}"
    log_sep
    echo ""
    echo -e "  ${BOLD}流量路径：${NC}"
    echo -e "  客户端 ──[VLESS+Reality]──▶ ${CYAN}${RELAY_IP}:${RELAY_ASSIGNED_PORT}${NC}"
    echo -e "  ──[iptables DNAT TCP+UDP]──[WireGuard wg0]──▶ ${CYAN}${LUODI_WG_ASSIGNED_IP}:${LUODI_PORT}${NC}"
    echo -e "  ──[落地机 Xray ${LUODI_NETWORK}]──▶ ${LUODI_IP} ──▶ 🌐 互联网"
    echo ""
    echo -e "  ${YELLOW}▲ 消除双重加密：Reality握手仅在落地机完成，中转机零协议开销${NC}"
    echo -e "  ${YELLOW}▲ MTU=1380（WireGuard）/ TCPMSS=1280（TCP握手兜底），若掉速可调低MTU${NC}"
    echo ""
    echo -e "  ${BOLD}LINK_ID   ：${NC}  ${LINK_ID}"
    echo -e "  ${BOLD}WG虚拟IP  ：${NC}  落地机 ${LUODI_WG_ASSIGNED_IP}  ←→  中转机 10.100.0.1"
    echo -e "  ${BOLD}节点标签  ：${NC}  ${NODE_LABEL}"
    echo ""

    # VLESS 链接
    echo -e "  ${BOLD}━━ ① VLESS 分享链接（主流客户端）：${NC}"
    echo -e "  ${GREEN}${NODE_LINK}${NC}"
    echo ""

    # [P1] Xray JSON 配置块（供不支持链接的客户端）
    echo -e "  ${BOLD}━━ ② Xray JSON outbound 配置（旧版客户端 / 路由插件）：${NC}"
    echo -e "  ${CYAN}（将下方 JSON 粘贴到客户端 outbound 配置中）${NC}"
    echo ""
    echo "$NODE_JSON" | sed 's/^/  /'
    echo ""

    log_sep
    echo -e "${YELLOW}常用命令：${NC}"
    echo -e "  WG状态（中转）  : (SSH) wg show wg0"
    echo -e "  WG状态（落地）  : wg show wg0"
    echo -e "  隧道连通测试    : (SSH) ping ${LUODI_WG_ASSIGNED_IP}"
    echo -e "  DNAT规则查看    : (SSH) iptables -t nat -L PREROUTING -n -v | grep luodi-dnat"
    echo -e "  节点管理        : bash duijie.sh --manage"
    log_sep
    echo ""
}

# ══════════════════════════════════════════════════════════════════
# §12 管理模式（--manage）
# ══════════════════════════════════════════════════════════════════

_manage_mode() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║        节点管理  duijie.sh v2.5  WireGuard版        ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
    _ssh::setup
    _info::read_relay

    local nodes_json
    nodes_json=$(_ssh::run "cat '${RELAY_NODES}' 2>/dev/null || echo '{\"nodes\":{}}'") \
        || nodes_json='{"nodes":{}}'

    _mgr::list "$nodes_json"

    local node_count
    node_count=$(echo "$nodes_json" | python3 -c \
        "import json,sys; d=json.load(sys.stdin); print(len(d.get('nodes',{})))" 2>/dev/null || echo 0)

    [[ "$node_count" == "0" ]] && { log_warn "暂无已对接节点"; return 0; }

    echo -e "  ${CYAN}[d]${NC} 删除节点  ${CYAN}[q]${NC} 退出"
    local choice
    read -rp "选择操作 [q]: " choice || true
    choice="${choice:-q}"

    case "$choice" in
        d) _mgr::delete "$nodes_json" ;;
        q) return 0 ;;
        *) log_warn "未知操作，已退出" ;;
    esac
}

# ══════════════════════════════════════════════════════════════════
# §13 主流程
# ══════════════════════════════════════════════════════════════════

main() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  duijie.sh  v2.5  —  WireGuard 隧道对接（单次解密）        ║${NC}"
    echo -e "${CYAN}║  落地机IP对外 · DNAT TCP/UDP · MTU=1380 · 固定节点          ║${NC}"
    if [[ "$AUTO_MODE" == "true" ]]; then
    echo -e "${CYAN}║  ${GREEN}${BOLD}⚡ AUTO_MODE：全零交互 · 须提前运行过交互模式${NC}            ${CYAN}║${NC}"
    else
    echo -e "${CYAN}║  提示: --auto 全自动模式  --manage 节点管理模式              ║${NC}"
    fi
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # 1. 落地机：读取配置，生成 LINK_ID，清理旧记录
    #    _info::read_luodi 内部自动调用 _info::_ensure_xray_listen
    _info::read_luodi

    # 2. 建立 SSH 连接，读取中转机配置
    _ssh::setup
    _info::read_relay

    # 3. WireGuard 双端配置
    _wg::allocate_ip        # 中转机分配 10.100.0.N
    _wg::add_peer           # 中转机热添加落地机 WG Peer
    _wg::setup_local        # 落地机配置 wg0

    # 4. 端口分配 + iptables DNAT
    _port::allocate         # 分配入站端口（ss 冲突检测）
    _fw::dnat_add           # DNAT + MASQUERADE + TCPMSS + UFW/Firewalld

    # 5. 连通性验证
    _check::connectivity    # ping WG 隧道 + 验证 iptables 规则

    # 6. 节点标签
    if [[ "$AUTO_MODE" != "true" ]]; then
        local i
        read -rp "节点标签 [落地-${LUODI_IP}]: " i || true
        NODE_LABEL="${i:-落地-${LUODI_IP}}"
    else
        NODE_LABEL="落地-${LUODI_IP}"
    fi

    # 7. 生成链接（VLESS + JSON），保存，打印摘要
    _out::node_link
    _out::save
    _print_result
}

# ══════════════════════════════════════════════════════════════════
# §14 入口
# ══════════════════════════════════════════════════════════════════
case "${1:-}" in
    --manage) _manage_mode ;;
    *)        main "$@" ;;
esac
