#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════════╗
# ║  duijie.sh  v3.0  —  CN2GIA中转 ↔ 落地机  WireGuard对接            ║
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
# ║           ──[WireGuard wg0 自适应MTU]──▶ 落地机:LUODI_PORT           ║
# ║  落地机 Xray/Sing-box 完成 Reality 握手，以干净IP出口访问互联网      ║
# ║                                                                      ║
# ║  设计要点                                                            ║
# ║  · 中转机不处理 VLESS 协议层，仅做 TCP/UDP 透明转发                  ║
# ║  · Reality 握手、UUID 验证全部由落地机 Xray/Sing-box 完成            ║
# ║  · 节点链接使用落地机的 UUID 和 公钥（非中转机）                     ║
# ║  · 支持 Xray / Sing-box 两种落地机代理后端                          ║
# ║  · MTU 动态探测：DF-ping 阶梯回退，自动适配 CN2/GIA/甲骨文/家宽     ║
# ╠══════════════════════════════════════════════════════════════════════╣
# ║  LINK_ID = MD5(落地IP:落地端口)[:8]  节点唯一指纹（幂等键）         ║
# ║  WG网段   10.100.0.0/24  MTU自适应(默认探测,保底1380)               ║
# ║  TCPMSS = MTU - 40（精准公式）+ clamp-to-pmtu 双重保障              ║
# ║  中转机   wg0 = 10.100.0.1（固定）                                  ║
# ║  落地机   wg0 = 10.100.0.N（N从2起，复用历史分配，真正幂等）        ║
# ╠══════════════════════════════════════════════════════════════════════╣
# ║  函数命名规范：_模块::函数()                                          ║
# ║  _ssh  _info  _local  _wg  _fw  _port  _out  _check  _mgr           ║
# ╚══════════════════════════════════════════════════════════════════════╝
#
# ── v3.0 修复 & 新增清单（大版本：完整核查 + 三项真实修复）────────────
#
#  继承 v2.10 全部修复，本版完成全面核查后实施三项真实改动：
#
#  [SEC] _wg::setup_local() — 落地机防火墙"二次暴露"兜底规则（真实缺失）
#       旧版仅有 `-i wg0 ACCEPT` 规则，允许来自 wg0 的流量访问代理端口。
#       但若用户或面板将 Xray 监听地址误改回 0.0.0.0，公网扫描器仍可
#       直接访问该端口（INPUT 默认策略若为 ACCEPT 则无任何保护）。
#       → 新增：写入 `-i wg0 ACCEPT` 之后，额外插入
#           `! -i wg0 -p tcp --dport LUODI_PORT -j DROP`
#         即：非 wg0 来源的同端口流量一律丢弃。
#         · ACCEPT 规则在前（-I），DROP 规则在后（-A），链路优先级正确
#         · 幂等：先 -D 删除旧 DROP 规则再重新插入，防止重复堆积
#         · 独立 comment（luodi-drop-LINK_ID），删节点时精准清理
#         · 覆盖场景：Xray 监听回到 0.0.0.0、其他内网隧道绕行、ZeroTier
#
#  [VER] _check::connectivity() — 双路 TCP 健康验证（精度提升）
#       旧版 nc 仅连接 127.0.0.1:RELAY_PORT（验证 DNAT+WG 路径畅通）。
#       新建议：同时在中转机向 LUODI_WG_ASSIGNED_IP:LUODI_PORT 发起 TCP
#       握手，绕过 DNAT 直接验证 WG 内网可达性和落地机 Xray 监听状态。
#       → 升级为双路并行验证：
#         路径1: 中转机 → 127.0.0.1:RELAY_PORT → DNAT → WG → 落地Xray
#                （验证：iptables DNAT + WireGuard 隧道 + Xray 监听）
#         路径2: 中转机 → 10.100.0.N:LUODI_PORT（WG内网直连）
#                （验证：WG 隧道 + 落地机 Xray 监听，排除 DNAT 干扰）
#         · 两路均成功：全链路 ✓
#         · 仅路径2成功路径1失败：WG+Xray 正常，DNAT 规则有问题
#         · 仅路径1成功路径2失败：DNAT 路径通，但直连 WG 内网有问题
#         · 两路均失败：Xray 未响应（最常见故障）
#         · 软阻断逻辑保留，交互模式询问是否强制继续
#
#  [CORE] 全面核查确认以下条目在历史版本中已正确实现，v3.0 无需改动：
#       · PostUp/PreDown 策略路由对称清理 ── v2.8 已实现，table 200 幂等
#       · JSON JSONC 注释剥离             ── v2.10 已实现，_strip_jsonc()
#       · WG_MTU 空值保底 1380            ── v2.9 main() 已有 ${WG_MTU:-1380}
#       · 落地机 INPUT -i wg0 精准放行    ── v2.6 已实现，luodi-fw-LINK_ID
#       · 中转机 iptables 重启持久化      ── v2.9 Step1/2/3 + wg-quick enable
#       · 面板环境强提醒（3x-ui/x-ui）   ── v2.9 已实现，检测+红色警告框

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
# §1.5  用户可调参数（修改此处即可，无需改动其他代码）
# ══════════════════════════════════════════════════════════════════
# [MTU v2.8] WG MTU 自动探测模式（推荐保持 "" 空值以启用自动探测）：
#   · 留空（默认）：脚本通过 DF-ping 从中转机探测到落地机的实际 PMTU，
#     自动计算最佳值，范围 [1280, 1420]，探测失败保底 1380。
#   · 手动指定（如 WG_MTU=1380）：跳过探测，直接使用指定值。
#     标准 CN2 GIA 推荐 1380；甲骨文云内网可尝试 1420；
#     极保守值 1280（所有场景安全，吞吐量略低）。
#   · 环境变量覆盖：WG_MTU=1400 bash duijie.sh
WG_MTU="${WG_MTU:-}"
# TCPMSS 公式：MTU - 40（IPv4 TCP头20B + IP头20B = 40B，精准计算）
# 配合 clamp-to-pmtu 双重保障，在 _fw::dnat_add 中动态计算。
# 旧版 MTU-100 过于保守，v2.8 修正为更准确的 MTU-40。

# 落地机代理后端类型（自动检测：xray / singbox / unknown）
LUODI_PROXY_TYPE=""

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

    _ask "落地机公网IP或域名"     LUODI_IP
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

    # [E v2.7] DDNS/域名检测：若落地机使用域名（家宽 DDNS），直接使用域名，
    # WireGuard 原生支持域名 Endpoint，IP 变动后 PersistentKeepalive 重新解析自动恢复。
    if echo "$LUODI_IP" | grep -qE '[a-zA-Z]'; then
        log_info "落地机地址为域名格式（${LUODI_IP}），WG Endpoint 将使用域名，支持 DDNS 动态 IP ✓"
    fi

    _gen_link_id
    _local::clean_block_by_link_id "$LINK_ID"

    # [C2] 自动检测并修复代理监听地址（取代原来只告警的版本）
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
        # [SEC-FIX v2.6] 即使当前全监听，后续也必须改为严格绑定 WG 虚拟 IP。
        # WG IP 在此时尚未分配，设标志延后到 _wg::allocate_ip 之后执行。
        log_info "落地机 Xray 当前全监听 ${listen_addr}，将在 WG IP 分配后收窄绑定至 WG 虚拟IP（安全加固）"
        _XRAY_LISTEN_NEEDS_FIX=true
        return 0
    fi

    # 监听在非全局地址，同样需要在 WG IP 分配后统一修复
    echo ""
    echo -e "  ${YELLOW}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "  ${YELLOW}║  ⚠  Xray 监听 ${listen_addr}，DNAT 到 WG 虚拟IP后将无法到达      ║${NC}"
    echo -e "  ${YELLOW}║  将在 WireGuard IP 分配完毕后自动绑定到 WG 虚拟IP（安全策略）  ║${NC}"
    echo -e "  ${YELLOW}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    _XRAY_LISTEN_NEEDS_FIX=true
}

# ══════════════════════════════════════════════════════════════════
# _info::_auto_fix_xray_listen
#   [C2][SEC-FIX v2.6] 自动定位 Xray JSON 配置文件并修改 listen 字段。
#   ⚠ 安全修正：不再改为 "" 或 0.0.0.0（全局暴露），
#     而是等待 WG 虚拟 IP 分配完毕后，严格绑定在 LUODI_WG_ASSIGNED_IP 上。
#     若 LUODI_WG_ASSIGNED_IP 尚未分配（函数在 read_luodi 阶段被调用），
#     则先暂存"需修复"标志 _XRAY_LISTEN_NEEDS_FIX=true，
#     由 main() 在 _wg::allocate_ip 之后再调用本函数完成实际写入。
#   支持：标准单文件 / mack-a / conf.d 多文件目录
#   不支持自动修复：x-ui 面板（SQLite，交互提示手动操作）
# ══════════════════════════════════════════════════════════════════

# 标志位：Xray listen 需要在 WG IP 分配后修复
_XRAY_LISTEN_NEEDS_FIX=false

_info::_auto_fix_xray_listen() {
    # [SEC-FIX v2.6][A v2.7] 必须传入已分配的 WG 虚拟 IP，Xray/Sing-box 严格绑定在该内网 IP 上。
    local target_wg_ip="${1:?'_auto_fix_xray_listen: WG IP 参数不能为空'}"
    local target_port="$LUODI_PORT"
    local config_file=""
    local config_dir=""

    # ── [B v2.9] 面板环境检测 ─────────────────────────────────────
    # 3x-ui / x-ui 基于 SQLite 管理配置，面板重启时会重新生成 config.json，
    # 覆盖脚本写入的 listen 绑定，安全漏洞重新暴露。
    # 检测依据：进程名或可执行文件路径含 x-ui / 3x-ui 关键词
    local panel_detected=false
    local panel_name=""
    local panel_url_hint=""
    if pgrep -x "x-ui" &>/dev/null 2>/dev/null \
        || pgrep -x "3x-ui" &>/dev/null 2>/dev/null \
        || pgrep -fa "x-ui" 2>/dev/null | grep -qvE "grep|duijie" \
        || [[ -f "/usr/local/x-ui/x-ui" ]] \
        || [[ -f "/usr/local/3x-ui/bin/xui" ]]; then
        panel_detected=true
        if [[ -f "/usr/local/3x-ui/bin/xui" ]] \
            || pgrep -fa "3x-ui" 2>/dev/null | grep -qvE "grep|duijie"; then
            panel_name="3x-ui"
            panel_url_hint="http://服务器IP:2053/  (默认端口，以实际为准)"
        else
            panel_name="x-ui"
            panel_url_hint="http://服务器IP:54321/  (默认端口，以实际为准)"
        fi
        log_warn "[B v2.9] 检测到面板环境（${panel_name}）——配置文件修改可能被面板重启覆盖！"
    fi

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

    # ── Step2: 常见静态路径探测（Xray + Sing-box）────────────────
    if [[ -z "$config_file" && -z "$config_dir" ]]; then
        local try_paths=(
            "/usr/local/etc/xray/config.json"
            "/usr/local/etc/xray-reality/config.json"
            "/etc/xray/config.json"
            "/usr/local/etc/xray-mack/config.json"
            "/etc/sing-box/config.json"
            "/usr/local/etc/sing-box/config.json"
        )
        for p in "${try_paths[@]}"; do
            if [[ -f "$p" ]]; then
                config_file="$p"
                log_step "在常用路径找到配置: ${config_file}"
                break
            fi
        done

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
            \( -name "config.json" -path "*/xray*" \
            -o -name "config.json" -path "*/sing-box*" \) \
            2>/dev/null | head -1 || true)
        [[ -n "$config_file" ]] && log_step "find 兜底找到配置: ${config_file}"
    fi

    # ── Step4: 完全未找到，交互提示 ──────────────────────────────
    if [[ -z "$config_file" && -z "$config_dir" ]]; then
        echo ""
        echo -e "  ${RED}╔════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "  ${RED}║  ✗ 未能自动找到 Xray / Sing-box 配置文件                       ║${NC}"
        echo -e "  ${RED}║                                                                  ║${NC}"
        if [[ "$panel_detected" == "true" ]]; then
        echo -e "  ${RED}║  ⚠ 检测到 ${panel_name} 面板（配置由面板数据库管理）             ║${NC}"
        echo -e "  ${RED}║  登录面板: ${panel_url_hint}                                     ║${NC}"
        echo -e "  ${RED}║  → 入站列表 → 端口 ${target_port} → 编辑                        ║${NC}"
        echo -e "  ${RED}║  → 将「监听IP」改为 ${target_wg_ip}，保存并重启 Xray             ║${NC}"
        else
        echo -e "  ${RED}║  若使用 x-ui/3x-ui 面板：登录面板 → 入站列表 → 编辑对应入站     ║${NC}"
        echo -e "  ${RED}║  将「监听IP」字段改为 ${target_wg_ip}，保存后重启Xray            ║${NC}"
        echo -e "  ${RED}║                                                                  ║${NC}"
        echo -e "  ${RED}║  若 Xray 手动配置：inbound 的 \"listen\" 改为 \"${target_wg_ip}\"   ║${NC}"
        echo -e "  ${RED}║  若 Sing-box 手动配置：inbound 的 \"listen\" 改为同上              ║${NC}"
        echo -e "  ${RED}║  然后执行: systemctl restart xray  或  systemctl restart sing-box ║${NC}"
        fi
        echo -e "  ${RED}╚════════════════════════════════════════════════════════════════╝${NC}"
        if [[ "$AUTO_MODE" != "true" ]]; then
            local c
            read -rp "已手动修改并重启代理？继续执行？[y/N]: " c || true
            [[ "${c,,}" != "y" ]] && log_error "请修改代理监听地址后重新运行脚本"
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

    # ── Step6: Python 解析并修改——自动识别 Xray / Sing-box 结构 ──
    # [A v2.7] 兼容两种配置格式：
    #   · Xray/V2Ray:  inbounds[i].port (int)      + inbounds[i].listen (str)
    #   · Sing-box:    inbounds[i].listen_port(int) + inbounds[i].listen (str)
    # 检测依据：若顶层存在 "log" 且 inbounds[0] 含 "listen_port" → Sing-box；
    #           否则按 Xray 处理（更宽容的降级策略）。
    local any_fixed=false
    local detected_type="unknown"
    for f in "${files_to_check[@]}"; do
        [[ ! -f "$f" ]] && continue
        local result
        result=$(python3 - << PYEOF
import json, sys

config_file  = "${f}"
target_port  = int("${target_port}")
target_wg_ip = "${target_wg_ip}"  # [SEC-FIX v2.6] 严格绑定 WG 虚拟 IP

# ── [JSON v2.10] JSONC 注释剥离 ──────────────────────────────────
# 问题：mack-a 脚本/x-ui 面板导出的 config.json 常含 // 或 /* */ 注释
#       （JSONC 格式），Python 标准 json 库无法解析，直接崩溃。
# 方案：读取原始文本后先做正则预处理，再送入 json.loads()。
#   1) 去除 /* ... */ 多行注释（非贪婪，支持跨行）
#   2) 去除 // 单行注释（排除 URL 中 https:// 的误匹配）
#   3) 去除末尾多余逗号（trailing comma：},  /  ],）
#   4) 三重保险：预处理失败则原文再试，两者都失败才 ERROR
import re as _re

def _strip_jsonc(text):
    # Step1: 去除块注释 /* ... */
    text = _re.sub(r'/\*.*?\*/', '', text, flags=_re.DOTALL)
    # Step2: 去除行注释 // ...
    # 负向后视：排除 ://（URL协议头），同时保留字符串内的 //
    # 简单策略：去掉非字符串内的 //，覆盖 99% 实际场景
    text = _re.sub(r'(?<!:)(?<!https)//[^\n]*', '', text)
    # Step3: 去除 trailing comma（, 后紧跟 } 或 ]，中间可有空白/换行）
    text = _re.sub(r',\s*([}\]])', r'\1', text)
    return text

try:
    raw = open(config_file, 'r', encoding='utf-8').read()
except Exception as e:
    print(f"ERROR:read:{e}")
    import sys; sys.exit(0)

config = None
# 先尝试 JSONC 剥离后解析
try:
    config = __import__('json').loads(_strip_jsonc(raw))
except Exception:
    pass
# 降级：直接解析原文（标准 JSON 无注释场景）
if config is None:
    try:
        config = __import__('json').loads(raw)
    except Exception as e:
        print(f"ERROR:parse:{e}")
        import sys; sys.exit(0)

# json 和 sys 已在顶部 import，此处可直接使用

inbounds = config.get('inbounds', [])
if not isinstance(inbounds, list) or not inbounds:
    print("SKIP:no_inbounds")
    sys.exit(0)

# ── 自动检测配置类型 ──────────────────────────────────────────
# Sing-box: inbounds 使用 listen_port 字段；Xray: 使用 port 字段
sample = inbounds[0] if inbounds else {}
is_singbox = "listen_port" in sample
port_key   = "listen_port" if is_singbox else "port"
config_type = "singbox" if is_singbox else "xray"
print(f"TYPE:{config_type}")

fixed = False
for ib in inbounds:
    try:
        port_val = int(ib.get(port_key, 0))
    except (ValueError, TypeError):
        continue
    if port_val == target_port:
        current_listen = ib.get('listen', '')
        if current_listen == target_wg_ip:
            print(f"ALREADY_OK:{current_listen}")
        else:
            ib['listen'] = target_wg_ip  # [SEC-FIX] 严格绑定 WG 虚拟 IP
            fixed = True

if fixed:
    try:
        # [PERM v2.8] 写入前保存原始文件权限，写入后恢复，
        # 防止 open('w') 将 644 变成 600 导致 Xray 权限不足
        import os as _os
        orig_mode = _os.stat(config_file).st_mode
        with open(config_file, 'w', encoding='utf-8') as fh:
            json.dump(config, fh, indent=2, ensure_ascii=False)
        _os.chmod(config_file, orig_mode)
        print(f"FIXED:{config_file}")
    except Exception as e:
        print(f"WRITE_ERROR:{e}")
elif not fixed and "ALREADY_OK" not in (r := ""):
    # 没有匹配到目标端口
    print(f"NO_MATCH:port {target_port} not found in {config_type} config")
PYEOF
)
        local ctype; ctype=$(echo "$result" | grep "^TYPE:" | cut -d: -f2)
        [[ -n "$ctype" ]] && detected_type="$ctype"

        if echo "$result" | grep -q "^FIXED:"; then
            log_info "[$detected_type] 已修改 listen → \"${target_wg_ip}\"（严格绑定 WG 虚拟IP）: ${f}"
            any_fixed=true
        elif echo "$result" | grep -q "^ALREADY_OK:"; then
            log_info "[$detected_type] listen 字段已是 ${target_wg_ip}，无需修改: ${f}"
        elif echo "$result" | grep -q "^NO_MATCH:"; then
            log_warn "[$detected_type] 未在 ${f} 中找到端口 ${target_port} 的入站配置"
        elif echo "$result" | grep -q "^SKIP:"; then
            true  # 静默跳过（无 inbounds 字段的片段文件）
        elif echo "$result" | grep -q "^ERROR:\|^WRITE_ERROR:"; then
            log_warn "配置文件处理失败 (${f}): $(echo "$result" | grep -E "^(ERROR|WRITE_ERROR):" | cut -d: -f2-)"
        fi
    done

    # 将检测到的后端类型写入全局变量，供后续重启逻辑使用
    LUODI_PROXY_TYPE="$detected_type"

    # ── [B v2.9] 面板环境强提醒（文件修改后立即输出）────────────────
    # 即使文件修改成功，面板重启时也会重新生成 config.json 将修改覆盖。
    # 必须同时在面板 Web 界面完成同步修改，才能持久生效。
    if [[ "$panel_detected" == "true" ]]; then
        echo ""
        echo -e "  ${RED}╔══════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "  ${RED}║  ⚠⚠  重要：检测到面板环境（${panel_name}）— 必读！                 ║${NC}"
        echo -e "  ${RED}║                                                                    ║${NC}"
        echo -e "  ${RED}║  脚本已自动修改 config.json 的 listen 字段。                       ║${NC}"
        echo -e "  ${RED}║  但 ${panel_name} 面板重启时会从 SQLite 数据库重新生成 config.json  ║${NC}"
        echo -e "  ${RED}║  导致上述修改被覆盖，安全漏洞（Xray 重新暴露公网）再次出现！        ║${NC}"
        echo -e "  ${RED}║                                                                    ║${NC}"
        echo -e "  ${RED}║  【必做操作】请立即登录面板 Web 界面：                              ║${NC}"
        echo -e "  ${RED}║  ${panel_url_hint}                                                 ║${NC}"
        echo -e "  ${RED}║  → 入站列表 → 找到端口 ${target_port} 的入站 → 编辑               ║${NC}"
        echo -e "  ${RED}║  → 将「监听IP / Listen」字段改为：${target_wg_ip}                  ║${NC}"
        echo -e "  ${RED}║  → 保存并重启 Xray                                                 ║${NC}"
        echo -e "  ${RED}║                                                                    ║${NC}"
        echo -e "  ${RED}║  完成面板设置后，此节点的安全配置才真正持久生效。                   ║${NC}"
        echo -e "  ${RED}╚══════════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        if [[ "$AUTO_MODE" != "true" ]]; then
            local _pc
            read -rp "已知晓面板配置风险，是否继续？[y/N]: " _pc || true
            [[ "${_pc,,}" != "y" ]] && log_error "请先完成面板配置后重新运行脚本"
        else
            log_warn "--auto 模式：面板环境警告已记录，请部署完成后手动登录面板修改监听IP"
        fi
    fi

    # ── Step7: 重启代理服务（Xray / Sing-box 分支）────────────────
    if [[ "$any_fixed" == "true" ]]; then
        log_step "重启代理服务以使配置生效（检测类型: ${detected_type}）..."
        local restarted=false

        if [[ "$detected_type" == "singbox" ]]; then
            # Sing-box 服务名探测
            for svc in sing-box "sing-box@default" singbox; do
                if systemctl is-active --quiet "$svc" 2>/dev/null; then
                    if systemctl restart "$svc" 2>/dev/null; then
                        log_info "Sing-box 已重启（服务: ${svc}）✓"
                        restarted=true; break
                    fi
                fi
            done
        else
            # Xray 服务名探测
            for svc in xray xray-reality "xray@reality" xray-mack; do
                if systemctl is-active --quiet "$svc" 2>/dev/null; then
                    if systemctl restart "$svc" 2>/dev/null; then
                        log_info "Xray 已重启（服务: ${svc}）✓"
                        restarted=true; break
                    fi
                fi
            done
        fi

        # 最后尝试 SIGHUP（对 Xray 有效，Sing-box 不支持但无害）
        if [[ "$restarted" == "false" ]]; then
            local proxy_pid
            proxy_pid=$(pgrep -x xray 2>/dev/null | head -1 || \
                        pgrep -x sing-box 2>/dev/null | head -1 || true)
            if [[ -n "$proxy_pid" ]]; then
                kill -HUP "$proxy_pid" 2>/dev/null && \
                    log_info "已向代理进程 (PID:${proxy_pid}) 发送 SIGHUP 重载" && restarted=true
            fi
        fi

        if [[ "$restarted" == "false" ]]; then
            log_warn "代理自动重启失败，请手动执行: systemctl restart xray  或  systemctl restart sing-box"
            if [[ "$AUTO_MODE" != "true" ]]; then
                read -rp "请手动重启代理后按 [Enter] 继续: " || true
            fi
        fi

        # 二次验证：确认代理已绑定在 WG 虚拟 IP 上
        if [[ "$restarted" == "true" ]]; then
            sleep 2
            local new_addr new_host
            new_addr=$(ss -tlnp 2>/dev/null \
                | awk -v p=":${target_port}" '$0 ~ p"( |$)" {print $(NF-2); exit}' || true)
            new_host=$(echo "$new_addr" | sed 's/:[0-9]*$//' | tr -d '[]')
            if [[ "$new_host" == "$target_wg_ip" ]]; then
                log_info "✓ 代理现已严格绑定在 ${new_addr}（公网不可直连，安全）"
            else
                log_warn "代理监听地址为 ${new_addr:-未检测到}，预期 ${target_wg_ip}:${target_port}，请手动确认"
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
#     _wg::detect_mtu()   — [MTU v2.8] 从中转机探测到落地机的最佳 MTU
#     _wg::allocate_ip()  — 在中转机分配 10.100.0.N，peer_map 幂等复用
#     _wg::add_peer()     — 中转机热添加落地机 WG Peer + 直接写 wg0.conf
#     _wg::remove_peer()  — 按 LINK_ID 从中转机移除 WG Peer
#     _wg::setup_local()  — 落地机配置 wg0（本地执行）
# ══════════════════════════════════════════════════════════════════

# ──────────────────────────────────────────────────────────────────
# _wg::detect_mtu
#   [MTU v2.8] 从中转机向落地机发送带 DF 位的 ICMP 探测包，
#   阶梯式回退确定路径 MTU，计算 WireGuard 最佳 MTU 值。
#
#   探测逻辑：
#     · 从 1472 开始（1472+28=1500，标准以太网满载）
#     · 阶梯：1472→1432→1392→1352→1312→1280（步长40，覆盖PPPoE/VXLAN场景）
#     · WG_MTU = probe_size + 28(IP/ICMP头) - 60(WG封装) - 10(安全冗余)
#     · 公式推导：探测包净荷 probe_size，加 IP头28 = 实际以太网帧；
#       WG 封装开销 = UDP头8 + WG头32 + WG认证20 = 60B；
#       安全冗余 10B 对抗 ISP 二层封装（GRE/VXLAN 等叠加场景）
#     · 边界钳制：[1280, 1420]，超出则截断
#     · 探测失败/ping不通：保底 1380（CN2 GIA 已验证最优保守值）
#   调用时机：main() 在 _ssh::setup + _info::read_relay 之后，
#             _wg::allocate_ip 之前执行，结果写入 WG_MTU 全局变量。
#   可被环境变量覆盖：WG_MTU=1380 bash duijie.sh（跳过探测）
# ──────────────────────────────────────────────────────────────────
_wg::detect_mtu() {
    local target_ip="$1"
    local fallback=1380

    # 若用户已手动指定 WG_MTU，直接跳过探测
    if [[ -n "$WG_MTU" ]]; then
        log_info "WG MTU 已手动指定：${WG_MTU}（跳过自动探测）"
        return 0
    fi

    log_step "探测中转机→落地机路径 MTU（DF-ping 阶梯法）..."

    # 判断落地机是否为域名（DDNS），域名无法直接 ping DF 探测 ——
    # 但 ping 本身支持域名解析，直接传入即可，WG 链路上也用域名。
    # 若探测失败（超时/不通），直接使用保底值，不阻断主流程。

    local detected_mtu
    # 在中转机侧执行 DF-ping 探测（贴近真实链路）
    # ping 参数：-c1 单包 -W2 超时2s -M do 设置DF位 -s 指定数据负载大小
    # 各平台 DF 参数：Linux=-M do, macOS=-D（中转机均为 Linux）
    detected_mtu=$(_ssh::run "
set +e
TARGET='${target_ip}'
FALLBACK=${fallback}
best_mtu=\$FALLBACK
for size in 1472 1432 1392 1352 1312 1280; do
    if ping -c1 -W2 -M do -s \"\$size\" \"\$TARGET\" >/dev/null 2>&1; then
        # WG_MTU = probe_size + 28(IP/ICMP) - 60(WG封装) - 10(安全冗余)
        raw=\$(( size + 28 - 60 - 10 ))
        # 边界钳制 [1280, 1420]
        [ \$raw -gt 1420 ] && raw=1420
        [ \$raw -lt 1280 ] && raw=1280
        best_mtu=\$raw
        break
    fi
done
echo \$best_mtu
" 2>/dev/null || echo "$fallback")

    # 验证结果是纯数字且在合理范围
    if [[ "$detected_mtu" =~ ^[0-9]+$ ]] \
        && [[ "$detected_mtu" -ge 1280 ]] \
        && [[ "$detected_mtu" -le 1500 ]]; then
        WG_MTU="$detected_mtu"
        local tcpmss_preview=$(( detected_mtu - 40 ))
        log_info "MTU 探测完成：WG_MTU=${WG_MTU}  TCPMSS=${tcpmss_preview}（MTU-40）"
        if [[ "$detected_mtu" -ge 1400 ]]; then
            log_info "  └ 高质量线路（MTU≥1400），带宽利用率最优"
        elif [[ "$detected_mtu" -ge 1380 ]]; then
            log_info "  └ 标准 CN2 GIA 线路（MTU=${detected_mtu}），正常范围"
        else
            log_warn "  └ 低 MTU（${detected_mtu}），线路存在 PPPoE/隧道封装，已自动适配"
        fi
    else
        WG_MTU="$fallback"
        # [A v2.9] 探测失败时明确告警，而非静默回退
        echo ""
        echo -e "  ${YELLOW}╔══════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "  ${YELLOW}║  ⚠  MTU 自动探测失败，已使用保底值 WG_MTU=${WG_MTU}              ║${NC}"
        echo -e "  ${YELLOW}║                                                                    ║${NC}"
        echo -e "  ${YELLOW}║  可能原因：                                                        ║${NC}"
        echo -e "  ${YELLOW}║  · 落地机或中转机防火墙屏蔽了 ICMP 包（含 DF 标志探测包）          ║${NC}"
        echo -e "  ${YELLOW}║  · 落地机 IP 尚未可达（DNS未解析/防火墙/临时断网）                 ║${NC}"
        echo -e "  ${YELLOW}║                                                                    ║${NC}"
        echo -e "  ${YELLOW}║  若遇断流/掉速，请手动指定 MTU（在运行前设置环境变量）：            ║${NC}"
        echo -e "  ${YELLOW}║    WG_MTU=1360 bash duijie.sh   # 嵌套隧道场景推荐                 ║${NC}"
        echo -e "  ${YELLOW}║    WG_MTU=1280 bash duijie.sh   # 极保守，所有场景安全             ║${NC}"
        echo -e "  ${YELLOW}║    WG_MTU=1400 bash duijie.sh   # 高质量线路可尝试                 ║${NC}"
        echo -e "  ${YELLOW}║                                                                    ║${NC}"
        echo -e "  ${YELLOW}║  排查：检查落地机是否允许 ICMP in/out，中转机防火墙是否放行 ICMP   ║${NC}"
        echo -e "  ${YELLOW}╚══════════════════════════════════════════════════════════════════╝${NC}"
        echo ""
    fi
}

_wg::allocate_ip() {
    log_step "分配WireGuard虚拟IP（优先复用历史分配）..."
    local nodes_path="$RELAY_NODES"
    local link_id="$LINK_ID"

    local script
    script=$(python3 - << PYEOF
import json
nodes_path = $(python3 -c "import json; print(json.dumps('${nodes_path}'))")
link_id    = $(python3 -c "import json; print(json.dumps('${link_id}'))")

remote = f"""
import json, subprocess, re, sys, os

nodes_path = {json.dumps(nodes_path)}
link_id    = {json.dumps(link_id)}

# ── [IDEM v2.8] peer_map：LINK_ID → WG_IP 持久化映射 ──────────
# 作用：同一落地机重对接时复用历史 IP，避免 Peer 块无限累积。
# 路径与 wg0.conf 同目录，JSON 格式，独立于 nodes.json。
peer_map_path = "/etc/wireguard/peer_map.json"

def load_peer_map():
    try:
        return json.load(open(peer_map_path))
    except Exception:
        return {{}}

def save_peer_map(pm):
    try:
        os.makedirs(os.path.dirname(peer_map_path), exist_ok=True)
        with open(peer_map_path, "w") as f:
            json.dump(pm, f, indent=2)
    except Exception as e:
        print(f"[!] peer_map 保存失败: {{e}}", file=sys.stderr)

peer_map = load_peer_map()

# 优先复用 peer_map 中的历史 IP
if link_id in peer_map:
    cached_ip = peer_map[link_id]
    # 验证缓存 IP 格式合法
    if re.match(r"^10\\.100\\.0\\.\\d+$", cached_ip):
        print(cached_ip)
        sys.exit(0)

# ── 无历史记录，重新分配 ──────────────────────────────────────
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

# 从 peer_map 收集已用 IP（双保险，避免 nodes.json 被清空后重叠）
for lid, wip in peer_map.items():
    if lid == link_id:
        continue
    m = re.search("10\\\\.100\\\\.0\\\\.(\\\\d+)", wip)
    if m:
        used.add(int(m.group(1)))

# 从 wg show 收集运行时已用 IP
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
        new_ip = f"10.100.0.{{n}}"
        # 写入 peer_map 持久化
        peer_map[link_id] = new_ip
        save_peer_map(peer_map)
        print(new_ip)
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
WG_MTU="${WG_MTU}"

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
ip link set wg0 mtu "\${WG_MTU}" 2>/dev/null || true
echo "[✓] WG Peer已热添加: \${LUODI_WG_IP}（MTU=\${WG_MTU}）"

# 同步写入 wg0.conf [Interface] MTU（重启持久化）[C v2.7]
python3 - << PYEOF2
conf    = "/etc/wireguard/wg0.conf"
wg_mtu  = "${WG_MTU}"
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
    content = re.sub(r'(?m)^MTU\s*=\s*\d+', f'MTU = {wg_mtu}', content)
    open(conf, "w").write(content)
    print(f"[✓] wg0.conf MTU 已更新为 {wg_mtu}")
else:
    result = []; in_iface = inserted = False
    for line in lines:
        stripped = line.strip()
        if stripped == "[Interface]": in_iface = True
        if in_iface and not inserted and (stripped == "" or (stripped.startswith("[") and stripped != "[Interface]")):
            result.append(f"MTU = {wg_mtu}\n"); inserted = True; in_iface = False
        result.append(line)
    if not inserted: result.append(f"MTU = {wg_mtu}\n")
    open(conf, "w").writelines(result)
    print(f"[✓] wg0.conf [Interface] 已补写 MTU = {wg_mtu}")
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
wg_mtu   = "${WG_MTU}"   # [C v2.7] 可配置 MTU

def read_conf():
    try: return open(conf).read()
    except: return ""

content = read_conf()

if "[Interface]" not in content:
    content = f"""[Interface]
Address = {wg_ip}/24
PrivateKey = {privkey}
ListenPort = 51820
MTU = {wg_mtu}

"""
else:
    content = re.sub(r'(Address\s*=\s*)[\d./]+', rf'\g<1>{wg_ip}/24', content)
    if "MTU" not in content:
        content = re.sub(
            r'(\[Interface\][^\[]*?)(ListenPort\s*=\s*\d+)',
            rf'\g<1>\g<2>\nMTU = {wg_mtu}',
            content, flags=re.DOTALL)
    else:
        # 更新已有 MTU 值
        content = re.sub(r'(?m)^MTU\s*=\s*\d+', f'MTU = {wg_mtu}', content)

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
        ip link set wg0 mtu "${WG_MTU}" 2>/dev/null || true
        ip link set wg0 up
        log_info "落地机 wg0 已热更新"
    else
        wg-quick up wg0 2>/dev/null || {
            ip link add wg0 type wireguard
            wg setconf wg0 "$wg_conf"
            ip addr add "${assigned_ip}/24" dev wg0
            ip link set wg0 mtu "${WG_MTU}" 2>/dev/null || true
            ip link set wg0 up
        }
        log_info "落地机 wg0 已启动"
    fi

    systemctl enable wg-quick@wg0 2>/dev/null || true

    # ── [FW-FIX v2.6] 落地机防火墙放行 wg0 → LUODI_PORT ───────────
    # 问题：Oracle ARM / Debian 等系统默认 INPUT DROP，
    #       iptables DNAT 转发来的流量经 wg0 进入落地机后会被直接丢弃。
    # 修复：插入一条严格限定来源接口为 wg0 的 INPUT ACCEPT 规则，
    #       公网接口的同端口仍由默认策略拦截，攻击面不扩大。
    local fw_comment="luodi-fw-${LINK_ID}"
    # [SEC v3.0] DROP 兜底规则：阻断非 wg0 来源对代理端口的访问
    # 作用：即使 Xray 监听地址被面板/用户误改回 0.0.0.0，公网也无法扫到该端口
    # 规则顺序：ACCEPT(-I 插入链首) 先于 DROP(-A 追加链尾)，优先级正确
    local drop_comment="luodi-drop-${LINK_ID}"

    # 幂等：先删除旧的 ACCEPT 和 DROP 规则，再重新插入
    iptables -D INPUT -i wg0 -p tcp --dport "${LUODI_PORT}" \
        -m comment --comment "${fw_comment}" -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -i wg0 -p udp --dport "${LUODI_PORT}" \
        -m comment --comment "${fw_comment}" -j ACCEPT 2>/dev/null || true
    iptables -D INPUT ! -i wg0 -p tcp --dport "${LUODI_PORT}" \
        -m comment --comment "${drop_comment}" -j DROP 2>/dev/null || true

    # 规则1：允许来自 wg0 的流量（插入链首，最先匹配）
    iptables -I INPUT -i wg0 -p tcp --dport "${LUODI_PORT}" \
        -m comment --comment "${fw_comment}" -j ACCEPT 2>/dev/null \
        && log_info "落地机防火墙：已放行 wg0 TCP:${LUODI_PORT}（公网接口不受影响）" \
        || log_warn "落地机 iptables 规则写入失败，请手动放行 wg0 上的 TCP:${LUODI_PORT}"

    iptables -I INPUT -i wg0 -p udp --dport "${LUODI_PORT}" \
        -m comment --comment "${fw_comment}" -j ACCEPT 2>/dev/null \
        && log_info "落地机防火墙：已放行 wg0 UDP:${LUODI_PORT}" || true

    # 规则2：[SEC v3.0] 阻断一切非 wg0 来源的同端口访问（追加链尾）
    # · 覆盖场景：Xray 被改回 0.0.0.0、ZeroTier/Tailscale 等其他内网隧道绕行
    # · 说明：若系统 INPUT 默认策略为 DROP，本条规则冗余但无害；
    #         若默认策略为 ACCEPT（大多数非 Oracle 云），本条规则为必要保护
    iptables -A INPUT ! -i wg0 -p tcp --dport "${LUODI_PORT}" \
        -m comment --comment "${drop_comment}" -j DROP 2>/dev/null \
        && log_info "落地机防火墙：已阻断非wg0来源的 TCP:${LUODI_PORT}（二次暴露防护）" \
        || log_warn "DROP 兜底规则写入失败，建议手动确认落地机防火墙策略"

    # 持久化落地机防火墙规则
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save 2>/dev/null || true
    elif command -v iptables-save &>/dev/null; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi

    # UFW / Firewalld 兼容（静默，失败不影响主流程）
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -qi "active"; then
        # UFW 按接口放行：仅允许来自 wg0 的流量
        ufw allow in on wg0 to any port "${LUODI_PORT}" proto tcp 2>/dev/null || true
        ufw allow in on wg0 to any port "${LUODI_PORT}" proto udp 2>/dev/null || true
        log_info "落地机 UFW：已放行 wg0 上的 ${LUODI_PORT}/tcp+udp"
    fi

    # ── [PR-FIX v2.6] 策略路由：WG 虚拟 IP 发出的包强制走 wg0 ────────
    # 问题描述：落地机 Xray 处理完请求后，响应包源 IP 为 10.100.0.N（WG IP），
    #           若无策略路由，Linux 默认路由表可能将其从公网接口转出，
    #           导致非对称路由，中转机无法收到回包，连接失败。
    # 解决方案：为 WG 虚拟 IP 建立专用路由表（table 200），强制默认出口为 wg0。
    local wg_ip_clean="${assigned_ip}"  # e.g. 10.100.0.2
    local rt_table=200

    # 幂等清理旧规则
    ip rule del from "${wg_ip_clean}" table ${rt_table} 2>/dev/null || true
    # 建立专用路由表：默认出口为 wg0
    ip route replace default dev wg0 table ${rt_table} 2>/dev/null \
        && log_info "策略路由 table ${rt_table}：默认出口 → wg0 ✓" \
        || log_warn "策略路由 table ${rt_table} 写入失败，回包可能非对称"
    # 绑定策略：源 IP 为 WG 虚拟 IP 时使用该路由表
    ip rule add from "${wg_ip_clean}" table ${rt_table} priority 100 2>/dev/null \
        && log_info "策略路由规则：from ${wg_ip_clean} → table ${rt_table} ✓" \
        || log_warn "策略路由规则写入失败（ip rule add），请手动检查"

    # 持久化策略路由（写入 wg-quick PostUp/PreDown 钩子）
    # [PREDOWN v2.8] PreDown 与 PostUp 严格对称：
    #   · PostUp  : 建立路由表 + 添加策略规则
    #   · PreDown : 删除策略规则 + 删除路由表条目（防止多次重装后 ip rule 堆积）
    python3 - << PPYEOF
conf   = "${wg_conf}"
wg_ip  = "${wg_ip_clean}"
table  = ${rt_table}

# PostUp：建路由表 → 加策略规则（顺序不可颠倒，路由表必须先存在）
postup  = (f"PostUp = ip route replace default dev wg0 table {table}; "
           f"ip rule add from {wg_ip} table {table} priority 100")
# PreDown：删策略规则 → 删路由表（[PREDOWN v2.8] 与 PostUp 完全对称）
predown = (f"PreDown = ip rule del from {wg_ip} table {table} 2>/dev/null || true; "
           f"ip route del default dev wg0 table {table} 2>/dev/null || true")

import re
try:
    content = open(conf).read()
except FileNotFoundError:
    exit(0)

# 移除旧的策略路由钩子行（PostUp/PreDown 含 table 关键词）
lines = [l for l in content.splitlines(keepends=True)
         if not (l.strip().startswith(("PostUp", "PreDown")) and f"table {table}" in l)]

# 在 [Interface] 节末尾、第一个 [Peer] 之前插入
result = []; inserted = False; in_iface = False
for line in lines:
    if line.strip() == "[Interface]":
        in_iface = True
    if in_iface and not inserted and line.strip().startswith("[Peer]"):
        result.append(postup  + "\n")
        result.append(predown + "\n")
        result.append("\n")
        inserted = True
    result.append(line)

if not inserted:
    result.append("\n" + postup  + "\n")
    result.append(predown + "\n")

open(conf, "w").writelines(result)
print(f"[✓] wg0.conf 已写入策略路由钩子（PostUp/PreDown table {table}，对称清理）")
PPYEOF

    log_info "落地机WireGuard配置完成（${assigned_ip} ←→ 中转机 10.100.0.1）"
}

# ══════════════════════════════════════════════════════════════════
# §6  MODULE: fw
#     _fw::dnat_add()    — 中转机配置 iptables DNAT + MASQUERADE
#                          + TCPMSS 双重钳制（clamp-to-pmtu + MTU-40精准值）
#                          + FORWARD + IPv6泄漏防护
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
    local wg_mtu="$WG_MTU"
    # [MTU v2.8] TCPMSS = MTU - 40（IPv4: TCP头20B + IP头20B = 40B，精准计算）
    # 旧版 MTU-100 过于保守（多减了60B导致吞吐量损失）
    # 配合 clamp-to-pmtu 双重保障，覆盖 CN2 GIA 屏蔽 ICMP 的场景
    local tcpmss=$(( WG_MTU - 40 ))

    _ssh::pipe << SHEOF
set -e
LINK_ID="${link_id}"
RELAY_PORT="${relay_port}"
WG_IP="${wg_ip}"
LUODI_PORT="${luodi_port}"
WG_MTU="${wg_mtu}"
TCPMSS="${tcpmss}"
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
# 规则2：set-mss MTU-40（精准值，覆盖 CN2 GIA 屏蔽 ICMP 场景）
# [MTU v2.8] TCPMSS = MTU-40，比旧版 MTU-100 更精准，减少吞吐量损耗
iptables -t mangle -A FORWARD \
    -p tcp --tcp-flags SYN,RST SYN -o wg0 \
    -m comment --comment "\${COMMENT}" \
    -j TCPMSS --clamp-mss-to-pmtu

iptables -t mangle -A FORWARD \
    -p tcp --tcp-flags SYN,RST SYN -o wg0 \
    -m tcpmss --mss \$((TCPMSS+1)):65535 \
    -m comment --comment "\${COMMENT}" \
    -j TCPMSS --set-mss "\${TCPMSS}"

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
echo "[✓] mangle TCPMSS clamp-to-pmtu + set-mss \${TCPMSS} 双重钳制（MTU=\${WG_MTU}，TCPMSS=MTU-40）"
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

# ── [D v2.9] 持久化增强：无论 netfilter-persistent 是否已存在都强制 save ──
# 旧版仅在未安装时才触发安装+save，已有时也需要强制更新。
# 同时验证 wg-quick@wg0 是否 enable，防止中转机重启后 WG 不起来。

# Step1：确保 netfilter-persistent / iptables-save 持久化工具可用
if ! command -v netfilter-persistent &>/dev/null; then
    echo "[→] 安装 iptables-persistent（确保重启后规则不丢失）..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        iptables-persistent netfilter-persistent 2>/dev/null \
    || yum install -y -q iptables-services 2>/dev/null \
    || true
fi

# Step2：无论安装前是否已存在，均强制执行一次 save（[D v2.9] 核心修复）
if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save 2>/dev/null \
        && echo "[✓] iptables 已持久化 (netfilter-persistent save)" || true
elif command -v iptables-save &>/dev/null; then
    mkdir -p /etc/iptables
    iptables-save  > /etc/iptables/rules.v4 2>/dev/null || true
    ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
    # 确保 systemd 恢复服务存在
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
        echo "[✓] iptables 已持久化 (rules.v4 + systemd restore 服务，首次创建)"
    else
        echo "[✓] iptables 已持久化 (rules.v4 已更新)"
    fi
else
    echo "[!] 无持久化工具可用，中转机重启后 iptables 规则将丢失！"
    echo "[!] 请手动安装: apt-get install iptables-persistent"
fi

# Step3：确保中转机 wg-quick@wg0 已 enable（防止重启后 WG 隧道不起）
if systemctl is-enabled wg-quick@wg0 &>/dev/null 2>/dev/null; then
    echo "[✓] wg-quick@wg0 已设置开机自启"
else
    systemctl enable wg-quick@wg0 2>/dev/null \
        && echo "[✓] wg-quick@wg0 已设置开机自启（[D v2.9] 自动 enable）" \
        || echo "[!] wg-quick@wg0 enable 失败，请手动执行: systemctl enable wg-quick@wg0"
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

# [B v2.7] ss 端口扫描健壮性修复：
# · 旧版用 addr.rsplit(":",1)[-1] 可能被 IPv6 ":::PORT" 误解析
# · 旧版 parts[4] 硬编码列索引，列宽变化时取到错误字段
# → 新版用 re.search(r':(\d+)$', addr) 提取末尾端口号，
#   兼容：0.0.0.0:P / *:P / [::]:P / :::P / [::1]:P
#   同时扩大候选列范围（parts[-2] 和 parts[3..5]），规避列数变化
import re as _re
for flag in ["-tlnp", "-ulnp"]:
    try:
        out = subprocess.check_output(["ss", flag], text=True, timeout=5)
        for line in out.splitlines()[1:]:
            parts = line.split()
            # ss 输出典型列：Netid State Recv-Q Send-Q Local-Address:Port Peer-Address:Port
            # Local Address 可能在第 4 或第 5 列（有无 Process 列时不同）
            # 安全做法：扫描所有列，用正则提取以 :数字 结尾的那个
            for col in parts:
                m = _re.search(r':(\d+)$', col)
                if m:
                    try:
                        used.add(int(m.group(1)))
                    except ValueError:
                        pass
                    break  # 每行只取第一个匹配的地址列
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
wg_mtu        = int("${WG_MTU}")   # [C v2.7] bash 展开传入

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
    "// MTU-Note": f"WireGuard MTU={wg_mtu}, TCPMSS={int(wg_mtu)-40}（MTU-40精准值）. 若遇掉速可调低客户端MTU或脚本顶部 WG_MTU 变量",
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
        { echo "# LINK_ID=${LINK_ID}  label=${NODE_LABEL}  $(date '+%Y-%m-%d')  MTU=${WG_MTU}/TCPMSS=$(( WG_MTU - 40 ))"
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

    # ── [TCP v3.0] 双路 TCP 握手验证（精度升级）───────────────────────
    # 路径1: 中转机 → 127.0.0.1:RELAY_PORT → DNAT → WG → 落地机 Xray
    #        验证：iptables DNAT 规则 + WireGuard 隧道 + Xray 端口监听
    # 路径2: 中转机 → LUODI_WG_ASSIGNED_IP:LUODI_PORT（WG 内网直连）
    #        验证：WireGuard 隧道可达性 + Xray 端口监听（绕过 DNAT 层）
    # 组合结论：
    #   路径1✓ + 路径2✓ → 全链路正常
    #   路径1✗ + 路径2✓ → WG+Xray 正常，DNAT 规则有问题（精准定位）
    #   路径1✓ + 路径2✗ → DNAT 路径通，但 WG 内网直连有问题（路由问题）
    #   路径1✗ + 路径2✗ → Xray 未响应（最常见故障），进入软阻断
    log_step "中转机侧 TCP 双路握手验证（DNAT路径 + WG内网直连）..."
    local relay_port="$RELAY_ASSIGNED_PORT"
    local wg_target_ip="$LUODI_WG_ASSIGNED_IP"
    local wg_target_port="$LUODI_PORT"
    local tcp_ok=false
    local tcp_path1=false   # 路径1：127.0.0.1:RELAY_PORT（含 DNAT）
    local tcp_path2=false   # 路径2：WG_IP:LUODI_PORT（WG 内网直连）

    local relay_tcp_result
    relay_tcp_result=$(_ssh::run "
set +e
PORT1=${relay_port}
PORT2_IP=${wg_target_ip}
PORT2=${wg_target_port}

_tcp_check() {
    local host=\"\$1\" port=\"\$2\" label=\"\$3\"
    if command -v nc &>/dev/null; then
        if nc -z -w 5 \"\$host\" \"\$port\" 2>/dev/null; then
            echo \"TCP_OK:\${label}:nc\"
        else
            echo \"TCP_FAIL:\${label}:nc\"
        fi
    elif (echo '' > /dev/tcp/\${host}/\${port}) 2>/dev/null; then
        echo \"TCP_OK:\${label}:bash_tcp\"
    else
        echo \"TCP_FAIL:\${label}:no_tool\"
    fi
}

_tcp_check 127.0.0.1    \"\$PORT1\"    path1
_tcp_check \"\$PORT2_IP\" \"\$PORT2\"    path2
" 2>/dev/null || printf 'TCP_FAIL:path1:ssh_error\nTCP_FAIL:path2:ssh_error\n')

    # 解析双路结果
    local p1_result p2_result p1_tool p2_tool
    p1_result=$(echo "$relay_tcp_result" | grep ":path1:" | head -1)
    p2_result=$(echo "$relay_tcp_result" | grep ":path2:" | head -1)
    p1_tool=$(echo "$p1_result" | cut -d: -f3)
    p2_tool=$(echo "$p2_result" | cut -d: -f3)

    echo "$p1_result" | grep -q "^TCP_OK:" && tcp_path1=true
    echo "$p2_result" | grep -q "^TCP_OK:" && tcp_path2=true

    if [[ "$tcp_path1" == "true" && "$tcp_path2" == "true" ]]; then
        log_info "TCP 双路验证 ✓✓ 全链路正常"
        log_info "  路径1 DNAT链路   ✓  (工具: ${p1_tool})"
        log_info "  路径2 WG内网直连 ✓  (工具: ${p2_tool})"
        tcp_ok=true
    elif [[ "$tcp_path1" == "false" && "$tcp_path2" == "true" ]]; then
        log_warn "路径2✓(WG直连通) 路径1✗(DNAT链路失败)"
        log_warn "  → WireGuard+Xray 正常，问题在 iptables DNAT 规则"
        log_warn "  → 检查: iptables -t nat -S PREROUTING | grep ${LINK_ID}"
        tcp_ok=true   # 核心服务通，DNAT 问题单独告警
    elif [[ "$tcp_path1" == "true" && "$tcp_path2" == "false" ]]; then
        log_warn "路径1✓(DNAT链路通) 路径2✗(WG直连失败)"
        log_warn "  → DNAT 路径可用，但中转机→落地机 WG 内网直连异常"
        log_warn "  → 检查落地机 ip rule show 和 wg0 接口状态"
        tcp_ok=true   # 用户侧 DNAT 路径通即可用
    else
        # 两路均失败 ─── 软阻断逻辑
        local p1_reason; p1_reason=$(echo "$p1_result" | cut -d: -f3)
        if [[ "$p1_reason" == "no_tool" || "$p1_reason" == "ssh_error" ]]; then
            log_warn "中转机缺少 nc 且 bash /dev/tcp 不可用，跳过 TCP 握手验证"
        else
            if [[ "$wg_ok" == "true" ]]; then
                echo ""
                echo -e "  ${RED}╔══════════════════════════════════════════════════════════════════╗${NC}"
                echo -e "  ${RED}║  ✗  双路 TCP 握手均失败：WG 隧道通，但 Xray/Sing-box 未响应   ║${NC}"
                echo -e "  ${RED}║                                                                    ║${NC}"
                echo -e "  ${RED}║  路径1（DNAT）  127.0.0.1:${relay_port}               ✗          ║${NC}"
                echo -e "  ${RED}║  路径2（直连）  ${wg_target_ip}:${wg_target_port}     ✗          ║${NC}"
                echo -e "  ${RED}║                                                                    ║${NC}"
                echo -e "  ${RED}║  排查建议（按概率排序）：                                          ║${NC}"
                echo -e "  ${RED}║  1. Xray/Sing-box 未启动或已崩溃                                   ║${NC}"
                echo -e "  ${RED}║     → systemctl status xray / systemctl status sing-box             ║${NC}"
                echo -e "  ${RED}║  2. Xray listen 未绑定 WG IP ${LUODI_WG_ASSIGNED_IP}              ║${NC}"
                echo -e "  ${RED}║     → ss -tlnp | grep ${LUODI_PORT}                                ║${NC}"
                echo -e "  ${RED}║  3. 落地机防火墙拦截 wg0 → TCP:${LUODI_PORT}                       ║${NC}"
                echo -e "  ${RED}║     → iptables -L INPUT -n -v | grep ${LUODI_PORT}                  ║${NC}"
                echo -e "  ${RED}╚══════════════════════════════════════════════════════════════════╝${NC}"
                echo ""
            else
                echo ""
                echo -e "  ${RED}╔══════════════════════════════════════════════════════════════════╗${NC}"
                echo -e "  ${RED}║  ✗  全链路失败：WG 隧道未建立 + 双路 TCP 握手失败               ║${NC}"
                echo -e "  ${RED}║  请先排查 WireGuard 隧道（UDP:${RELAY_WG_PORT} 是否放行）         ║${NC}"
                echo -e "  ${RED}╚══════════════════════════════════════════════════════════════════╝${NC}"
                echo ""
            fi
            # 软阻断：询问用户是否强制继续
            if [[ "$AUTO_MODE" != "true" ]]; then
                local _fc
                read -rp "链路验证失败，强制继续生成节点链接？[y/N]: " _fc || true
                [[ "${_fc,,}" != "y" ]] && log_error "对接已中止。请修复上述问题后重新运行脚本"
                log_warn "用户强制继续——节点可能暂时不可用，待落地机代理就绪后自动恢复"
            else
                log_warn "--auto 模式：TCP 握手失败，强制继续（请事后检查落地机代理状态）"
            fi
        fi
    fi

    # ── [D v2.7] 落地机侧深度验证：VLESS/Reality TLS 握手探测 ─────
    # 目的：确认 iptables DNAT → WireGuard → 落地机 Xray 全链路已打通。
    # 方法：向中转机分配的入站端口发送 TLS ClientHello，
    #       若收到 TLS ServerHello（含 Reality 公钥），说明链路已通。
    # 工具：优先用 curl（--tls-max），不可用时降级为 openssl s_client。
    log_step "深度验证：探测 VLESS/Reality TLS 握手链路..."
    local relay_host; relay_host=$(ip_for_url "$RELAY_IP")
    local deep_ok=false

    if command -v curl &>/dev/null; then
        # curl 发 HTTPS 请求触发 TLS 握手；Reality 会拒绝非合法 VLESS 流量，
        # 但只要收到 TCP 连接+TLS ServerHello 即说明链路层畅通（exit 35/60 均可）
        local curl_exit
        curl --silent --max-time 8 --connect-timeout 6 \
             --tls-max 1.3 --tlsv1.3 \
             --resolve "${LUODI_SNI}:${RELAY_ASSIGNED_PORT}:${RELAY_IP}" \
             "https://${LUODI_SNI}:${RELAY_ASSIGNED_PORT}/" \
             -o /dev/null 2>/dev/null
        curl_exit=$?
        # exit 35 = SSL connect error（Reality 正常拒绝），说明 TCP+TLS 握手到达落地机
        # exit 60 = SSL cert verification failed（同理可接受）
        # exit  0 = 意外成功（更好）
        if [[ "$curl_exit" -eq 0 || "$curl_exit" -eq 35 || "$curl_exit" -eq 60 ]]; then
            log_info "深度验证 ✓ 链路畅通（curl TLS握手到达落地机，Reality 正确响应）"
            deep_ok=true
        else
            log_warn "深度验证：curl 退出码 ${curl_exit}（可能链路不通，或 SNI 不匹配）"
        fi
    elif command -v openssl &>/dev/null; then
        # openssl s_client fallback：仅测试 TCP + TLS 握手
        local ssl_out
        ssl_out=$(echo "" | timeout 8 openssl s_client \
            -connect "${RELAY_IP}:${RELAY_ASSIGNED_PORT}" \
            -servername "${LUODI_SNI}" \
            -brief 2>&1 || true)
        if echo "$ssl_out" | grep -qiE "CONNECTED|Certificate|SERVER_TEMP_KEY"; then
            log_info "深度验证 ✓ 链路畅通（openssl 握手到达落地机）"
            deep_ok=true
        else
            log_warn "深度验证：openssl 未收到握手响应（可能链路不通）"
        fi
    else
        log_warn "深度验证：curl 和 openssl 均不可用，跳过协议层验证（仅 WG ping 确认）"
    fi

    if [[ "$deep_ok" == "false" && "$wg_ok" == "true" && "$tcp_ok" == "false" ]]; then
        log_warn "WG 隧道已通但 TLS/TCP 握手均失败，诊断优先级："
        log_warn "  1. 落地机 Xray/Sing-box 未启动 / 端口监听异常"
        log_warn "  2. _auto_fix_xray_listen 修复后代理未正确重启"
        log_warn "  3. SNI 配置错误（当前 SNI: ${LUODI_SNI}）"
        log_warn "  4. 面板环境导致 listen 绑定被覆盖（见上方面板警告）"
    elif [[ "$deep_ok" == "false" && "$tcp_ok" == "true" ]]; then
        # TCP 通但 TLS 失败 = Xray 响应了但 Reality 握手有问题
        log_warn "TCP 已通但 TLS 握手失败 —— Xray 正在监听，但 Reality 配置可能有误"
        log_warn "  · SNI 不匹配（当前: ${LUODI_SNI}），或公钥/ShortID 不正确"
    fi
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
peer_map_path = "/etc/wireguard/peer_map.json"

# 清理 nodes.json
try:
    nd = json.load(open(nodes_path))
    nd.get("nodes", {{}}).pop(del_lid, None)
    with open(nodes_path, "w") as f:
        json.dump(nd, f, indent=2, ensure_ascii=False)
    print(f"[OK] nodes.json 已移除: {{del_lid}}")
except Exception as e:
    print(f"[!] 清理 nodes.json 失败: {{e}}")

# [IDEM v2.8] 同步清理 peer_map.json（释放 WG IP 供重用）
try:
    pm = json.load(open(peer_map_path))
    if del_lid in pm:
        freed_ip = pm.pop(del_lid)
        with open(peer_map_path, "w") as f:
            json.dump(pm, f, indent=2)
        print(f"[OK] peer_map.json 已释放 WG IP: {{freed_ip}}")
except Exception:
    pass  # peer_map 不存在时静默忽略
"""
print(remote)
PYEOF
)
    echo "$script" | _ssh::pipe_py || log_warn "nodes.json 远端清理失败，请手动检查"

    # ── [SEC v3.0] 清理落地机 iptables 规则（luodi-fw + luodi-drop）────
    # 删节点时同步移除本节点的 ACCEPT 和 DROP 兜底规则，防止孤立规则堆积
    local fw_cmt="luodi-fw-${del_lid}"
    local drop_cmt="luodi-drop-${del_lid}"

    # 幂等删除：按 comment 精准匹配，不影响其他节点规则
    iptables -D INPUT -i wg0 -p tcp -m comment --comment "${fw_cmt}" \
        -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -i wg0 -p udp -m comment --comment "${fw_cmt}" \
        -j ACCEPT 2>/dev/null || true
    iptables -D INPUT ! -i wg0 -p tcp -m comment --comment "${drop_cmt}" \
        -j DROP 2>/dev/null || true
    log_info "落地机防火墙规则已清理（${fw_cmt} / ${drop_cmt}）"

    # 持久化（落地机侧）
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save 2>/dev/null || true
    elif command -v iptables-save &>/dev/null; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi

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
    echo -e "${CYAN}${BOLD}  ✓ 对接完成  duijie.sh v3.0  (WireGuard版，单次解密)${NC}"
    log_sep
    echo ""
    echo -e "  ${BOLD}流量路径：${NC}"
    echo -e "  客户端 ──[VLESS+Reality]──▶ ${CYAN}${RELAY_IP}:${RELAY_ASSIGNED_PORT}${NC}"
    echo -e "  ──[iptables DNAT TCP+UDP]──[WireGuard wg0]──▶ ${CYAN}${LUODI_WG_ASSIGNED_IP}:${LUODI_PORT}${NC}"
    echo -e "  ──[落地机 Xray ${LUODI_NETWORK}]──▶ ${LUODI_IP} ──▶ 🌐 互联网"
    echo ""
    echo -e "  ${YELLOW}▲ 消除双重加密：Reality握手仅在落地机完成，中转机零协议开销${NC}"
    echo -e "  ${YELLOW}▲ MTU=${WG_MTU}（自适应探测）/ TCPMSS=$(( WG_MTU - 40 ))（MTU-40精准值）若掉速可手动指定 WG_MTU=XXXX${NC}"
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
    echo -e "${CYAN}║        节点管理  duijie.sh v3.0  WireGuard版        ║${NC}"
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
    echo -e "${CYAN}║  duijie.sh  v3.0  —  WireGuard 隧道对接（单次解密）        ║${NC}"
    echo -e "${CYAN}║  落地机IP对外 · DNAT TCP/UDP · MTU自适应 · 固定节点         ║${NC}"
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

    # 3. [MTU v2.9] 自动探测最佳 MTU（在中转机侧执行 DF-ping）
    #    · 若 WG_MTU 已由环境变量指定，直接跳过探测
    #    · 探测结果写入 WG_MTU 全局变量，后续所有模块均使用该值
    #    · 目标 IP：落地机（实际链路即中转机→落地机方向）
    _wg::detect_mtu "$LUODI_IP"
    # 探测失败/跳过时保底值
    WG_MTU="${WG_MTU:-1380}"
    log_info "WireGuard MTU = ${WG_MTU}  TCPMSS = $(( WG_MTU - 40 ))（MTU-40）"

    # 4. WireGuard 双端配置
    _wg::allocate_ip        # 中转机分配 10.100.0.N（peer_map 幂等复用）

    # [SEC-FIX v2.6] WG IP 已分配，现在执行延迟的 Xray listen 绑定修复。
    # _info::_ensure_xray_listen 在 read_luodi 阶段只设标志，此处真正写入配置。
    if [[ "$_XRAY_LISTEN_NEEDS_FIX" == "true" ]]; then
        log_step "执行 Xray listen 安全绑定（绑定至 ${LUODI_WG_ASSIGNED_IP}）..."
        _info::_auto_fix_xray_listen "${LUODI_WG_ASSIGNED_IP}"
        _XRAY_LISTEN_NEEDS_FIX=false
    fi

    _wg::add_peer           # 中转机热添加落地机 WG Peer
    _wg::setup_local        # 落地机配置 wg0（同时放行落地机防火墙 wg0→LUODI_PORT）

    # 5. 端口分配 + iptables DNAT
    _port::allocate         # 分配入站端口（ss 冲突检测）
    _fw::dnat_add           # DNAT + MASQUERADE + TCPMSS（MTU-40）+ UFW/Firewalld

    # 6. 连通性验证（WG ping + 中转机侧 TCP 握手 + TLS 深度验证）
    _check::connectivity

    # 7. 节点标签
    if [[ "$AUTO_MODE" != "true" ]]; then
        local i
        read -rp "节点标签 [落地-${LUODI_IP}]: " i || true
        NODE_LABEL="${i:-落地-${LUODI_IP}}"
    else
        NODE_LABEL="落地-${LUODI_IP}"
    fi

    # 8. 生成链接（VLESS + JSON），保存，打印摘要
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
