#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════════╗
# ║  luodi.sh  v6.0  —  落地机信息收集脚本（WireGuard 版）              ║
# ╚══════════════════════════════════════════════════════════════════════╝
#
# 功能（仅做以下三件事）：
#   1. 读取落地机上已有代理软件（Xray / Sing-box）的 Reality 参数
#   2. 安装 WireGuard，生成 wg0 密钥对（不配置 wg0，由 duijie.sh 完成）
#   3. 输出 /root/xray_luodi_info.txt 和 /tmp/luodi_export.json
#
# 不做的事：
#   · 不修改 xray/sing-box 配置（由 duijie.sh 负责）
#   · 不配置 iptables（由 duijie.sh 负责）
#   · 不配置 WireGuard peers（由 duijie.sh 负责）
#   · 不 SSH 连接中转机（除 --reset 时用户主动触发的清理流程）
#
# 用法：
#   bash luodi.sh              # 标准交互流程
#   bash luodi.sh --status     # 仅查看当前状态
#   bash luodi.sh --refresh    # 重新读取代理参数（保留 WG 密钥）
#   bash luodi.sh --reset      # 完全重置（交互确认）
#   bash luodi.sh --check      # 检查 export.json 与实际配置一致性
#
# 嗅探优先级：
#   1. mack-a v2ray-agent Xray  (/etc/v2ray-agent/xray/conf/)
#   2. mack-a Sing-box          (/usr/local/etc/sing-box/config.json)
#   3. 独立 Sing-box            (/etc/sing-box/ 等)
#   4. x-ui / 3x-ui SQLite      (/etc/x-ui/x-ui.db 等)
#   5. 手动输入
# ══════════════════════════════════════════════════════════════════════

set -euo pipefail
trap 'echo -e "\033[0;31m[✗]\033[0m 脚本在第 $LINENO 行意外退出，请检查上方错误信息" >&2' ERR

# ══════════════════════════════════════════════════════════════════════
# §0  颜色 & 日志
# ══════════════════════════════════════════════════════════════════════
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log_info()  { echo -e "${GREEN}[✓]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
log_error() { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }
log_step()  { echo -e "${CYAN}[→]${NC} $*"; }
log_sep()   { echo -e "${CYAN}$(printf '─%.0s' {1..64})${NC}"; }

# ══════════════════════════════════════════════════════════════════════
# §1  常量 & 全局变量
# ══════════════════════════════════════════════════════════════════════
LUODI_VERSION="6.0"
INFO_FILE="/root/xray_luodi_info.txt"
EXPORT_JSON="/tmp/luodi_export.json"
WG_KEY_FILE="/etc/wireguard/luodi_wg.key"
WG_PUB_FILE="/etc/wireguard/luodi_wg.pub"

# 嗅探到的参数（全局）
LUODI_IP=""
LUODI_PORT=""
LUODI_UUID=""
LUODI_PUBKEY=""
LUODI_SHORTID=""
LUODI_SNI=""
LUODI_NETWORK="tcp"
LUODI_XHTTP_PATH="/"
LUODI_XHTTP_HOST=""
LUODI_XHTTP_MODE="auto"
LUODI_WS_PATH="/"
LUODI_WS_HOST=""
LUODI_GRPC_SERVICE=""
LUODI_WG_PUBKEY=""
LUODI_WG_PRIVKEY=""
LUODI_BACKEND_TYPE=""
LUODI_SOURCE_FILE=""

# 上次对接记录（来自 info.txt 中 duijie.sh 写入的段落）
_SAVED_RELAY_IP=""
_SAVED_RELAY_SSH_PORT="22"
_SAVED_RELAY_SSH_USER="root"

# ══════════════════════════════════════════════════════════════════════
# §2  基础工具
# ══════════════════════════════════════════════════════════════════════

check_root() {
    if [[ $EUID -ne 0 ]]; then log_error "请使用 root 权限运行"; fi
    command -v python3 &>/dev/null || log_error "python3 未找到，请安装: apt-get install -y python3"
}

detect_oracle() {
    # 甲骨文云默认 iptables 策略为 DROP，WireGuard 流量可能被拦截
    if curl -s --connect-timeout 2 http://169.254.169.254/opc/v1/instance/ &>/dev/null \
        || [[ -f /etc/oracle-cloud-agent/plugins ]] \
        || grep -qi "oracle" /sys/class/dmi/id/chassis_vendor 2>/dev/null; then
        echo ""
        echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║  ⚠  检测到甲骨文云（Oracle Cloud）                          ║${NC}"
        echo -e "${YELLOW}║  默认 iptables INPUT 策略为 DROP，WireGuard UDP 需要手动放行 ║${NC}"
        echo -e "${YELLOW}║  sudo iptables -I INPUT -p udp -j ACCEPT                    ║${NC}"
        echo -e "${YELLOW}║  或在安全组（Security List）添加入站 UDP 0.0.0.0/0          ║${NC}"
        echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
    fi
}

get_public_ip() {
    local ip
    # 依次尝试多个服务，任一成功即返回
    ip=$(curl -s4 --connect-timeout 5 https://api.ipify.org 2>/dev/null || true)
    [[ -z "$ip" ]] && ip=$(curl -s4 --connect-timeout 5 https://ifconfig.me 2>/dev/null || true)
    [[ -z "$ip" ]] && ip=$(curl -s4 --connect-timeout 5 https://checkip.amazonaws.com 2>/dev/null \
        | tr -d '[:space:]' || true)
    [[ -z "$ip" ]] && ip=$(curl -s --connect-timeout 5 https://api6.ipify.org 2>/dev/null || true)
    echo "${ip:-未知}"
}

# ══════════════════════════════════════════════════════════════════════
# §3  WireGuard 安装 & 密钥管理
# ══════════════════════════════════════════════════════════════════════

install_wireguard() {
    if command -v wg &>/dev/null && command -v wg-quick &>/dev/null; then
        log_info "WireGuard 已安装（$(wg --version 2>/dev/null | head -1 || echo 'ok')）"
        return 0
    fi

    log_step "安装 WireGuard..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq 2>/dev/null || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard wireguard-tools 2>/dev/null \
            || log_error "WireGuard 安装失败，请手动执行: apt-get install -y wireguard"
    elif command -v yum &>/dev/null; then
        yum install -y epel-release 2>/dev/null || true
        yum install -y wireguard-tools 2>/dev/null \
            || log_error "WireGuard 安装失败，请手动执行: yum install -y wireguard-tools"
    else
        log_error "不支持的包管理器，请手动安装 wireguard-tools"
    fi

    command -v wg &>/dev/null || log_error "WireGuard 安装后仍未找到 wg 命令"
    log_info "WireGuard 安装成功"
}

backup_wg_key() {
    # 备份旧密钥到 /root/.luodi_wg_key_backup（含时间戳）
    if [[ -f "$WG_KEY_FILE" ]]; then
        local bak="/root/.luodi_wg_key_backup.$(date +%Y%m%d_%H%M%S)"
        cp "$WG_KEY_FILE" "$bak" 2>/dev/null || true
        [[ -f "$WG_PUB_FILE" ]] && cp "$WG_PUB_FILE" "${bak}.pub" 2>/dev/null || true
        log_info "旧 WG 密钥已备份至 $bak"
    fi
}

manage_wg_keys() {
    local force_new="${1:-false}"

    if [[ "$force_new" == "false" && -f "$WG_KEY_FILE" && -s "$WG_KEY_FILE" ]]; then
        # 复用已有密钥
        LUODI_WG_PRIVKEY=$(cat "$WG_KEY_FILE")
        LUODI_WG_PUBKEY=$(cat "$WG_PUB_FILE" 2>/dev/null || echo "$LUODI_WG_PRIVKEY" | wg pubkey)

        local pub_short="${LUODI_WG_PUBKEY:0:20}"
        echo ""
        echo -e "  ${CYAN}检测到已有 WireGuard 密钥：${NC}"
        echo -e "  公钥前缀：${pub_short}..."
        echo ""

        local yn
        read -rp "  复用已有密钥？（推荐 Y，已有 WG Peer 仍可用）[Y/n]: " yn || true
        if [[ "${yn,,}" != "n" ]]; then
            log_info "复用已有 WG 密钥"
            return 0
        fi
        backup_wg_key
    fi

    # 生成新密钥
    log_step "生成 WireGuard 密钥对..."
    mkdir -p /etc/wireguard
    chmod 700 /etc/wireguard

    LUODI_WG_PRIVKEY=$(wg genkey)
    echo "$LUODI_WG_PRIVKEY" > "$WG_KEY_FILE"
    chmod 600 "$WG_KEY_FILE"

    LUODI_WG_PUBKEY=$(echo "$LUODI_WG_PRIVKEY" | wg pubkey)
    echo "$LUODI_WG_PUBKEY" > "$WG_PUB_FILE"
    chmod 644 "$WG_PUB_FILE"

    if [[ -z "$LUODI_WG_PRIVKEY" || -z "$LUODI_WG_PUBKEY" ]]; then log_error "WireGuard 密钥生成失败"; fi
    log_info "WG 密钥对已生成（公钥: ${LUODI_WG_PUBKEY:0:20}...）"
}

# ══════════════════════════════════════════════════════════════════════
# §4  JSONC 解析器（状态机实现，继承 duijie.sh v4.2 FIX-X）
# ══════════════════════════════════════════════════════════════════════

# 将 JSONC 文件路径转换为 Python 可解析的 JSON（写到 stdout）
# 使用方法：_parse_jsonc_file "/path/to/file.json" | python3 -c "import json,sys; ..."
_strip_jsonc_py() {
    # 输出一段 Python 函数定义（不含 import），供嵌入到其他 Python 脚本中
    cat << 'PYEOF'
import re as _re
def _strip_jsonc(text):
    BS = chr(92)
    out = []; i = 0; n = len(text); in_s = False
    while i < n:
        c = text[i]
        if in_s:
            if c == BS and i + 1 < n:
                out.append(c); out.append(text[i + 1]); i += 2
            elif c == '"':
                in_s = False; out.append(c); i += 1
            else:
                out.append(c); i += 1
        else:
            if c == '"':
                in_s = True; out.append(c); i += 1
            elif text[i:i+2] == '//':
                while i < n and text[i] != '\n':
                    i += 1
            elif text[i:i+2] == '/*':
                i += 2
                while i < n - 1 and text[i:i+2] != '*/':
                    i += 1
                i += 2
            else:
                out.append(c); i += 1
    s = ''.join(out)
    s = _re.sub(r',(\s*[}\]])', r'\1', s)
    return s

def _load_jsonc(path):
    raw = open(path, 'r', encoding='utf-8').read()
    try:
        return __import__('json').loads(_strip_jsonc(raw))
    except Exception:
        return __import__('json').loads(raw)
PYEOF
}

# ══════════════════════════════════════════════════════════════════════
# §5  代理后端嗅探函数
# ══════════════════════════════════════════════════════════════════════

# 辅助：格式化输出嗅探结果
_show_sniff_result() {
    echo ""
    log_info "嗅探成功：${LUODI_BACKEND_TYPE}"
    echo -e "  配置文件  : ${LUODI_SOURCE_FILE}"
    echo -e "  代理端口  : ${LUODI_PORT}"
    echo -e "  UUID      : ${LUODI_UUID:0:16}..."
    echo -e "  Reality公钥: ${LUODI_PUBKEY:0:20}..."
    echo -e "  SNI       : ${LUODI_SNI}"
    echo -e "  ShortID   : ${LUODI_SHORTID}"
    echo -e "  传输协议  : ${LUODI_NETWORK}"
    echo ""
}

# ── Level 1：mack-a v2ray-agent Xray ─────────────────────────────────
try_sniff_mack_xray() {
    local conf_dir="/etc/v2ray-agent/xray/conf"
    local alt_conf="/usr/local/etc/xray/config.json"

    # 检测 mack-a 特征文件
    if [[ ! -d "$conf_dir" ]] && [[ ! -f "$alt_conf" ]]; then
        return 1
    fi

    # 寻找包含 Reality inbound 的配置文件
    local found_file=""
    local search_files=()

    if [[ -d "$conf_dir" ]]; then
        # mack-a 惯例：Reality Vision 在 04_* 文件
        while IFS= read -r f; do
            search_files+=("$f")
        done < <(ls "${conf_dir}/"*reality*".json" "${conf_dir}/04_"*".json" \
                    "${conf_dir}/"*Reality*".json" 2>/dev/null | sort -u || true)
        # 兜底：扫描所有 json
        if [[ ${#search_files[@]} -eq 0 ]]; then
            while IFS= read -r f; do
                search_files+=("$f")
            done < <(ls "${conf_dir}/"*.json 2>/dev/null || true)
        fi
    fi
    [[ -f "$alt_conf" ]] && search_files+=("$alt_conf")

    if [[ ${#search_files[@]} -eq 0 ]]; then return 1; fi

    local sniff_result
    sniff_result=$(python3 - "${search_files[@]}" << 'PYEOF'
import json, sys, re as _re

def _strip_jsonc(text):
    BS = chr(92); out = []; i = 0; n = len(text); in_s = False
    while i < n:
        c = text[i]
        if in_s:
            if c == BS and i+1 < n: out.append(c); out.append(text[i+1]); i += 2
            elif c == '"': in_s = False; out.append(c); i += 1
            else: out.append(c); i += 1
        else:
            if c == '"': in_s = True; out.append(c); i += 1
            elif text[i:i+2] == '//':
                while i < n and text[i] != '\n': i += 1
            elif text[i:i+2] == '/*':
                i += 2
                while i < n-1 and text[i:i+2] != '*/': i += 1
                i += 2
            else: out.append(c); i += 1
    s = ''.join(out)
    s = _re.sub(r',(\s*[}\]])', r'\1', s)
    return s

def load_jsonc(path):
    raw = open(path,'r',encoding='utf-8').read()
    try: return json.loads(_strip_jsonc(raw))
    except: return json.loads(raw)

files = sys.argv[1:]
results = []  # list of (port, uuid_list, pubkey, shortid_list, sni, network, extra, path)

for fpath in files:
    try:
        cfg = load_jsonc(fpath)
    except Exception:
        continue
    inbounds = cfg.get('inbounds', [])
    if not isinstance(inbounds, list):
        continue
    for ib in inbounds:
        proto = ib.get('protocol', '') or ib.get('type', '')
        if proto.lower() not in ('vless', 'vmess', ''):
            continue
        port = ib.get('port', 0)
        stream = ib.get('streamSettings', {}) or {}
        security = stream.get('security', '')
        if security != 'reality':
            continue
        rs = stream.get('realitySettings', {}) or {}
        pubkey = rs.get('publicKey', '') or rs.get('dest', '')
        if not pubkey or not rs.get('publicKey'):
            continue
        pubkey = rs.get('publicKey', '')
        shortids = rs.get('shortIds', []) or [rs.get('shortId', '')]
        sni = rs.get('serverNames', [''])[0] if rs.get('serverNames') else ''
        network = stream.get('network', 'tcp')
        extra = {}
        if network == 'xhttp':
            xh = stream.get('xhttpSettings', {}) or {}
            extra = {'xhttp_path': xh.get('path','/'), 'xhttp_host': xh.get('host',''), 'xhttp_mode': xh.get('mode','auto')}
        elif network == 'ws':
            ws = stream.get('wsSettings', {}) or {}
            hdr = ws.get('headers', {}) or {}
            extra = {'ws_path': ws.get('path','/'), 'ws_host': hdr.get('Host', ws.get('host',''))}
        elif network == 'grpc':
            gr = stream.get('grpcSettings', {}) or {}
            extra = {'grpc_service': gr.get('serviceName','')}
        # collect UUIDs
        uuids = []
        settings = ib.get('settings', {}) or {}
        for client in settings.get('clients', []):
            uid = client.get('id', '')
            if uid: uuids.append(uid)
        if not uuids:
            continue
        shortids_clean = [s for s in shortids if s] or ['']
        results.append({'port': port, 'uuids': uuids, 'pubkey': pubkey,
                        'shortids': shortids_clean, 'sni': sni, 'network': network,
                        'extra': extra, 'path': fpath})

if not results:
    print('NOTFOUND')
    sys.exit(0)

def _emit(r, idx=None):
    prefix = f"R{idx}:" if idx is not None else ""
    e = r.get('extra', {})
    print(f"{prefix}PORT={r['port']}")
    print(f"{prefix}PUBKEY={r['pubkey']}")
    print(f"{prefix}SNI={r['sni']}")
    print(f"{prefix}NETWORK={r['network']}")
    print(f"{prefix}PATH={r['path']}")
    print(f"{prefix}UUIDS={'|'.join(r['uuids'])}")
    print(f"{prefix}SHORTIDS={'|'.join(r['shortids'])}")
    print(f"{prefix}XHTTP_PATH={e.get('xhttp_path','/')}")
    print(f"{prefix}XHTTP_HOST={e.get('xhttp_host','')}")
    print(f"{prefix}XHTTP_MODE={e.get('xhttp_mode','auto')}")
    print(f"{prefix}WS_PATH={e.get('ws_path','/')}")
    print(f"{prefix}WS_HOST={e.get('ws_host','')}")
    print(f"{prefix}GRPC_SERVICE={e.get('grpc_service','')}")

print(f"FOUND")
print(f"COUNT={len(results)}")
for i, r in enumerate(results):
    _emit(r, i)
PYEOF
    ) || return 1

    echo "$sniff_result" | grep -q "^FOUND" || return 1

    # ── 多 Reality inbound 选择 ────────────────────────────────────
    local count; count=$(echo "$sniff_result" | grep -m1 "^COUNT=" | cut -d= -f2-)
    count="${count:-1}"
    local chosen_idx=0

    if [[ "$count" -gt 1 ]]; then
        echo ""
        echo -e "  ${CYAN}检测到 ${count} 个 Reality 入站配置，请选择用于中转的那个：${NC}"
        echo ""
        local ci
        for (( ci=0; ci<count; ci++ )); do
            local _p _sni _net _src
            _p=$(echo   "$sniff_result" | grep -m1 "^R${ci}:PORT=" | cut -d= -f2-)
            _sni=$(echo "$sniff_result" | grep -m1 "^R${ci}:SNI="  | cut -d= -f2-)
            _net=$(echo "$sniff_result" | grep -m1 "^R${ci}:NETWORK=" | cut -d= -f2-)
            _src=$(echo "$sniff_result" | grep -m1 "^R${ci}:PATH=" | cut -d= -f2- | xargs basename 2>/dev/null || true)
            echo -e "  [$(( ci+1 ))] 端口 ${_p:-?}  SNI: ${_sni:-?}  协议: ${_net:-tcp}  文件: ${_src:-?}"
        done
        echo ""
        local sel
        read -rp "  选择 [1]: " sel || true
        sel="${sel:-1}"
        if [[ "$sel" =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= count )); then
            chosen_idx=$(( sel - 1 ))
        else
            log_warn "无效选择，使用第一个"
            chosen_idx=0
        fi
    fi

    # 从选定的结果中提取字段
    local pfx="R${chosen_idx}:"
    _kv() { echo "$sniff_result" | grep -m1 "^${pfx}${1}=" | cut -d= -f2-; }

    local uuids_raw; uuids_raw=$(_kv UUIDS)
    local shortids_raw; shortids_raw=$(_kv SHORTIDS)

    LUODI_PORT=$(_kv PORT)
    LUODI_PUBKEY=$(_kv PUBKEY)
    LUODI_SNI=$(_kv SNI)
    LUODI_NETWORK=$(_kv NETWORK)
    LUODI_SOURCE_FILE=$(_kv PATH)
    LUODI_XHTTP_PATH=$(_kv XHTTP_PATH)
    LUODI_XHTTP_HOST=$(_kv XHTTP_HOST)
    LUODI_XHTTP_MODE=$(_kv XHTTP_MODE)
    LUODI_WS_PATH=$(_kv WS_PATH)
    LUODI_WS_HOST=$(_kv WS_HOST)
    LUODI_GRPC_SERVICE=$(_kv GRPC_SERVICE)

    # UUID 多选
    _select_uuid "$uuids_raw"
    LUODI_SHORTID=$(echo "$shortids_raw" | cut -d'|' -f1)

    LUODI_BACKEND_TYPE="mack-a-xray"
    return 0
}

# ── Level 2：mack-a Sing-box ──────────────────────────────────────────
try_sniff_mack_singbox() {
    local conf="/usr/local/etc/sing-box/config.json"
    [[ -f "$conf" ]] || return 1
    _sniff_singbox_file "$conf" "mack-a-singbox"
}

# ── Level 3：独立 Sing-box ─────────────────────────────────────────────
try_sniff_standalone_singbox() {
    local paths=(
        "/etc/sing-box/config.json"
        "/usr/local/share/sing-box/config.json"
        "/root/sing-box/config.json"
    )
    for p in "${paths[@]}"; do
        [[ -f "$p" ]] && _sniff_singbox_file "$p" "singbox" && return 0
    done
    return 1
}

# 通用 Sing-box 配置嗅探（内部函数）
_sniff_singbox_file() {
    local conf="$1"
    local backend="$2"

    local sniff_result
    sniff_result=$(python3 - "$conf" << 'PYEOF'
import json, sys, re as _re

def _strip_jsonc(text):
    BS = chr(92); out = []; i = 0; n = len(text); in_s = False
    while i < n:
        c = text[i]
        if in_s:
            if c == BS and i+1 < n: out.append(c); out.append(text[i+1]); i += 2
            elif c == '"': in_s = False; out.append(c); i += 1
            else: out.append(c); i += 1
        else:
            if c == '"': in_s = True; out.append(c); i += 1
            elif text[i:i+2] == '//':
                while i < n and text[i] != '\n': i += 1
            elif text[i:i+2] == '/*':
                i += 2
                while i < n-1 and text[i:i+2] != '*/': i += 1
                i += 2
            else: out.append(c); i += 1
    return _re.sub(r',(\s*[}\]])', r'\1', ''.join(out))

conf_path = sys.argv[1]
try:
    raw = open(conf_path,'r',encoding='utf-8').read()
    try: cfg = json.loads(_strip_jsonc(raw))
    except: cfg = json.loads(raw)
except Exception as e:
    print(f"ERROR:{e}"); sys.exit(0)

inbounds = cfg.get('inbounds', [])
if not isinstance(inbounds, list):
    print("NOTFOUND"); sys.exit(0)

for ib in inbounds:
    t = ib.get('type', '')
    if t not in ('vless', 'vmess'): continue
    tls = ib.get('tls', {}) or {}
    reality = tls.get('reality', {}) or {}
    if not reality.get('enabled', False): continue

    port = ib.get('listen_port', 0)
    pubkey = reality.get('public_key','') or reality.get('private_key','')
    # sing-box only stores private_key server-side; public key derived elsewhere
    # Try public_key first; if missing, not exported here (user must input manually)
    pk = reality.get('public_key', '')
    if not pk:
        # sing-box server side has private_key, public key from key pair
        # For luodi.sh sniffing, we'll note this limitation
        pk = ''

    server_names = reality.get('server_name', [])
    if isinstance(server_names, str): server_names = [server_names]
    sni = server_names[0] if server_names else ''
    short_ids = reality.get('short_id', [])
    if isinstance(short_ids, str): short_ids = [short_ids]

    transport = ib.get('transport', {}) or {}
    network = transport.get('type', 'tcp') or 'tcp'
    extra = {}
    if network == 'http':
        network = 'xhttp'
        extra = {'xhttp_path': transport.get('path','/'),
                 'xhttp_host': (transport.get('host') or [''])[0] if isinstance(transport.get('host'), list) else transport.get('host',''),
                 'xhttp_mode': 'auto'}
    elif network == 'websocket':
        network = 'ws'
        extra = {'ws_path': transport.get('path','/'),
                 'ws_host': (transport.get('headers',{}) or {}).get('Host','')}
    elif network == 'grpc':
        extra = {'grpc_service': transport.get('service_name','')}

    users = ib.get('users', []) or []
    uuids = [u.get('uuid','') for u in users if u.get('uuid')]
    if not uuids: continue

    print("FOUND")
    print(f"COUNT=1")
    print(f"R0:PORT={port}")
    print(f"R0:PUBKEY={pk}")
    print(f"R0:SNI={sni}")
    print(f"R0:NETWORK={network}")
    print(f"R0:PATH={conf_path}")
    print(f"R0:UUIDS={'|'.join(uuids)}")
    print(f"R0:SHORTIDS={'|'.join(short_ids) if short_ids else ''}")
    print(f"R0:XHTTP_PATH={extra.get('xhttp_path','/')}")
    print(f"R0:XHTTP_HOST={extra.get('xhttp_host','')}")
    print(f"R0:XHTTP_MODE={extra.get('xhttp_mode','auto')}")
    print(f"R0:WS_PATH={extra.get('ws_path','/')}")
    print(f"R0:WS_HOST={extra.get('ws_host','')}")
    print(f"R0:GRPC_SERVICE={extra.get('grpc_service','')}")
    sys.exit(0)

print("NOTFOUND")
PYEOF
    ) || return 1

    echo "$sniff_result" | grep -q "^FOUND" || return 1

    local pfx="R0:"
    _kv() { echo "$sniff_result" | grep -m1 "^${pfx}${1}=" | cut -d= -f2-; }

    local uuids_raw; uuids_raw=$(_kv UUIDS)
    local shortids_raw; shortids_raw=$(_kv SHORTIDS)

    LUODI_PORT=$(_kv PORT)
    LUODI_PUBKEY=$(_kv PUBKEY)
    LUODI_SNI=$(_kv SNI)
    LUODI_NETWORK=$(_kv NETWORK)
    LUODI_SOURCE_FILE="$conf"
    LUODI_XHTTP_PATH=$(_kv XHTTP_PATH)
    LUODI_XHTTP_HOST=$(_kv XHTTP_HOST)
    LUODI_XHTTP_MODE=$(_kv XHTTP_MODE)
    LUODI_WS_PATH=$(_kv WS_PATH)
    LUODI_WS_HOST=$(_kv WS_HOST)
    LUODI_GRPC_SERVICE=$(_kv GRPC_SERVICE)

    _select_uuid "$uuids_raw"
    LUODI_SHORTID=$(echo "$shortids_raw" | cut -d'|' -f1)

    # Sing-box Reality 公钥注意：服务端存私钥，公钥需 xray x25519 或其他工具导出
    if [[ -z "$LUODI_PUBKEY" ]]; then
        log_warn "Sing-box 配置中未找到 Reality 公钥（服务端仅存私钥）"
        log_warn "请手动输入公钥（可通过 'xray x25519 -i <私钥>' 导出）"
        local i
        read -rp "Reality 公钥（base64）: " i || true
        LUODI_PUBKEY="$i"
        if [[ -z "$LUODI_PUBKEY" ]]; then log_error "Reality 公钥不能为空"; fi
    fi

    LUODI_BACKEND_TYPE="$backend"
    return 0
}

# ── Level 4：x-ui / 3x-ui SQLite 数据库 ──────────────────────────────
try_sniff_xui_3xui() {
    local db_paths=(
        "/etc/x-ui/x-ui.db"
        "/usr/local/x-ui/db/x-ui.db"
        "/root/x-ui.db"
        "/etc/3x-ui/x-ui.db"
        "/usr/local/3x-ui/db/x-ui.db"
    )

    local found_db=""
    for db in "${db_paths[@]}"; do
        [[ -f "$db" ]] && { found_db="$db"; break; }
    done
    if [[ -z "$found_db" ]]; then return 1; fi

    command -v sqlite3 &>/dev/null || {
        log_warn "检测到 x-ui 数据库，但 sqlite3 未安装"
        apt-get install -y -qq sqlite3 2>/dev/null \
            || { log_warn "sqlite3 安装失败，跳过 x-ui 嗅探"; return 1; }
    }

    local sniff_result
    sniff_result=$(python3 - "$found_db" << 'PYEOF'
import json, sys, re as _re, sqlite3

def _strip_jsonc(text):
    BS = chr(92); out = []; i = 0; n = len(text); in_s = False
    while i < n:
        c = text[i]
        if in_s:
            if c == BS and i+1 < n: out.append(c); out.append(text[i+1]); i += 2
            elif c == '"': in_s = False; out.append(c); i += 1
            else: out.append(c); i += 1
        else:
            if c == '"': in_s = True; out.append(c); i += 1
            elif text[i:i+2] == '//':
                while i < n and text[i] != '\n': i += 1
            elif text[i:i+2] == '/*':
                i += 2
                while i < n-1 and text[i:i+2] != '*/': i += 1
                i += 2
            else: out.append(c); i += 1
    return _re.sub(r',(\s*[}\]])', r'\1', ''.join(out))

def try_parse(s):
    if not s: return None
    try: return json.loads(_strip_jsonc(s))
    except:
        try: return json.loads(s)
        except: return None

db_path = sys.argv[1]
try:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    # 尝试 inbounds 表（x-ui / 3x-ui 通用）
    cur.execute("SELECT remark, port, protocol, settings, stream_settings FROM inbounds WHERE enable=1 OR enable='1' OR enable='true'")
    rows = cur.fetchall()
    conn.close()
except Exception as e:
    print(f"ERROR:{e}"); sys.exit(0)

for row in rows:
    remark, port, proto, settings_raw, stream_raw = row
    if proto.lower() not in ('vless', 'vmess'): continue

    stream = try_parse(stream_raw) or {}
    security = stream.get('security', '')
    if security != 'reality': continue

    settings = try_parse(settings_raw) or {}
    clients = settings.get('clients', []) or []
    uuids = [c.get('id','') for c in clients if c.get('id')]
    if not uuids: continue

    rs = stream.get('realitySettings', {}) or {}
    pubkey = rs.get('publicKey','')
    if not pubkey: continue

    shortids = rs.get('shortIds', []) or [rs.get('shortId','')]
    sni = rs.get('serverNames',[''])[0] if rs.get('serverNames') else ''
    network = stream.get('network','tcp')
    extra = {}
    if network == 'xhttp':
        xh = stream.get('xhttpSettings',{}) or {}
        extra = {'xhttp_path': xh.get('path','/'), 'xhttp_host': xh.get('host',''), 'xhttp_mode': xh.get('mode','auto')}
    elif network == 'ws':
        ws = stream.get('wsSettings',{}) or {}
        hdr = ws.get('headers',{}) or {}
        extra = {'ws_path': ws.get('path','/'), 'ws_host': hdr.get('Host',ws.get('host',''))}
    elif network == 'grpc':
        gr = stream.get('grpcSettings',{}) or {}
        extra = {'grpc_service': gr.get('serviceName','')}

    shortids_clean = [s for s in shortids if s] or ['']
    print("FOUND")
    print(f"COUNT=1")
    print(f"R0:PORT={port}")
    print(f"R0:PUBKEY={pubkey}")
    print(f"R0:SNI={sni}")
    print(f"R0:NETWORK={network}")
    print(f"R0:PATH={db_path}")
    print(f"R0:UUIDS={'|'.join(uuids)}")
    print(f"R0:SHORTIDS={'|'.join(shortids_clean)}")
    print(f"R0:XHTTP_PATH={extra.get('xhttp_path','/')}")
    print(f"R0:XHTTP_HOST={extra.get('xhttp_host','')}")
    print(f"R0:XHTTP_MODE={extra.get('xhttp_mode','auto')}")
    print(f"R0:WS_PATH={extra.get('ws_path','/')}")
    print(f"R0:WS_HOST={extra.get('ws_host','')}")
    print(f"R0:GRPC_SERVICE={extra.get('grpc_service','')}")
    sys.exit(0)

print("NOTFOUND")
PYEOF
    ) || return 1

    echo "$sniff_result" | grep -q "^FOUND" || return 1

    local pfx="R0:"
    _kv() { echo "$sniff_result" | grep -m1 "^${pfx}${1}=" | cut -d= -f2-; }

    local uuids_raw; uuids_raw=$(_kv UUIDS)
    local shortids_raw; shortids_raw=$(_kv SHORTIDS)

    LUODI_PORT=$(_kv PORT)
    LUODI_PUBKEY=$(_kv PUBKEY)
    LUODI_SNI=$(_kv SNI)
    LUODI_NETWORK=$(_kv NETWORK)
    LUODI_SOURCE_FILE=$(_kv PATH)
    LUODI_XHTTP_PATH=$(_kv XHTTP_PATH)
    LUODI_XHTTP_HOST=$(_kv XHTTP_HOST)
    LUODI_XHTTP_MODE=$(_kv XHTTP_MODE)
    LUODI_WS_PATH=$(_kv WS_PATH)
    LUODI_WS_HOST=$(_kv WS_HOST)
    LUODI_GRPC_SERVICE=$(_kv GRPC_SERVICE)

    _select_uuid "$uuids_raw"
    LUODI_SHORTID=$(echo "$shortids_raw" | cut -d'|' -f1)

    # 判断 x-ui 还是 3x-ui
    if echo "$found_db" | grep -q "3x-ui"; then
        LUODI_BACKEND_TYPE="3x-ui"
    else
        LUODI_BACKEND_TYPE="x-ui"
    fi
    return 0
}

# ── Level 5：手动输入 ─────────────────────────────────────────────────
fallback_manual_input() {
    echo ""
    log_warn "未能自动嗅探代理参数，请手动输入："
    echo ""

    local i
    _ask_field() {
        local label="$1" default="$2"
        read -rp "  ${label} [${default:-必填}]: " i || true
        echo "${i:-$default}"
    }

    LUODI_PORT=$(_ask_field "代理端口（Xray/Sing-box 监听端口）" "")
    if [[ -z "$LUODI_PORT" ]]; then log_error "代理端口不能为空"; fi

    LUODI_UUID=$(_ask_field "UUID" "")
    if [[ -z "$LUODI_UUID" ]]; then log_error "UUID 不能为空"; fi

    LUODI_PUBKEY=$(_ask_field "Reality 公钥（base64）" "")
    if [[ -z "$LUODI_PUBKEY" ]]; then log_error "Reality 公钥不能为空"; fi

    LUODI_SHORTID=$(_ask_field "Short ID（十六进制，可为空）" "")
    LUODI_SNI=$(_ask_field "SNI（伪装域名）" "www.microsoft.com")

    echo -e "  传输协议 [1] tcp  [2] xhttp  [3] ws  [4] grpc  [默认: 1]: "
    read -rp "  选择: " i || true
    case "${i:-1}" in
        2) LUODI_NETWORK="xhttp"
           LUODI_XHTTP_PATH=$(_ask_field "xhttp path" "/")
           LUODI_XHTTP_HOST=$(_ask_field "xhttp host（可空）" "") ;;
        3) LUODI_NETWORK="ws"
           LUODI_WS_PATH=$(_ask_field "WebSocket path" "/")
           LUODI_WS_HOST=$(_ask_field "WebSocket host（可空）" "") ;;
        4) LUODI_NETWORK="grpc"
           LUODI_GRPC_SERVICE=$(_ask_field "gRPC service name" "") ;;
        *) LUODI_NETWORK="tcp" ;;
    esac

    LUODI_BACKEND_TYPE="manual"
    LUODI_SOURCE_FILE="（手动输入）"
}

# 多 UUID 选择（供各嗅探函数调用）
_select_uuid() {
    local uuids_raw="$1"
    local -a uuids
    IFS='|' read -ra uuids <<< "$uuids_raw"

    # 过滤空值
    local clean_uuids=()
    for u in "${uuids[@]}"; do
        [[ -n "$u" ]] && clean_uuids+=("$u")
    done

    if [[ ${#clean_uuids[@]} -eq 0 ]]; then
        LUODI_UUID=""
        return
    fi

    if [[ ${#clean_uuids[@]} -eq 1 ]]; then
        LUODI_UUID="${clean_uuids[0]}"
        return
    fi

    echo ""
    echo -e "  ${CYAN}检测到多个 UUID，请选择用于链式代理的 UUID：${NC}"
    local j
    for j in "${!clean_uuids[@]}"; do
        echo -e "  [$(( j+1 ))] ${clean_uuids[$j]}"
    done
    echo -e "  [a] 全部使用（duijie.sh 将使用第一个）"
    echo ""

    local choice
    read -rp "  选择 [1]: " choice || true
    choice="${choice:-1}"

    if [[ "$choice" == "a" ]]; then
        LUODI_UUID="${clean_uuids[0]}"
        log_info "将使用第一个 UUID: ${LUODI_UUID:0:16}..."
    elif [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#clean_uuids[@]} )); then
        LUODI_UUID="${clean_uuids[$((choice-1))]}"
        log_info "已选择 UUID: ${LUODI_UUID:0:16}..."
    else
        LUODI_UUID="${clean_uuids[0]}"
        log_warn "无效选择，使用第一个 UUID"
    fi
}

# ══════════════════════════════════════════════════════════════════════
# §6  参数嗅探主流程
# ══════════════════════════════════════════════════════════════════════

sniff_proxy_params() {
    log_step "自动嗅探代理参数..."

    if try_sniff_mack_xray; then
        _show_sniff_result; return 0
    fi
    log_warn "mack-a Xray 未检测到，尝试下一个..."

    if try_sniff_mack_singbox; then
        _show_sniff_result; return 0
    fi
    log_warn "mack-a Sing-box 未检测到，尝试下一个..."

    if try_sniff_standalone_singbox; then
        _show_sniff_result; return 0
    fi
    log_warn "独立 Sing-box 未检测到，尝试下一个..."

    if try_sniff_xui_3xui; then
        _show_sniff_result; return 0
    fi
    log_warn "x-ui/3x-ui 未检测到，切换为手动输入模式..."

    fallback_manual_input
}

# ══════════════════════════════════════════════════════════════════════
# §7  参数确认 & 修改
# ══════════════════════════════════════════════════════════════════════

confirm_params() {
    echo ""
    log_sep
    echo -e "  ${BOLD}请确认以下参数：${NC}"
    log_sep
    echo -e "  落地机 IP   : ${LUODI_IP}"
    echo -e "  代理端口    : ${LUODI_PORT}"
    echo -e "  UUID        : ${LUODI_UUID}"
    echo -e "  Reality 公钥: ${LUODI_PUBKEY:0:24}..."
    echo -e "  SNI         : ${LUODI_SNI}"
    echo -e "  Short ID    : ${LUODI_SHORTID:-（空）}"
    echo -e "  传输协议    : ${LUODI_NETWORK}"
    [[ "$LUODI_NETWORK" == "xhttp" ]] && echo -e "  XHTTP Path  : ${LUODI_XHTTP_PATH}"
    [[ "$LUODI_NETWORK" == "ws"    ]] && echo -e "  WS Path     : ${LUODI_WS_PATH}"
    [[ "$LUODI_NETWORK" == "grpc"  ]] && echo -e "  gRPC Service: ${LUODI_GRPC_SERVICE}"
    echo -e "  WG 公钥     : ${LUODI_WG_PUBKEY:0:24}..."
    echo -e "  后端类型    : ${LUODI_BACKEND_TYPE}"
    log_sep
    echo ""

    local yn
    read -rp "  参数正确？[Y/n]: " yn || true
    if [[ "${yn,,}" == "n" ]]; then
        echo ""
        echo -e "  ${CYAN}请输入修正值（直接回车保留原值）：${NC}"
        echo ""

        local i
        _fix() {
            local label="$1" var="$2"
            read -rp "  ${label} [${!var}]: " i || true
            [[ -n "$i" ]] && printf -v "$var" '%s' "$i"
        }

        _fix "落地机 IP"   LUODI_IP
        _fix "代理端口"    LUODI_PORT
        _fix "UUID"        LUODI_UUID
        _fix "Reality 公钥" LUODI_PUBKEY
        _fix "SNI"         LUODI_SNI
        _fix "Short ID"    LUODI_SHORTID

        log_info "参数已更新"
    fi

    # 最终校验必填字段
    if [[ -z "$LUODI_PORT"   ]]; then log_error "代理端口不能为空"; fi
    if [[ -z "$LUODI_UUID"   ]]; then log_error "UUID 不能为空"; fi
    if [[ -z "$LUODI_PUBKEY" ]]; then log_error "Reality 公钥不能为空"; fi
    if [[ -z "$LUODI_SNI"    ]]; then log_error "SNI 不能为空"; fi
}

# ══════════════════════════════════════════════════════════════════════
# §8  旧文件检测 & 用户决策
# ══════════════════════════════════════════════════════════════════════

detect_existing_state() {
    # 返回：
    #   "fresh"      — 首次运行，无任何已有文件
    #   "partial"    — 有部分文件（如只有 WG 密钥，无 info.txt）
    #   "full"       — info.txt + export.json + WG 密钥均存在

    local has_info=false has_export=false has_wg_key=false

    [[ -f "$INFO_FILE"   ]] && has_info=true
    [[ -f "$EXPORT_JSON" ]] && has_export=true
    [[ -f "$WG_KEY_FILE" && -s "$WG_KEY_FILE" ]] && has_wg_key=true

    if [[ "$has_info" == "false" && "$has_export" == "false" && "$has_wg_key" == "false" ]]; then
        echo "fresh"
    elif [[ "$has_info" == "true" && "$has_wg_key" == "true" ]]; then
        echo "full"
    else
        echo "partial"
    fi
}

_load_existing_params() {
    # 从 info.txt 读取已保存的参数
    [[ -f "$INFO_FILE" ]] || return 1

    _ikv() { grep -m1 "^${1}=" "$INFO_FILE" 2>/dev/null | cut -d= -f2- | tr -d '\r'; }

    LUODI_IP=$(_ikv LUODI_IP)
    LUODI_PORT=$(_ikv LUODI_PORT)
    LUODI_UUID=$(_ikv LUODI_UUID)
    LUODI_PUBKEY=$(_ikv LUODI_PUBKEY)
    LUODI_SNI=$(_ikv LUODI_SNI)
    LUODI_SHORTID=$(_ikv LUODI_SHORTID)
    [[ -z "$LUODI_SHORTID" ]] && LUODI_SHORTID=$(_ikv LUODI_SHORT_ID)
    LUODI_NETWORK=$(_ikv LUODI_NETWORK)
    LUODI_XHTTP_PATH=$(_ikv LUODI_XHTTP_PATH)
    LUODI_XHTTP_HOST=$(_ikv LUODI_XHTTP_HOST)
    LUODI_XHTTP_MODE=$(_ikv LUODI_XHTTP_MODE)
    LUODI_WS_PATH=$(_ikv LUODI_WS_PATH)
    LUODI_WS_HOST=$(_ikv LUODI_WS_HOST)
    LUODI_GRPC_SERVICE=$(_ikv LUODI_GRPC_SERVICE)
    LUODI_WG_PUBKEY=$(_ikv LUODI_WG_PUBKEY)
    LUODI_WG_PRIVKEY=$(_ikv LUODI_WG_PRIVKEY)
    LUODI_BACKEND_TYPE=$(_ikv LUODI_BACKEND_TYPE)
    LUODI_SOURCE_FILE=$(_ikv LUODI_SOURCE_FILE)

    # duijie.sh 对接记录（最后一条）
    _SAVED_RELAY_IP=$(grep "^RELAY_IP=" "$INFO_FILE" 2>/dev/null | tail -1 | cut -d= -f2-)
    _SAVED_RELAY_SSH_PORT=$(grep "^RELAY_SSH_PORT=" "$INFO_FILE" 2>/dev/null | tail -1 | cut -d= -f2-)
    _SAVED_RELAY_SSH_USER=$(grep "^RELAY_SSH_USER=" "$INFO_FILE" 2>/dev/null | tail -1 | cut -d= -f2-)
}

_show_existing_summary() {
    local state="$1"

    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  检测到已有落地机配置                                        ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    echo -e "  ${BOLD}代理类型  :${NC} ${LUODI_BACKEND_TYPE:-未知}"
    echo -e "  ${BOLD}落地 IP   :${NC} ${LUODI_IP:-未读取}"
    echo -e "  ${BOLD}代理端口  :${NC} ${LUODI_PORT:-未读取}"
    [[ -n "$LUODI_PUBKEY" ]] && \
    echo -e "  ${BOLD}Reality公钥:${NC} ${LUODI_PUBKEY:0:24}..."
    [[ -n "$LUODI_WG_PUBKEY" ]] && \
    echo -e "  ${BOLD}WG 公钥   :${NC} ${LUODI_WG_PUBKEY:0:24}..."

    # WireGuard 运行状态
    if ip link show wg0 &>/dev/null 2>&1; then
        local wg_addr; wg_addr=$(ip addr show wg0 2>/dev/null | grep "inet " | awk '{print $2}' || true)
        echo -e "  ${BOLD}WG 状态   :${NC} ${GREEN}运行中${NC}（${wg_addr:-wg0}）"
    elif [[ -f "$WG_KEY_FILE" ]]; then
        echo -e "  ${BOLD}WG 状态   :${NC} 已有密钥，未配置（等待 duijie.sh）"
    else
        echo -e "  ${BOLD}WG 状态   :${NC} 未安装"
    fi

    # 关联中转机
    [[ -n "$_SAVED_RELAY_IP" ]] && \
    echo -e "  ${BOLD}关联中转机:${NC} ${_SAVED_RELAY_IP}"

    # export.json 时效
    if [[ -f "$EXPORT_JSON" ]]; then
        local age_min
        age_min=$(( ( $(date +%s) - $(stat -c %Y "$EXPORT_JSON" 2>/dev/null || echo 0) ) / 60 ))
        if [[ $age_min -lt 30 ]]; then
            echo -e "  ${BOLD}export.json:${NC} ${GREEN}存在（${age_min} 分钟前生成，仍有效）${NC}"
        else
            echo -e "  ${BOLD}export.json:${NC} ${YELLOW}存在（${age_min} 分钟前生成，建议刷新）${NC}"
        fi
    fi
    echo ""
}

user_decision() {
    local state="$1"

    echo ""
    echo -e "  ${CYAN}[1]${NC} 使用现有配置（推荐）— 仅刷新 IP + export.json 时间戳"
    echo -e "  ${CYAN}[2]${NC} 重新读取代理参数 — 保留 WG 密钥，重新嗅探 Reality 参数"
    echo -e "  ${CYAN}[3]${NC} 完全重置 — 重新生成 WG 密钥 + 重新嗅探（需重新运行 duijie.sh）"
    echo -e "  ${CYAN}[4]${NC} 退出"
    echo ""

    local choice
    read -rp "  请选择 [1]: " choice || true
    choice="${choice:-1}"

    case "$choice" in
        1)  log_info "使用现有配置，仅刷新 IP 和 export.json..."
            echo "reuse" ;;
        2)  log_info "重新读取代理参数（保留 WG 密钥）..."
            echo "refresh" ;;
        3)  echo "full_reset" ;;
        4)  log_info "已退出"; exit 0 ;;
        *)  log_warn "无效选择，使用现有配置"; echo "reuse" ;;
    esac
}

# ══════════════════════════════════════════════════════════════════════
# §9  完全重置 & 中转机远程清理
# ══════════════════════════════════════════════════════════════════════

do_full_reset() {
    echo ""
    echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  ⚠  警告：完全重置将生成新的 WireGuard 密钥                 ║${NC}"
    echo -e "${RED}║  中转机上已有的 WG Peer（用旧公钥）将失效                   ║${NC}"
    echo -e "${RED}║  必须重新在中转机删除旧 Peer，并重新运行 duijie.sh           ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    local confirm
    read -rp "  输入 'yes' 确认完全重置，其他取消: " confirm || true
    [[ "$confirm" != "yes" ]] && { log_info "已取消"; exit 0; }

    # 备份并删除旧密钥
    backup_wg_key
    rm -f "$WG_KEY_FILE" "$WG_PUB_FILE" 2>/dev/null || true

    # 删除 wg0.conf（duijie.sh 会重建）
    if [[ -f "/etc/wireguard/wg0.conf" ]]; then
        cp /etc/wireguard/wg0.conf "/root/.wg0_conf_backup.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
        rm -f /etc/wireguard/wg0.conf
        log_info "wg0.conf 已备份并删除"
    fi

    # 停止 wg0（如运行）
    if ip link show wg0 &>/dev/null 2>&1; then
        wg-quick down wg0 2>/dev/null || ip link del wg0 2>/dev/null || true
        log_info "wg0 已停止"
    fi

    # 询问是否 SSH 清理中转机
    prompt_relay_cleanup

    # 删除本地文件
    rm -f "$INFO_FILE" "$EXPORT_JSON" 2>/dev/null || true
    log_info "本地 info.txt / export.json 已删除"
    log_info "完全重置完成，将重新运行初始化流程..."
    echo ""
}

prompt_relay_cleanup() {
    echo ""
    local yn
    read -rp "  是否连接中转机删除旧 WG Peer 数据？[y/N]: " yn || true
    [[ "${yn,,}" != "y" ]] && {
        echo ""
        echo -e "  ${YELLOW}请手动在中转机执行清理：${NC}"
        echo -e "  wg show wg0 peers"
        echo -e "  wg set wg0 peer <旧公钥> remove"
        echo -e "  bash zhongzhuan.sh --check"
        echo ""
        return 0
    }

    # 收集中转机 SSH 信息
    local relay_ip="${_SAVED_RELAY_IP}"
    local relay_port="${_SAVED_RELAY_SSH_PORT:-22}"
    local relay_user="${_SAVED_RELAY_SSH_USER:-root}"
    local relay_pass=""
    local auth_type="key"

    echo ""
    local i
    read -rp "  中转机 IP [${relay_ip:-待输入}]: " i || true; [[ -n "$i" ]] && relay_ip="$i"
    [[ -z "$relay_ip" ]] && { log_warn "中转机 IP 为空，跳过远程清理"; return 0; }
    read -rp "  SSH 端口 [${relay_port}]: " i || true; relay_port="${i:-$relay_port}"
    read -rp "  SSH 用户 [${relay_user}]: " i || true; relay_user="${i:-$relay_user}"

    local ssh_opts=(-o StrictHostKeyChecking=no -o ConnectTimeout=10
                    -o ServerAliveInterval=15 -o ServerAliveCountMax=4
                    -p "$relay_port")

    # 优先尝试密钥登录
    log_step "测试 SSH 密钥登录..."
    if ssh -q "${ssh_opts[@]}" -o BatchMode=yes "${relay_user}@${relay_ip}" "exit" 2>/dev/null; then
        auth_type="key"
        log_info "SSH 密钥登录成功"
    else
        if ! command -v sshpass &>/dev/null; then
            apt-get install -y -qq sshpass 2>/dev/null || true
        fi
        read -rsp "  SSH 密码: " relay_pass; echo ""
        if sshpass -p "$relay_pass" ssh -q "${ssh_opts[@]}" "${relay_user}@${relay_ip}" "exit" 2>/dev/null; then
            auth_type="password"
            log_info "SSH 密码登录成功"
        else
            log_warn "SSH 连接失败，跳过远程清理"
            echo -e "  ${YELLOW}请手动在中转机执行：${NC}"
            echo -e "  wg set wg0 peer ${LUODI_WG_PUBKEY} remove"
            return 0
        fi
    fi

    _ssh_run() {
        case "$auth_type" in
            key)      ssh -q "${ssh_opts[@]}" "${relay_user}@${relay_ip}" "$1" ;;
            password) sshpass -p "$relay_pass" ssh -q "${ssh_opts[@]}" "${relay_user}@${relay_ip}" "$1" ;;
        esac
    }

    # 查询中转机 peer_map，找到与本落地机 IP 相关的条目
    local old_pubkey="$LUODI_WG_PUBKEY"
    local peer_map_path="/etc/wireguard/peer_map.json"
    local nodes_path="/usr/local/etc/xray-relay/nodes.json"

    log_step "查询中转机上关联此落地机的 peer 记录..."
    local relay_info
    relay_info=$(_ssh_run "
cat ${peer_map_path} 2>/dev/null || echo '{}'
" 2>/dev/null || echo '{}')

    # 展示将要删除的内容
    local old_wg_pk="$old_pubkey"
    echo ""
    echo -e "  ${BOLD}将在中转机执行以下清理：${NC}"
    echo -e "  · wg set wg0 peer ${old_wg_pk:0:20}... remove"
    echo -e "  · 从 peer_map.json 删除对应条目"
    echo -e "  · 从 nodes.json 删除对应条目"
    echo -e "  · 保存 iptables（已有 DNAT 规则下次 duijie.sh 会自动重建）"
    echo ""

    read -rp "  确认执行？[y/N]: " yn || true
    [[ "${yn,,}" != "y" ]] && { log_info "已取消远程清理"; return 0; }

    remote_cleanup "$old_wg_pk" "$peer_map_path" "$nodes_path" \
        "$auth_type" "$relay_pass" "${relay_user}@${relay_ip}" "${ssh_opts[@]}"
}

remote_cleanup() {
    local old_pubkey="$1"
    local peer_map_path="$2"
    local nodes_path="$3"
    local auth_type="$4"
    local relay_pass="$5"
    local relay_target="$6"
    shift 6
    local ssh_opts=("$@")

    _run() {
        case "$auth_type" in
            key)      ssh -q "${ssh_opts[@]}" "$relay_target" "bash -s" << 'REMOTE_EOF'
set +e
OLD_PUBKEY="$1"
PEER_MAP="$2"
NODES_PATH="$3"

# 1. 移除 wg0 peer
wg show wg0 peers 2>/dev/null | grep -q "^${OLD_PUBKEY}$" \
    && wg set wg0 peer "${OLD_PUBKEY}" remove 2>/dev/null \
    && echo "[✓] WG Peer 已移除" || echo "[!] WG Peer 未找到（可能已移除）"

# 2. 同步删除 wg0.conf 中的 [Peer] 块
python3 - << PYEOF
conf = "/etc/wireguard/wg0.conf"
pubkey = "${OLD_PUBKEY}"
try:
    lines = open(conf).readlines()
except FileNotFoundError:
    exit(0)
result = []; i = 0
while i < len(lines):
    if lines[i].strip() == "[Peer]":
        block = [lines[i]]; j = i+1
        while j < len(lines) and lines[j].strip() not in ("", "[Peer]", "[Interface]"):
            block.append(lines[j]); j += 1
        if pubkey not in "".join(block):
            result.extend(block)
            if j < len(lines) and lines[j].strip() == "": result.append("\n"); j += 1
        i = j
    else:
        result.append(lines[i]); i += 1
open(conf, "w").write("".join(result))
print("[✓] wg0.conf 已清理")
PYEOF

# 3. 从 peer_map.json 删除（按公钥匹配值）
python3 -c "
import json, os
pm_path = '${PEER_MAP}'
pubkey_val = '${OLD_PUBKEY}'  # peer_map: link_id → wg_ip，不直接存公钥
# 我们能找到的是：wg show dump 中公钥对应的 allowed-ip → 从 peer_map 找对应 link_id
try:
    pm = json.load(open(pm_path))
    # 如果从 wg dump 能得到 allowed-ip 就可以按 ip 反查 link_id
    # 此处保守做法：不删除 peer_map，留给下次 duijie.sh 幂等处理
    print('[i] peer_map 保留（IP 分配将由下次 duijie.sh 幂等复用）')
except: pass
" 2>/dev/null || true

# 4. iptables 规则由 duijie.sh 管理，不在此处操作
echo "[✓] 中转机清理完成"
REMOTE_EOF
;;
            password) sshpass -p "$relay_pass" ssh -q "${ssh_opts[@]}" "$relay_target" \
                "bash -s -- '${old_pubkey}' '${peer_map_path}' '${nodes_path}'" << 'REMOTE_EOF'
set +e
OLD_PUBKEY="$1"
PEER_MAP="$2"
wg show wg0 peers 2>/dev/null | grep -q "^${OLD_PUBKEY}$" \
    && wg set wg0 peer "${OLD_PUBKEY}" remove 2>/dev/null \
    && echo "[✓] WG Peer 已移除" || echo "[!] WG Peer 未找到"
echo "[✓] 中转机清理完成"
REMOTE_EOF
;;
        esac
    }

    local output
    output=$(_run 2>&1 || true)
    echo "$output" | while IFS= read -r line; do log_info "$line"; done
}

# ══════════════════════════════════════════════════════════════════════
# §10 保存输出文件
# ══════════════════════════════════════════════════════════════════════

save_export_json() {
    local timestamp; timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

    # 变量通过环境变量传入 Python，完全规避特殊字符 / 参数数量不匹配问题
    local result
    result=$(
        LUODI_IP="$LUODI_IP" LUODI_PORT="$LUODI_PORT" LUODI_UUID="$LUODI_UUID" \
        LUODI_PUBKEY="$LUODI_PUBKEY" LUODI_SNI="$LUODI_SNI" LUODI_SHORTID="$LUODI_SHORTID" \
        LUODI_NETWORK="$LUODI_NETWORK" LUODI_XHTTP_PATH="$LUODI_XHTTP_PATH" \
        LUODI_XHTTP_HOST="$LUODI_XHTTP_HOST" LUODI_XHTTP_MODE="$LUODI_XHTTP_MODE" \
        LUODI_WS_PATH="$LUODI_WS_PATH" LUODI_WS_HOST="$LUODI_WS_HOST" \
        LUODI_GRPC_SERVICE="$LUODI_GRPC_SERVICE" LUODI_WG_PUBKEY="$LUODI_WG_PUBKEY" \
        LUODI_BACKEND_TYPE="$LUODI_BACKEND_TYPE" LUODI_SOURCE_FILE="$LUODI_SOURCE_FILE" \
        TS="$timestamp" VER="$LUODI_VERSION" OUT="$EXPORT_JSON" \
        python3 - << 'PYEOF'
import json, os, sys

def e(k, default=''):
    return os.environ.get(k, default)

port_raw = e('LUODI_PORT', '0')
try:    port_val = int(port_raw)
except: port_val = port_raw

data = {
    "version": e('VER'),
    "generated_at": e('TS'),
    "nodes": [{
        "ip":           e('LUODI_IP'),
        "port":         port_val,
        "uuid":         e('LUODI_UUID'),
        "pubkey":       e('LUODI_PUBKEY'),
        "sni":          e('LUODI_SNI'),
        "shortid":      e('LUODI_SHORTID'),
        "network":      e('LUODI_NETWORK', 'tcp'),
        "xhttp_path":   e('LUODI_XHTTP_PATH', '/'),
        "xhttp_host":   e('LUODI_XHTTP_HOST'),
        "xhttp_mode":   e('LUODI_XHTTP_MODE', 'auto'),
        "ws_path":      e('LUODI_WS_PATH', '/'),
        "ws_host":      e('LUODI_WS_HOST'),
        "grpc_service": e('LUODI_GRPC_SERVICE'),
        "wg_pubkey":    e('LUODI_WG_PUBKEY'),
        "wg_ip":        "",
        "backend_type": e('LUODI_BACKEND_TYPE'),
        "source_file":  e('LUODI_SOURCE_FILE'),
    }]
}
out_path = e('OUT', '/tmp/luodi_export.json')
try:
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"OK:{out_path}")
except Exception as ex:
    print(f"FAIL:{ex}", file=sys.stderr)
    sys.exit(1)
PYEOF
    ) || { echo -e "\033[0;31m[✗]\033[0m export.json 写入失败" >&2; exit 1; }

    if echo "$result" | grep -q "^OK:"; then
        chmod 600 "$EXPORT_JSON"
        log_info "export.json 已写入: $EXPORT_JSON"
    else
        echo -e "\033[0;31m[✗]\033[0m export.json 写入异常: $result" >&2
        exit 1
    fi
}

save_info() {
    local timestamp; timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # 如果已有 info.txt，保留 duijie.sh 写入的对接记录段落（── 对接节点 ... ──── 格式）
    local relay_records=""
    if [[ -f "$INFO_FILE" ]]; then
        relay_records=$(python3 - "$INFO_FILE" << 'PYEOF'
import sys
fp = sys.argv[1]
lines = open(fp, encoding='utf-8', errors='replace').readlines()
result = []; in_relay = False
for line in lines:
    s = line.strip()
    if s.startswith('── 对接节点') and '────' in s:
        in_relay = True
    if in_relay:
        result.append(line)
print(''.join(result), end='')
PYEOF
        ) || relay_records=""
    fi

    # 写入新的 info 文件头
    cat > "$INFO_FILE" << EOF
============================================================
  落地机信息  ${timestamp}
  代理类型: ${LUODI_BACKEND_TYPE}
  版本: luodi.sh v${LUODI_VERSION}
============================================================
LUODI_IP=${LUODI_IP}
LUODI_PORT=${LUODI_PORT}
LUODI_UUID=${LUODI_UUID}
LUODI_PUBKEY=${LUODI_PUBKEY}
LUODI_SHORTID=${LUODI_SHORTID}
LUODI_SNI=${LUODI_SNI}
LUODI_NETWORK=${LUODI_NETWORK}
LUODI_XHTTP_PATH=${LUODI_XHTTP_PATH}
LUODI_XHTTP_HOST=${LUODI_XHTTP_HOST}
LUODI_XHTTP_MODE=${LUODI_XHTTP_MODE}
LUODI_WS_PATH=${LUODI_WS_PATH}
LUODI_WS_HOST=${LUODI_WS_HOST}
LUODI_GRPC_SERVICE=${LUODI_GRPC_SERVICE}
LUODI_WG_PUBKEY=${LUODI_WG_PUBKEY}
LUODI_WG_PRIVKEY=${LUODI_WG_PRIVKEY}
LUODI_BACKEND_TYPE=${LUODI_BACKEND_TYPE}
LUODI_SOURCE_FILE=${LUODI_SOURCE_FILE}

── 管理命令 ──────────────────────────────────────────────
查看状态     : bash luodi.sh --status
重新读取参数 : bash luodi.sh --refresh
完全重置     : bash luodi.sh --reset
对接中转机   : bash duijie.sh
EOF

    chmod 600 "$INFO_FILE"

    # 追加保留的对接记录
    if [[ -n "$relay_records" ]]; then
        echo "" >> "$INFO_FILE"
        printf '%s' "$relay_records" >> "$INFO_FILE"
    fi

    log_info "info.txt 已写入: $INFO_FILE"
}

# ══════════════════════════════════════════════════════════════════════
# §11 打印结果摘要
# ══════════════════════════════════════════════════════════════════════

print_result() {
    echo ""
    log_sep
    echo -e "${GREEN}${BOLD}  ✓ 落地机初始化完成  luodi.sh v${LUODI_VERSION}${NC}"
    log_sep
    echo ""
    echo -e "  ${BOLD}落地机 IP   :${NC}  ${LUODI_IP}"
    echo -e "  ${BOLD}代理端口    :${NC}  ${LUODI_PORT}"
    echo -e "  ${BOLD}UUID        :${NC}  ${LUODI_UUID:0:16}..."
    echo -e "  ${BOLD}Reality 公钥:${NC}  ${LUODI_PUBKEY:0:24}..."
    echo -e "  ${BOLD}SNI         :${NC}  ${LUODI_SNI}"
    echo -e "  ${BOLD}Short ID    :${NC}  ${LUODI_SHORTID:-（空）}"
    echo -e "  ${BOLD}传输协议    :${NC}  ${LUODI_NETWORK}"
    echo -e "  ${BOLD}WG 公钥     :${NC}  ${LUODI_WG_PUBKEY:0:24}..."
    echo -e "  ${BOLD}后端类型    :${NC}  ${LUODI_BACKEND_TYPE}"
    echo ""
    echo -e "  ${BOLD}输出文件    :${NC}"
    echo -e "    ${CYAN}${INFO_FILE}${NC}"
    echo -e "    ${CYAN}${EXPORT_JSON}${NC}"
    echo ""
    log_sep
    echo -e "  ${YELLOW}下一步：${NC}"
    echo -e "  在落地机上运行 duijie.sh 完成双端对接："
    echo -e "  ${GREEN}bash duijie.sh${NC}"
    echo ""
    echo -e "  ${YELLOW}建议在 30 分钟内运行 duijie.sh（export.json 时效性）${NC}"
    log_sep
    echo ""
}

# ══════════════════════════════════════════════════════════════════════
# §12 --status 命令
# ══════════════════════════════════════════════════════════════════════

cmd_status() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║       落地机状态  luodi.sh  v${LUODI_VERSION}                         ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    if [[ -f "$INFO_FILE" ]]; then
        _ikv() { grep -m1 "^${1}=" "$INFO_FILE" 2>/dev/null | cut -d= -f2- | tr -d '\r'; }

        echo -e "  ${BOLD}代理后端    :${NC} $(_ikv LUODI_BACKEND_TYPE)"
        echo -e "  ${BOLD}配置文件    :${NC} $(_ikv LUODI_SOURCE_FILE)"
        echo -e "  ${BOLD}落地机 IP   :${NC} $(_ikv LUODI_IP)"
        echo -e "  ${BOLD}代理端口    :${NC} $(_ikv LUODI_PORT)"
        echo -e "  ${BOLD}UUID        :${NC} $(_ikv LUODI_UUID | head -c 16)..."
        local pk; pk=$(_ikv LUODI_PUBKEY)
        [[ -n "$pk" ]] && echo -e "  ${BOLD}Reality 公钥:${NC} ${pk:0:24}..."
        echo -e "  ${BOLD}SNI         :${NC} $(_ikv LUODI_SNI)"
        echo -e "  ${BOLD}Short ID    :${NC} $(_ikv LUODI_SHORTID)"
        echo -e "  ${BOLD}传输协议    :${NC} $(_ikv LUODI_NETWORK)"
        echo ""
    else
        echo -e "  ${YELLOW}info.txt 不存在，请先运行 bash luodi.sh${NC}"
        echo ""
    fi

    # WireGuard 状态
    if command -v wg &>/dev/null; then
        local wg_pk=""
        [[ -f "$WG_PUB_FILE" ]] && wg_pk=$(cat "$WG_PUB_FILE" 2>/dev/null || true)
        if [[ -n "$wg_pk" ]]; then
            echo -e "  ${BOLD}WireGuard   :${NC} 已安装，公钥 ${wg_pk:0:20}..."
        else
            echo -e "  ${BOLD}WireGuard   :${NC} 已安装，密钥未生成"
        fi

        if ip link show wg0 &>/dev/null 2>&1; then
            local wg_addr; wg_addr=$(ip addr show wg0 2>/dev/null | grep "inet " | awk '{print $2}' || true)
            echo -e "  ${BOLD}wg0 状态    :${NC} ${GREEN}运行中（${wg_addr:-wg0}）${NC}"
            wg show wg0 2>/dev/null | grep -E "^  peer:|latest handshake" | head -8 \
                | while IFS= read -r line; do echo "    $line"; done || true
        else
            echo -e "  ${BOLD}wg0 状态    :${NC} 未运行（等待 duijie.sh 配置）"
        fi
    else
        echo -e "  ${BOLD}WireGuard   :${NC} ${RED}未安装${NC}"
    fi
    echo ""

    # export.json 状态
    if [[ -f "$EXPORT_JSON" ]]; then
        local age_min
        age_min=$(( ( $(date +%s) - $(stat -c %Y "$EXPORT_JSON" 2>/dev/null || echo 0) ) / 60 ))
        local age_str="${age_min} 分钟前"
        if [[ $age_min -lt 30 ]]; then
            echo -e "  ${BOLD}export.json :${NC} ${GREEN}存在（${age_str}生成，仍有效）${NC}"
        else
            echo -e "  ${BOLD}export.json :${NC} ${YELLOW}存在（${age_str}生成，建议刷新）${NC}"
        fi
    else
        echo -e "  ${BOLD}export.json :${NC} ${RED}不存在${NC}，请运行 bash luodi.sh"
    fi

    if [[ -f "$INFO_FILE" ]]; then
        echo -e "  ${BOLD}info.txt    :${NC} 存在（$INFO_FILE）"
    else
        echo -e "  ${BOLD}info.txt    :${NC} ${RED}不存在${NC}"
    fi

    # 对接记录
    local relay_count
    relay_count=$(grep -c "^── 对接节点" "$INFO_FILE" 2>/dev/null || echo 0)
    if [[ "$relay_count" -gt 0 ]]; then
        echo ""
        echo -e "  ${BOLD}对接记录（共 ${relay_count} 条）：${NC}"
        grep -A2 "^── 对接节点" "$INFO_FILE" 2>/dev/null \
            | grep "^RELAY_IP=" | cut -d= -f2- \
            | while IFS= read -r rip; do
                echo -e "    中转机 IP: ${rip}"
            done || true
    fi

    echo ""
    echo -e "  ${YELLOW}下一步：${NC} bash duijie.sh"
    echo ""
}

# ══════════════════════════════════════════════════════════════════════
# §13 --check 命令
# ══════════════════════════════════════════════════════════════════════

cmd_check() {
    echo ""
    log_step "检查 export.json 与实际配置一致性..."
    echo ""

    local issues=0

    # 1. 检查 export.json 存在
    if [[ ! -f "$EXPORT_JSON" ]]; then
        log_warn "export.json 不存在，请运行 bash luodi.sh 生成"
        (( issues++ )) || true
    else
        # 2. 检查 WG 公钥一致
        local export_wg_pk
        export_wg_pk=$(python3 -c "
import json, sys
try:
    d = json.load(open('$EXPORT_JSON'))
    n = d.get('nodes', [{}])[0]
    print(n.get('wg_pubkey',''))
except: print('')
" 2>/dev/null || true)

        local actual_wg_pk=""
        [[ -f "$WG_PUB_FILE" ]] && actual_wg_pk=$(cat "$WG_PUB_FILE" 2>/dev/null || true)

        if [[ -n "$actual_wg_pk" && -n "$export_wg_pk" && "$export_wg_pk" != "$actual_wg_pk" ]]; then
            log_warn "WG 公钥不一致！"
            log_warn "  export.json : ${export_wg_pk:0:20}..."
            log_warn "  实际文件    : ${actual_wg_pk:0:20}..."
            log_warn "  → 请重新运行 bash luodi.sh 刷新 export.json"
            (( issues++ )) || true
        else
            log_info "WG 公钥一致 ✓"
        fi

        # 3. 检查 export.json 时效
        local age_min
        age_min=$(( ( $(date +%s) - $(stat -c %Y "$EXPORT_JSON" 2>/dev/null || echo 0) ) / 60 ))
        if [[ $age_min -gt 60 ]]; then
            log_warn "export.json 生成于 ${age_min} 分钟前（> 60 分钟），建议刷新"
            (( issues++ )) || true
        else
            log_info "export.json 时效正常（${age_min} 分钟前）✓"
        fi

        # 4. 检查代理服务是否运行
        local export_port
        export_port=$(python3 -c "
import json
try:
    d = json.load(open('$EXPORT_JSON'))
    print(d.get('nodes',[{}])[0].get('port',''))
except: print('')
" 2>/dev/null || true)

        if [[ -n "$export_port" ]]; then
            if ss -tlnp 2>/dev/null | grep -q ":${export_port} " \
               || ss -tlnp 2>/dev/null | grep -q ":${export_port}$"; then
                log_info "代理端口 ${export_port} 正在监听 ✓"
            else
                log_warn "代理端口 ${export_port} 未监听（Xray/Sing-box 可能未启动）"
                log_warn "  → systemctl status xray / systemctl status sing-box"
                (( issues++ )) || true
            fi
        fi
    fi

    # 5. WG 密钥文件检查
    if [[ ! -f "$WG_KEY_FILE" ]]; then
        log_warn "WG 私钥文件不存在（${WG_KEY_FILE}），请重新运行 bash luodi.sh"
        (( issues++ )) || true
    else
        log_info "WG 私钥文件存在 ✓"
    fi

    echo ""
    if [[ $issues -eq 0 ]]; then
        log_info "所有检查通过，可以运行 bash duijie.sh"
    else
        log_warn "${issues} 项检查未通过，建议重新运行 bash luodi.sh 刷新数据"
    fi
    echo ""
}

# ══════════════════════════════════════════════════════════════════════
# §14 print_banner
# ══════════════════════════════════════════════════════════════════════

print_banner() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  luodi.sh  v${LUODI_VERSION}  —  落地机信息收集（WireGuard 版）             ║${NC}"
    echo -e "${CYAN}║  嗅探代理参数 · 安装 WG · 生成密钥 · 写入 export.json            ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ══════════════════════════════════════════════════════════════════════
# §15 参数处理
# ══════════════════════════════════════════════════════════════════════

handle_args() {
    case "${1:-}" in
        --status)
            check_root
            cmd_status
            exit 0 ;;
        --check)
            check_root
            cmd_check
            exit 0 ;;
        --refresh)
            check_root
            print_banner
            # 直接进入 refresh 流程（跳过决策菜单）
            detect_oracle
            _load_existing_params 2>/dev/null || true
            LUODI_IP=$(get_public_ip)
            install_wireguard
            manage_wg_keys "false"  # 保留已有密钥
            sniff_proxy_params
            confirm_params
            save_export_json
            save_info
            print_result
            exit 0 ;;
        --reset)
            check_root
            print_banner
            detect_oracle
            _load_existing_params 2>/dev/null || true
            do_full_reset
            # 重置后继续正常初始化流程（不 exit）
            ;;
        --help|-h)
            echo "用法: bash luodi.sh [选项]"
            echo "  --status    查看当前落地机状态"
            echo "  --refresh   重新读取代理参数（保留 WG 密钥）"
            echo "  --reset     完全重置（重新生成 WG 密钥）"
            echo "  --check     检查配置一致性"
            exit 0 ;;
    esac
}

# ══════════════════════════════════════════════════════════════════════
# §16 主流程
# ══════════════════════════════════════════════════════════════════════

main() {
    handle_args "$@"

    check_root
    print_banner
    detect_oracle

    # ── 检测已有状态 ────────────────────────────────────────────────
    local state
    state=$(detect_existing_state)

    local action="fresh"

    if [[ "$state" == "full" || "$state" == "partial" ]]; then
        # 加载已有参数（供摘要展示）
        _load_existing_params 2>/dev/null || true

        _show_existing_summary "$state"
        action=$(user_decision "$state")
    fi

    # ── 执行决策 ─────────────────────────────────────────────────────
    case "$action" in
        reuse)
            # 选项 1：使用现有配置，仅刷新 IP 和 export.json
            log_step "复用现有配置，刷新公网 IP..."
            LUODI_IP=$(get_public_ip)

            # 确保 WG 密钥已加载
            if [[ -z "$LUODI_WG_PRIVKEY" || -z "$LUODI_WG_PUBKEY" ]]; then
                if [[ -f "$WG_KEY_FILE" ]]; then
                    LUODI_WG_PRIVKEY=$(cat "$WG_KEY_FILE")
                    # 优先读公钥文件；回退派生时 wg 命令必须可用——先确保已安装
                    LUODI_WG_PUBKEY=$(cat "$WG_PUB_FILE" 2>/dev/null || true)
                    if [[ -z "$LUODI_WG_PUBKEY" ]]; then
                        install_wireguard
                        LUODI_WG_PUBKEY=$(echo "$LUODI_WG_PRIVKEY" | wg pubkey)
                        echo "$LUODI_WG_PUBKEY" > "$WG_PUB_FILE"
                        chmod 644 "$WG_PUB_FILE"
                        log_info "已从私钥重新派生公钥并写入 ${WG_PUB_FILE}"
                    fi
                else
                    log_warn "WG 密钥文件不存在，将重新生成..."
                    install_wireguard
                    manage_wg_keys "false"
                fi
            fi

            save_export_json
            save_info
            print_result
            ;;

        refresh)
            # 选项 2：重新嗅探，保留 WG 密钥
            LUODI_IP=$(get_public_ip)
            install_wireguard
            manage_wg_keys "false"  # 不强制重新生成
            sniff_proxy_params
            confirm_params
            save_export_json
            save_info
            print_result
            ;;

        full_reset)
            # 选项 3：先执行完全重置（备份旧密钥、停 wg0、询问 SSH 清理中转机）
            do_full_reset
            LUODI_IP=$(get_public_ip)
            install_wireguard
            manage_wg_keys "false"  # 旧密钥已删除，generate_wg_keys 生成新密钥
            sniff_proxy_params
            confirm_params
            save_export_json
            save_info
            print_result
            ;;

        fresh | *)
            # 首次安装 / 从 --reset 继续
            log_step "首次初始化落地机..."
            LUODI_IP=$(get_public_ip)
            install_wireguard
            manage_wg_keys "false"
            sniff_proxy_params
            confirm_params
            save_export_json
            save_info
            print_result
            ;;
    esac
}

main "$@"
