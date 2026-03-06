#!/bin/bash
# ============================================================
# wg_duijie.sh v2.0 — 落地机代理节点对接中转机一键脚本
# 功能：在落地机上运行，检测代理节点，SSH 到中转机添加
#       DNAT+SNAT 规则，生成用户节点链接
# 特性：
#   - 多认证方式 SSH：密钥(默认)/密钥文件/密码/手动
#   - 多代理后端检测：Xray / Sing-box / x-ui / 3x-ui
#   - 过滤 127.0.0.1 内部端口，避免误添加规则
#   - SNAT 源设为 10.0.0.1（中转机 WG IP），回程全走隧道
#   - 正确生成 Xray / Sing-box Reality 节点链接
# 用法：bash <(curl -s https://raw.githubusercontent.com/vpn3288/proxy/main/wg_duijie.sh)
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
NODES_FILE="$CONFIG_DIR/nodes.txt"
mkdir -p "$CONFIG_DIR"

# ── 全局变量 ─────────────────────────────────────────────────
LUODI_NAME="" LUODI_WG_IP="" LUODI_PUBLIC_IP=""
RELAY_IP="" RELAY_WG_IP="10.0.0.1" RELAY_WG_PORT=""
RELAY_SSH_PORT="22" RELAY_SSH_USER="root"   # SSH端口默认22，独立于WG端口
AUTH_TYPE="" RELAY_KEY_FILE="" RELAY_SSH_PASS=""
SSH_OPTS=""

declare -a SELECTED_PORTS=()
declare -a SELECTED_PROTOS=()
declare -a FINAL_LINKS=()

# ──────────────────────────────────────────────────────────────
# SSH 工具函数
# ──────────────────────────────────────────────────────────────
run_relay() {
    local cmd="$1"
    case "$AUTH_TYPE" in
        key)      ssh -q $SSH_OPTS "${RELAY_SSH_USER}@${RELAY_SSH_HOST}" "$cmd" ;;
        keyfile)  ssh -q $SSH_OPTS -i "$RELAY_KEY_FILE" "${RELAY_SSH_USER}@${RELAY_SSH_HOST}" "$cmd" ;;
        password) sshpass -p "$RELAY_SSH_PASS" \
                    ssh -q $SSH_OPTS "${RELAY_SSH_USER}@${RELAY_SSH_HOST}" "$cmd" ;;
        manual)   err "manual 模式下不支持自动 SSH" ;;
    esac
}

ssh_stdin() {
    # 将 stdin 通过 SSH 发给中转机的 bash
    case "$AUTH_TYPE" in
        key)      ssh -q $SSH_OPTS "${RELAY_SSH_USER}@${RELAY_SSH_HOST}" "bash -s" ;;
        keyfile)  ssh -q $SSH_OPTS -i "$RELAY_KEY_FILE" "${RELAY_SSH_USER}@${RELAY_SSH_HOST}" "bash -s" ;;
        password) sshpass -p "$RELAY_SSH_PASS" \
                    ssh -q $SSH_OPTS "${RELAY_SSH_USER}@${RELAY_SSH_HOST}" "bash -s" ;;
        manual)   err "manual 模式下不支持自动 SSH" ;;
    esac
}

# ──────────────────────────────────────────────────────────────
# 步骤1：读取落地机本机信息
# ──────────────────────────────────────────────────────────────
read_local_info() {
    hr; echo -e "${PURPLE}步骤 1/5: 读取本机信息${NC}"; hr
    echo ""

    # 从 peer-summary.txt 读取
    if [[ -f "$SUMMARY_FILE" ]]; then
        ok "从 $SUMMARY_FILE 读取..."
        while IFS='=' read -r key val; do
            val=$(echo "$val" | tr -d '\r' | sed 's/^[[:space:]]*//')
            case "$key" in
                LUODI_NAME)       LUODI_NAME="$val"       ;;
                LUODI_WG_IP)      LUODI_WG_IP="$val"      ;;
                LUODI_PUBLIC_IP)  LUODI_PUBLIC_IP="$val"  ;;
                RELAY_PUBLIC_IP)  RELAY_IP="$val"         ;;
                RELAY_WG_IP)      RELAY_WG_IP="$val"      ;;
                RELAY_WG_PORT)    RELAY_WG_PORT="$val"    ;;
            esac
        done < "$SUMMARY_FILE"
    else
        warn "未找到 $SUMMARY_FILE，请先运行 wg_luodi.sh"
        echo ""
        info "若已有 WireGuard 隧道，也可手动输入以下信息："
        read -rp "落地机名称: " LUODI_NAME
        read -rp "落地机 WireGuard IP（如 10.0.0.2）: " LUODI_WG_IP
        read -rp "落地机公网 IP: " LUODI_PUBLIC_IP
        read -rp "中转机公网 IP: " RELAY_IP
    fi

    # 验证 WireGuard 隧道
    step "验证 WireGuard 隧道..."
    if ! wg show wg0 &>/dev/null; then
        err "WireGuard wg0 未运行，请先执行: systemctl start wg-quick@wg0"
    fi
    if ping -c 1 -W 3 10.0.0.1 &>/dev/null; then
        ok "WireGuard 隧道正常（可 ping 到 10.0.0.1）"
    else
        warn "无法 ping 通 10.0.0.1，隧道可能异常"
        echo "  如果中转机仍可通过公网 IP SSH 访问，可继续"
        read -rp "继续？[y/N]: " cn; [[ "${cn,,}" == "y" ]] || exit 1
    fi

    echo ""
    ok "落地机名称:  $LUODI_NAME"
    ok "落地机 WG IP: $LUODI_WG_IP"
    ok "落地机公网IP: $LUODI_PUBLIC_IP"
    ok "中转机 IP:    $RELAY_IP"

    echo ""; read -rp "[按Enter继续...]"
}

# ──────────────────────────────────────────────────────────────
# 步骤2：检测代理后端 + 端口
# ──────────────────────────────────────────────────────────────
detect_proxy_nodes() {
    hr; echo -e "${PURPLE}步骤 2/5: 检测代理节点${NC}"; hr
    echo ""

    # ★ 用 Python 解析配置，过滤 127.0.0.1 内部端口
    local raw_nodes
    raw_nodes=$(python3 << 'PYEOF2'
import json, sys, glob, os

def is_local_listen(v):
    return str(v or "").startswith(("127.", "::1", "localhost"))

def parse_xray_dir(conf_dir):
    results = []
    for fpath in sorted(glob.glob(os.path.join(conf_dir, "*.json"))):
        try:
            with open(fpath) as f:
                data = json.load(f)
        except Exception:
            continue
        for ib in data.get("inbounds", []):
            if not isinstance(ib, dict): continue
            if is_local_listen(ib.get("listen", "")): continue
            port = ib.get("port")
            if not isinstance(port, int) or not (1 <= port <= 65535): continue
            proto = ib.get("protocol", "unknown")
            stream = ib.get("streamSettings", {})
            rc = stream.get("realitySettings", {})
            sids = rc.get("shortIds", [""])
            server_names = rc.get("serverNames", [])
            sni = server_names[0] if server_names else ""
            clients = ib.get("settings", {}).get("clients", [])
            uuids = [c.get("id","") for c in clients if c.get("id")]
            uuid = uuids[0] if uuids else ""
            results.append({
                "port": port, "proto": proto,
                "security": stream.get("security",""),
                "sni": sni,
                "short_id": sids[0] if sids else "",
                "privkey": rc.get("privateKey",""),
                "uuid": uuid, "backend": "xray"
            })
    return results

def parse_singbox(conf_path):
    results = []
    paths = [conf_path] if os.path.isfile(conf_path) else \
            glob.glob(os.path.join(conf_path, "*.json"))
    for fpath in sorted(paths):
        try:
            with open(fpath) as f:
                data = json.load(f)
        except Exception:
            continue
        for ib in data.get("inbounds", []):
            if not isinstance(ib, dict): continue
            if is_local_listen(ib.get("listen","")): continue
            port = ib.get("listen_port", ib.get("port"))
            if not isinstance(port, int) or not (1 <= port <= 65535): continue
            tls = ib.get("tls", {})
            reality = tls.get("reality", {})
            if not reality.get("enabled", False): continue
            priv_key = reality.get("private_key","")
            handshake = reality.get("handshake", {})
            sni = tls.get("server_name","") or handshake.get("server","")
            raw_sid = reality.get("short_id", reality.get("short_ids",""))
            if isinstance(raw_sid, list): short_id = raw_sid[0] if raw_sid else ""
            else: short_id = str(raw_sid)
            users = ib.get("users", [])
            uuid = ""
            for u in users:
                uid = u.get("uuid","") or u.get("password","")
                if uid: uuid = uid; break
            results.append({
                "port": port, "proto": ib.get("type","vless"),
                "security": "reality", "sni": sni, "short_id": short_id,
                "privkey": priv_key, "uuid": uuid, "backend": "singbox"
            })
    return results

def parse_xui(db_path):
    import sqlite3
    results = []
    try:
        conn = sqlite3.connect(db_path)
        rows = conn.execute(
            "SELECT port,protocol,settings,stream_settings FROM inbounds WHERE enable=1"
        ).fetchall()
        conn.close()
    except Exception:
        return results
    for port, proto, settings_raw, stream_raw in rows:
        try:
            stream = json.loads(stream_raw or "{}")
            settings = json.loads(settings_raw or "{}")
        except Exception:
            continue
        if stream.get("security") != "reality": continue
        rc = stream.get("realitySettings",{})
        priv_key = rc.get("privateKey","")
        if not priv_key: continue
        sni = rc.get("serverNames",[""])[0]
        sids = rc.get("shortIds",[""])
        short_id = sids[0] if sids else ""
        clients = settings.get("clients",[])
        uuid = next((c.get("id","") or c.get("password","") for c in clients
                     if c.get("id") or c.get("password")), "")
        results.append({"port":port,"proto":proto,"security":"reality",
            "sni":sni,"short_id":short_id,"privkey":priv_key,
            "uuid":uuid,"backend":"xui"})
    return results

all_results = []
if os.path.isdir("/etc/v2ray-agent/xray/conf"):
    all_results.extend(parse_xray_dir("/etc/v2ray-agent/xray/conf"))
if os.path.isdir("/etc/v2ray-agent/sing-box/conf"):
    all_results.extend(parse_singbox("/etc/v2ray-agent/sing-box/conf"))
for sb in ["/etc/sing-box/config.json","/usr/local/etc/sing-box/config.json",
           "/root/sbconfig.json","/opt/sing-box/config.json"]:
    if os.path.isfile(sb): all_results.extend(parse_singbox(sb))
for xui_db in ["/etc/x-ui/x-ui.db","/usr/local/x-ui/x-ui.db"]:
    if os.path.isfile(xui_db): all_results.extend(parse_xui(xui_db))

if not all_results:
    print("NOT_FOUND")
    sys.exit(0)

seen = set()
for r in all_results:
    if r["port"] in seen: continue
    seen.add(r["port"])
    print(f"PORT={r['port']}|PROTO={r['proto']}|SECURITY={r['security']}|"
          f"SNI={r['sni']}|SHORTID={r['short_id']}|PRIVKEY={r['privkey']}|"
          f"UUID={r['uuid']}|BACKEND={r['backend']}")
PYEOF2
    )

    if [[ "$raw_nodes" == "NOT_FOUND" || -z "$raw_nodes" ]]; then
        warn "未自动检测到代理节点配置"
        info "支持的后端：mack-a Xray / mack-a Sing-box / 独立 Sing-box / x-ui / 3x-ui"
        echo ""
        info "请手动输入代理节点信息："
        while true; do
            read -rp "代理端口: " _mport
            [[ "$_mport" =~ ^[0-9]+$ ]] && (( _mport >= 1 && _mport <= 65535 )) && break
            warn "端口格式错误"
        done
        read -rp "协议类型 (vless/vmess/trojan) [vless]: " _mproto
        _mproto="${_mproto:-vless}"
        SELECTED_PORTS=("$_mport")
        SELECTED_PROTOS=("$_mproto")
        # 手动输入 Reality 参数（用于生成链接）
        declare -gA NODE_UUID NODE_SNI NODE_SHORTID NODE_PUBKEY NODE_BACKEND
        read -rp "UUID: " NODE_UUID[$_mport]
        read -rp "SNI（伪装域名）: " NODE_SNI[$_mport]
        read -rp "Short ID（无则回车）: " NODE_SHORTID[$_mport]
        NODE_SHORTID[$_mport]="${NODE_SHORTID[$_mport]:-}"
        read -rp "公钥 (pubkey): " NODE_PUBKEY[$_mport]
        NODE_BACKEND[$_mport]="manual"
        return
    fi

    # 解析输出，展示给用户选择
    declare -ga ALL_PORTS=() ALL_PROTOS=() ALL_SECURITY=() ALL_SNIS=()
    declare -ga ALL_SHORTIDS=() ALL_PRIVKEYS=() ALL_UUIDS=() ALL_BACKENDS=()

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local _p _pr _sec _sni _sid _pk _uuid _be
        _p=$(echo "$line"    | grep -oE 'PORT=[^|]+' | cut -d= -f2)
        _pr=$(echo "$line"   | grep -oE 'PROTO=[^|]+' | cut -d= -f2)
        _sec=$(echo "$line"  | grep -oE 'SECURITY=[^|]+' | cut -d= -f2)
        _sni=$(echo "$line"  | grep -oE 'SNI=[^|]+' | cut -d= -f2)
        _sid=$(echo "$line"  | grep -oE 'SHORTID=[^|]+' | cut -d= -f2)
        _pk=$(echo "$line"   | grep -oE 'PRIVKEY=[^|]+' | cut -d= -f2)
        _uuid=$(echo "$line" | grep -oE 'UUID=[^|]+' | cut -d= -f2)
        _be=$(echo "$line"   | grep -oE 'BACKEND=[^|]+' | cut -d= -f2)
        ALL_PORTS+=("$_p"); ALL_PROTOS+=("$_pr"); ALL_SECURITY+=("$_sec")
        ALL_SNIS+=("$_sni"); ALL_SHORTIDS+=("$_sid"); ALL_PRIVKEYS+=("$_pk")
        ALL_UUIDS+=("$_uuid"); ALL_BACKENDS+=("$_be")
    done <<< "$raw_nodes"

    echo ""
    ok "检测到以下代理节点："
    echo ""
    for (( i=0; i<${#ALL_PORTS[@]}; i++ )); do
        printf "  ${CYAN}[%d]${NC} 端口: ${GREEN}%-6s${NC} 协议: %-12s 后端: %-10s SNI: %s\n" \
            "$((i+1))" "${ALL_PORTS[$i]}" "${ALL_PROTOS[$i]}" "${ALL_BACKENDS[$i]}" "${ALL_SNIS[$i]}"
    done
    echo ""

    local selection
    if [[ ${#ALL_PORTS[@]} -eq 1 ]]; then
        selection="1"
        info "只有一个节点，自动选择"
    else
        read -rp "选择要对接的节点编号（多个用空格隔开，直接回车选择全部）: " selection
    fi

    declare -gA NODE_UUID NODE_SNI NODE_SHORTID NODE_PUBKEY NODE_BACKEND NODE_PRIVKEY NODE_SECURITY

    if [[ -z "$selection" ]]; then
        for (( i=0; i<${#ALL_PORTS[@]}; i++ )); do
            local p="${ALL_PORTS[$i]}"
            SELECTED_PORTS+=("$p"); SELECTED_PROTOS+=("${ALL_PROTOS[$i]}")
            _store_node_info "$i" "$p"
        done
    else
        for idx in $selection; do
            if [[ "$idx" =~ ^[0-9]+$ ]] && (( idx >= 1 && idx <= ${#ALL_PORTS[@]} )); then
                local i=$((idx-1))
                local p="${ALL_PORTS[$i]}"
                SELECTED_PORTS+=("$p"); SELECTED_PROTOS+=("${ALL_PROTOS[$i]}")
                _store_node_info "$i" "$p"
            fi
        done
    fi

    echo ""; read -rp "[按Enter继续...]"
}

_store_node_info() {
    local i=$1 p=$2
    NODE_UUID[$p]="${ALL_UUIDS[$i]}"
    NODE_SNI[$p]="${ALL_SNIS[$i]}"
    NODE_SHORTID[$p]="${ALL_SHORTIDS[$i]}"
    NODE_BACKEND[$p]="${ALL_BACKENDS[$i]}"
    NODE_PRIVKEY[$p]="${ALL_PRIVKEYS[$i]}"
    NODE_SECURITY[$p]="${ALL_SECURITY[$i]}"
    # 从私钥推导公钥
    NODE_PUBKEY[$p]=$(derive_pubkey "${ALL_PRIVKEYS[$i]}" 2>/dev/null || echo "")
}

# ── 推导公钥 ─────────────────────────────────────────────────
derive_pubkey() {
    local priv="$1"
    [[ -z "$priv" ]] && return 1

    # 方法1：xray x25519
    local xray_bin=""
    for _p in /etc/v2ray-agent/xray/xray /usr/local/bin/xray /usr/bin/xray; do
        [[ -x "$_p" ]] && { xray_bin="$_p"; break; }
    done
    local w; w=$(command -v xray 2>/dev/null || true)
    [[ -z "$xray_bin" && -n "$w" ]] && xray_bin="$w"

    if [[ -n "$xray_bin" ]]; then
        local out; out=$("$xray_bin" x25519 -i "$priv" 2>/dev/null || true)
        local pub
        pub=$(echo "$out" | grep -iE "^(Public key|Password):" | awk '{print $NF}' | tr -d '[:space:]')
        [[ -z "$pub" ]] && pub=$(echo "$out" | awk 'NR==2{print $NF}')
        [[ -n "$pub" ]] && { echo "$pub"; return 0; }
    fi

    # 方法2：Python cryptography
    python3 - "$priv" << 'PYEOF' 2>/dev/null || true
import sys, base64
priv = sys.argv[1].strip()
pad = 4 - len(priv) % 4
if pad != 4: priv += '=' * pad
try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    raw = base64.urlsafe_b64decode(priv)
    if len(raw) != 32:
        raw = base64.b64decode(priv + '==')
    priv_obj = X25519PrivateKey.from_private_bytes(raw[:32])
    pub_raw = priv_obj.public_key().public_bytes_raw()
    print(base64.b64encode(pub_raw).decode())
except Exception:
    pass
PYEOF
}

# ──────────────────────────────────────────────────────────────
# 步骤3：配置 SSH 连接到中转机
# ──────────────────────────────────────────────────────────────
setup_ssh() {
    hr; echo -e "${PURPLE}步骤 3/5: 配置中转机 SSH 连接${NC}"; hr
    echo ""

    # SSH 主机优先用 WG 隧道地址（如果能通）
    if ping -c 1 -W 2 10.0.0.1 &>/dev/null; then
        RELAY_SSH_HOST="10.0.0.1"
        info "将通过 WireGuard 隧道 (10.0.0.1) SSH 到中转机"
    else
        RELAY_SSH_HOST="$RELAY_IP"
        warn "WireGuard 隧道不通，将通过公网 ($RELAY_IP) SSH 到中转机"
    fi

    read -rp "中转机 SSH 端口 [22]: " i; RELAY_SSH_PORT="${i:-22}"
    read -rp "中转机 SSH 用户 [root]: " i; RELAY_SSH_USER="${i:-root}"

    SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -p $RELAY_SSH_PORT"

    echo ""
    echo -e "${YELLOW}选择 SSH 认证方式：${NC}"
    echo -e "  ${CYAN}[1]${NC} 密钥登录（推荐，使用 ~/.ssh/id_rsa）"
    echo -e "  ${CYAN}[2]${NC} 指定密钥文件"
    echo -e "  ${CYAN}[3]${NC} 密码登录"
    echo -e "  ${CYAN}[4]${NC} 手动模式（无法 SSH 时，输出命令让你手动执行）"
    read -rp "选择 [默认1]: " choice; choice="${choice:-1}"

    case "$choice" in
        1)
            AUTH_TYPE="key"
            if ssh -q $SSH_OPTS -o BatchMode=yes "${RELAY_SSH_USER}@${RELAY_SSH_HOST}" "exit" 2>/dev/null; then
                ok "密钥认证测试成功"
            else
                warn "密钥认证失败（可能需要先 ssh-copy-id 到中转机）"
                read -rp "仍然继续使用密钥认证？[y/N]: " yn
                [[ "${yn,,}" != "y" ]] && { AUTH_TYPE="manual"; warn "切换到手动模式"; }
            fi
            ;;
        2)
            read -rp "密钥文件路径 [~/.ssh/id_rsa]: " RELAY_KEY_FILE
            RELAY_KEY_FILE="${RELAY_KEY_FILE:-~/.ssh/id_rsa}"
            RELAY_KEY_FILE="${RELAY_KEY_FILE/#\~/$HOME}"
            [[ -f "$RELAY_KEY_FILE" ]] || err "密钥文件不存在: $RELAY_KEY_FILE"
            AUTH_TYPE="keyfile"
            ok "密钥文件: $RELAY_KEY_FILE"
            ;;
        3)
            if ! command -v sshpass &>/dev/null; then
                step "安装 sshpass..."
                apt-get install -y -qq sshpass 2>/dev/null || true
            fi
            command -v sshpass &>/dev/null || err "sshpass 安装失败，请改用密钥登录"
            read -rsp "中转机 SSH 密码: " RELAY_SSH_PASS; echo ""
            AUTH_TYPE="password"
            ;;
        *)
            AUTH_TYPE="manual"
            warn "手动模式：脚本将输出需要在中转机执行的命令"
            ;;
    esac

    echo ""; read -rp "[按Enter继续...]"
}

# ──────────────────────────────────────────────────────────────
# 步骤4：在中转机添加 DNAT+SNAT 规则
# ──────────────────────────────────────────────────────────────
add_relay_rules() {
    hr; echo -e "${PURPLE}步骤 4/5: 添加中转机 DNAT+SNAT 规则${NC}"; hr
    echo ""
    info "DNAT: 外部流量 → 落地机 WG IP ($LUODI_WG_IP)"
    info "SNAT: 来源改为 10.0.0.1（确保回程流量走 WireGuard 隧道）"
    echo ""

    # 构建要在中转机执行的 shell 命令
    local CMDS=""
    for port in "${SELECTED_PORTS[@]}"; do
        CMDS+=$(cat << ENDRULES
# ── 端口 $port ──
# 删除旧规则（幂等）
iptables -t nat -D PREROUTING -p tcp --dport $port -j DNAT --to-destination ${LUODI_WG_IP}:${port} 2>/dev/null || true
iptables -t nat -D PREROUTING -p udp --dport $port -j DNAT --to-destination ${LUODI_WG_IP}:${port} 2>/dev/null || true
iptables -t nat -D POSTROUTING -d ${LUODI_WG_IP} -p tcp --dport $port -j SNAT --to-source 10.0.0.1 2>/dev/null || true
iptables -t nat -D POSTROUTING -d ${LUODI_WG_IP} -p udp --dport $port -j SNAT --to-source 10.0.0.1 2>/dev/null || true
iptables -D FORWARD -d ${LUODI_WG_IP} -p tcp --dport $port -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -d ${LUODI_WG_IP} -p udp --dport $port -j ACCEPT 2>/dev/null || true
iptables -D INPUT  -p tcp --dport $port -j ACCEPT 2>/dev/null || true
iptables -D INPUT  -p udp --dport $port -j ACCEPT 2>/dev/null || true
# 添加新规则
iptables -t nat -A PREROUTING -p tcp --dport $port -j DNAT --to-destination ${LUODI_WG_IP}:${port}
iptables -t nat -A PREROUTING -p udp --dport $port -j DNAT --to-destination ${LUODI_WG_IP}:${port}
iptables -t nat -A POSTROUTING -d ${LUODI_WG_IP} -p tcp --dport $port -j SNAT --to-source 10.0.0.1
iptables -t nat -A POSTROUTING -d ${LUODI_WG_IP} -p udp --dport $port -j SNAT --to-source 10.0.0.1
iptables -A FORWARD -d ${LUODI_WG_IP} -p tcp --dport $port -j ACCEPT
iptables -A FORWARD -d ${LUODI_WG_IP} -p udp --dport $port -j ACCEPT
iptables -I INPUT -p tcp --dport $port -j ACCEPT
iptables -I INPUT -p udp --dport $port -j ACCEPT
echo "[OK] 端口 $port DNAT+SNAT 规则已添加"
ENDRULES
)
    done
    CMDS+="
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4
command -v netfilter-persistent &>/dev/null && netfilter-persistent save &>/dev/null || true
echo '[OK] 规则已持久化'
"

    if [[ "$AUTH_TYPE" == "manual" ]]; then
        echo ""
        echo -e "${YELLOW}══ 请在中转机上执行以下命令 ══${NC}"
        echo -e "  （SSH到中转机后，将以下内容复制粘贴执行）"
        echo ""
        echo "────────────────────────────────────────"
        echo "$CMDS"
        echo "────────────────────────────────────────"
        echo ""
        read -rp "已在中转机执行完毕？按回车继续..." _
        ok "手动模式：已确认中转机规则已添加"
    else
        step "连接中转机并执行规则..."
        local result
        if result=$(echo "$CMDS" | ssh_stdin 2>&1); then
            while IFS= read -r line; do
                [[ -n "$line" ]] && ok "中转机: $line"
            done <<< "$result"
            ok "中转机规则添加成功"
        else
            warn "SSH 执行可能有误，输出："
            echo "$result"
            warn "如果以上错误不影响，可继续"
            read -rp "继续？[y/N]: " cn; [[ "${cn,,}" == "y" ]] || exit 1
        fi
    fi

    echo ""; read -rp "[按Enter继续...]"
}

# ──────────────────────────────────────────────────────────────
# 步骤5：生成节点链接
# ──────────────────────────────────────────────────────────────
generate_links() {
    hr; echo -e "${PURPLE}步骤 5/5: 生成节点链接${NC}"; hr
    echo ""

    for port in "${SELECTED_PORTS[@]}"; do
        local uuid="${NODE_UUID[$port]:-}"
        local sni="${NODE_SNI[$port]:-}"
        local short_id="${NODE_SHORTID[$port]:-}"
        local pubkey="${NODE_PUBKEY[$port]:-}"
        local backend="${NODE_BACKEND[$port]:-unknown}"
        local security="${NODE_SECURITY[$port]:-}"

        # 只有 Reality 协议才需要公钥
        if [[ "$security" == "reality" ]]; then
            if [[ -z "$pubkey" ]]; then
                warn "端口 $port：无法自动获取公钥"
                info "请运行 'xray x25519 -i <私钥>' 或在代理面板查看公钥"
                read -rp "端口 $port 的公钥 (pubkey): " pubkey
                NODE_PUBKEY[$port]="$pubkey"
            fi
        fi

        if [[ -z "$uuid" ]]; then
            warn "端口 $port：无法获取 UUID"
            read -rp "端口 $port 的 UUID: " uuid
            NODE_UUID[$port]="$uuid"
        fi

        if [[ -z "$sni" ]]; then
            warn "端口 $port：无法获取 SNI"
            read -rp "端口 $port 的 SNI（伪装域名）: " sni
            NODE_SNI[$port]="$sni"
        fi

        # 节点标签
        local label="${LUODI_NAME:-${LUODI_PUBLIC_IP}}-via-${RELAY_IP}"

        # 生成节点链接
        local link
        if [[ "$security" == "reality" && -n "$pubkey" && -n "$uuid" ]]; then
            # Reality 协议链接
            local params="encryption=none&flow=xtls-rprx-vision&security=reality"
            params+="&type=tcp&sni=${sni}"
            params+="&fp=chrome&pbk=${pubkey}"
            [[ -n "$short_id" ]] && params+="&sid=${short_id}"
            link="vless://${uuid}@${RELAY_IP}:${port}?${params}#${label}"
        elif [[ -n "$uuid" ]]; then
            # 普通 VLESS/VMess（无 Reality）
            local params="encryption=none&security=none&type=tcp"
            [[ -n "$sni" ]] && params+="&sni=${sni}"
            link="vless://${uuid}@${RELAY_IP}:${port}?${params}#${label}"
        else
            warn "端口 $port：参数不完整（缺少UUID），跳过生成链接"
            continue
        fi

        FINAL_LINKS+=("$link")
        ok "端口 $port 链接已生成（后端: $backend）"
    done
}

# ──────────────────────────────────────────────────────────────
# 保存 + 展示结果
# ──────────────────────────────────────────────────────────────
save_and_show() {
    # 保存节点链接
    {
        echo "============================================================"
        echo "  对接节点链接"
        echo "  生成时间: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  落地机: $LUODI_NAME ($LUODI_WG_IP / $LUODI_PUBLIC_IP)"
        echo "  中转机: $RELAY_IP"
        echo "============================================================"
        echo ""
        for (( i=0; i<${#SELECTED_PORTS[@]}; i++ )); do
            local p="${SELECTED_PORTS[$i]}"
            echo "【端口 $p | ${SELECTED_PROTOS[$i]}】"
            for link in "${FINAL_LINKS[@]:-}"; do
                [[ "$link" == *"@${RELAY_IP}:${p}?"* ]] && echo "$link"
            done
            echo ""
        done
    } > "$NODES_FILE"
    chmod 600 "$NODES_FILE"
    ok "节点链接已保存: $NODES_FILE"

    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                  ★ 对接完成！                                  ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}【流量路径】${NC}"
    echo -e "  用户 → ${GREEN}${RELAY_IP}:PORT${NC} (中转机 CN2GIA 入口)"
    echo -e "       → WireGuard 加密隧道"
    echo -e "       → ${GREEN}${LUODI_WG_IP}:PORT${NC} (落地机 WG IP)"
    echo -e "       → ${GREEN}${LUODI_PUBLIC_IP}${NC} (落地机出口 IP，真实 IP)"
    echo ""
    echo -e "${YELLOW}【节点链接】（导入客户端使用）${NC}"
    for link in "${FINAL_LINKS[@]:-}"; do
        echo -e "  ${GREEN}${link}${NC}"
        echo ""
    done
    echo -e "${YELLOW}【端口转发规则（中转机）】${NC}"
    for port in "${SELECTED_PORTS[@]}"; do
        echo -e "  ${RELAY_IP}:${GREEN}${port}${NC} → ${LUODI_WG_IP}:${GREEN}${port}${NC} (DNAT+SNAT→10.0.0.1)"
    done
    echo ""
    echo -e "  查看所有节点  → ${CYAN}relay-info${NC}"
    echo -e "  查看转发规则  → ${CYAN}ssh 中转机 iptables -t nat -L PREROUTING -n${NC}"
    echo -e "  管理转发规则  → ${CYAN}bash $WORK_DIR/wg_port.sh --list-relay-ports${NC}"
    echo ""
}

# ──────────────────────────────────────────────────────────────
# 主流程
# ──────────────────────────────────────────────────────────────
main() {
    clear
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║         落地机代理节点 ↔ 中转机 一键对接工具  v2.0             ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    read_local_info
    detect_proxy_nodes
    setup_ssh
    add_relay_rules
    generate_links
    save_and_show
}

main "$@"
