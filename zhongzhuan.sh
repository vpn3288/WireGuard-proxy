#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════════╗
# ║  zhongzhuan.sh  v6.8  —  CN2GIA 中转机初始化脚本（WireGuard 版）   ║
# ╚══════════════════════════════════════════════════════════════════════╝
#
# 功能：
#   · 安装 WireGuard，初始化 wg0 接口（10.100.0.1/24，UDP 51820）
#   · 生成 WireGuard 密钥对 + X25519 占位密钥
#   · 初始化 peer_map.json 和 nodes.json（供 duijie.sh 写入）
#   · 输出 /root/xray_zhongzhuan_info.txt（供 duijie.sh SSH 读取）
#   · 旧文件完整检测 + 用户决策菜单（保留 / 重置密钥 / 完全重置）
#   · 完全重置时清理 iptables / ip6tables DNAT 规则和 WireGuard peers
#
# 用法：
#   bash <(curl -fsSL https://raw.githubusercontent.com/vpn3288/proxy/main/zhongzhuan.sh)
#   bash zhongzhuan.sh --status    # 仅查看状态
#   bash zhongzhuan.sh --reset     # 完全重置（交互确认）
#   bash zhongzhuan.sh --reset --yes  # 完全重置（跳过确认）
#   bash zhongzhuan.sh --check     # 数据一致性检查
#
# ── v6.8 修复清单 ────────────────────────────────────────────────────
#
# [BUG-FW-DELETE 严重] _clean_relay_input_rules() 规则删除实际完全失效
#     根因：旧版用 iptables -C INPUT -m comment --comment "$comment" -j ACCEPT
#           进行存在性检测，iptables -C/-D 需要精确匹配全部参数规格；
#           实际规则含 -p udp --dport 51820 等额外参数，仅凭 comment 的
#           不完整规格无法命中，while 循环一次都不执行，旧规则从未被删除。
#           端口变更时规则持续堆积，--reset 语义失效。
#     修复：改为解析 iptables -S INPUT 完整输出，grep 含目标 comment 的规则行，
#           将 -A INPUT 替换为 -D INPUT 后逐条精确删除；与 _clean_all_dnat_rules()
#           采用相同的安全解析模式，彻底解决删除失效问题。
#
# [BUG-FW-IDEMPOTENT 高] _apply_firewall_rules() 端口变更时旧规则残留
#     根因：旧版用 -C 检查"完全相同的规则"是否存在，若端口参数发生变化
#           （WG_PORT 或端口范围调整），旧 comment 标记的旧端口规则残留，
#           新规则追加，产生孤儿规则堆积。
#           且由于 BUG-FW-DELETE，即使手动调用 _clean_relay_input_rules() 也无效。
#     修复：_apply_firewall_rules() 开头先调用修复后的 _clean_relay_input_rules()
#           清除所有同 comment 的旧规则，再无条件写入当前端口参数的新规则；
#           移除冗余的 -C 逐条检查（先删后加已保证幂等）。
#
# [BUG-MTU 中] wg0 MTU 1420 与 duijie.sh 落地机保底值 1380 不一致
#     根因：zhongzhuan.sh 固定 MTU=1420，duijie.sh 的 _wg::detect_mtu()
#           探测失败时保底 1380（duijie.sh 第25、60行注释，main() 行2762）；
#           TCPMSS=MTU-40 精准公式下两端 MTU 不对齐会导致 SYN 包截断或
#           CN2 GIA 路径 UDP 大包丢弃。
#     修复：WG_MTU 常量从 1420 改为 1380，与 duijie.sh 保底值对齐；
#           save_info() 新增 ZHONGZHUAN_WG_MTU 字段供 duijie.sh 未来读取；
#           print_result() 显示 MTU 及 TCPMSS 计算值（MTU-40）。
#
# [BUG-RESET-SYSCTL 中] do_full_reset() 未删除 99-zhongzhuan.conf
#     根因：完全重置后 sysctl 配置残留，"重置"语义不完整；
#           网段变更后旧配置仍存在也无实际影响，但破坏语义一致性。
#     修复：do_full_reset() 步骤8补加 rm -f "$SYSCTL_CONF"，
#           同时在 _action_full_reset() 确认框中列出该步骤。
#
# [BUG-RESET-IP6 中] do_full_reset() 未删除 /etc/iptables/rules.v6
#     根因：v6.7 开始支持 IPv6 转发并写入 rules.v6；完全重置后该文件残留，
#           重启后孤立 ip6tables 规则被 netfilter-persistent 恢复。
#     修复：do_full_reset() 步骤9补加 rm -f "$IP6TABLES_RULES"，
#           同时在 _action_full_reset() 确认框中列出该步骤。
#
# [架构说明] PostUp MASQUERADE 分工澄清（无代码变更，仅注释）
#     外部评审报告称 PostUp 含错误的 MASQUERADE，与实际代码不符。
#     架构分工：
#       · zhongzhuan.sh wg0.conf PostUp：仅 FORWARD 放行 + TCPMSS 钳制
#       · duijie.sh _fw::dnat_add()：per-node 写入
#           PREROUTING DNAT (TCP+UDP) + POSTROUTING MASQUERADE (-d WG_IP/32 -o wg0)
#     MASQUERADE 方向正确：-o wg0 出口，SNAT 为 10.100.0.1；落地机回包
#     经 WG 隧道正确返回中转机，无需修改。已在 wg0.conf 注释中说明分工。
#
# ── v6.7 修复（保留记录） ─────────────────────────────────────────────
# [BUG-IPv6]   sysctl 文件改名 99-zhongzhuan.conf，避免与 duijie.sh 互覆；
#               同时写入 net.ipv6.conf.all.forwarding=1
# [BUG-FW-MGMT] INPUT 规则全部加 comment 标记；do_full_reset() 新增清理逻辑
# [BUG-SEC]    nodes.json 补 chmod 600
# [BUG-COMPAT] save_info() 新增 ZHONGZHUAN_WG_ADDR 字段
# [BUG-DPKG]   dpkg -s "Status: install ok" 精确判断
# [BUG-REGEX]  _count_dnat_rules() 正则固定 [a-f0-9]{8}
# [BUG-TOOL]   check_wg_port() netstat 降级 + [[:space:]] 模式
# [ENH-CHECK]  cmd_check() 新增 sysctl 转发参数运行时验证
# ── v6.6 修复（保留记录） ─────────────────────────────────────────────
# [ENH-1] wg0.conf MTU 显式写入（v6.8 调整为 1380）
# [ENH-2] INFO_FILE 新增 ZHONGZHUAN_SSH_PORT 字段
# [BUG-9]  PostUp FORWARD/mangle TCPMSS 幂等性修复
# [BUG-10] open_firewall_ports() IS_FIRST_RUN=false 检查粒度修复
# [BUG-11] TCP/UDP 端口范围规则独立检查修复
# [BUG-2]  do_full_reset() nodes.json rm 而非清空
# [BUG-3]  _action_reset_keys_only() 补读 WG_PORT
# [BUG-4]  _action_reset_keys_only() 同步清空 X25519_PUBKEY
# [BUG-5]  _count_dnat_rules() LINK_ID 去重计数
# [BUG-6]  cmd_check() WG 公钥从 nodes.json 读取
# [BUG-7]  _save_iptables() 同步保存 ip6tables rules.v6
# [BUG-8]  init_wg_interface() 路径C Python 输出校验
# ══════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── §0 颜色 & 日志 ────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log_info()  { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; exit 1; }
log_step()  { echo -e "${CYAN}[→]${NC} $1"; }

# ── §1 全局常量 ───────────────────────────────────────────────────────
VERSION="6.8"
INFO_FILE="/root/xray_zhongzhuan_info.txt"
WG_CONF="/etc/wireguard/wg0.conf"
WG_PEER_MAP="/etc/wireguard/peer_map.json"
NODES_JSON_DIR="/usr/local/etc/xray-relay"
NODES_JSON="$NODES_JSON_DIR/nodes.json"

# [BUG-IPv6 修复] 改名为 99-zhongzhuan.conf，避免与 duijie.sh 的
# _info::read_relay() 写入的 /etc/sysctl.d/99-duijie.conf 相互覆盖。
SYSCTL_CONF="/etc/sysctl.d/99-zhongzhuan.conf"

IPTABLES_RULES="/etc/iptables/rules.v4"
IP6TABLES_RULES="/etc/iptables/rules.v6"

WG_IFACE="wg0"
WG_ADDR="10.100.0.1"
WG_CIDR="10.100.0.0/24"
WG_PORT_DEFAULT=51820

# [BUG-MTU 修复] MTU 从 1420 降至 1380，与 duijie.sh _wg::detect_mtu() 探测保底值对齐
# duijie.sh 注释（第25、60行）及 main() 行2762：探测失败保底 WG_MTU=1380
# CN2 GIA 路径 MTU 可能小于 1420；1380 提供足够安全余量，避免 UDP 大包被丢弃
# TCPMSS 精准公式 = MTU-40（IPv4: TCP头20B + IP头20B），见 duijie.sh v2.8
WG_MTU=1380

DNAT_COMMENT_PREFIX="luodi-dnat-"

# [BUG-FW-MGMT 修复] 防火墙 INPUT 规则的 comment 标记常量（便于统一管理）
FW_COMMENT_WG="relay-wg-port"
FW_COMMENT_TCP="relay-range-tcp"
FW_COMMENT_UDP="relay-range-udp"

# nodes.json 完整初始格式（forward_type 供 duijie.sh 判断对接模式）
NODES_JSON_INIT='{"nodes":{},"forward_type":"iptables","schema_version":"6.0"}'

# ── §2 运行时变量 ─────────────────────────────────────────────────────
WG_PRIVKEY="" WG_PUBKEY=""
X25519_PUBKEY=""
PUBLIC_IP=""
START_PORT="" MAX_NODES=""
WG_PORT=$WG_PORT_DEFAULT
IS_FIRST_RUN=true
AUTO_YES=false
WG_CONF_NEEDS_REWRITE=false

# ── §3 前置检查 ───────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && log_error "请使用 root 权限运行"
command -v python3 &>/dev/null || log_error "需要 python3，请先安装：apt-get install -y python3"

# ══════════════════════════════════════════════════════════════════════
# §4 横幅
# ══════════════════════════════════════════════════════════════════════
print_banner() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  ${BOLD}zhongzhuan.sh  v${VERSION}  —  中转机初始化（WireGuard版）${NC}   ${CYAN}║${NC}"
    echo -e "${CYAN}║  架构：iptables DNAT → WireGuard → 落地机                    ║${NC}"
    echo -e "${CYAN}║  协议隔离：不影响已有 xray / sing-box 节点                   ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ══════════════════════════════════════════════════════════════════════
# §5 旧文件检测与用户决策
# ══════════════════════════════════════════════════════════════════════

# 读取 info 文件中的某个 key
_ikv() { grep -m1 "^${1}=" "$INFO_FILE" 2>/dev/null | cut -d= -f2- | tr -d '\r' || true; }

# 统计 nodes.json 中的节点数
_count_nodes() {
    [[ -f "$NODES_JSON" ]] || { echo 0; return; }
    python3 -c "
import json
try:
    d = json.load(open('$NODES_JSON'))
    ns = d.get('nodes', {})
    print(len(ns))
except:
    print(0)
" 2>/dev/null || echo 0
}

# 统计 peer_map.json 中的条目数
_count_peers() {
    [[ -f "$WG_PEER_MAP" ]] || { echo 0; return; }
    python3 -c "
import json
try:
    print(len(json.load(open('$WG_PEER_MAP'))))
except:
    print(0)
" 2>/dev/null || echo 0
}

# [BUG-5 修复 + BUG-REGEX 修复] 统计 iptables 中的 DNAT 节点数
# · 按 LINK_ID 去重（每节点 TCP+UDP 两条规则，去重后 = 节点数）
# · 正则固定为 [a-f0-9]{8}（LINK_ID = md5sum[:8]），与 cmd_check() 及
#   duijie.sh _gen_link_id() 对齐，消除旧版 [a-f0-9]* 可匹配空串的歧义
_count_dnat_rules() {
    iptables -t nat -S PREROUTING 2>/dev/null \
        | grep -oE "${DNAT_COMMENT_PREFIX}[a-f0-9]{8}" \
        | sort -u \
        | wc -l \
        | tr -d ' ' 2>/dev/null || echo 0
}

# 检测 WireGuard 是否运行
_wg_running() {
    ip link show wg0 &>/dev/null && return 0 || return 1
}

# 检测旧版 xray-relay 服务
_detect_legacy_relay() {
    systemctl is-enabled xray-relay &>/dev/null 2>&1 \
        || systemctl is-active xray-relay &>/dev/null 2>&1 \
        || [[ -f /etc/systemd/system/xray-relay.service ]]
}

# 展示已有配置摘要
_show_existing_summary() {
    local node_count peer_count dnat_count wg_status

    node_count=$(_count_nodes)
    peer_count=$(_count_peers)
    dnat_count=$(_count_dnat_rules)
    wg_status=$( _wg_running && echo "运行中" || echo "未运行" )

    echo ""
    echo -e "${YELLOW}══ 检测到已有中转机配置 ══${NC}"
    echo ""
    if [[ -f "$INFO_FILE" ]]; then
        local saved_ip saved_wg_pub saved_start saved_max
        saved_ip=$(_ikv ZHONGZHUAN_IP)
        saved_wg_pub=$(_ikv ZHONGZHUAN_WG_PUBKEY)
        saved_start=$(_ikv ZHONGZHUAN_START_PORT)
        saved_max=$(_ikv ZHONGZHUAN_MAX_NODES)
        echo -e "  ${BOLD}中转机 IP    :${NC} ${saved_ip:-（未知）}"
        echo -e "  ${BOLD}WG 公钥      :${NC} ${saved_wg_pub:0:24}...（前24字符）"
        echo -e "  ${BOLD}端口范围     :${NC} ${saved_start:-?} ~ $(( ${saved_start:-0} + ${saved_max:-0} - 1 ))（共 ${saved_max:-?} 个）"
    fi
    echo -e "  ${BOLD}WireGuard    :${NC} ${wg_status}"
    echo -e "  ${BOLD}已对接节点   :${NC} ${node_count} 个（nodes.json）"
    echo -e "  ${BOLD}peer_map 条目:${NC} ${peer_count} 个"
    echo -e "  ${BOLD}DNAT 规则    :${NC} ${dnat_count} 个节点"

    if [[ "$node_count" -gt 0 && -f "$NODES_JSON" ]]; then
        echo ""
        echo -e "  ${CYAN}已对接节点列表：${NC}"
        python3 - "$NODES_JSON" << 'PYEOF' 2>/dev/null || true
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    ns = d.get("nodes", {})
    items = list(ns.items()) if isinstance(ns, dict) else [(str(i), n) for i, n in enumerate(ns)]
    for lid, n in items[:10]:
        wg_ip    = n.get("wg_ip", "?")
        r_port   = n.get("relay_port", "?")
        l_ip     = n.get("luodi_ip", "?")
        label    = n.get("node_label", n.get("label", ""))
        print(f"    [{lid[:8]}] WG={wg_ip}  中转端口={r_port}  落地={l_ip}  {label}")
    if len(items) > 10:
        print(f"    ... 共 {len(items)} 个节点")
except Exception as e:
    print(f"    （解析失败: {e}）")
PYEOF
    fi
    echo ""
}

# 用户决策菜单
user_decision() {
    local has_info wg_has_config
    has_info=false; wg_has_config=false

    [[ -f "$INFO_FILE" ]] && has_info=true
    [[ -f "$WG_CONF"   ]] && wg_has_config=true

    if [[ "$has_info" == "false" && "$wg_has_config" == "false" ]]; then
        IS_FIRST_RUN=true
        log_step "首次运行，开始初始化..."
        return 0
    fi

    _show_existing_summary

    local node_count
    node_count=$(_count_nodes)

    echo -e "${YELLOW}请选择操作：${NC}"
    echo ""
    echo -e "  ${CYAN}[1]${NC} 继续使用现有配置（推荐）"
    echo -e "       仅更新公网 IP，保留所有密钥和已对接节点"
    echo ""
    echo -e "  ${CYAN}[2]${NC} 重置 WireGuard 密钥（保留节点记录）"
    echo -e "       ${YELLOW}警告：密钥更换后，所有已对接节点需重新运行 duijie.sh${NC}"
    echo ""
    echo -e "  ${CYAN}[3]${NC} 完全重置（清除全部节点 + 密钥 + DNAT 规则）"
    if [[ "$node_count" -gt 0 ]]; then
        echo -e "       ${RED}警告：将删除 ${node_count} 个已对接节点的所有数据，操作不可逆！${NC}"
    fi
    echo ""
    echo -e "  ${CYAN}[4]${NC} 仅更新公网 IP"
    echo ""
    echo -e "  ${CYAN}[q]${NC} 退出"
    echo ""

    local choice
    read -rp "请选择 [1/2/3/4/q，默认 1]: " choice || true
    choice="${choice:-1}"

    case "$choice" in
        1)
            IS_FIRST_RUN=false
            load_existing_config
            log_info "已加载现有配置，仅更新公网 IP"
            ;;
        2)
            IS_FIRST_RUN=false
            _action_reset_keys_only
            ;;
        3)
            _action_full_reset
            ;;
        4)
            IS_FIRST_RUN=false
            load_existing_config
            ;;
        q|Q)
            echo "已退出。"
            exit 0
            ;;
        *)
            log_warn "无效选择，使用默认选项 [1]"
            IS_FIRST_RUN=false
            load_existing_config
            ;;
    esac
}

# 加载已有配置（选项1/4）
load_existing_config() {
    WG_PRIVKEY=$(_ikv ZHONGZHUAN_WG_PRIVKEY)
    WG_PUBKEY=$(_ikv ZHONGZHUAN_WG_PUBKEY)
    X25519_PUBKEY=$(_ikv ZHONGZHUAN_PUBKEY)
    START_PORT=$(_ikv ZHONGZHUAN_START_PORT)
    MAX_NODES=$(_ikv ZHONGZHUAN_MAX_NODES)
    WG_PORT=$(_ikv ZHONGZHUAN_WG_PORT)
    WG_PORT="${WG_PORT:-$WG_PORT_DEFAULT}"

    if [[ -z "$WG_PRIVKEY" || -z "$WG_PUBKEY" ]]; then
        log_warn "已有配置中未找到 WireGuard 密钥，将重新生成"
        IS_FIRST_RUN=true
    else
        log_info "已加载现有 WG 密钥（公钥: ${WG_PUBKEY:0:16}...）"
    fi
}

# [BUG-3 修复][BUG-4 修复] 选项2：仅重置密钥
_action_reset_keys_only() {
    echo ""
    echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  ⚠  警告：重置 WG 密钥后，所有已对接节点链接将失效！         ║${NC}"
    echo -e "${RED}║  需要在每台落地机上重新运行 duijie.sh 才能恢复连接。          ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    local confirm
    read -rp "确认重置密钥？输入 'yes' 继续，其他取消: " confirm || true
    if [[ "$confirm" != "yes" ]]; then
        log_warn "已取消，退出。"
        exit 0
    fi

    # [BUG-3 修复] 读取完整端口配置（包括 WG_PORT）
    START_PORT=$(_ikv ZHONGZHUAN_START_PORT)
    MAX_NODES=$(_ikv ZHONGZHUAN_MAX_NODES)
    local saved_wg_port; saved_wg_port=$(_ikv ZHONGZHUAN_WG_PORT)
    WG_PORT="${saved_wg_port:-$WG_PORT_DEFAULT}"

    # [BUG-4 修复] 同步清空 X25519_PUBKEY
    WG_PRIVKEY=""
    WG_PUBKEY=""
    X25519_PUBKEY=""

    log_info "将重新生成 WireGuard 密钥，端口配置保留（WG: ${WG_PORT}, 中转: ${START_PORT}~$(( START_PORT + MAX_NODES - 1 ))）"
}

# 选项3：完全重置
_action_full_reset() {
    echo ""
    echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  ⚠  完全重置确认                                              ║${NC}"
    echo -e "${RED}║  将执行以下操作：                                              ║${NC}"
    echo -e "${RED}║  · 停止 WireGuard wg0                                         ║${NC}"
    echo -e "${RED}║  · 删除所有 iptables / ip6tables DNAT 规则（luodi-dnat-*）    ║${NC}"
    echo -e "${RED}║  · 清理中转机防火墙 INPUT 规则（relay-wg-port / relay-range） ║${NC}"
    echo -e "${RED}║  · 清空 peer_map.json 和 nodes.json                           ║${NC}"
    echo -e "${RED}║  · 删除 wg0.conf 并重新生成                                   ║${NC}"
    echo -e "${RED}║  · 删除 xray_zhongzhuan_info.txt                              ║${NC}"
    echo -e "${RED}║  · 删除 /etc/sysctl.d/99-zhongzhuan.conf                      ║${NC}"
    echo -e "${RED}║  · 删除 /etc/iptables/rules.v6（ip6tables 规则持久化文件）    ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}此操作不可逆。已对接的落地机需要重新运行 duijie.sh 才能恢复。${NC}"
    echo ""
    if [[ "$AUTO_YES" == "true" ]]; then
        log_warn "--yes 标志已设置，跳过交互确认，直接执行完全重置"
    else
        local confirm
        read -rp "确认完全重置？输入 'RESET' 继续，其他取消: " confirm || true
        if [[ "$confirm" != "RESET" ]]; then
            log_warn "已取消，退出。"
            exit 0
        fi
    fi

    do_full_reset
    IS_FIRST_RUN=true
    log_info "完全重置完成，将重新初始化..."
    echo ""
}

# 执行完全重置
do_full_reset() {
    log_step "执行完全重置..."

    # 1. 停止 wg0
    if _wg_running; then
        log_step "停止 WireGuard wg0..."
        wg-quick down wg0 2>/dev/null || ip link del wg0 2>/dev/null || true
        log_info "WireGuard wg0 已停止"
    fi

    # 2. 清理所有 luodi-dnat-* iptables / ip6tables 规则
    _clean_all_dnat_rules

    # 3. [BUG-FW-MGMT 修复] 清理中转机防火墙 INPUT 规则（relay-wg-port / relay-range-*）
    #    旧版 do_full_reset() 不清理这些规则，导致端口变更后 INPUT 链规则堆积
    _clean_relay_input_rules

    # 4. 清空 peer_map.json
    if [[ -f "$WG_PEER_MAP" ]]; then
        echo '{}' > "$WG_PEER_MAP"
        chmod 600 "$WG_PEER_MAP"
        log_info "peer_map.json 已清空"
    fi

    # 5. [BUG-2 修复] 删除 nodes.json 而非清空为 '{}'
    #    旧版写入 '{"nodes":{}}' 后 init_data_files() 见文件存在跳过，
    #    导致 forward_type/schema_version 字段永久丢失。
    if [[ -f "$NODES_JSON" ]]; then
        rm -f "$NODES_JSON"
        log_info "nodes.json 已删除（将由初始化流程重建为完整格式）"
    fi

    # 6. 删除 wg0.conf（重新初始化时会重建）
    [[ -f "$WG_CONF" ]] && rm -f "$WG_CONF" && log_info "wg0.conf 已删除"

    # 7. 删除 info 文件
    [[ -f "$INFO_FILE" ]] && rm -f "$INFO_FILE" && log_info "xray_zhongzhuan_info.txt 已删除"

    # 8. [BUG-RESET-SYSCTL 修复] 删除本脚本写入的 sysctl 配置文件
    #    旧版遗漏此步骤，导致 --reset 语义不完整（sysctl 配置残留）
    if [[ -f "$SYSCTL_CONF" ]]; then
        rm -f "$SYSCTL_CONF"
        log_info "sysctl 配置已删除：$SYSCTL_CONF"
    fi

    # 9. [BUG-RESET-IP6 修复] 删除 ip6tables 规则持久化文件
    #    v6.7 开始写入 rules.v6；不清理会导致重启后孤立 ip6tables 规则被恢复
    if [[ -f "$IP6TABLES_RULES" ]]; then
        rm -f "$IP6TABLES_RULES"
        log_info "ip6tables 规则文件已删除：$IP6TABLES_RULES"
    fi

    # 10. 持久化 iptables（规则已清空）
    _save_iptables
}

# [BUG-FW-DELETE 修复] _clean_relay_input_rules()
# ──────────────────────────────────────────────────────────────────────
# 旧版缺陷：iptables -C INPUT -m comment --comment "$comment" -j ACCEPT
#   iptables -C/-D 需要精确匹配全部规格参数；实际规则含 -p udp --dport 51820
#   等额外字段，仅凭 comment 的不完整规格无法命中，while 循环一次都不执行，
#   旧规则实际从未被删除，端口变更时规则持续堆积，--reset 语义失效。
# 修复方案：解析 iptables -S INPUT 完整输出，grep 含目标 comment 的规则行，
#   将 -A INPUT 替换为 -D INPUT 后逐条精确删除，与 _clean_all_dnat_rules()
#   采用完全相同的安全解析模式。
# ──────────────────────────────────────────────────────────────────────
_clean_relay_input_rules() {
    local found=false
    for comment in "$FW_COMMENT_WG" "$FW_COMMENT_TCP" "$FW_COMMENT_UDP"; do
        # 解析完整规则行，grep 含目标 comment（含引号）的行
        local rules
        rules=$(iptables -S INPUT 2>/dev/null \
            | grep -- "--comment \"${comment}\"" || true)
        if [[ -n "$rules" ]]; then
            found=true
            local deleted=0
            while IFS= read -r rule; do
                [[ -z "$rule" ]] && continue
                # 将 -A INPUT 替换为 -D INPUT，得到完整精确的删除规格
                local del_rule="${rule/-A INPUT/-D INPUT}"
                eval "iptables $del_rule" 2>/dev/null \
                    && deleted=$(( deleted + 1 )) || true
            done <<< "$rules"
            [[ "$deleted" -gt 0 ]] && \
                log_info "已清理 INPUT 规则（comment: ${comment}）共 ${deleted} 条"
        fi
    done
    if [[ "$found" == "false" ]]; then
        log_info "未检测到中转机 INPUT 防火墙规则，跳过清理"
    fi
}

# 清理所有 luodi-dnat-* 规则（遍历 nat/mangle/filter 表 + ip6tables）
_clean_all_dnat_rules() {
    local count
    count=$(_count_dnat_rules)

    if [[ "$count" -eq 0 ]]; then
        log_info "未检测到 luodi-dnat-* iptables 规则，跳过清理"
        return
    fi

    log_step "清理 ${count} 个节点的 luodi-dnat-* iptables 规则..."

    local rules del_rule

    # nat PREROUTING（DNAT）
    rules=$(iptables -t nat -S PREROUTING 2>/dev/null | grep "${DNAT_COMMENT_PREFIX}" || true)
    while IFS= read -r rule; do
        [[ -z "$rule" ]] && continue
        del_rule="${rule/-A PREROUTING/-D PREROUTING}"
        eval "iptables -t nat $del_rule" 2>/dev/null || true
    done <<< "$rules"

    # nat POSTROUTING（MASQUERADE）
    rules=$(iptables -t nat -S POSTROUTING 2>/dev/null | grep "${DNAT_COMMENT_PREFIX}" || true)
    while IFS= read -r rule; do
        [[ -z "$rule" ]] && continue
        del_rule="${rule/-A POSTROUTING/-D POSTROUTING}"
        eval "iptables -t nat $del_rule" 2>/dev/null || true
    done <<< "$rules"

    # mangle FORWARD（TCPMSS）
    rules=$(iptables -t mangle -S FORWARD 2>/dev/null | grep "${DNAT_COMMENT_PREFIX}" || true)
    while IFS= read -r rule; do
        [[ -z "$rule" ]] && continue
        del_rule="${rule/-A FORWARD/-D FORWARD}"
        eval "iptables -t mangle $del_rule" 2>/dev/null || true
    done <<< "$rules"

    # filter FORWARD
    rules=$(iptables -t filter -S FORWARD 2>/dev/null | grep "${DNAT_COMMENT_PREFIX}" || true)
    while IFS= read -r rule; do
        [[ -z "$rule" ]] && continue
        del_rule="${rule/-A FORWARD/-D FORWARD}"
        eval "iptables -t filter $del_rule" 2>/dev/null || true
    done <<< "$rules"

    # ip6tables FORWARD（duijie.sh _fw::dnat_add() 写入的 IPv6 泄漏防护规则）
    if command -v ip6tables &>/dev/null; then
        rules=$(ip6tables -S FORWARD 2>/dev/null | grep "${DNAT_COMMENT_PREFIX}" || true)
        local ip6_count
        ip6_count=$(echo "$rules" | grep -c "${DNAT_COMMENT_PREFIX}" 2>/dev/null || echo 0)
        if [[ "$ip6_count" -gt 0 ]]; then
            log_step "清理 ${ip6_count} 条 ip6tables luodi-dnat-* 规则..."
            while IFS= read -r rule; do
                [[ -z "$rule" ]] && continue
                del_rule="${rule/-A FORWARD/-D FORWARD}"
                bash -c "ip6tables $del_rule" 2>/dev/null || true
            done <<< "$rules"
            log_info "ip6tables 规则清理完成"
        fi
    fi

    log_info "iptables / ip6tables 规则清理完成"
}

# ══════════════════════════════════════════════════════════════════════
# §6 旧版 xray-relay 服务检测与处理
# ══════════════════════════════════════════════════════════════════════
detect_and_handle_legacy_relay() {
    if _detect_legacy_relay; then
        echo ""
        echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║  检测到旧版 xray-relay.service（zhongzhuan.sh v5.x 遗留）    ║${NC}"
        echo -e "${YELLOW}║  新版架构使用纯 WireGuard，不再需要 xray-relay 服务。        ║${NC}"
        echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        local yn
        read -rp "是否停止并禁用旧版 xray-relay 服务？[Y/n]: " yn || true
        if [[ "${yn,,}" != "n" ]]; then
            systemctl stop    xray-relay 2>/dev/null || true
            systemctl disable xray-relay 2>/dev/null || true
            log_info "旧版 xray-relay.service 已停止并禁用（二进制保留）"
        else
            log_warn "跳过。旧版 xray-relay 服务仍在运行，可能与新版冲突。"
        fi
        echo ""
    fi
}

# ══════════════════════════════════════════════════════════════════════
# §7 WireGuard 安装
# ══════════════════════════════════════════════════════════════════════
install_wireguard() {
    if command -v wg &>/dev/null && command -v wg-quick &>/dev/null; then
        log_info "WireGuard 已安装：$(wg --version 2>/dev/null | head -1)"
        return 0
    fi

    log_step "安装 WireGuard..."

    local distro=""
    if [[ -f /etc/os-release ]]; then
        distro=$(grep -oP '^ID=\K\w+' /etc/os-release | head -1 || true)
    fi

    case "${distro:-}" in
        ubuntu|debian)
            apt-get update -qq 2>/dev/null || true
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard wireguard-tools 2>/dev/null \
                && log_info "WireGuard 安装成功（apt）" \
                || log_error "WireGuard 安装失败，请手动安装：apt-get install -y wireguard"
            ;;
        centos|rhel|fedora|rocky|almalinux)
            yum install -y -q wireguard-tools 2>/dev/null \
                || dnf install -y -q wireguard-tools 2>/dev/null \
                && log_info "WireGuard 安装成功（yum/dnf）" \
                || log_error "WireGuard 安装失败，请手动安装 wireguard-tools"
            ;;
        alpine)
            apk add --quiet wireguard-tools 2>/dev/null \
                && log_info "WireGuard 安装成功（apk）" \
                || log_error "WireGuard 安装失败，请手动安装"
            ;;
        *)
            if command -v apt-get &>/dev/null; then
                apt-get update -qq 2>/dev/null || true
                DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard wireguard-tools 2>/dev/null \
                    && log_info "WireGuard 安装成功" \
                    || log_error "WireGuard 安装失败，请手动安装 wireguard"
            else
                log_error "未能识别发行版，请手动安装 WireGuard 后重试"
            fi
            ;;
    esac

    command -v wg &>/dev/null || log_error "WireGuard 安装后仍未找到 wg 命令"
    log_info "WireGuard 版本：$(wg --version 2>/dev/null | head -1)"
}

# ══════════════════════════════════════════════════════════════════════
# §8 WireGuard 子网冲突检测
# ══════════════════════════════════════════════════════════════════════
check_wg_subnet() {
    local existing_route
    existing_route=$(ip route show 2>/dev/null | grep "^10\.100\.0\.0" || true)
    if [[ -n "$existing_route" ]]; then
        local via_dev
        via_dev=$(echo "$existing_route" | grep -o "dev [^ ]*" | head -1 | awk '{print $2}')
        if [[ -n "$via_dev" && "$via_dev" != "$WG_IFACE" ]]; then
            log_warn "检测到 10.100.0.0/24 已被接口 ${via_dev} 占用"
            log_warn "路由：$existing_route"
            local yn
            read -rp "是否仍然继续使用 10.100.0.0/24？[y/N]: " yn || true
            [[ "${yn,,}" != "y" ]] && log_error "请修改 WG 网段后重试（编辑脚本中的 WG_ADDR/WG_CIDR 变量）"
        fi
    fi
}

# ══════════════════════════════════════════════════════════════════════
# §8b WireGuard 监听端口占用检测
# ══════════════════════════════════════════════════════════════════════
check_wg_port() {
    # wg0 已运行时跳过检测（端口已被自己占用，属正常状态）
    if _wg_running; then
        return 0
    fi

    # [BUG-TOOL 修复] 优先 ss，降级 netstat，均不可用则跳过并告警
    # grep 模式改为 -E ":${WG_PORT}[[:space:]]"，兼容 tab / 多空格输出
    local port_occupied=false
    local occupier=""

    if command -v ss &>/dev/null; then
        if ss -ulnp 2>/dev/null | grep -qE ":${WG_PORT}[[:space:]]"; then
            port_occupied=true
            occupier=$(ss -ulnp 2>/dev/null | grep -E ":${WG_PORT}[[:space:]]" | head -1 || true)
        fi
    elif command -v netstat &>/dev/null; then
        if netstat -ulnp 2>/dev/null | grep -qE ":${WG_PORT}[[:space:]]"; then
            port_occupied=true
            occupier=$(netstat -ulnp 2>/dev/null | grep -E ":${WG_PORT}[[:space:]]" | head -1 || true)
        fi
    else
        log_warn "未找到 ss / netstat 命令，跳过 UDP ${WG_PORT} 端口占用检测"
        return 0
    fi

    if [[ "$port_occupied" == "true" ]]; then
        log_warn "检测到 UDP ${WG_PORT} 端口已被占用："
        log_warn "  ${occupier}"
        echo ""
        echo -e "  ${YELLOW}请先停止占用该端口的服务，或修改 WG_PORT 变量后重试。${NC}"
        echo ""
        local yn
        read -rp "是否仍然继续（可能导致 WireGuard 启动失败）？[y/N]: " yn || true
        [[ "${yn,,}" != "y" ]] && log_error "请释放 UDP ${WG_PORT} 端口后重试"
        log_warn "已选择继续，WireGuard 启动失败时请手动处理端口冲突"
    else
        log_info "UDP ${WG_PORT} 端口空闲，可以使用"
    fi
}

# ══════════════════════════════════════════════════════════════════════
# §9 生成 WireGuard 密钥
# ══════════════════════════════════════════════════════════════════════
generate_wg_keys() {
    if [[ -n "$WG_PRIVKEY" && -n "$WG_PUBKEY" ]]; then
        log_info "使用已有 WireGuard 密钥（公钥: ${WG_PUBKEY:0:16}...）"
        return 0
    fi

    log_step "生成 WireGuard 密钥对..."
    WG_PRIVKEY=$(wg genkey)
    WG_PUBKEY=$(echo "$WG_PRIVKEY" | wg pubkey)

    [[ -z "$WG_PRIVKEY" || -z "$WG_PUBKEY" ]] && log_error "WireGuard 密钥生成失败"
    WG_CONF_NEEDS_REWRITE=true
    log_info "WG 公钥: $WG_PUBKEY"
}

# ══════════════════════════════════════════════════════════════════════
# §10 生成 X25519 占位密钥（duijie.sh v4.x RELAY_PUBKEY 兼容检查）
# ══════════════════════════════════════════════════════════════════════
generate_x25519_placeholder() {
    if [[ -n "$X25519_PUBKEY" ]]; then
        log_info "占位公钥已存在，保留"
        return 0
    fi

    # 使用 WG 公钥作为占位（WG 密钥也是 X25519，格式兼容）
    X25519_PUBKEY="$WG_PUBKEY"
    log_info "ZHONGZHUAN_PUBKEY（占位）: ${X25519_PUBKEY:0:16}...（duijie.sh 兼容用）"
}

# ══════════════════════════════════════════════════════════════════════
# §11 获取公网 IP
# ══════════════════════════════════════════════════════════════════════
get_public_ip() {
    log_step "获取中转机公网 IP..."

    local detected_ip
    detected_ip=$(
        curl -s4 --connect-timeout 5 https://api.ipify.org    2>/dev/null ||
        curl -s4 --connect-timeout 5 https://ifconfig.me      2>/dev/null ||
        curl -s4 --connect-timeout 5 https://icanhazip.com    2>/dev/null ||
        curl -s4 --connect-timeout 5 https://api4.my-ip.io/ip 2>/dev/null ||
        echo ""
    )
    detected_ip=$(echo "$detected_ip" | tr -d '[:space:]')

    if [[ "$IS_FIRST_RUN" == "false" && -f "$INFO_FILE" ]]; then
        local old_ip
        old_ip=$(_ikv ZHONGZHUAN_IP)
        if [[ -n "$old_ip" && -n "$detected_ip" && "$old_ip" != "$detected_ip" ]]; then
            log_warn "检测到 IP 变更：${old_ip} → ${detected_ip}"
        fi
    fi

    if [[ -n "$detected_ip" ]]; then
        read -rp "中转机公网 IP [回车使用 ${detected_ip}]: " i || true
        PUBLIC_IP="${i:-$detected_ip}"
    else
        log_warn "自动获取公网 IP 失败"
        while true; do
            read -rp "请手动输入中转机公网 IP: " PUBLIC_IP || true
            [[ "$PUBLIC_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] && break
            log_warn "IP 格式不正确，请重新输入（示例：1.2.3.4）"
        done
    fi
    log_info "公网 IP: $PUBLIC_IP"
}

# ══════════════════════════════════════════════════════════════════════
# §12 端口配置
# ══════════════════════════════════════════════════════════════════════
get_port_config() {
    if [[ "$IS_FIRST_RUN" == "false" && -n "$START_PORT" && -n "$MAX_NODES" ]]; then
        log_info "保留端口配置：${START_PORT} ~ $(( START_PORT + MAX_NODES - 1 ))（共 ${MAX_NODES} 个）"
        return 0
    fi

    echo ""
    echo -e "${YELLOW}── 端口规划 ──────────────────────────────────────────────────${NC}"
    echo "  中转机为每台落地机分配一个独立的入站端口（TCP/UDP）。"
    echo ""

    while true; do
        read -rp "计划对接落地机数量（1-50）[默认 10]: " i || true
        MAX_NODES="${i:-10}"
        [[ "$MAX_NODES" =~ ^[0-9]+$ ]] && (( MAX_NODES >= 1 && MAX_NODES <= 50 )) && break
        log_warn "请输入 1-50 之间的整数"
    done

    while true; do
        read -rp "入站端口起始值（1024-64000）[默认 30001]: " i || true
        START_PORT="${i:-30001}"
        [[ "$START_PORT" =~ ^[0-9]+$ ]] && \
            (( START_PORT >= 1024 && START_PORT <= 64000 )) && break
        log_warn "请输入 1024-64000 之间的整数"
    done

    local end_port=$(( START_PORT + MAX_NODES - 1 ))
    log_info "已规划端口范围：${START_PORT} ~ ${end_port}（共 ${MAX_NODES} 个）"
    echo -e "  ${YELLOW}请确保云服务商安全组已放行 TCP/UDP ${START_PORT}~${end_port}${NC}"
}

# ══════════════════════════════════════════════════════════════════════
# §13 初始化 WireGuard wg0 接口
# ══════════════════════════════════════════════════════════════════════
init_wg_interface() {
    log_step "初始化 WireGuard wg0 接口..."

    mkdir -p /etc/wireguard
    chmod 700 /etc/wireguard

    # 辅助：写全新 wg0.conf
    # [BUG-MTU] 使用 WG_MTU 变量（1380），与 duijie.sh 保底值对齐
    # [BUG-9]   PostUp 幂等：-D 先删 || true，再 -I/-A
    # [架构说明] PostUp 仅管理 FORWARD 链 + TCPMSS 钳制；
    #            PREROUTING DNAT + POSTROUTING MASQUERADE (-d WG_IP/32 -o wg0)
    #            由 duijie.sh _fw::dnat_add() 负责，per-node 对接时写入
    _write_fresh_conf() {
        cat > "$WG_CONF" << EOF
[Interface]
Address = ${WG_ADDR}/24
PrivateKey = ${WG_PRIVKEY}
ListenPort = ${WG_PORT}
MTU = ${WG_MTU}
SaveConfig = false

# PostUp/PostDown 职责：
#   1. 放行 WireGuard 流量的 FORWARD 链（ACCEPT in/out wg0）
#   2. TCPMSS 钳制（-o wg0 出口精确匹配，避免影响 Docker 等其他服务）
# 注意：PREROUTING DNAT + POSTROUTING MASQUERADE 由 duijie.sh _fw::dnat_add() 负责，
#       zhongzhuan.sh 不重复添加
PostUp = iptables -D FORWARD -i ${WG_IFACE} -j ACCEPT 2>/dev/null || true; iptables -I FORWARD -i ${WG_IFACE} -j ACCEPT; iptables -D FORWARD -o ${WG_IFACE} -j ACCEPT 2>/dev/null || true; iptables -I FORWARD -o ${WG_IFACE} -j ACCEPT; iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -o ${WG_IFACE} -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true; iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -o ${WG_IFACE} -j TCPMSS --clamp-mss-to-pmtu
PostDown = iptables -D FORWARD -i ${WG_IFACE} -j ACCEPT 2>/dev/null || true; iptables -D FORWARD -o ${WG_IFACE} -j ACCEPT 2>/dev/null || true; iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -o ${WG_IFACE} -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true

# ── Peers ──────────────────────────────────────────────────────────
# 由 duijie.sh 通过 'wg set wg0 peer ...' 动态添加
# 并通过 Python 直接追加到本文件 [Peer] 块
# zhongzhuan.sh 不直接写 [Peer] 块
EOF
        chmod 600 "$WG_CONF"
    }

    # 辅助：启动 wg0（含手动降级方式）
    _start_wg0() {
        if wg-quick up wg0 2>/dev/null; then
            log_info "WireGuard wg0 启动成功"
        else
            log_warn "wg-quick up 失败，尝试手动方式..."
            ip link add wg0 type wireguard 2>/dev/null || true
            wg setconf wg0 "$WG_CONF" 2>/dev/null || true
            ip addr add "${WG_ADDR}/24" dev wg0 2>/dev/null || true
            ip link set wg0 up 2>/dev/null || true
            log_info "手动启动 wg0 完成"
        fi
        if ! ip link show wg0 &>/dev/null; then
            log_error "WireGuard wg0 接口创建失败，请检查系统内核是否支持 WireGuard"
        fi
    }

    if [[ "$WG_CONF_NEEDS_REWRITE" == "true" ]]; then
        # ── 路径 A：密钥已变更（首次安装 / 全重置 / 仅重置密钥） ─────────────
        _write_fresh_conf
        log_info "wg0.conf 已写入（新密钥；旧 Peer 配置已清除，等待 duijie.sh 重新对接）"

        if _wg_running; then
            log_step "密钥已变更，重启 WireGuard wg0..."
            wg-quick down wg0 2>/dev/null || ip link del wg0 2>/dev/null || true
            sleep 1
        fi
        _start_wg0

    elif [[ ! -f "$WG_CONF" ]]; then
        # ── 路径 B：conf 文件丢失（密钥未变，但 conf 不存在）──
        _write_fresh_conf
        log_info "wg0.conf 重建完成（已有密钥，注意：[Peer] 需重新由 duijie.sh 写入）"
        if ! _wg_running; then
            _start_wg0
        fi

    else
        # ── 路径 C：密钥未变更（继续使用 / 仅更新 IP） ─────────────────────────
        # 只更新 [Interface] 段，完整保留 duijie.sh 写入的所有 [Peer] 块。
        # [BUG-8 修复] 捕获 Python 输出并校验是否含 [OK]，失败时 log_error 终止
        local py_result
        py_result=$(python3 - "$WG_ADDR" "$WG_PRIVKEY" "$WG_PORT" "$WG_IFACE" "$WG_CONF" "$WG_MTU" 2>&1 << 'PYEOF'
import sys, re, os

wg_addr    = sys.argv[1]
wg_privkey = sys.argv[2]
wg_port    = sys.argv[3]
wg_iface   = sys.argv[4]
conf_path  = sys.argv[5]
wg_mtu     = sys.argv[6]

new_iface = (
    "[Interface]\n"
    f"Address = {wg_addr}/24\n"
    f"PrivateKey = {wg_privkey}\n"
    f"ListenPort = {wg_port}\n"
    f"MTU = {wg_mtu}\n"
    "SaveConfig = false\n"
    "\n"
    "# PostUp/PostDown 职责：\n"
    "#   1. 放行 WireGuard 流量的 FORWARD 链（ACCEPT in/out wg0）\n"
    "#   2. TCPMSS 钳制（-o wg0 出口精确匹配，避免影响 Docker 等其他服务）\n"
    "# 注意：PREROUTING DNAT + POSTROUTING MASQUERADE 由 duijie.sh _fw::dnat_add() 负责，\n"
    "#       zhongzhuan.sh 不重复添加\n"
    f"PostUp = iptables -D FORWARD -i {wg_iface} -j ACCEPT 2>/dev/null || true; "
    f"iptables -I FORWARD -i {wg_iface} -j ACCEPT; "
    f"iptables -D FORWARD -o {wg_iface} -j ACCEPT 2>/dev/null || true; "
    f"iptables -I FORWARD -o {wg_iface} -j ACCEPT; "
    f"iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -o {wg_iface} -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true; "
    f"iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -o {wg_iface} -j TCPMSS --clamp-mss-to-pmtu\n"
    f"PostDown = iptables -D FORWARD -i {wg_iface} -j ACCEPT 2>/dev/null || true; "
    f"iptables -D FORWARD -o {wg_iface} -j ACCEPT 2>/dev/null || true; "
    f"iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -o {wg_iface} -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true\n"
    "\n"
    "# ── Peers ──────────────────────────────────────────────────────────\n"
    "# 由 duijie.sh 通过 'wg set wg0 peer ...' 动态添加\n"
    "# 并通过 Python 直接追加到本文件 [Peer] 块\n"
    "# zhongzhuan.sh 不直接写 [Peer] 块"
)

try:
    content = open(conf_path).read()
except FileNotFoundError:
    content = ""

peer_blocks = []
parts = re.split(r'(?=^\[Peer\])', content, flags=re.MULTILINE)
for part in parts:
    stripped = part.strip()
    if stripped.startswith('[Peer]'):
        peer_blocks.append(stripped)

result = new_iface
for block in peer_blocks:
    result += "\n\n" + block
result += "\n"

try:
    open(conf_path, "w").write(result)
    os.chmod(conf_path, 0o600)
    print(f"[OK] wg0.conf [Interface] 已更新，保留 {len(peer_blocks)} 个 [Peer] 块（MTU={wg_mtu}）")
except Exception as e:
    print(f"[ERROR] wg0.conf 写入失败: {e}")
    sys.exit(1)
PYEOF
)

        # [BUG-8 修复] 校验 Python 输出，失败即终止
        if echo "$py_result" | grep -q "^\[OK\]"; then
            log_info "$(echo "$py_result" | grep "^\[OK\]")"
        else
            log_error "wg0.conf 更新失败：${py_result}"
        fi

        if ! _wg_running; then
            log_step "wg0 未运行，启动中..."
            _start_wg0
        else
            log_info "wg0 已在运行，不重启（保护已有落地机隧道不中断）"
            log_info "  PostUp 规则更新将于下次 wg-quick restart 时生效"
        fi
    fi

    # 开机自启（所有路径均设置）
    systemctl enable wg-quick@wg0 2>/dev/null || true
    log_info "已启用 wg-quick@wg0 开机自启"

    local wg_info
    wg_info=$(wg show wg0 2>/dev/null | head -5 || true)
    [[ -n "$wg_info" ]] && echo -e "${CYAN}${wg_info}${NC}"
}

# ══════════════════════════════════════════════════════════════════════
# §14 开启内核 IP 转发
# ══════════════════════════════════════════════════════════════════════
enable_ip_forward() {
    log_step "开启内核 IP 转发（IPv4 + IPv6）..."

    # [BUG-IPv6 修复1] 文件改名为 99-zhongzhuan.conf
    #   避免与 duijie.sh _info::read_relay() 写入的 99-duijie.conf 相互覆盖。
    # [BUG-IPv6 修复2] 同时写入 IPv6 转发参数
    #   防御 IPv6 泄漏并为未来 IPv6 隧道转发做准备。
    mkdir -p /etc/sysctl.d
    cat > "$SYSCTL_CONF" << 'EOF'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
    chmod 644 "$SYSCTL_CONF"

    sysctl --system 2>/dev/null | grep -E "ip_forward|ipv6.*forward" || \
        sysctl -q -p "$SYSCTL_CONF" 2>/dev/null || \
        sysctl -q -w net.ipv4.ip_forward=1 2>/dev/null || true

    local ipv4_fwd ipv6_fwd
    ipv4_fwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "?")
    ipv6_fwd=$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo "?")

    if [[ "$ipv4_fwd" == "1" ]]; then
        log_info "IP 转发已开启（IPv4=1，IPv6=${ipv6_fwd}）"
    else
        log_warn "IP 转发状态异常（IPv4=${ipv4_fwd}，IPv6=${ipv6_fwd}），请手动检查"
    fi
}

# ══════════════════════════════════════════════════════════════════════
# §15 iptables 持久化机制
# ══════════════════════════════════════════════════════════════════════

# [BUG-7 修复] _save_iptables() 同步保存 ip6tables 规则
_save_iptables() {
    mkdir -p /etc/iptables
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save 2>/dev/null || true
    elif command -v iptables-save &>/dev/null; then
        iptables-save > "$IPTABLES_RULES" 2>/dev/null || true
        if command -v ip6tables-save &>/dev/null; then
            ip6tables-save > "$IP6TABLES_RULES" 2>/dev/null || true
        fi
    fi
}

setup_iptables_persist() {
    # [BUG-DPKG 修复] 改用 dpkg -s + "Status: install ok" 精确判断已安装状态
    # 旧版 dpkg -l 会包含 rc（已卸载但残留配置）状态，误判为已安装
    local already_installed=false
    if command -v netfilter-persistent &>/dev/null; then
        already_installed=true
    elif dpkg -s iptables-persistent 2>/dev/null | grep -q "^Status: install ok"; then
        already_installed=true
    fi

    if [[ "$already_installed" == "false" ]]; then
        log_step "安装 iptables-persistent（保证规则重启后持久化）..."
        echo iptables-persistent iptables-persistent/autosave_v4 boolean true | \
            debconf-set-selections 2>/dev/null || true
        echo iptables-persistent iptables-persistent/autosave_v6 boolean false | \
            debconf-set-selections 2>/dev/null || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
            iptables-persistent netfilter-persistent 2>/dev/null \
            && log_info "iptables-persistent 安装成功" \
            || log_warn "iptables-persistent 安装失败，规则在重启后可能丢失"
    else
        log_info "iptables-persistent 已安装"
    fi

    mkdir -p /etc/iptables
    if [[ ! -f "$IPTABLES_RULES" ]]; then
        iptables-save > "$IPTABLES_RULES" 2>/dev/null || true
        log_info "初始化 /etc/iptables/rules.v4"
    fi
}

# ══════════════════════════════════════════════════════════════════════
# §16 防火墙端口开放
# ══════════════════════════════════════════════════════════════════════

# [BUG-FW-MGMT] 所有 INPUT 规则均加 comment 标记，便于精准清理
# [BUG-FW-IDEMPOTENT 修复] 先调用 _clean_relay_input_rules() 清除同 comment 旧规则，
#   再无条件写入当前端口参数的新规则，保证任意次调用、任意端口变更后结果幂等。
#   旧版用 -C 检查存在则跳过，端口变更后旧规则残留、新规则追加，产生孤儿规则堆积。
_apply_firewall_rules() {
    local end_port=$(( START_PORT + MAX_NODES - 1 ))

    # UFW 优先（UFW 自带规则去重，无需额外 comment 标记）
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -qi "active"; then
        ufw allow "${WG_PORT}/udp" 2>/dev/null || true
        ufw allow "${START_PORT}:${end_port}/tcp" 2>/dev/null || true
        ufw allow "${START_PORT}:${end_port}/udp" 2>/dev/null || true
        log_info "ufw 已放行端口（UDP ${WG_PORT} + TCP/UDP ${START_PORT}~${end_port}）"
        return
    fi

    # iptables：先清除所有旧 relay comment 规则，再无条件写入新规则
    if command -v iptables &>/dev/null; then
        # 先删（防止端口变更后旧规则堆积）—— BUG-FW-IDEMPOTENT 核心修复
        _clean_relay_input_rules

        # 无条件写入当前端口参数的新规则（删后加，幂等）
        iptables -I INPUT -p udp --dport "$WG_PORT" \
            -m comment --comment "$FW_COMMENT_WG" -j ACCEPT 2>/dev/null \
            && log_info "已放行 UDP ${WG_PORT}（WireGuard，comment: ${FW_COMMENT_WG}）" || true

        # [BUG-11 修复] TCP 和 UDP 端口范围规则分别独立添加
        iptables -I INPUT -p tcp --dport "${START_PORT}:${end_port}" \
            -m comment --comment "$FW_COMMENT_TCP" -j ACCEPT 2>/dev/null \
            && log_info "已放行 TCP ${START_PORT}~${end_port}（comment: ${FW_COMMENT_TCP}）" || true

        iptables -I INPUT -p udp --dport "${START_PORT}:${end_port}" \
            -m comment --comment "$FW_COMMENT_UDP" -j ACCEPT 2>/dev/null \
            && log_info "已放行 UDP ${START_PORT}~${end_port}（comment: ${FW_COMMENT_UDP}）" || true

        _save_iptables
    else
        log_warn "未检测到防火墙工具，请手动在云服务商安全组放行端口"
    fi
}

open_firewall_ports() {
    local end_port=$(( START_PORT + MAX_NODES - 1 ))

    # [BUG-10 修复 + BUG-FW-MGMT 修复] IS_FIRST_RUN=false 路径
    # 按 comment 标记检测规则存在性（与 _apply_firewall_rules() 写入逻辑一致）
    # 任意规则缺失均触发静默重建
    if [[ "$IS_FIRST_RUN" == "false" ]]; then
        local wg_ok=true relay_tcp_ok=true relay_udp_ok=true

        iptables -C INPUT -p udp --dport "$WG_PORT" \
            -m comment --comment "$FW_COMMENT_WG" -j ACCEPT &>/dev/null 2>&1 || wg_ok=false
        iptables -C INPUT -p tcp --dport "${START_PORT}:${end_port}" \
            -m comment --comment "$FW_COMMENT_TCP" -j ACCEPT &>/dev/null 2>&1 || relay_tcp_ok=false
        iptables -C INPUT -p udp --dport "${START_PORT}:${end_port}" \
            -m comment --comment "$FW_COMMENT_UDP" -j ACCEPT &>/dev/null 2>&1 || relay_udp_ok=false

        if [[ "$wg_ok" == "true" && "$relay_tcp_ok" == "true" && "$relay_udp_ok" == "true" ]]; then
            log_info "端口已开放（UDP ${WG_PORT} + TCP/UDP ${START_PORT}~${end_port}），跳过"
            return 0
        fi
        log_warn "检测到防火墙规则丢失（wg=${wg_ok} tcp=${relay_tcp_ok} udp=${relay_udp_ok}），正在静默重建..."
        _apply_firewall_rules
        return
    fi

    # 首次初始化：询问用户
    echo ""
    read -rp "是否自动开放防火墙端口（UDP ${WG_PORT} + TCP/UDP ${START_PORT}~${end_port}）？[Y/n]: " yn || true
    if [[ "${yn,,}" == "n" ]]; then
        log_warn "跳过防火墙配置，请手动放行："
        log_warn "  UDP ${WG_PORT}（WireGuard）"
        log_warn "  TCP/UDP ${START_PORT}~${end_port}（中转入站端口）"
        return
    fi

    _apply_firewall_rules
}

# ══════════════════════════════════════════════════════════════════════
# §17 初始化数据文件
# ══════════════════════════════════════════════════════════════════════
init_data_files() {
    # peer_map.json（LINK_ID → WG_IP 映射）
    if [[ ! -f "$WG_PEER_MAP" ]]; then
        echo '{}' > "$WG_PEER_MAP"
        chmod 600 "$WG_PEER_MAP"
        log_info "初始化 peer_map.json: $WG_PEER_MAP"
    else
        log_info "peer_map.json 已存在（$(_count_peers) 条），保留"
    fi

    # nodes.json（节点注册表）
    # [BUG-2 修复] do_full_reset() 已改为 rm nodes.json，此处始终写入完整格式
    # forward_type 字段：告知 duijie.sh 本中转机使用 iptables 网络层转发
    mkdir -p "$NODES_JSON_DIR"
    if [[ ! -f "$NODES_JSON" ]]; then
        echo "$NODES_JSON_INIT" > "$NODES_JSON"
        # [BUG-SEC 修复] nodes.json 包含节点 IP / WG 公钥等架构信息，需限制读取权限
        chmod 600 "$NODES_JSON"
        log_info "初始化 nodes.json（含 forward_type/schema_version）: $NODES_JSON"
    else
        log_info "nodes.json 已存在（$(_count_nodes) 个节点），保留"
    fi
}

# 探测当前 SSH 服务端口（供 save_info() 写入 ZHONGZHUAN_SSH_PORT）
# 优先读取 sshd_config，其次检测 ss/netstat 监听端口，最后默认 22
_detect_ssh_port() {
    local port=""

    # 方法1：读取 sshd_config（最权威）
    if [[ -f /etc/ssh/sshd_config ]]; then
        port=$(grep -E "^Port\s+" /etc/ssh/sshd_config 2>/dev/null \
               | awk '{print $2}' | head -1 | tr -d '[:space:]')
    fi

    # 方法2：检测 ss 监听端口（应对 sshd_config 使用 Include 指令的情况）
    if [[ -z "$port" ]] && command -v ss &>/dev/null; then
        port=$(ss -tlnp 2>/dev/null \
               | grep -E 'sshd|:22 ' \
               | grep -oP ':\K[0-9]+(?= )' \
               | head -1)
    fi

    # 方法3：检测 netstat（旧系统兼容）
    if [[ -z "$port" ]] && command -v netstat &>/dev/null; then
        port=$(netstat -tlnp 2>/dev/null \
               | grep sshd \
               | grep -oP ':\K[0-9]+(?= )' \
               | head -1)
    fi

    echo "${port:-22}"
}

# ══════════════════════════════════════════════════════════════════════
# §18 保存 info 文件
# ══════════════════════════════════════════════════════════════════════
save_info() {
    local end_port=$(( START_PORT + MAX_NODES - 1 ))
    local node_count; node_count=$(_count_nodes)
    local timestamp; timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    # [ENH-2] 探测 SSH 端口，供 duijie.sh 使用非标准端口时连接中转机
    local ssh_port; ssh_port=$(_detect_ssh_port)

    cat > "$INFO_FILE" << EOF
============================================================
  中转机信息  ${timestamp}
  版本: zhongzhuan.sh v${VERSION}  (WireGuard版)
  已对接落地机: ${node_count} 台
============================================================
ZHONGZHUAN_IP=${PUBLIC_IP}

# ── SSH 连接参数（duijie.sh SSH 连接中转机使用）──────────────
# duijie.sh 可通过 ssh -p \$ZHONGZHUAN_SSH_PORT 连接
ZHONGZHUAN_SSH_PORT=${ssh_port}

# ── WireGuard 参数（duijie.sh 主要读取字段）──────────────────
ZHONGZHUAN_WG_PUBKEY=${WG_PUBKEY}
ZHONGZHUAN_WG_PORT=${WG_PORT}
ZHONGZHUAN_WG_PRIVKEY=${WG_PRIVKEY}

# ── WireGuard 网络配置 ────────────────────────────────────────
# ZHONGZHUAN_WG_ADDR: duijie.sh 可读取替换硬编码的 10.100.0.1
ZHONGZHUAN_WG_ADDR=${WG_ADDR}
# [BUG-MTU] MTU 与 duijie.sh 探测保底值（1380）对齐，导出供落地机参考
ZHONGZHUAN_WG_MTU=${WG_MTU}

# ── duijie.sh v4.x 兼容占位字段 ───────────────────────────────
# ZHONGZHUAN_PUBKEY: duijie.sh _info::read_relay() 检查此字段非空
# WireGuard 架构下此字段无业务含义，复用 WG 公钥作为占位
ZHONGZHUAN_PUBKEY=${X25519_PUBKEY}
ZHONGZHUAN_SHORT_ID=placeholder
ZHONGZHUAN_SNI=placeholder
ZHONGZHUAN_DEST=placeholder:443

# ── 端口规划 ─────────────────────────────────────────────────
ZHONGZHUAN_START_PORT=${START_PORT}
ZHONGZHUAN_MAX_NODES=${MAX_NODES}

# ── 文件路径 ─────────────────────────────────────────────────
ZHONGZHUAN_NODES=${NODES_JSON}
ZHONGZHUAN_PEER_MAP=${WG_PEER_MAP}
ZHONGZHUAN_WG_CONF=${WG_CONF}

# ── 端口摘要 ─────────────────────────────────────────────────
ZHONGZHUAN_PORT_RANGE=${START_PORT}~${end_port}
ZHONGZHUAN_PORTS_USED=${node_count}

# ── 管理命令 ─────────────────────────────────────────────────
# 查看状态      : bash zhongzhuan.sh --status
# 数据一致性检查: bash zhongzhuan.sh --check
# 完全重置      : bash zhongzhuan.sh --reset
# WireGuard 状态: wg show wg0
# 重启 WG       : systemctl restart wg-quick@wg0
# 已对接节点    : python3 -m json.tool ${NODES_JSON}
# peer 映射表   : python3 -m json.tool ${WG_PEER_MAP}
# iptables 规则 : iptables -t nat -S PREROUTING | grep luodi-dnat
============================================================
EOF
    chmod 600 "$INFO_FILE"
    log_info "info 文件已保存：$INFO_FILE"
}

# ══════════════════════════════════════════════════════════════════════
# §19 打印结果摘要
# ══════════════════════════════════════════════════════════════════════
print_result() {
    local end_port=$(( START_PORT + MAX_NODES - 1 ))
    local node_count; node_count=$(_count_nodes)
    local wg_status; wg_status=$(_wg_running && echo "active" || echo "inactive")

    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  ${GREEN}${BOLD}✓ 中转机初始化完成  zhongzhuan.sh v${VERSION}  WireGuard版${NC}    ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}中转机公网 IP   :${NC} $PUBLIC_IP"
    echo -e "  ${BOLD}SSH 端口        :${NC} $(_detect_ssh_port)"
    echo -e "  ${BOLD}WG 公钥         :${NC} $WG_PUBKEY"
    echo -e "  ${BOLD}WG 端口         :${NC} $WG_PORT（UDP）"
    echo -e "  ${BOLD}WG 接口地址     :${NC} ${WG_ADDR}/24"
    echo -e "  ${BOLD}WG MTU          :${NC} ${WG_MTU}（TCPMSS = $(( WG_MTU - 40 ))，与 duijie.sh 保底值对齐）"
    echo -e "  ${BOLD}端口范围        :${NC} ${START_PORT} ~ ${end_port}（共 ${MAX_NODES} 个）"
    echo -e "  ${BOLD}WireGuard 状态  :${NC} ${wg_status}"
    echo -e "  ${BOLD}已对接落地机    :${NC} ${node_count} 台"
    echo ""

    if [[ "$node_count" -gt 0 ]]; then
        echo -e "${YELLOW}已对接节点列表：${NC}"
        python3 - "$NODES_JSON" << 'PYEOF' 2>/dev/null || true
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    ns = d.get("nodes", {})
    items = list(ns.items()) if isinstance(ns, dict) else [(str(i), n) for i, n in enumerate(ns)]
    for lid, n in items:
        wg_ip  = n.get("wg_ip", "?")
        r_port = n.get("relay_port", "?")
        l_ip   = n.get("luodi_ip", "?")
        label  = n.get("node_label", n.get("label", ""))
        print(f"  [{lid[:8]}]  WG={wg_ip}  中转端口={r_port}  落地={l_ip}  {label}")
except:
    pass
PYEOF
        echo ""
    fi

    echo -e "${YELLOW}── 下一步 ─────────────────────────────────────────────────────${NC}"
    echo -e "  1. ${BOLD}在每台落地机上运行：${NC}"
    echo -e "     bash <(curl -fsSL .../luodi.sh)"
    echo ""
    echo -e "  2. ${BOLD}在每台落地机上运行对接脚本：${NC}"
    echo -e "     bash <(curl -fsSL .../duijie.sh)"
    echo -e "     （duijie.sh 会 SSH 连接此中转机并自动配置）"
    echo ""
    echo -e "  3. ${BOLD}查看此中转机状态：${NC}"
    echo -e "     bash zhongzhuan.sh --status"
    echo ""
    echo -e "${YELLOW}── 重要提示 ────────────────────────────────────────────────────${NC}"
    echo -e "  · 链式代理节点与中转机已有代理节点完全隔离，互不影响"
    echo -e "  · WireGuard 密钥已保存至 $INFO_FILE"
    echo -e "  · 请勿重置密钥，否则所有已对接节点需重新运行 duijie.sh"
    echo ""
}

# ══════════════════════════════════════════════════════════════════════
# §20 --status 命令
# ══════════════════════════════════════════════════════════════════════
cmd_status() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║    中转机状态  zhongzhuan.sh  v${VERSION}  WireGuard版       ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    local wg_status
    wg_status=$(_wg_running && echo "${GREEN}active${NC}" || echo "${RED}inactive${NC}")
    echo -e "  ${BOLD}WireGuard 状态 :${NC} $(echo -e "$wg_status")"

    if [[ -f "$INFO_FILE" ]]; then
        echo -e "  ${BOLD}中转机 IP      :${NC} $(_ikv ZHONGZHUAN_IP)"
        echo -e "  ${BOLD}SSH 端口       :${NC} $(_ikv ZHONGZHUAN_SSH_PORT)"
        echo -e "  ${BOLD}WG 公钥        :${NC} $(_ikv ZHONGZHUAN_WG_PUBKEY | head -c 24)..."
        echo -e "  ${BOLD}WG 端口        :${NC} $(_ikv ZHONGZHUAN_WG_PORT)"
        echo -e "  ${BOLD}WG 网关地址    :${NC} $(_ikv ZHONGZHUAN_WG_ADDR)/24"
        echo -e "  ${BOLD}WG MTU         :${NC} $(_ikv ZHONGZHUAN_WG_MTU)"
        local start max
        start=$(_ikv ZHONGZHUAN_START_PORT)
        max=$(_ikv ZHONGZHUAN_MAX_NODES)
        echo -e "  ${BOLD}端口范围       :${NC} ${start} ~ $(( ${start:-0} + ${max:-0} - 1 ))（共 ${max:-?} 个）"
    else
        echo -e "  ${YELLOW}未找到 xray_zhongzhuan_info.txt，请运行初始化${NC}"
    fi

    if _wg_running; then
        echo ""
        echo -e "  ${BOLD}WireGuard 接口详情：${NC}"
        wg show wg0 2>/dev/null | while IFS= read -r line; do
            echo "    $line"
        done

        local peer_count online_count
        peer_count=$(wg show wg0 peers 2>/dev/null | wc -l || echo 0)
        peer_count=$(echo "$peer_count" | tr -d ' ')
        online_count=0
        if [[ "$peer_count" -gt 0 ]]; then
            online_count=$(wg show wg0 latest-handshakes 2>/dev/null \
                | awk -v now="$(date +%s)" '{if(now-$2 < 180) count++} END{print count+0}' || echo 0)
        fi
        echo ""
        echo -e "  ${BOLD}WG Peers       :${NC} ${peer_count} 个（${online_count} 个最近握手 < 3 分钟）"
    fi

    echo ""

    local node_count; node_count=$(_count_nodes)
    local peer_map_count; peer_map_count=$(_count_peers)
    local dnat_count; dnat_count=$(_count_dnat_rules)

    echo -e "  ${BOLD}已对接落地机   :${NC} ${node_count} 个（nodes.json）"
    echo -e "  ${BOLD}peer_map 条目  :${NC} ${peer_map_count} 个"
    # [BUG-5 修复] dnat_count 按 LINK_ID 去重，与 node_count 直接可比
    echo -e "  ${BOLD}DNAT 节点数    :${NC} ${dnat_count} 个（每节点 TCP+UDP 各一条规则，已去重）"

    if [[ "$node_count" != "$peer_map_count" || "$node_count" != "$dnat_count" ]]; then
        echo ""
        echo -e "  ${YELLOW}⚠ 数据不一致（nodes=${node_count}, peers=${peer_map_count}, dnat=${dnat_count}）${NC}"
        echo -e "  ${YELLOW}  运行 'bash zhongzhuan.sh --check' 查看详情${NC}"
    fi

    if [[ "$node_count" -gt 0 && -f "$NODES_JSON" ]]; then
        echo ""
        echo -e "  ${CYAN}已对接节点：${NC}"
        python3 - "$NODES_JSON" << 'PYEOF' 2>/dev/null || true
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    ns = d.get("nodes", {})
    items = list(ns.items()) if isinstance(ns, dict) else [(str(i), n) for i, n in enumerate(ns)]
    for lid, n in items:
        wg_ip  = n.get("wg_ip", "?")
        r_port = n.get("relay_port", "?")
        l_ip   = n.get("luodi_ip", "?")
        label  = n.get("node_label", n.get("label", ""))
        print(f"    [{lid[:8]}] WG={wg_ip}  端口={r_port}  落地={l_ip}  {label}")
except Exception as e:
    print(f"    （解析失败: {e}）")
PYEOF
    fi

    if [[ "$dnat_count" -gt 0 ]]; then
        echo ""
        echo -e "  ${CYAN}iptables DNAT 规则（前 5 个节点的 TCP 规则）：${NC}"
        iptables -t nat -S PREROUTING 2>/dev/null \
            | grep "${DNAT_COMMENT_PREFIX}" \
            | grep -- "-p tcp" \
            | head -5 \
            | while IFS= read -r r; do echo "    $r"; done
    fi

    echo ""
}

# ══════════════════════════════════════════════════════════════════════
# §21 --check 数据一致性检查
# ══════════════════════════════════════════════════════════════════════
cmd_check() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║    数据一致性检查  zhongzhuan.sh  v${VERSION}                ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    python3 - "$NODES_JSON" "$WG_PEER_MAP" << 'PYEOF' 2>/dev/null
import json, sys, subprocess, re, os

nodes_path    = sys.argv[1]
peer_map_path = sys.argv[2]

# 读取 nodes.json
try:
    d = json.load(open(nodes_path))
    ns = d.get("nodes", {})
    nodes_ids = set(ns.keys()) if isinstance(ns, dict) else set(str(i) for i in range(len(ns)))
except Exception as e:
    print(f"  [✗] nodes.json 读取失败: {e}")
    nodes_ids = set()

# 读取 peer_map.json
try:
    pm = json.load(open(peer_map_path))
    peer_map_ids = set(pm.keys())
except Exception as e:
    print(f"  [✗] peer_map.json 读取失败: {e}")
    peer_map_ids = set()

# 读取 iptables DNAT 规则中的 LINK_ID（去重，固定8位十六进制）
iptables_ids = set()
try:
    out = subprocess.check_output(
        ["iptables", "-t", "nat", "-S", "PREROUTING"],
        stderr=subprocess.DEVNULL, text=True)
    for line in out.splitlines():
        m = re.search(r'luodi-dnat-([a-f0-9]{8})', line)
        if m:
            iptables_ids.add(m.group(1))
except Exception as e:
    print(f"  [!] iptables 读取失败: {e}")

# 读取 WG peers（内核中已加载的公钥）
wg_peers = set()
try:
    out = subprocess.check_output(
        ["wg", "show", "wg0", "peers"],
        stderr=subprocess.DEVNULL, text=True)
    wg_peers = {line.strip() for line in out.splitlines() if line.strip()}
except:
    pass

# 统计汇总
print(f"  nodes.json    : {len(nodes_ids)} 个 LINK_ID")
print(f"  peer_map.json : {len(peer_map_ids)} 个 LINK_ID")
print(f"  iptables DNAT : {len(iptables_ids)} 个 LINK_ID（TCP+UDP 去重）")
print(f"  WG peers      : {len(wg_peers)} 个公钥")
print()

only_nodes    = nodes_ids - peer_map_ids - iptables_ids
only_peer_map = peer_map_ids - nodes_ids
only_iptables = iptables_ids - nodes_ids
consistent    = nodes_ids & peer_map_ids & iptables_ids

print(f"  ✓ 三者一致   : {len(consistent)} 个")

if only_nodes:
    print(f"  ✗ 仅在 nodes.json（peer_map/iptables 缺失）: {only_nodes}")
if only_peer_map:
    print(f"  ✗ 仅在 peer_map（nodes.json 缺失）: {only_peer_map}")
if only_iptables:
    print(f"  ✗ 仅在 iptables（nodes.json 缺失）: {only_iptables}")

# [BUG-6 修复] WG peers 公钥对比
# 从 nodes.json 各节点 entry 中提取 wg_pubkey（peer_map 格式为 {link_id: "IP字符串"}，不含公钥）
nodes_pubkeys = set()
try:
    nd = json.load(open(nodes_path))
    for lid, n in nd.get("nodes", {}).items():
        if isinstance(n, dict):
            pk = n.get("wg_pubkey", "")
            if pk:
                nodes_pubkeys.add(pk)
except:
    pass

if nodes_pubkeys:
    missing_in_wg = nodes_pubkeys - wg_peers
    extra_in_wg   = wg_peers - nodes_pubkeys
    if missing_in_wg:
        print(f"\n  ✗ nodes.json 中 {len(missing_in_wg)} 个落地机公钥未在 wg0 peers 中找到")
        print(f"    （落地机 WG 可能已重建，需在落地机重新运行 duijie.sh）")
    if extra_in_wg:
        print(f"\n  ⚠ wg0 peers 中有 {len(extra_in_wg)} 个公钥不在 nodes.json")
        print(f"    （孤立 peer，可能是 nodes.json 被手动清空所致）")
    if not missing_in_wg and not extra_in_wg:
        print(f"\n  ✓ nodes.json 中所有落地机公钥均在 wg0 peers 中存在")
elif wg_peers:
    print(f"\n  [!] nodes.json 中无 wg_pubkey 字段（落地机尚未对接，或字段格式变更）")

# [ENH-CHECK] 检查 sysctl 转发参数运行时状态
# 系统更新后 ip_forward 可能被重置，导致中转功能静默中断
print()
print("  ── sysctl 转发参数检查 ──")
try:
    ipv4_fwd = open('/proc/sys/net/ipv4/ip_forward').read().strip()
    print(f"  net.ipv4.ip_forward              : {'✓ 已启用 (1)' if ipv4_fwd == '1' else f'✗ 未启用 ({ipv4_fwd}) ← 警告！中转功能将不工作'}")
except Exception as e:
    print(f"  net.ipv4.ip_forward              : [!] 读取失败 ({e})")

ipv6_fwd_path = '/proc/sys/net/ipv6/conf/all/forwarding'
if os.path.exists(ipv6_fwd_path):
    try:
        ipv6_fwd = open(ipv6_fwd_path).read().strip()
        print(f"  net.ipv6.conf.all.forwarding     : {'✓ 已启用 (1)' if ipv6_fwd == '1' else f'⚠ 未启用 ({ipv6_fwd})（如无 IPv6 需求可忽略）'}")
    except Exception as e:
        print(f"  net.ipv6.conf.all.forwarding     : [!] 读取失败 ({e})")
else:
    print(f"  net.ipv6.conf.all.forwarding     : [!] /proc 路径不存在（内核可能无 IPv6 支持）")

if not (only_nodes or only_peer_map or only_iptables):
    print("\n  ✓ 数据一致性检查通过")
else:
    print("\n  ⚠ 发现不一致。建议：在对应落地机重新运行 duijie.sh，或运行 zhongzhuan.sh --reset 清理")
PYEOF
    echo ""
}

# ══════════════════════════════════════════════════════════════════════
# §22 入口 main
# ══════════════════════════════════════════════════════════════════════
main() {
    for arg in "$@"; do
        [[ "$arg" == "--yes" ]] && AUTO_YES=true
    done

    case "${1:-}" in
        --status)
            cmd_status
            exit 0
            ;;
        --check)
            cmd_check
            exit 0
            ;;
        --reset)
            print_banner
            [[ $EUID -ne 0 ]] && log_error "请使用 root 权限运行"
            _show_existing_summary
            _action_full_reset
            echo ""
            echo -e "${GREEN}完全重置完成。如需重新初始化，直接运行 bash zhongzhuan.sh${NC}"
            exit 0
            ;;
        --help|-h)
            echo "用法："
            echo "  bash zhongzhuan.sh              # 标准初始化流程"
            echo "  bash zhongzhuan.sh --status     # 查看当前状态"
            echo "  bash zhongzhuan.sh --check      # 数据一致性检查"
            echo "  bash zhongzhuan.sh --reset      # 完全重置（交互确认）"
            echo "  bash zhongzhuan.sh --reset --yes # 完全重置（跳过确认）"
            exit 0
            ;;
    esac

    # ── 标准初始化流程 ────────────────────────────────────────────
    print_banner

    # 1. 旧文件检测 + 用户决策
    user_decision

    # 2. 旧版 xray-relay 处理
    detect_and_handle_legacy_relay

    # 3. WireGuard 子网冲突检测
    check_wg_subnet

    # 3b. WireGuard 监听端口占用检测
    check_wg_port

    # 4. 安装 WireGuard
    install_wireguard

    # 5. 生成 WG 密钥（已有则跳过）
    generate_wg_keys

    # 6. 生成占位密钥（duijie.sh 兼容）
    generate_x25519_placeholder

    # 7. 获取公网 IP
    get_public_ip

    # 8. 端口配置（已有则跳过）
    get_port_config

    # 9. 初始化 wg0.conf 并启动
    init_wg_interface

    # 10. 开启 IP 转发（IPv4 + IPv6）
    enable_ip_forward

    # 11. 安装 iptables-persistent
    setup_iptables_persist

    # 12. 开放防火墙端口
    open_firewall_ports

    # 13. 初始化数据文件（peer_map.json + nodes.json）
    init_data_files

    # 14. 保存 info 文件
    save_info

    # 15. 打印结果
    print_result
}

main "$@"
