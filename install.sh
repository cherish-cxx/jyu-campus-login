#!/usr/bin/env bash
# 校园网自动登录 —— 一键安装脚本
#
# 用法：
#   bash install.sh            安装（会问你账号密码）
#   bash install.sh --remove   卸载
#
# 需要：本目录下要有 campus_login.py；安装过程需要 sudo。

set -euo pipefail

APP_DIR=/opt/campus-login
SVC=/etc/systemd/system/campus-login.service
SVC_NAME=campus-login
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

c_ok()   { printf '\033[32m%s\033[0m\n' "$*"; }
c_warn() { printf '\033[33m%s\033[0m\n' "$*"; }
c_err()  { printf '\033[31m%s\033[0m\n' "$*" >&2; }

need_root() {
    if [ "$(id -u)" -ne 0 ]; then
        c_err "需要管理员权限，请用：sudo bash $0 $*"
        exit 1
    fi
}

do_remove() {
    need_root "$@"
    if systemctl list-unit-files 2>/dev/null | grep -q "^${SVC_NAME}.service"; then
        systemctl disable --now "$SVC_NAME" 2>/dev/null || true
        rm -f "$SVC"
        systemctl daemon-reload
        c_ok "服务已停止并移除。"
    else
        c_warn "没有发现已安装的服务。"
    fi
    if [ -d "$APP_DIR" ]; then
        rm -rf "$APP_DIR"
        c_ok "已删除 $APP_DIR"
    fi
    c_ok "卸载完成。"
}

main() {
    if [ "${1:-}" = "--remove" ]; then
        do_remove "$@"
        exit 0
    fi

    echo
    echo "==============================================="
    echo "        校园网自动登录 · 安装向导"
    echo "==============================================="
    echo

    # ---- 1. 检查依赖 ----
    if ! command -v python3 >/dev/null 2>&1; then
        c_err "没找到 python3。Debian/Ubuntu 先执行：sudo apt install -y python3"
        exit 1
    fi
    PYV=$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')
    echo "Python 版本：$PYV"
    python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,7) else 1)' || {
        c_err "Python 版本太低，需要 3.7 以上。"; exit 1; }

    if [ ! -f "$HERE/campus_login.py" ]; then
        c_err "当前目录没有 campus_login.py，请在解压出来的目录里运行本脚本。"
        exit 1
    fi

    if ! systemctl --version >/dev/null 2>&1; then
        c_err "这台机器没有 systemd，无法用本脚本安装（可以手动运行 python3 campus_login.py）。"
        exit 1
    fi

    # ---- 2. 输入账号密码 ----
    echo
    read -r -p "学号 / 账号： " USER_ID
    [ -n "${USER_ID:-}" ] || { c_err "账号不能为空"; exit 1; }

    while :; do
        read -r -s -p "密码（输入时不显示）： " USER_PW; echo
        [ -n "$USER_PW" ] || { c_warn "密码不能为空，重来"; continue; }
        read -r -s -p "再输入一次确认： " USER_PW2; echo
        if [ "$USER_PW" = "$USER_PW2" ]; then break; fi
        c_warn "两次输入不一致，重来。"
    done

    echo
    read -r -p "接入方式 service（直接回车用默认值「实验室」）： " SERVICE_RAW
    SERVICE="${SERVICE_RAW:-实验室}"

    echo
    echo "可选：只在某个时段内自动登录（宿舍晚上断网的话建议设置）。"
    read -r -p "开始时间 [07:00]： " T_START
    read -r -p "结束时间 [22:30]： " T_END
    T_START="${T_START:-07:00}"
    T_END="${T_END:-22:30}"

    need_root "$@"

    # ---- 3. 落盘 ----
    echo
    echo "安装到 $APP_DIR ..."
    mkdir -p "$APP_DIR"
    install -m 755 "$HERE/campus_login.py" "$APP_DIR/campus_login.py"

    printf '%s\n' "$USER_PW" | python3 "$APP_DIR/campus_login.py" --write-config \
        --out "$APP_DIR/config.json" \
        --user "$USER_ID" \
        --password-stdin \
        --service "$SERVICE" \
        --active-start "$T_START" \
        --active-end "$T_END"
    chmod 600 "$APP_DIR/config.json"

    cat > "$SVC" <<EOF
[Unit]
Description=校园网 ePortal 自动登录
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
WorkingDirectory=$APP_DIR
ExecStart=/usr/bin/env python3 $APP_DIR/campus_login.py -c $APP_DIR/config.json
Restart=always
RestartSec=30
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now "$SVC_NAME" >/dev/null 2>&1
    c_ok "服务已安装并启动。"

    # ---- 4. 自检 ----
    echo
    echo "正在做一次登录测试（最多等 30 秒）..."
    echo
    if python3 "$APP_DIR/campus_login.py" -c "$APP_DIR/config.json" --once; then
        echo
        c_ok "测试成功：已经能自动登录了。"
    else
        echo
        c_warn "登录没成功。脚本会继续在后台每 30 秒重试。"
        c_warn "排查：python3 $APP_DIR/campus_login.py -c $APP_DIR/config.json --check -v"
        c_warn "日志：journalctl -u $SVC_NAME -n 30 --no-pager"
    fi

    echo
    echo "-----------------------------------------------"
    echo " 常用命令"
    echo "   看状态：systemctl status $SVC_NAME --no-pager"
    echo "   看日志：journalctl -u $SVC_NAME -f"
    echo "   改配置：sudo nano $APP_DIR/config.json   然后"
    echo "           sudo systemctl restart $SVC_NAME"
    echo "   卸载：  sudo bash $0 --remove"
    echo "-----------------------------------------------"
    echo
    echo "注意：本机插网线 / 连别的 WiFi 时脚本会自动跳过，不会乱发登录请求。"
    echo
}

main "$@"
