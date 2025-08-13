#!/usr/bin/env bash

# --- Natter 配置 ---
NATTER_MODE="sudo-iptables" # Natter转发流量模式 (可选: "iptables", "sudo-iptables")
# "iptables": 需要以root权限运行此脚本
# "sudo-iptables": Natter所在用户需要对iptables有免密sudo权限
NATTER_ARGS=(                   # Natter 启动参数
    "-m" "$NATTER_MODE"
    "-p" "25565"                # 转发的Minecraft服务器端口 (默认: 25565)
    "-r"                        # 持续重试，直到Minecraft服务器端口开放
    "-U"                        # 若路由器已开启UPnP，则添加此项 (使用DMZ则不需要)
    "-e" "/Natter-in-Minecraft/srv/ali-srv.py"       # 指定更新SRV记录的脚本 (以阿里云为例)
)
# 更多Natter用法请参考项目主页: https://github.com/MikeWang000000/Natter

RUN_MINECRAFT="./start.sh"      # 启动Minecraft服务器的脚本位置


# --- 前置检查 ---
# 1. 检查Natter模式对应的运行权限
if [ "$NATTER_MODE" = "iptables" ]; then
    if [ "$EUID" -ne 0 ]; then
        echo "错误：使用 'iptables' 模式时，请通过 sudo 运行此脚本。"
        exit 1
    fi
elif [ "$NATTER_MODE" = "sudo-iptables" ]; then
    echo "信息：检测到 'sudo-iptables' 模式，将以当前用户身份运行。"
    # 此模式下，假定用户已为iptables配置免密sudo权限
else
    echo "错误：无效的 NATTER_MODE: '$NATTER_MODE'。请选择 'iptables' 或 'sudo-iptables'。"
    exit 1
fi

# 2. 检查依赖命令
if ! command -v python3 &> /dev/null || ! command -v java &> /dev/null; then
    echo "错误：未找到 'python3' 或 'java' 命令。请确保它们已安装并位于系统的PATH中。"
    exit 1
fi

# --- 清理逻辑 ---
NATTER_PID=""
cleanup() {
    echo "正在执行清理操作..."
    if [ -n "$NATTER_PID" ] && ps -p $NATTER_PID > /dev/null; then
        echo "正在停止 Natter (PID: $NATTER_PID)..."
        kill $NATTER_PID
        sleep 2
        if ps -p $NATTER_PID > /dev/null; then
            echo "Natter 未能优雅地停止，正在强制终止..."
            kill -9 $NATTER_PID
        fi
        echo "Natter 已停止。"
    else
        echo "Natter 进程未运行或PID未知，无需清理。"
    fi
}
trap cleanup INT TERM

# --- 主程序 ---
echo "正在启动 Natter (转发模式: $NATTER_MODE)..."
python3 ./natter/natter.py "${NATTER_ARGS[@]}" > ./natter/natter.log 2>&1 & #输出natter日志，并且使natter在后台运行

NATTER_PID=$!
echo "Natter 已启动，PID: $NATTER_PID"  

echo "正在启动 Minecraft 服务器..."
bash ./$RUN_MINECRAFT # 启动 Minecraft 服务器

echo "Minecraft 服务器已停止。"
# 脚本结束前，调用清理函数来停止Natter

