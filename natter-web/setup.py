#!/usr/bin/env python3
"""
Natter Web Admin 依赖安装脚本
将自动安装所有依赖到 lib 文件夹
"""

import os
import sys
import subprocess
import platform

def ensure_lib_dir():
    """确保 lib 目录存在"""
    lib_dir = os.path.join(os.path.dirname(__file__), 'lib')
    if not os.path.exists(lib_dir):
        os.makedirs(lib_dir)
    return lib_dir

def install_dependencies():
    """安装依赖到 lib 目录"""
    lib_dir = ensure_lib_dir()
    
    # 获取当前 Python 解释器路径
    python_executable = sys.executable
    
    print("=" * 60)
    print("正在安装 Natter Web Admin 依赖...")
    print(f"目标目录: {lib_dir}")
    print(f"Python 版本: {platform.python_version()}")
    print("=" * 60)
    
    # 安装依赖
    cmd = [
        python_executable,
        "-m", "pip", "install",
        "--target", lib_dir,
        "-r", "requirements.txt"
    ]
    
    try:
        result = subprocess.run(cmd, check=True, text=True, capture_output=True)
        print("依赖安装成功!")
        print("-" * 60)
        print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print("依赖安装失败:")
        print("-" * 60)
        print(e.stderr)
        print("-" * 60)
        print("请检查网络连接后重试")
        return False

def check_dependencies():
    """检查依赖是否已安装"""
    try:
        from flask import Flask
        import psutil
        import sqlite3
        return True
    except ImportError:
        return False

def add_lib_to_path():
    """将 lib 目录添加到系统路径"""
    lib_dir = os.path.join(os.path.dirname(__file__), 'lib')
    if lib_dir not in sys.path:
        sys.path.insert(0, lib_dir)

if __name__ == "__main__":
    # 检查是否已安装依赖
    if check_dependencies():
        print("所有依赖已安装，无需操作")
        sys.exit(0)
    
    # 尝试安装依赖
    if install_dependencies():
        print("依赖安装完成，请运行 app.py 启动服务")
    else:
        print("依赖安装失败，请检查错误信息")
        sys.exit(1)