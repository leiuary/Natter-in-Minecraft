#!/usr/bin/env python3
"""
Natter Web Admin 主程序
带自动依赖检测功能
"""

import os
import sys
import logging
import sqlite3
import subprocess
import time
import json
from datetime import datetime
from functools import wraps

# 获取当前脚本所在的目录
basedir = os.path.abspath(os.path.dirname(__file__))

# 检查依赖是否安装
try:
    from flask import Flask, jsonify, request, render_template, send_from_directory, session, redirect, url_for
    import psutil
    from werkzeug.security import generate_password_hash, check_password_hash
except ImportError:
    # 尝试从本地 lib 目录导入
    try:
        lib_path = os.path.join(os.path.dirname(__file__), 'lib')
        if lib_path not in sys.path:
            sys.path.insert(0, lib_path)
        from flask import Flask, jsonify, request, render_template, send_from_directory, session, redirect, url_for, flash
        import psutil
        from werkzeug.security import generate_password_hash, check_password_hash
    except ImportError:
        print("依赖未安装，请先运行 setup.py 安装依赖")
        sys.exit(1)

# 初始化应用
app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['DATABASE'] = os.path.join(basedir, 'natter.db')
app.config['LOG_DIR'] = os.path.join(basedir, 'logs')
app.config['LIB_DIR'] = os.path.join(basedir, 'lib')

# 确保日志目录存在
os.makedirs(app.config['LOG_DIR'], exist_ok=True)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(app.config['LOG_DIR'], 'web-admin.log'), encoding='utf-8')
    ]
)
logger = logging.getLogger('NatterWebAdmin')

# 打印关键路径信息
logger.info(f"当前工作目录: {os.getcwd()}")
logger.info(f"模板目录: {os.path.join(os.path.dirname(__file__), 'templates')}")

# --- 认证与授权 ---

# 防暴力破解机制
login_attempts = {}
ban_durations = [1, 5, 10, 30, 60] # 分钟

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- 数据库与核心功能 ---

# 初始化数据库
def init_db():
    try:
        with sqlite3.connect(app.config['DATABASE']) as conn:
            c = conn.cursor()
            c.execute('''
                CREATE TABLE IF NOT EXISTS connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    command TEXT NOT NULL,
                    is_auto_detected BOOLEAN DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    pid INTEGER
                )
            ''')
            
            # Add new columns if they don't exist for backward compatibility
            c.execute("PRAGMA table_info(connections)")
            columns = [row[1] for row in c.fetchall()]
            
            if 'autostart' not in columns:
                c.execute("ALTER TABLE connections ADD COLUMN autostart BOOLEAN DEFAULT 0")
            
            if 'params' not in columns:
                c.execute("ALTER TABLE connections ADD COLUMN params TEXT")

            # 创建 settings 表用于存储密码哈希
            c.execute('''
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            ''')
            # 不再创建默认密码
            conn.commit()
            logger.info("数据库初始化或更新完成")
    except Exception as e:
        logger.error(f"数据库初始化失败: {str(e)}")

# 检测运行中的Natter进程 - 最终修复版
def detect_natter_processes():
    natter_processes = []
    try:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
            try:
                proc_name = proc.info.get('name', '').lower()
                cmdline = proc.info.get('cmdline')
                
                if cmdline and 'python' in proc_name and any('natter.py' in c for c in cmdline):
                    natter_processes.append({
                        'pid': proc.info['pid'],
                        'cmdline': ' '.join(cmdline),
                        'create_time': proc.info['create_time'],
                        'status': 'running'
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception as e:
        logger.error(f"进程检测失败: {str(e)}")
    return natter_processes

# 获取所有连接（包括自动检测的）- 重构版
def get_all_connections():
    db_connections = []
    try:
        conn = sqlite3.connect(app.config['DATABASE'])
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM connections")
        db_connections = [dict(row) for row in c.fetchall()]
    except Exception as e:
        logger.error(f"数据库查询失败: {str(e)}")
    
    running_processes = {p['pid']: p for p in detect_natter_processes()}
    
    final_connections = []
    db_pids_to_clear = []

    for conn_dict in db_connections:
        pid = conn_dict.get('pid')
        if pid:
            if pid in running_processes:
                conn_dict['status'] = 'running'
                running_processes.pop(pid)
            else:
                conn_dict['status'] = 'stopped'
                db_pids_to_clear.append(conn_dict['id'])
                conn_dict['pid'] = None
        else:
            conn_dict['status'] = 'stopped'
        
        final_connections.append(conn_dict)

    if db_pids_to_clear:
        try:
            with sqlite3.connect(app.config['DATABASE']) as conn:
                c = conn.cursor()
                c.execute("UPDATE connections SET pid = NULL WHERE id IN ({})".format(','.join('?' for _ in db_pids_to_clear)), db_pids_to_clear)
                conn.commit()
                logger.info(f"已清理无效的PID，涉及的连接ID: {db_pids_to_clear}")
        except Exception as e:
            logger.error(f"清理无效PID失败: {str(e)}")

    for pid, proc_info in running_processes.items():
        final_connections.append({
            'id': None,
            'name': f"手动进程 ({proc_info['pid']})",
            'command': proc_info['cmdline'],
            'is_auto_detected': True,
            'created_at': datetime.fromtimestamp(proc_info['create_time']).isoformat(),
            'pid': proc_info['pid'],
            'status': 'running',
            'autostart': False,
            'params': None
        })
        
    return final_connections

# 启动Natter连接 - 最终修复版
def start_connection(conn_id):
    try:
        with sqlite3.connect(app.config['DATABASE']) as conn_db:
            c = conn_db.cursor()
            c.execute("SELECT * FROM connections WHERE id = ?", (conn_id,))
            connection_data = c.fetchone()
            
            if not connection_data:
                return False, "连接不存在"
            
            # Create a dictionary from the tuple
            columns = [desc[0] for desc in c.description]
            connection = dict(zip(columns, connection_data))

            command_str = connection['command']
            
            if connection['pid'] and psutil.pid_exists(connection['pid']):
                return False, "连接已在运行中"

            log_file = os.path.join(app.config['LOG_DIR'], f"natter_{conn_id}.log")
            
            logger.info(f"准备启动命令: {command_str}")
            
            # 强制子进程使用 UTF-8 编码输出
            proc_env = os.environ.copy()
            proc_env['PYTHONIOENCODING'] = 'utf-8'
            
            parent_process = subprocess.Popen(
                command_str,
                shell=True,
                stdout=open(log_file, 'w', encoding='utf-8'),
                stderr=subprocess.STDOUT,
                env=proc_env
            )
            
            time.sleep(1.0)
            
            try:
                p = psutil.Process(parent_process.pid)
                children = p.children(recursive=True)
            except psutil.NoSuchProcess:
                children = []

            natter_process = None
            for child in children:
                try:
                    if 'python' in child.name().lower() and any('natter.py' in s for s in child.cmdline()):
                        natter_process = child
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            if natter_process and psutil.pid_exists(natter_process.pid):
                pid_to_save = natter_process.pid
                logger.info(f"成功识别到 Natter 子进程，PID: {pid_to_save}")
                c.execute("UPDATE connections SET pid = ? WHERE id = ?", (pid_to_save, conn_id))
                conn_db.commit()
                return True, "启动成功"
            else:
                logger.error(f"启动命令 '{command_str}' 后未找到预期的 Python 子进程。")
                if psutil.pid_exists(parent_process.pid):
                    parent_process.terminate()
                return False, "启动失败：未找到Natter进程。请检查命令和日志。"

    except Exception as e:
        logger.error(f"启动连接过程中出错: {str(e)}")
        return False, f"启动失败: {str(e)}"

# 停止Natter连接
def stop_connection(conn_id):
    try:
        with sqlite3.connect(app.config['DATABASE']) as conn_db:
            c = conn_db.cursor()
            c.execute("SELECT pid FROM connections WHERE id = ?", (conn_id,))
            result = c.fetchone()
            
            if not result or not result[0]:
                return False, "连接未运行"
            
            pid = result[0]
            
            try:
                process = psutil.Process(pid)
                process.terminate()
                process.wait(timeout=10)
                
                c.execute("UPDATE connections SET pid = NULL WHERE id = ?", (conn_id,))
                conn_db.commit()
                
                return True, "停止成功"
            except psutil.NoSuchProcess:
                c.execute("UPDATE connections SET pid = NULL WHERE id = ?", (conn_id,))
                conn_db.commit()
                return False, "进程不存在"
            except Exception as e:
                return False, f"停止失败: {str(e)}"
    except Exception as e:
        logger.error(f"停止连接过程中出错: {str(e)}")
        return False, f"停止失败: {str(e)}"

# 自动启动连接
def autostart_connections():
    logger.info("检查自动启动连接...")
    try:
        with sqlite3.connect(app.config['DATABASE']) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT id FROM connections WHERE autostart = 1")
            connections_to_start = c.fetchall()
            
            if connections_to_start:
                logger.info(f"发现 {len(connections_to_start)} 个需要自动启动的连接。")
                for row in connections_to_start:
                    conn_id = row['id']
                    logger.info(f"正在自动启动连接 ID: {conn_id}")
                    success, message = start_connection(conn_id)
                    if not success:
                        logger.error(f"自动启动连接 ID: {conn_id} 失败: {message}")
            else:
                logger.info("没有需要自动启动的连接。")
    except Exception as e:
        logger.error(f"自动启动连接时出错: {str(e)}")

# 从参数构建命令
def build_command_from_params(params):
    param_map = {
        'v': '-v', 'q': '-q', 'u': '-u', 'U': '-U', 'r': '-r',
        'k': '-k', 's': '-s', 'h': '-h', 'e': '-e',
        'i': '-i', 'b': '-b', 'm': '-m', 't': '-t', 'p': '-p',
        'target_os': '' # 内部使用，不生成参数
    }
    command_parts = ['python', 'natter.py']
    
    for key, value in params.items():
        if not value:
            continue
        
        arg = param_map.get(key)
        if arg is None or key == 'target_os': # 忽略 target_os
            continue

        if isinstance(value, bool):
            command_parts.append(arg)
        else:
            command_parts.append(arg)
            command_parts.append(str(value))
            
    return ' '.join(command_parts)

# API路由
@app.route('/api/connections', methods=['GET'])
def get_connections_api():
    connections = get_all_connections()
    return jsonify(connections)

@app.route('/api/connections', methods=['POST'])
@login_required
def create_connection_api():
    try:
        data = request.get_json()
        name = data.get('name')
        command = data.get('command')
        params = data.get('params')
        autostart = data.get('autostart', False)

        if not name:
            return jsonify({"error": "缺少必要参数 (名称)"}), 400
        
        # 如果是参数模式，则构建命令；否则确保命令不为空
        if params is not None:
            command = build_command_from_params(params)
        elif not command:
            return jsonify({"error": "缺少必要参数 (命令)"}), 400

        with sqlite3.connect(app.config['DATABASE']) as conn:
            c = conn.cursor()
            c.execute(
                "INSERT INTO connections (name, command, autostart, params) VALUES (?, ?, ?, ?)",
                (name, command, autostart, json.dumps(params) if params else None)
            )
            conn_id = c.lastrowid
            conn.commit()
            return jsonify({"id": conn_id, "message": "连接创建成功"}), 201
    except Exception as e:
        logger.error(f"创建连接失败: {str(e)}")
        return jsonify({"error": "创建连接时发生内部错误"}), 500

@app.route('/api/connections/<int:conn_id>', methods=['PUT'])
@login_required
def update_connection_api(conn_id):
    try:
        data = request.get_json()
        name = data.get('name')
        command = data.get('command')
        params = data.get('params')
        autostart = data.get('autostart')

        if not name:
            return jsonify({"error": "缺少必要参数 (名称)"}), 400

        # 如果是参数模式，则构建命令；否则确保命令不为空
        if params is not None:
            command = build_command_from_params(params)
        elif not command:
            return jsonify({"error": "缺少必要参数 (命令)"}), 400

        with sqlite3.connect(app.config['DATABASE']) as conn:
            c = conn.cursor()
            c.execute("SELECT id FROM connections WHERE id = ?", (conn_id,))
            if not c.fetchone():
                return jsonify({"error": "连接不存在"}), 404
            
            c.execute(
                "UPDATE connections SET name = ?, command = ?, autostart = ?, params = ? WHERE id = ?",
                (name, command, autostart, json.dumps(params) if params else None, conn_id)
            )
            conn.commit()
        
        return jsonify({"success": True, "message": "连接更新成功"})
    except Exception as e:
        logger.error(f"更新连接 {conn_id} 失败: {str(e)}")
        return jsonify({"error": "更新连接时发生内部错误"}), 500

@app.route('/api/connections/<int:conn_id>/start', methods=['POST'])
@login_required
def start_connection_api(conn_id):
    success, message = start_connection(conn_id)
    return jsonify({"success": success, "message": message})

@app.route('/api/connections/<int:conn_id>/stop', methods=['POST'])
@login_required
def stop_connection_api(conn_id):
    success, message = stop_connection(conn_id)
    return jsonify({"success": success, "message": message})

@app.route('/api/processes/<int:pid>/stop', methods=['POST'])
@login_required
def stop_manual_process(pid):
    try:
        logger.info(f"尝试停止手动进程，PID: {pid}")
        process = psutil.Process(pid)
        process.terminate()
        process.wait(timeout=10)
        logger.info(f"进程 {pid} 已成功终止。")
        return jsonify({"success": True, "message": f"进程 {pid} 已成功停止"})
    except psutil.NoSuchProcess:
        logger.warning(f"进程 {pid} 不存在。")
        return jsonify({"success": False, "message": "进程不存在"}), 404
    except psutil.AccessDenied:
        logger.error(f"尝试停止进程 {pid} 时权限不足。")
        return jsonify({"success": False, "message": "权限不足，无法停止进程"}), 403
    except Exception as e:
        logger.error(f"停止进程 {pid} 失败: {str(e)}")
        return jsonify({"success": False, "message": f"停止失败: {str(e)}"}), 500

@app.route('/api/connections/<int:conn_id>', methods=['DELETE'])
@login_required
def delete_connection(conn_id):
    try:
        with sqlite3.connect(app.config['DATABASE']) as conn:
            c = conn.cursor()
            
            c.execute("SELECT pid FROM connections WHERE id = ?", (conn_id,))
            result = c.fetchone()
            if result and result[0]:
                try:
                    process = psutil.Process(result[0])
                    process.terminate()
                except psutil.NoSuchProcess:
                    pass
            
            c.execute("DELETE FROM connections WHERE id = ?", (conn_id,))
            conn.commit()
            
            log_file = os.path.join(app.config['LOG_DIR'], f"natter_{conn_id}.log")
            if os.path.exists(log_file):
                try:
                    os.remove(log_file)
                except:
                    pass
                
            return jsonify({"success": True}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/connections/<int:conn_id>/log', methods=['GET'])
@login_required
def get_connection_log(conn_id):
    log_file = os.path.join(app.config['LOG_DIR'], f"natter_{conn_id}.log")
    if not os.path.exists(log_file):
        return jsonify({"error": "日志文件不存在"}), 404
    
    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            content = f.read()
        return jsonify({"log": content})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- 认证路由 ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    # 检查是否已设置密码，如果没有，则重定向到注册页面
    db_path = app.config['DATABASE']
    if not os.path.exists(db_path):
        init_db()

    with sqlite3.connect(db_path) as conn:
        c = conn.cursor()
        c.execute("SELECT value FROM settings WHERE key = 'password_hash'")
        password_hash_row = c.fetchone()

    if not password_hash_row:
        return redirect(url_for('register'))

    if request.method == 'POST':
        password = request.form.get('password')
        
        # 从数据库获取密码哈希
        with sqlite3.connect(db_path) as conn:
            c = conn.cursor()
            c.execute("SELECT value FROM settings WHERE key = 'password_hash'")
            password_hash = c.fetchone()[0]

        if check_password_hash(password_hash, password):
            session['logged_in'] = True
            logger.info(f"用户 {request.remote_addr} 登录成功")
            # 登录成功后，重置该IP的失败尝试次数
            login_attempts.pop(request.remote_addr, None)
            return jsonify({"success": True})
        else:
            # 登录失败处理
            ip = request.remote_addr
            if ip not in login_attempts:
                login_attempts[ip] = {'count': 0, 'ban_until': 0, 'ban_level': 0}
            
            # 检查是否仍在封禁期
            if time.time() < login_attempts[ip]['ban_until']:
                remaining = int(login_attempts[ip]['ban_until'] - time.time())
                return jsonify({"success": False, "message": f"IP因多次失败尝试已被封禁，请在 {remaining} 秒后重试。"}), 403

            login_attempts[ip]['count'] += 1
            logger.warning(f"用户 {ip} 登录失败，尝试次数: {login_attempts[ip]['count']}")

            if login_attempts[ip]['count'] >= 5:
                ban_level = login_attempts[ip]['ban_level']
                if ban_level < len(ban_durations):
                    duration = ban_durations[ban_level]
                    login_attempts[ip]['ban_until'] = time.time() + duration
                    login_attempts[ip]['ban_level'] += 1
                    login_attempts[ip]['count'] = 0 # 重置计数器
                    logger.warning(f"IP {ip} 已被封禁 {duration} 秒")
                    return jsonify({"success": False, "message": f"密码错误次数过多，IP已被封禁 {duration} 秒。"}), 403
                else: # 达到最大封禁级别
                    duration = ban_durations[-1]
                    login_attempts[ip]['ban_until'] = time.time() + duration
                    logger.warning(f"IP {ip} 已达到最大封禁级别，继续封禁 {duration} 秒")
                    return jsonify({"success": False, "message": f"密码错误次数过多，IP已被封禁 {duration} 秒。"}), 403

            return jsonify({"success": False, "message": "密码错误"}), 401

    if 'logged_in' in session:
        return redirect(url_for('index'))
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    # 检查是否已存在密码
    with sqlite3.connect(app.config['DATABASE']) as conn:
        c = conn.cursor()
        c.execute("SELECT value FROM settings WHERE key = 'password_hash'")
        if c.fetchone() is not None:
            return redirect(url_for('login')) # 如果密码已存在，则重定向到登录

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not password or not confirm_password:
            flash('密码不能为空', 'danger')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('两次输入的密码不一致', 'danger')
            return redirect(url_for('register'))

        password_hash = generate_password_hash(password)
        with sqlite3.connect(app.config['DATABASE']) as conn:
            c = conn.cursor()
            c.execute("INSERT INTO settings (key, value) VALUES (?, ?)", ('password_hash', password_hash))
            conn.commit()
        
        session['logged_in'] = True
        logger.info("初始密码设置成功，用户已自动登录")
        return redirect(url_for('index'))

    return render_template('register.html')


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/api/change-password', methods=['POST'])
@login_required
def change_password():
    data = request.get_json()
    old_password = data.get('old_password')
    new_password = data.get('new_password')

    if not old_password or not new_password:
        return jsonify({"success": False, "message": "必须提供旧密码和新密码。"}), 400

    db_path = app.config['DATABASE']
    try:
        with sqlite3.connect(db_path) as conn:
            c = conn.cursor()
            c.execute("SELECT value FROM settings WHERE key = 'password_hash'")
            password_hash_row = c.fetchone()

            if password_hash_row and check_password_hash(password_hash_row[0], old_password):
                new_password_hash = generate_password_hash(new_password)
                c.execute("UPDATE settings SET value = ? WHERE key = 'password_hash'", (new_password_hash,))
                conn.commit()
                logger.info(f"用户 {request.remote_addr} 成功修改密码")
                return jsonify({"success": True, "message": "密码修改成功"})
            else:
                logger.warning(f"用户 {request.remote_addr} 尝试修改密码失败：旧密码错误")
                return jsonify({"success": False, "message": "旧密码错误"}), 401
    except Exception as e:
        logger.error(f"修改密码时发生内部错误: {e}")
        return jsonify({"success": False, "message": f"内部错误: {str(e)}"}), 500


# --- 前端页面 ---

@app.route('/')
@login_required
def index():
    logger.info("渲染 index.html")
    return render_template('index.html')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')

# 主入口
if __name__ == '__main__':
    init_db()
    autostart_connections()
    
    try:
        logger.info("启动 Natter Web Admin 服务")
        # 切换到 127.0.0.1 并启用调试模式，以帮助诊断启动问题
        app.run(host='0.0.0.0', port=5000, debug=True)
    except Exception as e:
        logger.error(f"服务启动失败: {str(e)}")
        sys.exit(1)