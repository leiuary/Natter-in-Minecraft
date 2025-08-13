# 使用一个轻量级的 Python 官方镜像作为基础
FROM python:3.9-slim

# 设置工作目录，之后的所有命令都会在这个目录下执行
WORKDIR /app

# 复制依赖配置文件到工作目录
COPY requirements.txt .

# 安装应用所需的依赖
# --no-cache-dir 选项可以减小镜像体积
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用的所有文件到工作目录
# 第一个 . 代表当前目录（natter-web-admin），第二个 . 代表容器内的工作目录（/app）
COPY . .

# 声明容器在运行时监听的端口
EXPOSE 5000

# 容器启动时要执行的命令
# 这会启动您的 Flask 应用
CMD ["python", "app.py"]
