#!/usr/bin/env python3
import os
import sys
import json
import subprocess
protocol, private_ip, private_port, public_ip, public_port = sys.argv[1:6]


# 阿里云AccessKey信息
access_key_id = '填写AccessKey ID'
access_key_secret = '填写AccessKey Secret'

# 阿里云域名信息
domain_name = 'example.com'
rr = '_minecraft._tcp.mc'  # 记录名称
value = f'0 0 {public_port} ip.mc.example.com'  # 记录值


# 以下不要修改
type = 'SRV'  # 解析类型
record_id = '您的记录ID'  # 需要更新的记录ID

# 将打包的依赖项目录添加到 Python 路径
script_dir = os.path.dirname(os.path.abspath(__file__))
lib_dir = os.path.join(script_dir, 'lib')
sys.path.insert(0, lib_dir)

# 自动检测并安装 pip 与依赖
def _ensure_pip():
    try:
        import pip  # noqa
        return True
    except Exception:
        try:
            import ensurepip
            ensurepip.bootstrap()
            import pip  # noqa
            return True
        except Exception:
            return False

def _pip_install(target_dir, packages):
    os.makedirs(target_dir, exist_ok=True)
    if not _ensure_pip():
        print("pip 不可用，无法自动安装依赖。", file=sys.stderr)
        sys.exit(1)
    cmd = [sys.executable, '-m', 'pip', 'install', '--upgrade', '--no-input',
           '--timeout', '600', '-i', 'https://mirrors.aliyun.com/pypi/simple/']
    if target_dir:
        cmd.extend(['--target', target_dir])
    subprocess.check_call(cmd + list(packages))

def _ensure_deps():
    missing = []
    try:
        import aliyunsdkcore  # noqa
    except Exception:
        missing.append("aliyun-python-sdk-core")
    try:
        import aliyunsdkalidns  # noqa
    except Exception:
        missing.append("aliyun-python-sdk-alidns")
    if missing:
        _pip_install(lib_dir, missing)

# 确保依赖可用后再导入
_ensure_deps()
try:
    from aliyunsdkcore.client import AcsClient
    from aliyunsdkalidns.request.v20150109 import UpdateDomainRecordRequest
    from aliyunsdkalidns.request.v20150109 import DescribeDomainRecordsRequest
    from aliyunsdkalidns.request.v20150109 import AddDomainRecordRequest
except ImportError:
    _ensure_deps()
    from aliyunsdkcore.client import AcsClient
    from aliyunsdkalidns.request.v20150109 import UpdateDomainRecordRequest
    from aliyunsdkalidns.request.v20150109 import DescribeDomainRecordsRequest
    from aliyunsdkalidns.request.v20150109 import AddDomainRecordRequest


# 初始化阿里云客户端
client = AcsClient(access_key_id, access_key_secret, 'cn-hangzhou')

# 创建DDNS更新请求
request = UpdateDomainRecordRequest.UpdateDomainRecordRequest()
request.set_Type(type)
request.set_RR(rr)
request.set_Value(value)
request.set_RecordId(record_id)

# 创建查询域名解析记录的请求
test = DescribeDomainRecordsRequest.DescribeDomainRecordsRequest()
test.set_DomainName(domain_name)
test.set_KeyWord(rr)
test.set_SearchMode('EXACT')

# 执行查询域名解析记录
response = client.do_action_with_exception(test)
response_json = json.loads(response)

print(response_json)

# 检查记录是否存在
if response_json['TotalCount'] == 0:
    # 记录不存在，创建新记录
    print(f"记录 '{rr}.{domain_name}' 不存在，正在创建...")
    add_request = AddDomainRecordRequest.AddDomainRecordRequest()
    add_request.set_DomainName(domain_name)
    add_request.set_RR(rr)
    add_request.set_Type(type)
    add_request.set_Value(value)
    
    add_response = client.do_action_with_exception(add_request)
    print("创建成功:", add_response)
else:
    # 遍历返回的记录，查找精确匹配的记录
    record_found = False
    for record in response_json['DomainRecords']['Record']:
        if record['RR'] == rr and record['Type'] == type:
            record_found = True
            record_id = record['RecordId']
            current_value = record['Value']
            
            if current_value == value:
                print(f"记录 '{rr}.{domain_name}'(类型:{type}) 的解析值已经是 '{value}'，无需更新。")
            else:
                print(f"记录 '{rr}.{domain_name}'(类型:{type}) 已存在，正在更新解析值...")
                update_request = UpdateDomainRecordRequest.UpdateDomainRecordRequest()
                update_request.set_RecordId(record_id)
                update_request.set_RR(rr)
                update_request.set_Type(type)
                update_request.set_Value(value)
                
                update_response = client.do_action_with_exception(update_request)
                print("更新成功:", update_response)
            break  # 找到并处理后即可退出循环

    # 如果遍历完所有返回的记录后，没有找到精确匹配的记录
    if not record_found:
        print(f"未找到与 '{rr}.{domain_name}'(类型:{type}) 完全匹配的记录，正在创建新记录...")
        add_request = AddDomainRecordRequest.AddDomainRecordRequest()
        add_request.set_DomainName(domain_name)
        add_request.set_RR(rr)
        add_request.set_Type(type)
        add_request.set_Value(value)
        
        add_response = client.do_action_with_exception(add_request)
        print("创建成功:", add_response)