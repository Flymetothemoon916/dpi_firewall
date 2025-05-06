#!/usr/bin/env python
# coding: utf-8
import sys
import time
import random
import argparse
from scapy.all import IP, TCP, UDP, Raw, send, sr1, conf
from colorama import init, Fore, Style

# 初始化colorama
init()

def print_banner():
    banner = """
    ╔═══════════════════════════════════════════════╗
    ║                                               ║
    ║  网络层攻击测试工具 - 真实源IP伪造            ║
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

def construct_http_payload(attack_type, payload):
    """构造HTTP负载"""
    if attack_type == "sql_injection":
        # SQL注入攻击的HTTP请求
        http_request = f"""GET /accounts/login/?username=admin{payload}&password=test HTTP/1.1
Host: 127.0.0.1:8000
User-Agent: WAFTest/1.0
Accept: text/html
X-Attack-Type: sql_injection
X-Test: true
Connection: close

"""
    elif attack_type == "xss":
        # XSS攻击的HTTP请求
        http_request = f"""GET /search?q={payload}&test=1 HTTP/1.1
Host: 127.0.0.1:8000
User-Agent: WAFTest/1.0
Accept: text/html
X-Attack-Type: xss
X-Test: true
Connection: close

"""
    elif attack_type == "command_injection":
        # 命令注入攻击的HTTP请求
        http_request = f"""GET /api/system?cmd=ping{payload} HTTP/1.1
Host: 127.0.0.1:8000
User-Agent: WAFTest/1.0
Accept: text/html
X-Attack-Type: command_injection
X-Test: true
Connection: close

"""
    elif attack_type == "path_traversal":
        # 路径遍历攻击的HTTP请求
        http_request = f"""GET /file?path={payload} HTTP/1.1
Host: 127.0.0.1:8000
User-Agent: WAFTest/1.0
Accept: text/html
X-Attack-Type: path_traversal
X-Test: true
Connection: close

"""
    else:
        # 默认攻击的HTTP请求
        http_request = f"""GET /?payload={payload} HTTP/1.1
Host: 127.0.0.1:8000
User-Agent: WAFTest/1.0
Accept: text/html
X-Attack-Type: generic
X-Test: true
Connection: close

"""
    
    return http_request

def send_http_packet_with_spoofed_ip(target_ip, target_port, spoofed_ip, attack_type, payload, verbose=False):
    """
    使用伪造源IP发送HTTP数据包
    
    Args:
        target_ip: 目标服务器IP
        target_port: 目标服务器端口
        spoofed_ip: 伪造的源IP
        attack_type: 攻击类型
        payload: 攻击负载
        verbose: 是否详细输出
    """
    # 构造HTTP请求
    http_payload = construct_http_payload(attack_type, payload)
    
    # 随机源端口
    src_port = random.randint(10000, 65000)
    
    # 构造IP和TCP层
    ip_layer = IP(src=spoofed_ip, dst=target_ip)
    tcp_layer = TCP(sport=src_port, dport=target_port, flags="S")  # SYN标志
    
    if verbose:
        print_info(f"攻击类型: {attack_type}")
        print_info(f"伪造源IP: {spoofed_ip}")
        print_info(f"目标: {target_ip}:{target_port}")
        print_info(f"负载: {payload}")
        print_info("HTTP请求:")
        print(http_payload)
    
    # 第一步：尝试发送SYN包建立连接
    try:
        print_info("正在发送TCP SYN包...")
        packet = ip_layer/tcp_layer
        
        # 发送SYN包并等待响应
        # 注意：这一步无法在真实网络中成功，因为三次握手需要真实IP
        # 这里主要是让防火墙捕获到我们的伪造包
        send(packet, verbose=0)
        
        # 构造带有攻击负载的最终数据包
        tcp_data = TCP(sport=src_port, dport=target_port, flags="PA")  # PSH-ACK标志
        data = Raw(load=http_payload.encode())
        final_packet = ip_layer/tcp_data/data
        
        # 发送最终数据包
        print_info("正在发送包含攻击负载的数据包...")
        send(final_packet, verbose=0)
        
        print_success(f"已发送伪造源IP为 {spoofed_ip} 的 {attack_type} 攻击数据包")
        return True
        
    except Exception as e:
        print_error(f"发送数据包失败: {str(e)}")
        return False

def execute_sql_injection_attack(target_ip, target_port, spoofed_ip, payload=None, verbose=False):
    """执行SQL注入攻击"""
    print_info("开始SQL注入攻击测试...")
    
    # SQL注入测试负载
    sql_payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR 1=1 --",
        "' UNION SELECT username, password FROM users --"
    ]
    
    # 如果指定了自定义负载，则只使用它
    if payload:
        sql_payloads = [payload]
    
    # 发送所有测试负载
    success_count = 0
    for payload in sql_payloads:
        if send_http_packet_with_spoofed_ip(target_ip, target_port, spoofed_ip, "sql_injection", payload, verbose):
            success_count += 1
        time.sleep(1)  # 延迟1秒
    
    print_success(f"SQL注入测试完成: 发送了 {success_count} 个伪造IP数据包")
    return success_count

def execute_xss_attack(target_ip, target_port, spoofed_ip, payload=None, verbose=False):
    """执行XSS攻击"""
    print_info("开始XSS攻击测试...")
    
    # XSS测试负载
    xss_payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>"
    ]
    
    # 如果指定了自定义负载，则只使用它
    if payload:
        xss_payloads = [payload]
    
    # 发送所有测试负载
    success_count = 0
    for payload in xss_payloads:
        if send_http_packet_with_spoofed_ip(target_ip, target_port, spoofed_ip, "xss", payload, verbose):
            success_count += 1
        time.sleep(1)  # 延迟1秒
    
    print_success(f"XSS测试完成: 发送了 {success_count} 个伪造IP数据包")
    return success_count

def execute_command_injection_attack(target_ip, target_port, spoofed_ip, payload=None, verbose=False):
    """执行命令注入攻击"""
    print_info("开始命令注入攻击测试...")
    
    # 命令注入测试负载
    cmd_payloads = [
        "; cat /etc/passwd",
        "| ls -la",
        "& cat /etc/passwd",
        "; ping -c 4 8.8.8.8"
    ]
    
    # 如果指定了自定义负载，则只使用它
    if payload:
        cmd_payloads = [payload]
    
    # 发送所有测试负载
    success_count = 0
    for payload in cmd_payloads:
        if send_http_packet_with_spoofed_ip(target_ip, target_port, spoofed_ip, "command_injection", payload, verbose):
            success_count += 1
        time.sleep(1)  # 延迟1秒
    
    print_success(f"命令注入测试完成: 发送了 {success_count} 个伪造IP数据包")
    return success_count

def execute_path_traversal_attack(target_ip, target_port, spoofed_ip, payload=None, verbose=False):
    """执行路径遍历攻击"""
    print_info("开始路径遍历攻击测试...")
    
    # 路径遍历测试负载
    path_payloads = [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "..\\..\\..\\Windows\\system.ini",
        "/etc/passwd"
    ]
    
    # 如果指定了自定义负载，则只使用它
    if payload:
        path_payloads = [payload]
    
    # 发送所有测试负载
    success_count = 0
    for payload in path_payloads:
        if send_http_packet_with_spoofed_ip(target_ip, target_port, spoofed_ip, "path_traversal", payload, verbose):
            success_count += 1
        time.sleep(1)  # 延迟1秒
    
    print_success(f"路径遍历测试完成: 发送了 {success_count} 个伪造IP数据包")
    return success_count

def get_random_ip():
    """生成随机IP地址"""
    return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

def main():
    parser = argparse.ArgumentParser(description="网络层攻击测试工具 - 真实源IP伪造")
    parser.add_argument("--target", "-t", default="127.0.0.1", help="目标服务器IP，默认127.0.0.1")
    parser.add_argument("--port", "-p", type=int, default=8000, help="目标服务器端口，默认8000")
    parser.add_argument("--spoof-ip", "-s", help="伪造的源IP地址，默认随机生成")
    parser.add_argument("--attack-type", "-a", choices=["all", "sql", "xss", "cmd", "path"], default="all", 
                        help="攻击类型: sql=SQL注入, xss=跨站脚本, cmd=命令注入, path=路径遍历, all=所有攻击")
    parser.add_argument("--payload", help="自定义攻击负载")
    parser.add_argument("--verbose", "-v", action="store_true", help="显示详细输出")
    parser.add_argument("--delay", "-d", type=float, default=1.0, help="攻击之间的延迟时间(秒)")
    
    args = parser.parse_args()
    
    print_banner()
    print_info(f"目标: {args.target}:{args.port}")
    print_info(f"攻击类型: {args.attack_type}")
    print_info(f"详细模式: {'启用' if args.verbose else '禁用'}")
    
    # 设置伪造IP
    spoofed_ip = args.spoof_ip if args.spoof_ip else get_random_ip()
    print_info(f"伪造源IP: {spoofed_ip}")
    
    # 设置Scapy不要检查返回包的源IP (避免在本地测试环境出现问题)
    conf.checkIPaddr = False
    
    total_packets = 0
    
    try:
        if args.attack_type in ["all", "sql"]:
            print_warning(f"即将开始SQL注入测试，延迟 {args.delay} 秒...")
            time.sleep(args.delay)
            total_packets += execute_sql_injection_attack(args.target, args.port, spoofed_ip, args.payload, args.verbose)
        
        if args.attack_type in ["all", "xss"]:
            print_warning(f"即将开始XSS测试，延迟 {args.delay} 秒...")
            time.sleep(args.delay)
            total_packets += execute_xss_attack(args.target, args.port, spoofed_ip, args.payload, args.verbose)
        
        if args.attack_type in ["all", "cmd"]:
            print_warning(f"即将开始命令注入测试，延迟 {args.delay} 秒...")
            time.sleep(args.delay)
            total_packets += execute_command_injection_attack(args.target, args.port, spoofed_ip, args.payload, args.verbose)
        
        if args.attack_type in ["all", "path"]:
            print_warning(f"即将开始路径遍历测试，延迟 {args.delay} 秒...")
            time.sleep(args.delay)
            total_packets += execute_path_traversal_attack(args.target, args.port, spoofed_ip, args.payload, args.verbose)
        
        print("\n" + "="*50)
        print_info("测试统计:")
        print(f"总发送数据包: {total_packets}")
        print("="*50)
        
        print_success("所有测试完成！请检查防火墙日志以验证攻击是否被检测。")
        print_info(f"在防火墙日志中查找来源IP为 {spoofed_ip} 的记录")
        print_info(f"查看方法: 访问 http://{args.target}:{args.port}/packets/ 并在源IP搜索框中输入 {spoofed_ip}")
        
    except KeyboardInterrupt:
        print_warning("\n测试被用户中断")
        print_info("已完成部分测试，请查看防火墙日志")
    except Exception as e:
        print_error(f"测试过程中发生错误: {str(e)}")
        print_info("这可能是因为没有足够的权限发送原始数据包，请尝试使用管理员权限运行脚本")

if __name__ == "__main__":
    # 检查是否以管理员权限运行
    try:
        if sys.platform.startswith('win'):
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print(Fore.RED + "警告: 此脚本需要管理员权限才能发送原始数据包。" + Style.RESET_ALL)
                print(Fore.YELLOW + "请右键点击PowerShell或命令提示符，选择'以管理员身份运行'，然后再次运行此脚本。" + Style.RESET_ALL)
                sys.exit(1)
    except:
        pass
    
    main() 