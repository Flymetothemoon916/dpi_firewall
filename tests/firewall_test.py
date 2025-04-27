import socket
import threading
import time
import logging
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class FirewallTester:
    def __init__(self, target_ip="127.0.0.1"):
        self.target_ip = target_ip
        self.results = []
        
    def test_tcp_connection(self, port, should_block=False):
        """测试TCP连接"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((self.target_ip, port))
            sock.close()
            
            blocked = result != 0
            success = blocked == should_block
            
            self.results.append({
                'type': 'TCP',
                'port': port,
                'expected': 'blocked' if should_block else 'allowed',
                'actual': 'blocked' if blocked else 'allowed',
                'success': success
            })
            
            logger.info(f"TCP测试 - 端口 {port}: {'成功' if success else '失败'}")
            return success
        except Exception as e:
            logger.error(f"TCP测试错误: {str(e)}")
            return False
            
    def test_udp_packet(self, port, should_block=False):
        """测试UDP数据包"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.sendto(b'test', (self.target_ip, port))
            try:
                data, addr = sock.recvfrom(1024)
                blocked = False
            except socket.timeout:
                blocked = True
            sock.close()
            
            success = blocked == should_block
            
            self.results.append({
                'type': 'UDP',
                'port': port,
                'expected': 'blocked' if should_block else 'allowed',
                'actual': 'blocked' if blocked else 'allowed',
                'success': success
            })
            
            logger.info(f"UDP测试 - 端口 {port}: {'成功' if success else '失败'}")
            return success
        except Exception as e:
            logger.error(f"UDP测试错误: {str(e)}")
            return False
            
    def test_icmp_packet(self, should_block=False):
        """测试ICMP数据包"""
        try:
            response = sr1(IP(dst=self.target_ip)/ICMP(), timeout=2, verbose=0)
            blocked = response is None
            
            success = blocked == should_block
            
            self.results.append({
                'type': 'ICMP',
                'expected': 'blocked' if should_block else 'allowed',
                'actual': 'blocked' if blocked else 'allowed',
                'success': success
            })
            
            logger.info(f"ICMP测试: {'成功' if success else '失败'}")
            return success
        except Exception as e:
            logger.error(f"ICMP测试错误: {str(e)}")
            return False
            
    def print_results(self):
        """打印测试结果"""
        logger.info("\n测试结果汇总:")
        logger.info("-" * 50)
        for result in self.results:
            status = "✓" if result['success'] else "✗"
            logger.info(f"{status} {result['type']}测试 - 预期: {result['expected']}, 实际: {result['actual']}")
        logger.info("-" * 50)
        
        total = len(self.results)
        success = sum(1 for r in self.results if r['success'])
        logger.info(f"总测试数: {total}, 成功: {success}, 失败: {total - success}")

def main():
    # 创建测试器实例
    tester = FirewallTester()
    
    # 测试常用端口
    # 这些端口应该被阻止
    blocked_ports = [22, 23, 445, 3389]  # SSH, Telnet, SMB, RDP
    
    # 这些端口应该允许
    allowed_ports = [80, 443, 53]  # HTTP, HTTPS, DNS
    
    # 测试TCP连接
    for port in blocked_ports:
        tester.test_tcp_connection(port, should_block=True)
        
    for port in allowed_ports:
        tester.test_tcp_connection(port, should_block=False)
        
    # 测试UDP数据包
    for port in blocked_ports:
        tester.test_udp_packet(port, should_block=True)
        
    for port in allowed_ports:
        tester.test_udp_packet(port, should_block=False)
        
    # 测试ICMP
    tester.test_icmp_packet(should_block=False)
    
    # 打印结果
    tester.print_results()

if __name__ == "__main__":
    main() 