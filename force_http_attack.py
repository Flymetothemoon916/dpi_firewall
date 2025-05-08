#!/usr/bin/env python
import os
import django
import sys
import time
import argparse
from scapy.all import IP, TCP, Raw

# 设置Django环境
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'DPI_Firewall.settings')
django.setup()

from packet_analyzer.dpi.firewall_engine import FirewallEngine
from packet_analyzer.dpi.packet_analyzer import DPIPacketAnalyzer
from firewall_rules.models import Rule
from django.utils import timezone
from packet_analyzer.models import PacketLog, Protocol
from dashboard.models import AlertLog

def create_attack_packet(attack_type="sql_injection"):
    """
    创建带有不同类型攻击载荷的数据包
    
    Args:
        attack_type: 攻击类型 (sql_injection, xss, command_injection, path_traversal)
        
    Returns:
        Scapy数据包
    """
    # 各种攻击类型的载荷
    payloads = {
        "sql_injection": {
            "payload": "' OR '1'='1",
            "desc": "SQL注入测试 - OR条件",
            "params": {
                "username": "admin' OR '1'='1",
                "password": "pass' OR '1'='1",
                "query": "' OR '1'='1"
            }
        },
        "xss": {
            "payload": "<script>alert('XSS')</script>",
            "desc": "XSS攻击测试 - 脚本标签",
            "params": {
                "comment": "<script>alert('XSS')</script>",
                "name": "<img src=x onerror=alert('XSS')>",
                "message": "test<script>alert(document.cookie)</script>"
            }
        },
        "command_injection": {
            "payload": "; cat /etc/passwd",
            "desc": "命令注入测试 - 分号分隔",
            "params": {
                "command": "ls; cat /etc/passwd",
                "exec": "ping 127.0.0.1 | dir",
                "run": "echo hello; rm -rf /"
            }
        },
        "path_traversal": {
            "payload": "../../../etc/passwd",
            "desc": "路径遍历测试 - 点点斜杠",
            "params": {
                "file": "../../../etc/passwd",
                "path": "..\\..\\windows\\win.ini",
                "include": "/var/www/../../etc/shadow"
            }
        }
    }
    
    # 获取选定的攻击信息
    attack_info = payloads.get(attack_type, payloads["sql_injection"])
    
    # 构建POST数据
    post_data = "&".join([f"{k}={v}" for k, v in attack_info["params"].items()])
    
    # 构建HTTP请求
    http_request = (
        f"POST /attack_test HTTP/1.1\r\n"
        f"Host: localhost:8000\r\n"
        f"User-Agent: DPI-Firewall-Tester\r\n"
        f"X-Attack-Type: {attack_type}\r\n"
        f"X-Test-Payload-Description: {attack_info['desc']}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(post_data)}\r\n"
        f"\r\n"
        f"{post_data}"
    )
    
    # 创建Scapy数据包
    packet = (
        IP(src="127.0.0.1", dst="127.0.0.1") /
        TCP(sport=12345, dport=8000) /
        Raw(load=http_request)
    )
    
    return packet, attack_info

def create_alert_from_attack(attack_type, rule, attack_info=None):
    """
    根据攻击类型和规则创建告警日志
    
    Args:
        attack_type: 攻击类型
        rule: 匹配的规则
        attack_info: 额外的攻击信息
    """
    # 为不同攻击类型设置不同告警级别和信息
    alert_level_map = {
        "sql_injection": "warning",
        "xss": "warning",
        "command_injection": "critical", 
        "path_traversal": "warning"
    }
    
    alert_level = alert_level_map.get(attack_type, "warning")
    attack_desc = attack_info["desc"] if attack_info else f"测试{attack_type}攻击"
    
    # 创建告警记录
    alert = AlertLog.objects.create(
        title=f"测试攻击检测: {attack_type}",
        description=f"{attack_desc}\n\n触发规则: {rule.name}\n规则描述: {rule.description}",
        level=alert_level,
        source_ip="127.0.0.1"
    )
    
    return alert

def inject_attack_packets(attack_types=None, force_block=True):
    """
    直接向防火墙注入攻击数据包
    
    Args:
        attack_types: 要测试的攻击类型列表
        force_block: 是否强制标记为阻止
    """
    if attack_types is None:
        attack_types = ["sql_injection", "xss", "command_injection", "path_traversal"]
    
    print(f"直接向防火墙注入攻击数据包: {', '.join(attack_types)}")
    
    # 启动防火墙引擎
    engine = FirewallEngine()
    if not engine.is_running():
        engine.start()
        print("防火墙引擎已启动")
    
    # 创建数据包分析器
    analyzer = DPIPacketAnalyzer()
    
    # 获取攻击规则
    rules = {}
    for attack_type in attack_types:
        rule_name_map = {
            "sql_injection": "SQL注入攻击检测",
            "xss": "XSS攻击检测",
            "command_injection": "命令注入攻击检测",
            "path_traversal": "路径遍历攻击检测"
        }
        
        rule_name = rule_name_map.get(attack_type)
        if not rule_name:
            continue
            
        try:
            rule = Rule.objects.get(name=rule_name)
            rules[attack_type] = rule
            print(f"找到规则: {rule.name}, 优先级: {rule.priority}, 状态: {'启用' if rule.is_enabled else '禁用'}")
            
            # 确保规则已启用
            if not rule.is_enabled:
                rule.is_enabled = True
                rule.save()
                print(f"已启用规则: {rule.name}")
        except Rule.DoesNotExist:
            print(f"未找到规则: {rule_name}")
    
    # 注入每种攻击类型的数据包
    for attack_type in attack_types:
        packet, attack_info = create_attack_packet(attack_type)
        
        print(f"\n注入 {attack_type} 攻击数据包")
        print(f"攻击描述: {attack_info['desc']}")
        print(f"数据包内容预览: {packet[Raw].load.decode('utf-8', 'ignore')[:100]}...")
        
        # 使用指定规则强制阻止数据包
        if force_block and attack_type in rules:
            # 创建告警日志
            alert = create_alert_from_attack(attack_type, rules[attack_type], attack_info)
            print(f"已创建告警记录，ID: {alert.id}, 级别: {alert.level}")
            
            analyzer.process_packet(
                packet, 
                status='blocked', 
                rule=rules[attack_type], 
                block_reason=f"{attack_info['desc']} - 强制阻止"
            )
            print(f"使用强制阻止方式注入 {attack_type} 数据包，规则: {rules[attack_type].name}")
        else:
            # 使用正常匹配过程处理数据包
            analyzer.process_packet(packet)
            print(f"使用常规处理流程注入 {attack_type} 数据包")
        
        # 暂停一下，以便数据库操作完成
        time.sleep(0.5)
    
    print("\n数据包注入完成，请检查数据包捕获页面和告警日志页面查看结果！")
    print("如需查看捕获日志，请运行: python test_firewall_rules.py --check-logs")

def directly_insert_packet_logs():
    """直接在数据库中创建数据包日志记录"""
    print("直接在数据库中创建攻击数据包日志记录...")
    
    # 获取或创建HTTP协议
    protocol, _ = Protocol.objects.get_or_create(
        name="HTTP",
        defaults={"description": "HTTP协议"}
    )
    
    # 获取SQL注入规则
    try:
        sql_rule = Rule.objects.get(name='SQL注入攻击检测')
    except Rule.DoesNotExist:
        print("未找到SQL注入规则，请运行 test_firewall_rules.py --setup 创建规则")
        return
    
    # 创建攻击载荷
    sql_payload = "' OR '1'='1"
    raw_request = (
        f"POST /login HTTP/1.1\r\n"
        f"Host: localhost:8000\r\n"
        f"User-Agent: DPI-Firewall-Tester\r\n"
        f"X-Attack-Type: sql_injection\r\n"
        f"X-Test-Payload-Description: 基本 ' OR '1'='1\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"\r\n"
        f"username=admin{sql_payload}&password=pass{sql_payload}&query={sql_payload}"
    )
    
    # 直接创建数据包日志
    packet_log = PacketLog.objects.create(
        timestamp=timezone.now(),
        source_ip="127.0.0.1",
        source_port=12345,
        destination_ip="127.0.0.1",
        destination_port=8000,
        protocol=protocol,
        payload=raw_request,
        raw_request=raw_request,
        packet_size=len(raw_request),
        direction="inbound",
        status="blocked",
        matched_rule=sql_rule,
        attack_type="sql_injection", 
        processing_time=0.0,
        is_important=True,
        is_read=False,
        block_reason="SQL注入攻击 - 数据库直接创建",
        notes=f"攻击载荷: {sql_payload}"
    )
    
    # 创建告警记录
    alert = AlertLog.objects.create(
        title="测试攻击检测: SQL注入",
        description=f"SQL注入测试 - 基本 ' OR '1'='1\n\n触发规则: {sql_rule.name}\n攻击载荷: {sql_payload}",
        level="warning",
        source_ip="127.0.0.1"
    )
    
    print(f"成功创建数据包日志，ID: {packet_log.id}")
    print(f"成功创建告警记录，ID: {alert.id}")
    print("请检查数据包捕获页面和告警日志页面查看结果！")

def main():
    parser = argparse.ArgumentParser(description="DPI防火墙HTTP攻击测试工具")
    parser.add_argument("--attacks", nargs="+", choices=["sql_injection", "xss", "command_injection", "path_traversal", "all"],
                        default=["all"], help="要测试的攻击类型")
    parser.add_argument("--db-insert", action="store_true", help="直接在数据库中创建数据包日志记录")
    parser.add_argument("--no-force", action="store_true", help="不强制阻止，使用常规匹配过程")
    
    args = parser.parse_args()
    
    # 处理攻击类型
    if "all" in args.attacks:
        attack_types = ["sql_injection", "xss", "command_injection", "path_traversal"]
    else:
        attack_types = args.attacks
    
    # 是否直接在数据库中插入
    if args.db_insert:
        directly_insert_packet_logs()
    else:
        inject_attack_packets(attack_types, force_block=not args.no_force)

if __name__ == "__main__":
    main() 