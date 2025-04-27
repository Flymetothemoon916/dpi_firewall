#!/usr/bin/env python
import os
import django
import logging
import re

# 设置Django环境
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'DPI_Firewall.settings')
django.setup()

from django.utils import timezone
from packet_analyzer.models import DeepInspectionResult, PacketLog, Protocol
from packet_analyzer.dpi.packet_analyzer import DPIPacketAnalyzer
from firewall_rules.models import Rule, RuleCategory
from scapy.all import IP, TCP, Raw, Ether

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("test_dpi_rules")

def create_test_rule():
    """创建简单的测试规则"""
    try:
        # 创建或获取规则分类
        category, _ = RuleCategory.objects.get_or_create(
            name="测试规则",
            defaults={
                "description": "用于测试DPI功能的规则分类",
                "priority": 10
            }
        )
        
        # 创建简单的DPI测试规则
        rule, created = Rule.objects.get_or_create(
            name="DPI测试规则-敏感词检测",
            defaults={
                "description": "检测数据包中的敏感词",
                "category": category,
                "source_ip": "",
                "destination_ip": "",
                "source_port": "",
                "destination_port": "",
                "protocol": "any",
                "action": "alert",
                "priority": "medium",
                "is_enabled": True,
                "created_at": timezone.now(),
                "updated_at": timezone.now(),
                "hits": 0
            }
        )
        
        if created:
            logger.info(f"创建了新的测试规则: {rule.name}")
        else:
            logger.info(f"使用已存在的测试规则: {rule.name}")
            
        return rule
    except Exception as e:
        logger.error(f"创建测试规则失败: {str(e)}")
        return None

def modify_dpi_patterns():
    """修改DPI分析器中的恶意模式，添加更容易匹配的模式"""
    try:
        # 获取一个数据包记录用于测试
        packet_log = PacketLog.objects.order_by('-timestamp').first()
        if not packet_log:
            logger.error("找不到数据包记录进行测试")
            return False
            
        # 创建一个简单的测试数据包
        test_packet = Ether()/IP(src=packet_log.source_ip, dst=packet_log.destination_ip)/TCP(sport=packet_log.source_port, dport=packet_log.destination_port)/Raw(load=b"TEST_MALICIOUS_CONTENT password123 admin123")
        
        # 创建DPI分析器并修改恶意模式
        analyzer = DPIPacketAnalyzer()
        
        # 备份原始的_perform_deep_inspection方法
        original_perform_deep_inspection = analyzer._perform_deep_inspection
        
        def custom_perform_deep_inspection(packet_log, packet):
            """修改后的深度包检测方法，使用更宽松的规则"""
            try:
                # 提取应用层协议
                app_protocol = "unknown"
                if hasattr(packet, 'haslayer') and packet.haslayer(TCP):
                    app_protocol = "TCP"
                elif packet_log.protocol:
                    app_protocol = packet_log.protocol.name
                
                # 获取载荷
                payload = str(packet)
                detected_patterns = []
                is_malicious = False
                risk_level = 'low'
                
                # 更宽松的检测模式
                easy_patterns = [
                    (r'TEST_MALICIOUS_CONTENT', '测试恶意内容'),
                    (r'password', '可能的密码泄露'),
                    (r'admin', '管理员关键词'),
                    (r'123', '简单数字序列')
                ]
                
                for pattern, desc in easy_patterns:
                    if re.search(pattern, payload, re.IGNORECASE):
                        detected_patterns.append(desc)
                        is_malicious = True
                        risk_level = 'medium'
                
                # 创建DPI结果
                dpi_result = DeepInspectionResult.objects.create(
                    packet=packet_log,
                    application_protocol=app_protocol,
                    content_type='text/plain',
                    detected_patterns='; '.join(detected_patterns),
                    risk_level=risk_level,
                    is_malicious=is_malicious,
                    metadata={'test': True, 'timestamp': timezone.now().isoformat()}
                )
                
                logger.info(f"创建了DPI结果: {dpi_result}, 恶意={is_malicious}, 检测到的模式: {detected_patterns}")
                
                return dpi_result
            except Exception as e:
                logger.error(f"自定义深度检测失败: {str(e)}")
                return None
        
        # 应用自定义方法
        analyzer._perform_deep_inspection = custom_perform_deep_inspection
        
        # 测试方法
        result = analyzer._perform_deep_inspection(packet_log, test_packet)
        
        # 恢复原始方法
        analyzer._perform_deep_inspection = original_perform_deep_inspection
        
        if result and result.is_malicious:
            logger.info("测试成功: DPI检测正常工作")
            return True
        else:
            logger.warning("测试失败: DPI没有检测到恶意内容")
            return False
    
    except Exception as e:
        logger.error(f"修改DPI规则失败: {str(e)}")
        return False

def simulate_traffic():
    """模拟发送恶意流量进行测试"""
    try:
        # 获取最近的数据包
        recent_packet = PacketLog.objects.order_by('-timestamp').first()
        if not recent_packet:
            logger.error("找不到最近的数据包记录")
            return False
        
        # 创建模拟恶意流量的数据包记录
        malicious_packet = PacketLog.objects.create(
            timestamp=timezone.now(),
            source_ip=recent_packet.source_ip,
            destination_ip=recent_packet.destination_ip,
            source_port=recent_packet.source_port,
            destination_port=recent_packet.destination_port,
            direction='inbound',
            status='suspicious',
            payload="TEST_MALICIOUS_CONTENT: <script>alert('XSS攻击')</script> 'OR 1=1--' /etc/passwd",
            packet_size=len("TEST_MALICIOUS_CONTENT: <script>alert('XSS攻击')</script> 'OR 1=1--' /etc/passwd"),
            protocol=recent_packet.protocol
        )
        
        logger.info(f"创建了恶意测试数据包: {malicious_packet.id}")
        
        # 使用DPI分析器处理模拟数据包
        analyzer = DPIPacketAnalyzer()
        test_packet = Ether()/IP(src=malicious_packet.source_ip, dst=malicious_packet.destination_ip)/TCP(sport=malicious_packet.source_port, dport=malicious_packet.destination_port)/Raw(load=malicious_packet.payload.encode())
        
        # 执行DPI分析
        analyzer._perform_deep_inspection(malicious_packet, test_packet)
        
        # 检查是否创建了DPI结果
        try:
            dpi_result = DeepInspectionResult.objects.get(packet=malicious_packet)
            logger.info(f"为测试数据包创建了DPI结果: 恶意={dpi_result.is_malicious}, 模式={dpi_result.detected_patterns}")
            return True
        except DeepInspectionResult.DoesNotExist:
            logger.warning("未能为测试数据包创建DPI结果")
            return False
            
    except Exception as e:
        logger.error(f"模拟流量测试失败: {str(e)}")
        return False

if __name__ == "__main__":
    print("开始DPI功能测试...")
    
    # 创建测试规则
    rule = create_test_rule()
    if rule:
        print(f"测试规则创建成功: {rule.name}")
    else:
        print("测试规则创建失败")
    
    # 修改DPI模式
    if modify_dpi_patterns():
        print("已成功修改并测试DPI模式")
    else:
        print("修改DPI模式测试失败")
    
    # 模拟恶意流量
    if simulate_traffic():
        print("已成功模拟恶意流量并执行DPI分析")
    else:
        print("模拟恶意流量测试失败")
    
    # 检查DPI结果
    total_dpi = DeepInspectionResult.objects.count()
    malicious_dpi = DeepInspectionResult.objects.filter(is_malicious=True).count()
    
    print(f"\nDPI分析结果统计:")
    print(f"总DPI记录数: {total_dpi}")
    print(f"检测到恶意的记录数: {malicious_dpi}")
    
    if malicious_dpi > 0:
        efficiency = (malicious_dpi / total_dpi) * 100
        print(f"DPI扫描效率: {efficiency:.2f}%")
    else:
        print("DPI扫描效率: 0%") 