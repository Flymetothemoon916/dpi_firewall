import re
import logging
import json
from typing import Dict, List, Tuple, Optional, Any, Union
from dataclasses import dataclass

from django.utils import timezone
from django.db.models import F
from scapy.all import IP, TCP, Raw
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse

from packet_analyzer.models import Protocol, PacketLog, DeepInspectionResult
from firewall_rules.models import Rule, RulePattern
from packet_analyzer.dpi.waf_rule_matcher import waf_rule_matcher
from packet_analyzer.dpi.protocol_rule_manager import protocol_rule_manager

logger = logging.getLogger(__name__)

@dataclass
class WAFDetectionResult:
    """WAF检测结果数据类"""
    is_attack: bool = False
    attack_type: str = ""
    confidence: float = 0.0
    description: str = ""
    matched_patterns: List[str] = None
    matched_rules: List[Rule] = None
    risk_level: str = "low"
    protocol: str = "HTTP"
    
    def __post_init__(self):
        if self.matched_patterns is None:
            self.matched_patterns = []
        if self.matched_rules is None:
            self.matched_rules = []


class WAFModule:
    """Web应用防火墙模块，专门用于检测和防护Web应用层攻击"""
    
    def __init__(self):
        self.initialized = False
        
        # 攻击类型映射
        self.attack_type_map = {
            'SQL注入': 'sql_injection',
            '跨站脚本': 'xss',
            '命令注入': 'command_injection',
            '文件访问': 'file_inclusion',
            '协议异常': 'http_protocol_violation'
        }
        
        # 确保规则匹配器已初始化
        waf_rule_matcher.reload_if_needed()
        
        # 确保协议规则管理器已初始化
        protocol_rule_manager.reload_if_needed()
        
        self.initialized = True
        logger.info("WAF模块初始化完成")
    
    def inspect_http_traffic(self, packet, packet_log: Optional[PacketLog] = None) -> WAFDetectionResult:
        """
        检查HTTP流量是否包含Web攻击
        
        Args:
            packet: scapy捕获的数据包
            packet_log: 可选，已存在的PacketLog对象
            
        Returns:
            WAFDetectionResult: 检测结果
        """
        result = WAFDetectionResult()
        
        # 确保包含TCP层和Raw层
        if not (packet.haslayer(TCP) and packet.haslayer(Raw)):
            return result
        
        # 提取原始负载
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
        except Exception as e:
            logger.error(f"解码HTTP负载失败: {str(e)}")
            return result
        
        # 确定协议类型
        protocol = self._determine_protocol(packet, payload)
        result.protocol = protocol
        
        # 判断是否为HTTP请求
        if 'HTTP/' in payload or 'GET ' in payload or 'POST ' in payload:
            # 分析HTTP请求
            return self._analyze_http_request(payload, protocol)
        
        return result
    
    def _determine_protocol(self, packet, payload) -> str:
        """
        确定协议类型
        
        Args:
            packet: 数据包
            payload: 解码后的负载
            
        Returns:
            str: 'HTTP' 或 'HTTPS'
        """
        # 初始化变量
        dst_port = 0
        
        # 检查端口
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            if dst_port == 443:
                return 'HTTPS'
            elif dst_port == 80:
                return 'HTTP'
        
        # 检查TLS握手
        if packet.haslayer(TCP) and len(packet) > 100:
            try:
                data = bytes(packet.payload)
                # TLS握手标记 (0x16)
                if data and len(data) > 5 and data[0] == 0x16:
                    return 'HTTPS'
            except:
                pass
        
        # 检查HTTP头
        if 'HTTP/' in payload or 'GET ' in payload or 'POST ' in payload:
            return 'HTTP'
        
        # 默认返回HTTP
        return 'HTTP'
    
    def _analyze_http_request(self, payload: str, protocol: str = 'HTTP') -> WAFDetectionResult:
        """
        分析HTTP请求是否包含Web攻击
        
        Args:
            payload: HTTP请求的原始负载
            protocol: 'HTTP' 或 'HTTPS'
            
        Returns:
            WAFDetectionResult: 检测结果
        """
        result = WAFDetectionResult(protocol=protocol)
        
        # 设置默认置信度和风险等级
        result.confidence = 0.1
        
        # 检查规则匹配
        waf_rule_matcher.reload_if_needed()
        
        # 对于HTTPS流量，跳过内容检测，直接返回
        if protocol == 'HTTPS':
            # HTTPS流量仅支持基于IP/端口/协议的检测，不进行内容检测
            return result
            
        # 获取所有匹配的规则和模式
        matches = waf_rule_matcher.match_content(payload)
        
        if not matches:
            return result
            
        # 按优先级排序
        matches.sort(key=lambda x: self._get_rule_priority_value(x[0]), reverse=True)
        
        # 获取最高优先级的匹配
        top_rule, top_pattern = matches[0]
        attack_type = self._get_attack_type_from_category(top_rule.category.name if top_rule.category else "")
        
        # 设置结果
        result.is_attack = True
        result.attack_type = attack_type
        result.confidence = self._calculate_confidence(top_rule, top_pattern)
        result.risk_level = top_rule.priority
        result.description = self._get_attack_description(attack_type)
        
        # 保存匹配的模式和规则
        for rule, pattern in matches:
            result.matched_patterns.append(pattern.name)
            result.matched_rules.append(rule)
        
        return result
    
    def _get_attack_type_from_category(self, category_name: str) -> str:
        """根据规则类别获取攻击类型"""
        return self.attack_type_map.get(category_name, "generic_attack")
    
    def _calculate_confidence(self, rule: Rule, pattern: RulePattern) -> float:
        """计算检测结果的置信度"""
        # 基于规则优先级设置基础置信度
        base_confidence = {
            'critical': 0.9,
            'high': 0.7,
            'medium': 0.5,
            'low': 0.3
        }.get(rule.priority, 0.1)
        
        # 给精确匹配的规则更高的置信度
        if not pattern.is_regex:
            base_confidence += 0.1
            
        return min(base_confidence, 1.0)
        
    def _get_rule_priority_value(self, rule: Rule) -> int:
        """获取规则优先级的数值表示"""
        priority_map = {
            'critical': 400,
            'high': 300,
            'medium': 200,
            'low': 100
        }
        
        return priority_map.get(rule.priority, 0)
    
    def _get_attack_description(self, attack_type: str) -> str:
        """获取攻击类型的描述"""
        descriptions = {
            'sql_injection': "SQL注入攻击试图通过特殊构造的SQL语句操纵数据库",
            'xss': "跨站脚本攻击尝试在Web页面中注入恶意脚本",
            'command_injection': "命令注入攻击尝试在服务器上执行未授权的命令",
            'file_inclusion': "文件包含攻击尝试访问或包含未授权的文件或路径",
            'path_traversal': "路径遍历攻击尝试访问文件系统中的受限目录",
            'http_protocol_violation': "HTTP协议违规可能表明有人在尝试绕过安全措施"
        }
        
        return descriptions.get(attack_type, "检测到可能的Web攻击")
    
    def save_detection_result(self, packet_log: PacketLog, result: WAFDetectionResult):
        """
        保存检测结果到数据库
        
        Args:
            packet_log: 数据包日志对象
            result: WAF检测结果
        """
        if not result.is_attack:
            return
            
        try:
            # 创建深度检测结果
            dpi_result = DeepInspectionResult(
                packet_log=packet_log,
                inspection_type="WAF",
                is_threat=result.is_attack,
                threat_type=result.attack_type,
                confidence=result.confidence,
                details={
                    'description': result.description,
                    'matched_patterns': result.matched_patterns,
                    'matched_rules': [rule.name for rule in result.matched_rules],
                    'risk_level': result.risk_level,
                    'protocol': result.protocol,
                    'recommendations': self._get_defense_recommendations(result.attack_type)
                }
            )
            dpi_result.save()
            
            # 创建告警记录
            try:
                from dashboard.models import AlertLog
                
                # 判断风险等级对应的告警级别
                alert_level = 'info'
                if result.risk_level == 'critical':
                    alert_level = 'critical'
                elif result.risk_level == 'high':
                    alert_level = 'warning'
                elif result.risk_level == 'medium': 
                    alert_level = 'warning'
                
                source_ip = packet_log.source_ip if packet_log else None
                
                AlertLog.objects.create(
                    title=f"WAF检测告警: {result.attack_type}",
                    description=f"{result.description}\n协议: {result.protocol}\n匹配模式: {', '.join(result.matched_patterns)}\n推荐措施: {self._get_defense_recommendations(result.attack_type)}",
                    level=alert_level,
                    source_ip=source_ip
                )
            except Exception as e:
                logger.error(f"创建WAF告警记录失败: {str(e)}")
            
            # 更新规则命中次数
            for rule in result.matched_rules:
                Rule.objects.filter(id=rule.id).update(hits=F('hits') + 1)
                
        except Exception as e:
            logger.error(f"保存WAF检测结果时出错: {str(e)}")
            
    def _get_defense_recommendations(self, attack_type: str) -> str:
        """获取防御建议"""
        recommendations = {
            'sql_injection': "使用参数化查询；验证和净化用户输入；限制数据库账户权限",
            'xss': "使用内容安全策略(CSP)；对输出进行HTML编码；使用现代框架的XSS保护措施",
            'command_injection': "避免直接执行系统命令；使用API替代命令执行；净化和验证用户输入",
            'file_inclusion': "使用白名单验证文件路径；禁用PHP等危险功能；使用安全的文件操作API",
            'path_traversal': "对文件路径进行规范化和验证；使用相对路径而非绝对路径；实施文件系统访问控制",
            'http_protocol_violation': "配置Web服务器正确处理异常HTTP请求；使用WAF防护；规范化处理HTTP头"
        }
        
        return recommendations.get(attack_type, "实施深度防御策略；定期更新软件和补丁；进行安全审计") 