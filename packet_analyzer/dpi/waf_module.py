import re
import logging
import json
from typing import Dict, List, Tuple, Optional, Any, Union
from dataclasses import dataclass

from django.utils import timezone
from scapy.all import IP, TCP, Raw
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse

from packet_analyzer.models import Protocol, PacketLog, DeepInspectionResult
from firewall_rules.models import Rule

logger = logging.getLogger(__name__)

@dataclass
class WAFDetectionResult:
    """WAF检测结果数据类"""
    is_attack: bool = False
    attack_type: str = ""
    confidence: float = 0.0
    description: str = ""
    matched_patterns: List[str] = None
    risk_level: str = "low"
    
    def __post_init__(self):
        if self.matched_patterns is None:
            self.matched_patterns = []


class WAFModule:
    """Web应用防火墙模块，专门用于检测和防护Web应用层攻击"""
    
    def __init__(self):
        self.initialized = False
        
        # 攻击模式字典 {攻击类型: [模式列表]}
        self.attack_patterns = {
            'sql_injection': [],
            'xss': [],
            'command_injection': [],
            'path_traversal': [],
            'file_inclusion': [],
            'http_protocol': []
        }
        
        # 初始化模式
        self._initialize_patterns()
        self.initialized = True
        logger.info("WAF模块初始化完成")
    
    def _initialize_patterns(self):
        """初始化攻击模式"""
        # SQL注入模式
        self.attack_patterns['sql_injection'] = [
            # 错误消息和关键字
            r"SQL syntax.*?",
            r"mysql.*?error",
            r"postgresql.*?error",
            r"oracle.*?error",
            r"ORA-[0-9]+",
            r"Warning.*?mysql_.*?",
            
            # 常见SQL注入攻击向量
            r"'.*?--",
            r"'.*?;",
            r"'.*?#",
            r"'.*?\*\/?",  
            r"union\s+select",
            r"select.*?from",
            r"insert\s+into",
            r"delete\s+from",
            r"drop\s+table",
            r"update\s+.*?set",
            r"1=1",
            r"or\s+1=1",
            r"and\s+1=1",
        ]
        
        # XSS攻击模式
        self.attack_patterns['xss'] = [
            r"<script.*?>",
            r"</script>",
            r"javascript:",
            r"vbscript:",
            r"onload\s*=",
            r"onclick\s*=",
            r"onerror\s*=",
            r"onmouseover\s*=",
            r"onfocus\s*=",
            r"onblur\s*=",
            r"alert\s*\(",
            r"String\.fromCharCode",
            r"eval\s*\(",
            r"document\.cookie",
            r"document\.location",
            r"document\.write",
            r"<img.*?src.*?onerror.*?>",
            r"<iframe.*?>",
            r"<svg.*?>",
        ]
        
        # 命令注入模式
        self.attack_patterns['command_injection'] = [
            r"(?:[;|&])\s*(?:ls|dir|cat|more|type|nano|vi|vim)",
            r"(?:[;|&])\s*(?:wget|curl)",
            r"(?:[;|&])\s*(?:bash|sh|csh|ksh|tcsh|zsh)",
            r"(?:[;|&])\s*(?:nc|netcat|ncat)",
            r"\|\s*(?:bash|sh|csh|ksh|tcsh|zsh)",
            r"ping\s+-[a-z]*c",
            r"nslookup",
            r"/etc/passwd",
            r"/bin/bash",
            r"/bin/sh",
        ]
        
        # 路径遍历模式
        self.attack_patterns['path_traversal'] = [
            r"\.\.\/",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"%252e%252e%252f",
            r"%c0%ae%c0%ae%c0%af",
            r"\.\.%c0%af",
            r"\.\.%252f",
            r"etc.*passwd",
            r"etc.*shadow",
            r"proc.*self.*environ",
            r"\/etc\/",
            r"C:\/",
        ]
        
        # 文件包含模式
        self.attack_patterns['file_inclusion'] = [
            r"(?:https?|ftp|php|data|jsp|file|php|phtml|zip|rar|tar)://",
            r"php://filter",
            r"php://input",
            r"php://wrapper",
            r"include\s*\(",
            r"require\s*\(",
            r"include_once\s*\(",
            r"require_once\s*\(",
            r"allow_url_include",
            r"allow_url_fopen",
        ]
        
        # HTTP协议异常模式
        self.attack_patterns['http_protocol'] = [
            r"Content-Length:\s*-\d+",
            r"Transfer-Encoding:\s*chunked.*?Content-Length",
            r"Referer:\s*https?://(?:127\.0\.0\.1|localhost)",
            r"User-Agent:\s*(?:nikto|nessus|nmap|sqlmap|w3af|acunetix|netsparker)",
        ]
        
        # 将所有正则表达式编译以提高性能
        for attack_type, patterns in self.attack_patterns.items():
            self.attack_patterns[attack_type] = [re.compile(p, re.IGNORECASE) for p in patterns]
    
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
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        
        # 判断是否为HTTP请求
        if 'HTTP/' in payload or 'GET ' in payload or 'POST ' in payload:
            # 分析HTTP请求
            return self._analyze_http_request(payload)
        
        return result
    
    def _analyze_http_request(self, payload: str) -> WAFDetectionResult:
        """
        分析HTTP请求是否包含Web攻击
        
        Args:
            payload: HTTP请求的原始负载
            
        Returns:
            WAFDetectionResult: 检测结果
        """
        result = WAFDetectionResult()
        
        # 设置默认置信度和风险等级
        result.confidence = 0.1
        
        # 逐个检查攻击模式
        for attack_type, patterns in self.attack_patterns.items():
            for pattern in patterns:
                matches = pattern.findall(payload)
                if matches:
                    result.is_attack = True
                    result.attack_type = attack_type
                    result.matched_patterns.extend(matches)
                    
                    # 更新置信度和风险等级
                    if len(matches) >= 3:  # 多个模式匹配时增加置信度
                        result.confidence = 0.9
                        result.risk_level = "high"
                    elif len(matches) >= 2:
                        result.confidence = 0.7
                        result.risk_level = "medium"
                    else:
                        result.confidence = 0.5
                        result.risk_level = "low"
                    
                    # 设置描述信息
                    result.description = self._get_attack_description(attack_type)
                    
                    # 如果是高置信度攻击，立即返回
                    if result.confidence >= 0.9:
                        return result
        
        return result
    
    def _get_attack_description(self, attack_type: str) -> str:
        """获取攻击类型的描述信息"""
        descriptions = {
            'sql_injection': 'SQL注入攻击尝试 - 尝试利用SQL注入漏洞获取或修改数据库数据',
            'xss': '跨站脚本攻击尝试 - 尝试注入恶意JavaScript代码',
            'command_injection': '命令注入攻击尝试 - 尝试执行系统命令',
            'path_traversal': '路径遍历攻击尝试 - 尝试访问系统敏感文件',
            'file_inclusion': '文件包含攻击尝试 - 尝试加载恶意文件',
            'http_protocol': 'HTTP协议异常 - 可能是扫描器或恶意工具探测'
        }
        return descriptions.get(attack_type, '未知攻击类型')
    
    def save_detection_result(self, packet_log: PacketLog, result: WAFDetectionResult):
        """
        保存WAF检测结果
        
        Args:
            packet_log: 数据包日志对象
            result: WAF检测结果
        """
        if not result.is_attack:
            return
        
        # 创建DPI分析结果
        DeepInspectionResult.objects.create(
            packet=packet_log,
            application_protocol='HTTP',
            content_type='text/plain',
            detected_patterns=', '.join(result.matched_patterns[:5]),  # 最多保存5个模式
            risk_level=result.risk_level,
            is_malicious=True,
            metadata={
                'attack_type': result.attack_type,
                'confidence': result.confidence,
                'description': result.description,
                'waf_detection': True
            }
        )
        
        logger.warning(
            f"WAF检测到攻击: {result.attack_type}, 风险级别: {result.risk_level}, "
            f"来源IP: {packet_log.source_ip}, 目标: {packet_log.destination_ip}:{packet_log.destination_port}"
        ) 