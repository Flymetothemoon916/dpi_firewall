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
        
        try:
            # 确保有效的风险级别
            risk_level = result.risk_level
            if risk_level not in ['low', 'medium', 'high']:
                risk_level = 'medium'
            
            # 提取原始数据包内容
            content = ""
            raw_payload = None
            if hasattr(packet_log, 'payload') and packet_log.payload:
                if isinstance(packet_log.payload, bytes):
                    raw_payload = packet_log.payload
                else:
                    # 尝试从字符串中提取数据包内容
                    content = packet_log.payload
                    # 检查是否包含HTTP请求/响应格式
                    if '===' in content and ('HTTP' in content or 'GET ' in content or 'POST ' in content):
                        # 已经是格式化后的内容，不需要进一步处理
                        pass
                    else:
                        # 尝试将字符串转换为更友好的格式
                        content = self._format_http_content(content)
            elif hasattr(result, 'raw_payload') and result.raw_payload:
                raw_payload = result.raw_payload
            
            # 如果有原始二进制负载，尝试解码和格式化
            if raw_payload:
                try:
                    # 尝试解码为文本
                    decoded = raw_payload.decode('utf-8', errors='replace')
                    
                    # 检查是否是HTTP内容
                    if 'HTTP/' in decoded or 'GET ' in decoded or 'POST ' in decoded:
                        content = self._format_http_content(decoded)
                    else:
                        content = decoded
                except Exception as e:
                    logger.debug(f"WAF解码数据包内容失败: {str(e)}")
                    # 使用十六进制表示
                    if isinstance(raw_payload, bytes):
                        hex_content = ' '.join(f'{b:02x}' for b in raw_payload[:100])
                        content = f"[二进制内容] 前100字节十六进制表示:\n{hex_content}..."
                    else:
                        content = str(raw_payload)
            
            # 格式化匹配的模式，并高亮显示在内容中
            patterns_text = "未检测到具体模式"
            if result.matched_patterns and len(result.matched_patterns) > 0:
                patterns_text = "检测到的攻击模式:\n"
                for i, pattern in enumerate(result.matched_patterns[:10]):
                    patterns_text += f"- [{i+1}] {pattern}\n"
                    
                    # 尝试在内容中高亮显示此模式
                    if content and isinstance(pattern, str):
                        try:
                            # 用特殊标记包裹匹配的模式，用于高亮显示
                            pattern_escaped = pattern.replace('[', '\\[').replace(']', '\\]')
                            content = content.replace(pattern, f"[!!!ATTACK!!!]{pattern}[/!!!ATTACK!!!]")
                        except:
                            pass
                
                if len(result.matched_patterns) > 10:
                    patterns_text += f"... 以及其他 {len(result.matched_patterns) - 10} 个模式\n"
            
            # 添加攻击分析段落
            analysis = f"""
===== WAF攻击分析 =====
攻击类型: {result.attack_type}
风险级别: {risk_level}
置信度: {result.confidence:.2f}
匹配模式数: {len(result.matched_patterns) if result.matched_patterns else 0}
时间戳: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}

{patterns_text}

===== 攻击描述 =====
{self._get_attack_description(result.attack_type)}

===== 推荐防御措施 =====
{self._get_defense_recommendations(result.attack_type)}
"""
            
            # 组合完整内容，将分析放在前面
            full_content = analysis
            
            if content:
                # 处理高亮标记
                content = content.replace("[!!!ATTACK!!!]", "【危险】").replace("[/!!!ATTACK!!!]", "【/危险】")
                
                full_content += f"\n===== 数据包内容 =====\n{content}"
            
            # 创建检测结果元数据
            metadata = {
                'attack_type': result.attack_type,
                'confidence': result.confidence,
                'detection_time': timezone.now().isoformat(),
                'source_ip': packet_log.source_ip,
                'destination_ip': packet_log.destination_ip,
                'matched_patterns_count': len(result.matched_patterns) if result.matched_patterns else 0,
            }
            
            # 创建DPI结果
            DeepInspectionResult.objects.create(
                packet=packet_log,
                application_protocol=packet_log.protocol.name if packet_log.protocol else 'HTTP/HTTPS',
                content_type='text/plain',
                detected_patterns=patterns_text,
                risk_level=risk_level,
                is_malicious=True,
                decoded_content=full_content[:10000] if len(full_content) > 10000 else full_content,  # 限制长度，避免过大
                metadata=metadata
            )
            
            logger.info(f"WAF检测到{result.attack_type}攻击，置信度: {result.confidence}, 源IP: {packet_log.source_ip}")
            
        except Exception as e:
            logger.error(f"保存WAF检测结果失败: {str(e)}")
        
        # 创建告警
        from dashboard.models import AlertLog
        from django.utils import timezone
        
        # 使用改进的标题格式
        title = f"WAF安全告警 - 检测到{result.attack_type.upper()}攻击"
        
        # 准备告警描述
        description = f"""Web应用防火墙检测到攻击流量。

===== 攻击详情 =====
源IP: {packet_log.source_ip}:{packet_log.source_port}
目标IP: {packet_log.destination_ip}:{packet_log.destination_port}
协议: {packet_log.protocol.name if packet_log.protocol else 'HTTP/HTTPS'}
攻击类型: {result.attack_type}
风险级别: {risk_level}
置信度: {result.confidence:.2f}

===== 攻击特征 =====
{patterns_text}

===== 检测的有效载荷 =====
"""
        
        # 添加最重要的载荷部分（有限的行数）
        if content:
            # 提取最重要的部分（前20行）
            content_lines = content.split('\n')
            if len(content_lines) > 20:
                important_content = '\n'.join(content_lines[:20]) + "\n... [内容已截断] ..."
            else:
                important_content = content
            
            description += important_content
        
        AlertLog.objects.create(
            timestamp=timezone.now(),
            level="critical" if result.risk_level == "high" else "warning",
            title=title,
            description=description,
            source_ip=packet_log.source_ip
        )
        
        logger.warning(
            f"WAF检测到攻击: {result.attack_type}, 风险级别: {result.risk_level}, "
            f"来源IP: {packet_log.source_ip}, 目标: {packet_log.destination_ip}:{packet_log.destination_port}"
        )

    def _format_http_content(self, content):
        """格式化HTTP内容，使其更可读"""
        if not content:
            return ""
        
        # 如果是字符串但可能包含HTTP请求/响应
        lines = content.split('\n')
        formatted = ""
        
        # 检查是否包含HTTP请求或响应标头
        is_http_request = False
        is_http_response = False
        request_line = ""
        
        for line in lines:
            if line.startswith('GET ') or line.startswith('POST ') or line.startswith('PUT '):
                is_http_request = True
                request_line = line
                break
            elif line.startswith('HTTP/'):
                is_http_response = True
                request_line = line
                break
        
        if is_http_request:
            # 格式化HTTP请求
            formatted += "===== HTTP请求 =====\n"
            formatted += f"请求行: {request_line}\n\n"
            
            # 提取并格式化HTTP头部
            headers_section = False
            body_section = False
            headers = []
            body_lines = []
            
            for line in lines:
                if line == request_line:
                    headers_section = True
                    continue
                
                if headers_section and not line.strip():
                    headers_section = False
                    body_section = True
                    continue
                
                if headers_section:
                    if ':' in line:
                        headers.append(line)
                elif body_section:
                    body_lines.append(line)
            
            if headers:
                formatted += "===== HTTP头部 =====\n"
                for header in headers:
                    formatted += f"{header}\n"
            
            if body_lines:
                formatted += "\n===== HTTP主体 =====\n"
                body = '\n'.join(body_lines)
                
                # 检查是否是URL编码的表单数据
                is_form = False
                for header in headers:
                    if 'content-type:' in header.lower() and 'application/x-www-form-urlencoded' in header.lower():
                        is_form = True
                        break
                
                if is_form:
                    # 尝试解析表单数据
                    try:
                        import urllib.parse
                        body_params = []
                        for param in body.split('&'):
                            if '=' in param:
                                key, value = param.split('=', 1)
                                decoded_key = urllib.parse.unquote_plus(key)
                                decoded_value = urllib.parse.unquote_plus(value)
                                body_params.append(f"{decoded_key} = {decoded_value}")
                            else:
                                body_params.append(param)
                        
                        formatted += "表单数据:\n" + '\n'.join(body_params)
                    except:
                        formatted += body
                else:
                    formatted += body
        
        elif is_http_response:
            # 格式化HTTP响应
            formatted += "===== HTTP响应 =====\n"
            formatted += f"状态行: {request_line}\n\n"
            # 其余处理类似于请求
            # ...此处省略，如有需要可以添加响应格式化逻辑
        else:
            # 不是HTTP请求或响应，返回原始内容
            formatted = content
        
        return formatted

    def _get_defense_recommendations(self, attack_type: str) -> str:
        """获取针对特定攻击类型的防御建议"""
        recommendations = {
            'sql_injection': """
1. 使用参数化查询/预处理语句，而不是直接拼接SQL
2. 实施输入验证和清洁，限制特殊字符
3. 使用最小权限原则配置数据库用户
4. 启用WAF规则以检测和阻止SQL注入攻击
5. 定期更新和修补数据库软件
            """,
            
            'xss': """
1. 对所有用户输入实施内容安全策略(CSP)
2. 使用HTML转义函数处理动态内容
3. 使用现代框架的内置XSS保护
4. 实施X-XSS-Protection HTTP标头
5. 应用输入验证，过滤危险标签和属性
            """,
            
            'command_injection': """
1. 避免使用shell命令执行函数
2. 如需使用命令执行，实施白名单验证
3. 使用安全API代替系统命令
4. 对所有用户输入进行严格过滤，移除特殊字符
5. 以最小权限运行应用程序
            """,
            
            'path_traversal': """
1. 使用安全的文件访问API
2. 规范和验证所有文件路径
3. 实施基于白名单的验证
4. 限制应用程序的文件系统访问权限
5. 不要将用户输入直接用于文件操作
            """,
            
            'file_inclusion': """
1. 避免使用动态包含函数
2. 使用预定义的包含映射
3. 禁用远程文件包含功能
4. 实施严格的文件类型检查
5. 验证所有包含的文件来源
            """,
            
            'http_protocol': """
1. 使用最新的Web服务器软件
2. 正确配置HTTP安全标头
3. 实施请求速率限制
4. 禁用不必要的HTTP方法
5. 监控异常的HTTP流量模式
            """
        }
        
        return recommendations.get(attack_type, "没有针对此攻击类型的特定建议。建议参考通用Web安全最佳实践。") 