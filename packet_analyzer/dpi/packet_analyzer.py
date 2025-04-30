import logging
import time
from datetime import datetime
import ipaddress
import re
import threading
from typing import Dict, List, Optional, Tuple, Union, Any

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTP
from scapy.layers.dns import DNS

from django.utils import timezone
from django.db import transaction

from packet_analyzer.models import Protocol, PacketLog, DeepInspectionResult
from firewall_rules.models import Rule, IPBlacklist, IPWhitelist
from dashboard.models import TrafficStatistics, AlertLog, SystemStatus

logger = logging.getLogger(__name__)

class DPIPacketAnalyzer:
    """深度包检测分析器，用于分析网络数据包"""
    
    def __init__(self):
        self.protocols = {}  # 缓存协议对象
        self.rules = {}  # 缓存规则对象
        self.blacklist = set()  # 缓存黑名单IP
        self.whitelist = set()  # 缓存白名单IP
        self.stats = {
            'inbound_packets': 0,
            'outbound_packets': 0,
            'inbound_bytes': 0,
            'outbound_bytes': 0,
            'blocked_packets': 0,
            'last_update': datetime.now()
        }
        self.lock = threading.Lock()  # 线程锁，用于并发访问
        self.last_stats_time = timezone.now()
        self.load_configurations()
    
    def load_configurations(self):
        """从数据库加载配置信息"""
        try:
            # 加载协议
            for protocol in Protocol.objects.all():
                self.protocols[protocol.name.lower()] = protocol
            
            # 加载规则
            for rule in Rule.objects.filter(is_enabled=True):
                self.rules[rule.id] = rule
            
            # 加载黑名单
            for ip in IPBlacklist.objects.filter(is_permanent=True):
                self.blacklist.add(ip.ip_address)
            
            # 加载黑名单
            for ip in IPWhitelist.objects.all():
                self.whitelist.add(ip.ip_address)
                
            logger.info(f"配置加载完成: {len(self.protocols)} 协议, {len(self.rules)} 规则")
        except Exception as e:
            logger.error(f"加载配置失败: {str(e)}")
    
    def start_packet_capture(self, interface: str = None, packet_count: int = 0, timeout: int = None):
        """启动数据包捕获
        
        Args:
            interface: 网络接口名称，如eth0
            packet_count: 要捕获的数据包数量，0表示无限制
            timeout: 捕获超时时间(秒)
        """
        def packet_callback(packet):
            self.process_packet(packet)
        
        try:
            # 更新系统状态
            SystemStatus.objects.update_or_create(
                defaults={
                    'status': 'running',
                    'started_at': timezone.now()
                }
            )
            
            logger.info(f"开始捕获数据包 (接口: {interface or '默认'}, 数量: {packet_count or '无限制'})")
            scapy.sniff(
                iface=interface,
                prn=packet_callback,
                count=packet_count,
                timeout=timeout,
                store=False
            )
        except KeyboardInterrupt:
            logger.info("手动停止数据包捕获")
        except Exception as e:
            logger.error(f"数据包捕获错误: {str(e)}")
            # 更新系统状态为错误
            SystemStatus.objects.update_or_create(
                defaults={
                    'status': 'error',
                }
            )
    
    def process_packet(self, packet: scapy.Packet):
        """处理捕获的数据包
        
        Args:
            packet: scapy捕获的数据包
        """
        # 确保包含IP层
        if not packet.haslayer(IP):
            return
        
        # 提取基本信息
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        # 确定方向（入站/出站）
        direction = self._determine_direction(src_ip, dst_ip)
        
        # 提取协议和端口
        protocol_name, src_port, dst_port = self._extract_protocol_info(packet)
        
        # 更新统计信息
        packet_size = len(packet)
        self._update_stats(direction, packet_size)
        
        # 检查IP黑白名单
        if self._check_ip_blacklist(src_ip):
            status = 'blocked'
            self.stats['blocked_packets'] += 1
            return
        
        if self._check_ip_whitelist(src_ip):
            status = 'allowed'
        else:
            # 应用防火墙规则
            status, matched_rule = self._apply_rules(
                src_ip, dst_ip, src_port, dst_port, protocol_name, packet
            )
        
        # 保存到数据库
        self._save_packet_log(
            src_ip, dst_ip, src_port, dst_port, 
            protocol_name, packet, direction, status,
            matched_rule
        )
    
    def _determine_direction(self, src_ip: str, dst_ip: str) -> str:
        """确定数据包方向
        
        Args:
            src_ip: 源IP地址
            dst_ip: 目标IP地址
            
        Returns:
            str: 'inbound' 或 'outbound'
        """
        # 这里简化处理，实际应根据本机IP或网络范围判断
        # 可以通过检查是否为私有IP地址或局域网地址来判断
        try:
            src_is_private = ipaddress.ip_address(src_ip).is_private
            dst_is_private = ipaddress.ip_address(dst_ip).is_private
            
            if src_is_private and not dst_is_private:
                return 'outbound'
            elif not src_is_private and dst_is_private:
                return 'inbound'
            else:
                # 如果都是私有IP或都是公共IP，可能是内部通信或转发流量
                # 这里简单地认为是入站流量
                return 'inbound'
        except:
            return 'inbound'
    
    def _extract_protocol_info(self, packet: scapy.Packet) -> Tuple[str, int, int]:
        """提取协议和端口信息
        
        Args:
            packet: 数据包
            
        Returns:
            Tuple[str, int, int]: 协议名称, 源端口, 目标端口
        """
        protocol_name = "UNKNOWN"
        src_port = 0
        dst_port = 0
        
        # TCP协议
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            protocol_name = "TCP"
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            
            # 尝试识别应用层协议
            if dst_port == 80 or src_port == 80:
                protocol_name = "HTTP"
            elif dst_port == 443 or src_port == 443:
                protocol_name = "HTTPS"
            elif dst_port == 21 or src_port == 21:
                protocol_name = "FTP"
            elif dst_port == 22 or src_port == 22:
                protocol_name = "SSH"
            elif dst_port == 25 or src_port == 25:
                protocol_name = "SMTP"
        
        # UDP协议
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            protocol_name = "UDP"
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            
            # 尝试识别应用层协议
            if dst_port == 53 or src_port == 53:
                protocol_name = "DNS"
            elif dst_port == 67 or dst_port == 68:
                protocol_name = "DHCP"
        
        # HTTP协议的详细识别
        if packet.haslayer(HTTP):
            protocol_name = "HTTP"
        
        # DNS协议的详细识别
        if packet.haslayer(DNS):
            protocol_name = "DNS"
        
        return protocol_name, src_port, dst_port
    
    def _update_stats(self, direction: str, packet_size: int):
        """更新流量统计
        
        Args:
            direction: 数据包方向
            packet_size: 数据包大小(字节)
        """
        with self.lock:
            if direction == 'inbound':
                self.stats['inbound_packets'] += 1
                self.stats['inbound_bytes'] += packet_size
            else:
                self.stats['outbound_packets'] += 1
                self.stats['outbound_bytes'] += packet_size
            
            # 每10秒存储一次统计数据
            now = datetime.now()
            if (now - self.stats['last_update']).total_seconds() >= 10:
                self._save_stats()
                self.stats['last_update'] = now
    
    def _save_stats(self):
        """保存统计数据到数据库"""
        try:
            with transaction.atomic():
                # 计算每秒流量
                current_time = timezone.now()
                if hasattr(self, 'last_stats_time'):
                    time_diff = (current_time - self.last_stats_time).total_seconds()
                    if time_diff > 0:
                        inbound_bytes_per_sec = self.stats['inbound_bytes'] / time_diff
                        outbound_bytes_per_sec = self.stats['outbound_bytes'] / time_diff
                    else:
                        inbound_bytes_per_sec = self.stats['inbound_bytes']
                        outbound_bytes_per_sec = self.stats['outbound_bytes']
                else:
                    inbound_bytes_per_sec = self.stats['inbound_bytes']
                    outbound_bytes_per_sec = self.stats['outbound_bytes']
                
                TrafficStatistics.objects.create(
                    timestamp=current_time,
                    inbound_packets=self.stats['inbound_packets'],
                    outbound_packets=self.stats['outbound_packets'],
                    inbound_bytes=self.stats['inbound_bytes'],
                    outbound_bytes=self.stats['outbound_bytes'],
                    blocked_packets=self.stats['blocked_packets'],
                    inbound_bytes_per_sec=inbound_bytes_per_sec,
                    outbound_bytes_per_sec=outbound_bytes_per_sec
                )
                
                # 更新最后统计时间
                self.last_stats_time = current_time
                
                # 重置统计值
                self.stats.update({
                    'inbound_packets': 0,
                    'outbound_packets': 0,
                    'inbound_bytes': 0,
                    'outbound_bytes': 0,
                    'blocked_packets': 0,
                    'last_update': datetime.now()
                })
        except Exception as e:
            logger.error(f"保存统计数据失败: {str(e)}")
    
    def _check_ip_blacklist(self, ip: str) -> bool:
        """检查IP是否在黑名单中
        
        Args:
            ip: IP地址
            
        Returns:
            bool: 是否在黑名单中
        """
        return ip in self.blacklist
    
    def _check_ip_whitelist(self, ip: str) -> bool:
        """检查IP是否在白名单中
        
        Args:
            ip: IP地址
            
        Returns:
            bool: 是否在白名单中
        """
        return ip in self.whitelist
    
    def _apply_rules(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, 
                    protocol: str, packet: scapy.Packet) -> Tuple[str, Optional[Rule]]:
        """应用防火墙规则
        
        Args:
            src_ip: 源IP地址
            dst_ip: 目标IP地址
            src_port: 源端口
            dst_port: 目标端口
            protocol: 协议名称
            packet: 原始数据包
            
        Returns:
            Tuple[str, Optional[Rule]]: 状态('allowed', 'blocked', 'suspicious'), 匹配的规则(如有)
        """
        for rule_id, rule in self.rules.items():
            # 检查IP匹配
            if rule.source_ip and not self._ip_matches(src_ip, rule.source_ip):
                continue
            
            if rule.destination_ip and not self._ip_matches(dst_ip, rule.destination_ip):
                continue
            
            # 检查端口匹配
            if rule.source_port and not self._port_matches(src_port, rule.source_port):
                continue
            
            if rule.destination_port and not self._port_matches(dst_port, rule.destination_port):
                continue
            
            # 检查协议匹配
            if rule.protocol and rule.protocol.lower() != protocol.lower():
                continue
            
            # TODO: 实现深度包检测匹配
            # 目前简单实现，实际项目中需要根据规则模式在包内容中搜索
            
            # 规则匹配，更新命中次数
            rule.hits += 1
            rule.save()
            
            # 根据规则动作返回状态
            if rule.action == 'allow':
                return 'allowed', rule
            elif rule.action == 'block':
                self.stats['blocked_packets'] += 1
                return 'blocked', rule
            elif rule.action == 'alert':
                # 创建告警
                self._create_alert(rule, src_ip, packet)
                return 'suspicious', rule
            else:  # log
                return 'allowed', rule
        
        # 没有匹配规则，默认允许
        return 'allowed', None
    
    def _ip_matches(self, ip: str, rule_ip: str) -> bool:
        """检查IP是否匹配规则
        
        Args:
            ip: 要检查的IP地址
            rule_ip: 规则中的IP(可能是CIDR格式)
            
        Returns:
            bool: 是否匹配
        """
        # 如果规则IP为空，则匹配所有
        if not rule_ip:
            return True
        
        # 如果规则IP包含/，表示是CIDR格式
        if '/' in rule_ip:
            try:
                network = ipaddress.ip_network(rule_ip, strict=False)
                return ipaddress.ip_address(ip) in network
            except:
                return False
        
        # 否则直接比较
        return ip == rule_ip
    
    def _port_matches(self, port: int, rule_port: str) -> bool:
        """检查端口是否匹配规则
        
        Args:
            port: 要检查的端口
            rule_port: 规则中的端口(可能是范围格式)
            
        Returns:
            bool: 是否匹配
        """
        # 如果规则端口为空，则匹配所有
        if not rule_port:
            return True
        
        # 如果是逗号分隔的多个端口
        if ',' in rule_port:
            ports = [p.strip() for p in rule_port.split(',')]
            for p in ports:
                if self._port_matches(port, p):
                    return True
            return False
        
        # 如果是端口范围
        if '-' in rule_port:
            try:
                start, end = rule_port.split('-')
                return int(start) <= port <= int(end)
            except:
                return False
        
        # 否则直接比较
        try:
            return port == int(rule_port)
        except:
            return False
    
    def _create_alert(self, rule: Rule, src_ip: str, packet: scapy.Packet):
        """创建告警
        
        Args:
            rule: 触发告警的规则
            src_ip: 源IP地址
            packet: 原始数据包
        """
        try:
            # 根据规则优先级设置告警级别
            level = 'info'
            if rule.priority == 'high':
                level = 'warning'
            elif rule.priority == 'critical':
                level = 'critical'
            
            # 创建告警记录
            AlertLog.objects.create(
                level=level,
                title=f"规则告警: {rule.name}",
                description=f"检测到规则 '{rule.name}' 被触发。源IP: {src_ip}",
                source_ip=src_ip
            )
        except Exception as e:
            logger.error(f"创建告警失败: {str(e)}")
    
    def _save_packet_log(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                        protocol_name: str, packet: scapy.Packet, direction: str, 
                        status: str, matched_rule: Optional[Rule]):
        """保存数据包日志到数据库
        
        Args:
            src_ip: 源IP地址
            dst_ip: 目标IP地址
            src_port: 源端口
            dst_port: 目标端口
            protocol_name: 协议名称
            packet: 原始数据包
            direction: 方向(inbound/outbound)
            status: 状态(allowed/blocked/suspicious)
            matched_rule: 匹配的规则
        """
        try:
            with transaction.atomic():
                # 获取或创建协议对象
                protocol_obj = self.protocols.get(protocol_name.lower())
                if not protocol_obj:
                    protocol_obj, _ = Protocol.objects.get_or_create(
                        name=protocol_name,
                        defaults={'description': f'{protocol_name}协议'}
                    )
                    self.protocols[protocol_name.lower()] = protocol_obj
                
                # 创建数据包日志
                packet_log = PacketLog.objects.create(
                    timestamp=timezone.now(),
                    source_ip=src_ip,
                    source_port=src_port,
                    destination_ip=dst_ip,
                    destination_port=dst_port,
                    protocol=protocol_obj,
                    payload=str(packet),
                    packet_size=len(packet),
                    direction=direction,
                    status=status,
                    matched_rule=matched_rule
                )
                
                # 对可疑和阻止的包进行深度检测
                if status in ['suspicious', 'blocked']:
                    dpi_result = self._perform_deep_inspection(packet_log, packet)
                    if dpi_result is None:  # 如果深度检测失败，确保创建一个基本的DPI结果
                        self._create_basic_dpi_result(packet_log, status)
                    elif dpi_result.is_malicious:
                        logger.info(f"发现恶意流量: {src_ip}:{src_port} -> {dst_ip}:{dst_port}, 风险级别: {dpi_result.risk_level}")
                # 对正常流量也进行轻量级检测
                elif status == 'allowed' and self._should_inspect_allowed_packet(packet):
                    self._perform_light_inspection(packet_log, packet)
        except Exception as e:
            logger.error(f"保存数据包日志失败: {str(e)}")
            # 尝试在事务外部记录，确保数据不丢失
            try:
                # 在事务外创建协议对象
                protocol_obj, _ = Protocol.objects.get_or_create(
                    name=protocol_name,
                    defaults={'description': f'{protocol_name}协议'}
                )
                
                # 创建数据包日志
                packet_log = PacketLog.objects.create(
                    timestamp=timezone.now(),
                    source_ip=src_ip,
                    source_port=src_port,
                    destination_ip=dst_ip,
                    destination_port=dst_port,
                    protocol=protocol_obj,
                    payload=str(packet)[:1000],  # 限制大小
                    packet_size=len(packet),
                    direction=direction,
                    status=status,
                    matched_rule=matched_rule
                )
                
                # 确保至少创建一个基本的DPI结果
                if status in ['suspicious', 'blocked']:
                    self._create_basic_dpi_result(packet_log, status)
                
            except Exception as recovery_error:
                logger.critical(f"恢复记录数据包日志失败: {str(recovery_error)}")
    
    def _should_inspect_allowed_packet(self, packet: scapy.Packet) -> bool:
        """判断是否应该对允许通过的数据包进行检测
        
        Args:
            packet: 数据包
            
        Returns:
            bool: 是否应该检测
        """
        # 检查是否包含应用层数据
        if packet.haslayer(TCP) and packet[TCP].payload:
            return True
        if packet.haslayer(UDP) and packet[UDP].payload:
            return True
        # 检查常见敏感端口
        sensitive_ports = [80, 443, 21, 22, 25, 53, 3306, 1433, 5432]
        if packet.haslayer(TCP) and (packet[TCP].dport in sensitive_ports or packet[TCP].sport in sensitive_ports):
            return True
        if packet.haslayer(UDP) and (packet[UDP].dport in sensitive_ports or packet[UDP].sport in sensitive_ports):
            return True
        return False
    
    def _perform_light_inspection(self, packet_log: PacketLog, packet: scapy.Packet):
        """对正常流量执行轻量级检测
        
        Args:
            packet_log: 数据包日志
            packet: 原始数据包
        """
        try:
            # 提取应用层协议和基本信息
            app_protocol = packet_log.protocol.name if packet_log.protocol else "UNKNOWN"
            dst_port = packet_log.destination_port
            
            # 设置默认值
            content_type = ""
            risk_level = "low"
            is_malicious = False
            detected_patterns = ""
            
            # 根据端口推断应用层协议
            if dst_port == 80:
                app_protocol = "HTTP"
            elif dst_port == 443:
                app_protocol = "HTTPS"
            elif dst_port in [20, 21]:
                app_protocol = "FTP"
            elif dst_port == 22:
                app_protocol = "SSH"
            elif dst_port == 25:
                app_protocol = "SMTP"
            elif dst_port == 53:
                app_protocol = "DNS"
            
            # 创建基本元数据
            metadata = {
                'source_ip': packet_log.source_ip,
                'destination_ip': packet_log.destination_ip,
                'source_port': packet_log.source_port,
                'destination_port': packet_log.destination_port,
                'direction': packet_log.direction,
                'status': packet_log.status,
                'inspection_type': 'light',
                'timestamp': timezone.now().isoformat()
            }
            
            # 创建DPI结果
            DeepInspectionResult.objects.create(
                packet=packet_log,
                application_protocol=app_protocol,
                content_type=content_type,
                detected_patterns=detected_patterns,
                risk_level=risk_level,
                is_malicious=is_malicious,
                metadata=metadata
            )
        except Exception as e:
            logger.error(f"执行轻量级检测失败: {str(e)}")
    
    def _perform_deep_inspection(self, packet_log: PacketLog, packet: scapy.Packet):
        """执行深度包检测
        
        Args:
            packet_log: 数据包日志对象
            packet: 原始数据包
            
        Returns:
            DeepInspectionResult: 深度检测结果对象
        """
        try:
            # 提取应用层协议和内容类型
            app_protocol = "UNKNOWN"
            content_type = self._determine_content_type(packet)
            detected_patterns = ""
            risk_level = "low"
            is_malicious = False
            
            # 提取元数据
            metadata = self._extract_metadata(packet)
            metadata.update({
                'source_ip': packet_log.source_ip,
                'destination_ip': packet_log.destination_ip,
                'source_port': packet_log.source_port,
                'destination_port': packet_log.destination_port,
                'direction': packet_log.direction,
                'status': packet_log.status,
                'inspection_timestamp': timezone.now().isoformat()
            })
            
            # 根据端口识别应用层协议
            if packet.haslayer(TCP):
                dst_port = packet[TCP].dport
                if dst_port == 80:
                    app_protocol = "HTTP"
                elif dst_port == 443:
                    app_protocol = "HTTPS"
                elif dst_port == 21:
                    app_protocol = "FTP"
                elif dst_port == 22:
                    app_protocol = "SSH"
                elif dst_port == 25:
                    app_protocol = "SMTP"
            elif packet.haslayer(UDP):
                dst_port = packet[UDP].dport
                if dst_port == 53:
                    app_protocol = "DNS"
            
            # 如果无法从包中识别，尝试从数据包日志中获取
            if app_protocol == "UNKNOWN" and packet_log.protocol:
                app_protocol = packet_log.protocol.name
            
            # 检查是否包含HTTP内容
            if packet.haslayer(scapy.Raw):
                payload = packet[scapy.Raw].load
                try:
                    # 尝试解码为文本
                    payload_text = payload.decode('utf-8', 'ignore')
                    
                    # 检测常见攻击模式
                    malicious_patterns = [
                        (r'(?i)(?:union\s+all|union\s+select|insert\s+into|select\s+from)', 'SQL注入尝试'),
                        (r'(?i)(?:<script>|alert\(|document\.cookie|eval\(|javascript:)', 'XSS尝试'),
                        (r'(?i)(?:\.\.\/|\.\.\\|\/etc\/passwd|\/bin\/bash|cmd\.exe)', '路径遍历尝试'),
                        (r'(?i)(?:password=|passwd=|pwd=|user=|username=|login=)', '潜在的密码泄露'),
                        (r'(?i)(?:exec\(|system\(|shell_exec\(|passthru\(|eval\()', '命令注入尝试')
                    ]
                    
                    # 检查所有恶意模式
                    for pattern, desc in malicious_patterns:
                        if re.search(pattern, payload_text, re.IGNORECASE):
                            detected_patterns = detected_patterns + ("; " if detected_patterns else "") + desc
                            is_malicious = True
                            risk_level = "high"
                            metadata['detected_malicious_pattern'] = desc
                            metadata['detection_timestamp'] = timezone.now().isoformat()
                    
                    # 提取HTTP头信息
                    if app_protocol == "HTTP" or app_protocol == "HTTPS":
                        if "Content-Type:" in payload_text:
                            content_type_match = re.search(r"Content-Type:\s*([^\r\n]+)", payload_text)
                            if content_type_match:
                                content_type = content_type_match.group(1)
                except:
                    pass
            
            # 根据数据包状态设置风险级别
            if packet_log.status == 'blocked':
                if risk_level != 'high':  # 如果之前没有设置为高风险
                    risk_level = "high"
                    is_malicious = True
                    detected_patterns = detected_patterns or "自动阻止的流量"
            elif packet_log.status == 'suspicious':
                if risk_level == 'low':  # 如果之前没有设置为高或中风险
                    risk_level = "medium"
                    detected_patterns = detected_patterns or "可疑流量模式"
            
            # 创建深度检测结果
            dpi_result = DeepInspectionResult.objects.create(
                packet=packet_log,
                application_protocol=app_protocol,
                content_type=content_type,
                detected_patterns=detected_patterns,
                risk_level=risk_level,
                is_malicious=is_malicious,
                metadata=metadata
            )
            
            logger.info(f"创建DPI分析结果: ID={dpi_result.id}, 协议={app_protocol}, 风险={risk_level}")
            return dpi_result
            
        except Exception as e:
            logger.error(f"执行深度包检测失败: {str(e)}")
            return None
    
    def _create_basic_dpi_result(self, packet_log: PacketLog, status: str):
        """为数据包创建基本的DPI结果，当正常的深度检测失败时使用
        
        Args:
            packet_log: 数据包日志
            status: 数据包状态
            
        Returns:
            DeepInspectionResult: 基本的DPI结果对象
        """
        try:
            # 设置默认值
            app_protocol = "UNKNOWN"
            risk_level = "low"
            is_malicious = False
            detected_patterns = "自动生成的DPI结果"
            
            # 根据端口识别应用层协议
            dst_port = packet_log.destination_port
            if dst_port == 80:
                app_protocol = "HTTP"
            elif dst_port == 443:
                app_protocol = "HTTPS"
            elif dst_port in [20, 21]:
                app_protocol = "FTP"
            elif dst_port == 22:
                app_protocol = "SSH"
            elif dst_port == 25:
                app_protocol = "SMTP"
            elif dst_port == 53:
                app_protocol = "DNS"
            elif packet_log.protocol:
                app_protocol = packet_log.protocol.name
            
            # 根据状态设置风险级别
            if status == 'blocked':
                risk_level = "high"
                is_malicious = True
                detected_patterns = "自动阻止的流量"
            elif status == 'suspicious':
                risk_level = "medium"
                detected_patterns = "可疑流量模式"
            
            # 基本元数据
            metadata = {
                'source_ip': packet_log.source_ip,
                'destination_ip': packet_log.destination_ip,
                'source_port': packet_log.source_port,
                'destination_port': packet_log.destination_port,
                'direction': packet_log.direction,
                'status': packet_log.status,
                'generated_by': 'basic_dpi_fallback',
                'timestamp': timezone.now().isoformat()
            }
            
            # 创建DPI结果
            dpi_result = DeepInspectionResult.objects.create(
                packet=packet_log,
                application_protocol=app_protocol,
                content_type="",
                detected_patterns=detected_patterns,
                risk_level=risk_level,
                is_malicious=is_malicious,
                metadata=metadata
            )
            
            logger.info(f"已创建基本DPI分析结果: ID={dpi_result.id}, 协议={app_protocol}, 风险={risk_level}")
            return dpi_result
            
        except Exception as e:
            logger.error(f"创建基本DPI结果失败: {str(e)}")
            return None
    
    def _determine_content_type(self, packet: scapy.Packet) -> str:
        """确定数据包内容类型
        
        Args:
            packet: 数据包
            
        Returns:
            str: 内容类型
        """
        # 这里是简化实现，实际项目中需要更复杂的内容类型识别
        if packet.haslayer(HTTP):
            try:
                http_layer = packet[HTTP]
                if 'Content-Type' in http_layer.fields:
                    return http_layer['Content-Type']
            except:
                pass
            return 'text/html'
        
        # 根据协议猜测内容类型
        if packet.haslayer(DNS):
            return 'application/dns'
        
        return 'application/octet-stream'
    
    def _extract_metadata(self, packet: scapy.Packet) -> Dict[str, Any]:
        """提取数据包元数据
        
        Args:
            packet: 数据包
            
        Returns:
            Dict[str, Any]: 元数据字典
        """
        metadata = {}
        
        try:
            # IP层信息
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                metadata['ip'] = {
                    'version': ip_layer.version,
                    'ttl': ip_layer.ttl,
                    'id': ip_layer.id,
                    'flags': str(ip_layer.flags)
                }
            
            # TCP层信息
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                metadata['tcp'] = {
                    'flags': str(tcp_layer.flags),
                    'window': tcp_layer.window,
                    'seq': tcp_layer.seq,
                    'ack': tcp_layer.ack if hasattr(tcp_layer, 'ack') else None
                }
            
            # HTTP层信息
            if packet.haslayer(HTTP):
                http_layer = packet[HTTP]
                metadata['http'] = {}
                
                if hasattr(http_layer, 'Method'):
                    metadata['http']['method'] = http_layer.Method.decode() if isinstance(http_layer.Method, bytes) else http_layer.Method
                
                if hasattr(http_layer, 'Path'):
                    metadata['http']['path'] = http_layer.Path.decode() if isinstance(http_layer.Path, bytes) else http_layer.Path
                
                if hasattr(http_layer, 'User-Agent'):
                    metadata['http']['user_agent'] = http_layer['User-Agent'].decode() if isinstance(http_layer['User-Agent'], bytes) else http_layer['User-Agent']
            
            # DNS层信息
            if packet.haslayer(DNS):
                dns_layer = packet[DNS]
                metadata['dns'] = {
                    'qr': dns_layer.qr,
                    'opcode': dns_layer.opcode,
                    'qd_count': dns_layer.qdcount
                }
                
                if dns_layer.qd and dns_layer.qd.qname:
                    qname = dns_layer.qd.qname.decode() if isinstance(dns_layer.qd.qname, bytes) else dns_layer.qd.qname
                    metadata['dns']['query_name'] = qname
        except Exception as e:
            logger.debug(f"提取元数据时出错: {str(e)}")
        
        return metadata 