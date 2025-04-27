import os
import logging
import time
import threading
import re
import ipaddress
import socket
import struct
from typing import Dict, List, Optional, Tuple, Any, Set, Union
from datetime import datetime, timedelta

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.all import send, sr1, ARP, Ether, get_if_hwaddr, get_if_addr, get_if_list
from django.utils import timezone
from django.db import transaction

from packet_analyzer.models import Protocol, PacketLog, DeepInspectionResult
from firewall_rules.models import Rule, RulePattern, IPBlacklist, IPWhitelist
from dashboard.models import TrafficStatistics, AlertLog, SystemStatus
from packet_analyzer.dpi.waf_module import WAFModule, WAFDetectionResult

logger = logging.getLogger(__name__)

class FirewallEngine:
    """
    防火墙引擎 - 核心组件，处理实时数据包分析、过滤和处理
    """
    
    _instance = None
    _lock = threading.RLock()
    
    def __new__(cls):
        """单例模式实现"""
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(FirewallEngine, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance
    
    def __init__(self):
        """初始化防火墙引擎"""
        if self._initialized:
            return
            
        # 基本属性
        self._initialized = True
        self._running = False
        self._packet_filter_thread = None
        self._stats_thread = None
        
        # 规则和配置
        self.rules = []                # 规则列表
        self.blacklist_ips = set()     # IP黑名单
        self.whitelist_ips = set()     # IP白名单
        self.local_ips = set()         # 本地IP列表
        self.local_networks = []       # 本地网络
        
        # 会话跟踪
        self.active_sessions = {}      # 活动会话 {session_id: session_info}
        self.session_lock = threading.Lock()
        
        # 统计数据
        self.stats = {
            'inbound_packets': 0,
            'outbound_packets': 0,
            'inbound_bytes': 0,
            'outbound_bytes': 0,
            'blocked_packets': 0,
            'suspicious_packets': 0,
            'waf_blocked_attacks': 0,  # WAF阻止的攻击数量
            'last_update': datetime.now()
        }
        
        # 缓存
        self.protocol_cache = {}      # 协议缓存 {protocol_name: Protocol对象}
        
        # 添加锁保护
        self.lock = threading.Lock()  # 用于保护统计数据的线程安全
        
        # 初始化WAF模块
        self.waf = WAFModule()
        
        # 加载初始配置
        self.last_stats_time = timezone.now()
        self._init_local_network()
        self._load_configurations()
        
        # 设置详细日志记录
        self.detailed_logging = True
        
        logger.info("防火墙引擎初始化完成")
    
    def _init_local_network(self):
        """初始化本地网络信息"""
        try:
            # 获取本机IP地址和网络
            for iface in get_if_list():
                try:
                    ip = get_if_addr(iface)
                    if ip and ip != '0.0.0.0' and ip != '127.0.0.1':
                        self.local_ips.add(ip)
                        # 尝试获取子网信息
                        try:
                            # 这里简化处理，假设是标准C类网络
                            # 实际应用中应该通过netmask获取正确的网络地址
                            network = '.'.join(ip.split('.')[:3]) + '.0/24'
                            self.local_networks.append(ipaddress.ip_network(network, strict=False))
                        except:
                            pass
                except:
                    pass
            
            # 添加标准的私有网络
            private_networks = [
                '10.0.0.0/8',      # 10.0.0.0 - 10.255.255.255
                '172.16.0.0/12',   # 172.16.0.0 - 172.31.255.255
                '192.168.0.0/16',  # 192.168.0.0 - 192.168.255.255
                '127.0.0.0/8'      # 本地回环
            ]
            
            for net in private_networks:
                try:
                    self.local_networks.append(ipaddress.ip_network(net))
                except:
                    pass
                    
            logger.info(f"本地IP地址: {self.local_ips}")
            logger.info(f"本地网络: {[str(net) for net in self.local_networks]}")
        except Exception as e:
            logger.error(f"初始化本地网络信息失败: {str(e)}")
    
    def _load_configurations(self):
        """从数据库加载配置信息"""
        try:
            # 加载规则
            self._load_rules()
            
            # 加载黑白名单
            self._load_ip_lists()
            
            # 加载协议
            self._load_protocols()
            
            logger.info(f"配置加载完成: {len(self.rules)} 规则, {len(self.blacklist_ips)} 黑名单IP, {len(self.whitelist_ips)} 白名单IP")
        except Exception as e:
            logger.error(f"加载配置失败: {str(e)}")
    
    def _load_rules(self):
        """从数据库加载防火墙规则"""
        self.rules = []
        active_rules = Rule.objects.filter(is_enabled=True).order_by('category__priority')
        
        for rule in active_rules:
            # 获取规则的所有模式
            rule_patterns = list(rule.pattern.all())
            compiled_patterns = []
            
            # 处理每个模式
            for pattern in rule_patterns:
                if pattern.is_regex:
                    try:
                        compiled_patterns.append(re.compile(pattern.pattern_string))
                    except:
                        logger.error(f"正则表达式编译失败: {pattern.pattern_string}")
                else:
                    compiled_patterns.append(pattern.pattern_string)
            
            # 存储规则信息
            self.rules.append({
                'id': rule.id,
                'name': rule.name,
                'source_ip': rule.source_ip,
                'destination_ip': rule.destination_ip,
                'source_port': rule.source_port,
                'destination_port': rule.destination_port,
                'protocol': rule.protocol,
                'application_protocol': rule.application_protocol,
                'action': rule.action,
                'priority': rule.priority,
                'patterns': compiled_patterns,
                'rule_obj': rule,
            })
        
        logger.info(f"已加载 {len(self.rules)} 条防火墙规则")
    
    def _load_ip_lists(self):
        """加载IP黑白名单"""
        # 加载黑名单
        self.blacklist_ips = set()
        for entry in IPBlacklist.objects.all():
            # 检查是否过期
            if entry.is_permanent or (entry.expiry and entry.expiry > timezone.now()):
                self.blacklist_ips.add(entry.ip_address)
        
        # 加载白名单
        self.whitelist_ips = set()
        for entry in IPWhitelist.objects.all():
            self.whitelist_ips.add(entry.ip_address)
        
        logger.info(f"已加载 {len(self.blacklist_ips)} 个黑名单IP和 {len(self.whitelist_ips)} 个白名单IP")
    
    def _load_protocols(self):
        """加载协议信息"""
        self.protocol_cache = {}
        for protocol in Protocol.objects.all():
            self.protocol_cache[protocol.name.lower()] = protocol
        
        logger.info(f"已加载 {len(self.protocol_cache)} 个协议")
    
    def start(self):
        """启动防火墙引擎"""
        with self._lock:
            if self._running:
                logger.info("防火墙引擎已经在运行中")
                return True
            
            # 重新加载配置
            self._load_configurations()
            
            # 标记为运行中
            self._running = True
            
            # 更新系统状态
            SystemStatus.objects.update_or_create(
                defaults={
                    'status': 'running',
                    'started_at': timezone.now()
                }
            )
            
            # 启动统计数据更新线程
            self._stats_thread = threading.Thread(
                target=self._statistics_updater,
                daemon=True
            )
            self._stats_thread.start()
            
            logger.info("防火墙引擎已启动")
            return True
    
    def stop(self):
        """停止防火墙引擎"""
        with self._lock:
            if not self._running:
                logger.info("防火墙引擎已经停止")
                return True
            
            # 标记为停止
            self._running = False
            
            # 更新系统状态
            SystemStatus.objects.update_or_create(
                defaults={
                    'status': 'stopped'
                }
            )
            
            # 保存最终统计数据
            self._save_stats()
            
            logger.info("防火墙引擎已停止")
            return True
    
    def is_running(self):
        """检查防火墙引擎是否运行中"""
        with self._lock:
            return self._running
    
    def restart(self):
        """重启防火墙引擎"""
        self.stop()
        time.sleep(1)  # 等待资源释放
        return self.start()
    
    def reload_rules(self):
        """重新加载规则和配置"""
        with self._lock:
            self._load_configurations()
        return True
    
    def process_packet(self, packet):
        """
        处理捕获的数据包
        
        Args:
            packet (scapy.Packet): 捕获的数据包
            
        Returns:
            tuple: (action, matched_rule) - 操作和匹配的规则
        """
        # 初始化变量
        action = "allowed"
        matched_rule = None
        
        if not self._running:
            return action, matched_rule
        
        # 跳过非IP包
        if not packet.haslayer(IP):
            return action, matched_rule
        
        # 提取基本信息
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto
        
        # 获取端口信息和协议
        src_port = 0
        dst_port = 0
        protocol_name = "UNKNOWN"
        
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            protocol_name = "TCP"
            
            # 简单的应用层协议检测
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
            
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            protocol_name = "UDP"
            
            # 简单的UDP协议检测
            if dst_port == 53 or src_port == 53:
                protocol_name = "DNS"
            
        elif packet.haslayer(ICMP):
            protocol_name = "ICMP"
        
        # 确定方向（入站/出站）
        direction = self._determine_direction(src_ip, dst_ip)
        
        # 更新统计信息
        self._update_stats(direction, len(packet))
        
        # 检查IP黑白名单
        if src_ip in self.blacklist_ips:
            self.stats['blocked_packets'] += 1
            action = "blocked"
            
            # 记录详细日志
            if self.detailed_logging:
                self._log_packet(
                    src_ip, dst_ip, src_port, dst_port,
                    protocol_name, packet, direction, action,
                    None  # 黑名单没有关联规则
                )
            
            return action, matched_rule
        
        if src_ip in self.whitelist_ips:
            action = "allowed"
            return action, matched_rule
        
        # WAF检测 - 仅HTTP和HTTPS流量
        if protocol_name in ["HTTP", "HTTPS"] and packet.haslayer(TCP) and packet.haslayer(scapy.Raw):
            packet_log = None
            
            # 如果启用了详细日志，先创建日志对象以便WAF模块使用
            if self.detailed_logging:
                packet_log = self._create_packet_log(
                    src_ip, dst_ip, src_port, dst_port,
                    protocol_name, packet, direction, "inspecting"
                )
            
            # 执行WAF检测
            waf_result = self.waf.inspect_http_traffic(packet, packet_log)
            
            # 如果检测到攻击
            if waf_result.is_attack and waf_result.confidence >= 0.7:  # 中高置信度
                action = "blocked"
                self.stats['waf_blocked_attacks'] += 1
                self.stats['blocked_packets'] += 1
                
                # 更新日志状态
                if packet_log:
                    packet_log.status = action
                    packet_log.save()
                    
                    # 保存WAF检测结果
                    self.waf.save_detection_result(packet_log, waf_result)
                    
                    # 创建告警
                    self._create_waf_alert(waf_result, src_ip, dst_ip, protocol_name)
                
                return action, {"name": f"WAF-{waf_result.attack_type}"}
        
        # 应用防火墙规则
        action, matched_rule = self._apply_rules(
            src_ip, dst_ip, src_port, dst_port, protocol_name, packet
        )
        
        if action == "blocked":
            self.stats['blocked_packets'] += 1
        elif action == "suspicious":
            self.stats['suspicious_packets'] += 1
        
        # 如果启用了规则日志，记录数据包信息
        if matched_rule and matched_rule.get('rule_obj') and matched_rule['rule_obj'].log_prefix:
            self._log_packet(
                src_ip, dst_ip, src_port, dst_port,
                protocol_name, packet, direction, action,
                matched_rule['rule_obj']
            )
        # 如果启用详细日志但没有匹配规则，也记录日志
        elif self.detailed_logging and (action != "allowed" or src_port == 0 or dst_port == 0):
            self._log_packet(
                src_ip, dst_ip, src_port, dst_port,
                protocol_name, packet, direction, action,
                None
            )
        
        return action, matched_rule
    
    def _determine_direction(self, src_ip: str, dst_ip: str) -> str:
        """
        确定数据包方向
        
        Args:
            src_ip: 源IP地址
            dst_ip: 目标IP地址
            
        Returns:
            str: 'inbound' 或 'outbound'
        """
        try:
            # 如果目标IP是本地IP，则是入站
            if dst_ip in self.local_ips:
                return 'inbound'
            
            # 如果源IP是本地IP，则是出站
            if src_ip in self.local_ips:
                return 'outbound'
            
            # 检查IP是否在本地网络范围内
            src_ip_obj = ipaddress.ip_address(src_ip)
            dst_ip_obj = ipaddress.ip_address(dst_ip)
            
            src_is_local = False
            dst_is_local = False
            
            for network in self.local_networks:
                if src_ip_obj in network:
                    src_is_local = True
                if dst_ip_obj in network:
                    dst_is_local = True
            
            if src_is_local and not dst_is_local:
                return 'outbound'
            elif not src_is_local and dst_is_local:
                return 'inbound'
            
            # 默认作为入站流量
            return 'inbound'
        except:
            return 'inbound'
    
    def _apply_rules(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, 
                    protocol: str, packet) -> Tuple[str, Optional[Dict]]:
        """
        应用防火墙规则
        
        Args:
            src_ip: 源IP地址
            dst_ip: 目标IP地址
            src_port: 源端口
            dst_port: 目标端口
            protocol: 协议名称
            packet: 原始数据包
            
        Returns:
            Tuple[str, Optional[Dict]]: (决策, 匹配的规则)
        """
        # 获取数据包的原始内容用于深度检测
        payload = bytes(packet)
        
        # 初始化默认返回值
        default_action = "allowed"
        default_rule = None
        
        try:
            for rule in self.rules:
                # 检查IP匹配
                if rule['source_ip'] and not self._ip_matches(src_ip, rule['source_ip']):
                    continue
                    
                if rule['destination_ip'] and not self._ip_matches(dst_ip, rule['destination_ip']):
                    continue
                
                # 检查端口匹配
                if rule['source_port'] and not self._port_matches(src_port, rule['source_port']):
                    continue
                    
                if rule['destination_port'] and not self._port_matches(dst_port, rule['destination_port']):
                    continue
                
                # 检查协议匹配
                if rule['protocol'] and rule['protocol'].lower() != protocol.lower():
                    # 特殊情况: TCP/UDP检查
                    if not (rule['protocol'].lower() == 'tcp' and protocol.lower() in ['http', 'https']) and \
                       not (rule['protocol'].lower() == 'udp' and protocol.lower() == 'dns'):
                        continue
                
                # 检查应用层协议
                if rule['application_protocol'] and rule['application_protocol'].lower() != protocol.lower():
                    continue
                
                # 对HTTP/HTTPS流量进行深度内容检测
                if protocol.lower() in ['http', 'https'] and rule['patterns']:
                    content_matched = False
                    
                    # 转换为字符串进行模式匹配
                    try:
                        content = payload.decode('utf-8', errors='ignore')
                    except:
                        content = str(payload)
                    
                    # 检查每个模式
                    for pattern in rule['patterns']:
                        if isinstance(pattern, re.Pattern):
                            if pattern.search(content):
                                content_matched = True
                                break
                        else:
                            if pattern in content:
                                content_matched = True
                                break
                    
                    if not content_matched:
                        continue
                
                # 匹配规则后更新规则命中计数
                rule['rule_obj'].hits += 1
                rule['rule_obj'].save(update_fields=['hits'])
                
                # 根据规则动作返回结果
                return rule['action'], rule
            
            # 如果没有匹配的规则，返回默认值
            return default_action, default_rule
            
        except Exception as e:
            logger.error(f"应用规则时出错: {str(e)}")
            return default_action, default_rule
    
    def _ip_matches(self, ip: str, rule_ip: str) -> bool:
        """
        检查IP是否匹配规则
        
        Args:
            ip: 要检查的IP
            rule_ip: 规则中的IP表达式
            
        Returns:
            bool: 是否匹配
        """
        # 如果规则IP为空，视为匹配任何IP
        if not rule_ip or rule_ip == '*':
            return True
        
        # 如果是精确匹配
        if rule_ip == ip:
            return True
        
        # 如果是CIDR格式
        if '/' in rule_ip:
            try:
                network = ipaddress.ip_network(rule_ip, strict=False)
                return ipaddress.ip_address(ip) in network
            except:
                return False
        
        # 如果是IP范围 (格式如: 192.168.1.1-192.168.1.100)
        if '-' in rule_ip:
            try:
                start_ip, end_ip = rule_ip.split('-')
                start_ip = ipaddress.ip_address(start_ip.strip())
                end_ip = ipaddress.ip_address(end_ip.strip())
                ip_addr = ipaddress.ip_address(ip)
                return start_ip <= ip_addr <= end_ip
            except:
                return False
        
        # 如果是通配符格式 (格式如: 192.168.1.*)
        if '*' in rule_ip:
            pattern = rule_ip.replace('.', '\\.').replace('*', '.*')
            return re.match(f'^{pattern}$', ip) is not None
        
        return False
    
    def _port_matches(self, port: int, rule_port: str) -> bool:
        """
        检查端口是否匹配规则
        
        Args:
            port: 要检查的端口
            rule_port: 规则中的端口表达式
            
        Returns:
            bool: 是否匹配
        """
        # 如果规则端口为空，视为匹配任何端口
        if not rule_port or rule_port == '*':
            return True
        
        # 如果是精确匹配
        try:
            if int(rule_port) == port:
                return True
        except:
            pass
        
        # 如果是端口范围 (格式如: 1000-2000)
        if '-' in rule_port:
            try:
                start_port, end_port = rule_port.split('-')
                start_port = int(start_port.strip())
                end_port = int(end_port.strip())
                return start_port <= port <= end_port
            except:
                return False
        
        # 如果是端口列表 (格式如: 80,443,8080)
        if ',' in rule_port:
            try:
                ports = [int(p.strip()) for p in rule_port.split(',')]
                return port in ports
            except:
                return False
        
        return False
    
    def _update_stats(self, direction: str, packet_size: int):
        """
        更新统计信息
        
        Args:
            direction: 数据包方向 ('inbound' or 'outbound')
            packet_size: 数据包大小(字节)
        """
        if direction == 'inbound':
            self.stats['inbound_packets'] += 1
            self.stats['inbound_bytes'] += packet_size
        else:
            self.stats['outbound_packets'] += 1
            self.stats['outbound_bytes'] += packet_size
        
        # 每5秒保存一次统计数据
        now = datetime.now()
        if (now - self.stats['last_update']).total_seconds() >= 5:
            self._save_stats()
            self.stats['last_update'] = now
    
    def _save_stats(self):
        """保存流量统计到数据库"""
        try:
            with self.lock:  # 添加锁保护
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
                
                # 创建新的统计记录
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
                
                # 重置统计值（使用统一的方式）
                for key in self.stats:
                    if key != 'last_update':
                        self.stats[key] = 0
                self.stats['last_update'] = datetime.now()
                
                logger.info("流量统计已保存到数据库")
        except Exception as e:
            logger.error(f"保存统计数据失败: {str(e)}")
    
    def _statistics_updater(self):
        """统计数据更新线程"""
        while self._running:
            time.sleep(5)  # 保持5秒更新一次
            try:
                with transaction.atomic():
                    self._save_stats()
            except Exception as e:
                logger.error(f"更新统计数据失败: {str(e)}")
    
    def _log_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                   protocol: str, packet, direction: str, action: str, rule: Rule):
        """记录数据包日志"""
        try:
            with transaction.atomic():  # 添加事务保护
                # 获取或创建协议对象
                protocol_obj = self.protocol_cache.get(protocol.lower())
                if not protocol_obj:
                    protocol_obj, _ = Protocol.objects.get_or_create(
                        name=protocol,
                        defaults={'description': f'{protocol}协议'}
                    )
                    self.protocol_cache[protocol.lower()] = protocol_obj
                
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
                    status=action,
                    matched_rule=rule
                )
                
                # 如果是可疑或阻断的数据包，进行深度检测
                if action in ['suspicious', 'blocked']:
                    self._perform_deep_inspection(packet_log, packet)
                
                # 如果规则动作是告警，创建告警日志
                if action == 'alert':
                    self._create_alert(rule, src_ip, packet)
                    
                # 更新统计计数
                if action == 'blocked':
                    with self.lock:
                        self.stats['blocked_packets'] += 1
                    
        except Exception as e:
            logger.error(f"记录数据包日志失败: {str(e)}")
    
    def _perform_deep_inspection(self, packet_log: PacketLog, packet):
        """
        执行深度包检测
        
        Args:
            packet_log: 数据包日志对象
            packet: 原始数据包
        """
        try:
            # 提取应用层协议和内容类型
            app_protocol = "UNKNOWN"
            content_type = ""
            detected_patterns = ""
            risk_level = "low"
            is_malicious = False
            metadata = {}
            
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
                
                # 尝试提取更多HTTP信息
                if app_protocol in ["HTTP", "HTTPS"] and packet.haslayer(scapy.Raw):
                    try:
                        raw_data = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
                        
                        # 提取HTTP头信息
                        if "Content-Type:" in raw_data:
                            content_type = re.search(r"Content-Type:\s*([^\r\n]+)", raw_data).group(1)
                        
                        # 检查是否包含常见攻击模式
                        attack_patterns = {
                            "SQL注入": [r"SELECT.*FROM", r"INSERT.*INTO", r"UPDATE.*SET", r"DELETE.*FROM", r"DROP.*TABLE"],
                            "XSS": [r"<script>", r"javascript:", r"alert\(", r"onload=", r"onerror="],
                            "命令注入": [r"system\(", r"exec\(", r"shell_exec", r"passthru", r";ls", r";cat", r"|grep"]
                        }
                        
                        found_patterns = []
                        for attack_type, patterns in attack_patterns.items():
                            for pattern in patterns:
                                if re.search(pattern, raw_data, re.IGNORECASE):
                                    found_patterns.append(f"{attack_type}:{pattern}")
                                    is_malicious = True
                                    risk_level = "high"
                        
                        if found_patterns:
                            detected_patterns = "; ".join(found_patterns[:5])  # 最多记录5个模式
                            metadata["attack_details"] = found_patterns
                        
                        # 提取HTTP方法、URL和用户代理
                        if "GET " in raw_data or "POST " in raw_data or "HTTP/" in raw_data:
                            method_match = re.search(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+([^\s]+)", raw_data)
                            if method_match:
                                metadata["http_method"] = method_match.group(1)
                                metadata["http_url"] = method_match.group(2)
                            
                            user_agent_match = re.search(r"User-Agent:\s*([^\r\n]+)", raw_data)
                            if user_agent_match:
                                metadata["user_agent"] = user_agent_match.group(1)
                    except:
                        pass
                
            elif packet.haslayer(UDP):
                dst_port = packet[UDP].dport
                if dst_port == 53:
                    app_protocol = "DNS"
                    
                    # 尝试提取DNS查询信息
                    if packet.haslayer(scapy.DNS):
                        try:
                            dns = packet[scapy.DNS]
                            if dns.qr == 0:  # 0表示查询
                                metadata["dns_query"] = dns.qd.qname.decode() if hasattr(dns, 'qd') and dns.qd else ""
                                metadata["dns_type"] = dns.qd.qtype if hasattr(dns, 'qd') and dns.qd else 0
                        except:
                            pass
            
            # 检测风险级别
            if packet_log.status == 'blocked':
                if not is_malicious:  # 如果之前没有设置为恶意
                    risk_level = "high"
                    is_malicious = True
            elif packet_log.status == 'suspicious':
                if risk_level == 'low':  # 如果之前没有设置为高风险
                    risk_level = "medium"
            
            # 创建深度检测结果
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
            logger.error(f"执行深度包检测失败: {str(e)}")
    
    def _create_alert(self, rule: Rule, src_ip: str, packet):
        """
        创建告警日志
        
        Args:
            rule: 触发告警的规则
            src_ip: 源IP
            packet: 原始数据包
        """
        try:
            level = "info"
            if rule.priority == "high":
                level = "warning"
            elif rule.priority == "critical":
                level = "critical"
            
            title = f"{rule.name} - 发现{rule.get_priority_display()}风险流量"
            description = f"规则 '{rule.name}' 检测到可疑流量。\n"
            description += f"源IP: {src_ip}\n"
            if rule.log_prefix:
                description += f"详情: {rule.log_prefix}\n"
            
            AlertLog.objects.create(
                timestamp=timezone.now(),
                level=level,
                title=title,
                description=description,
                source_ip=src_ip
            )
            
        except Exception as e:
            logger.error(f"创建告警日志失败: {str(e)}")
    
    def block_ip(self, ip_address: str, reason: str = "", permanent: bool = False, 
                duration: int = 24) -> bool:
        """
        将IP添加到黑名单
        
        Args:
            ip_address: 要阻止的IP
            reason: 阻止原因
            permanent: 是否永久阻止
            duration: 阻止时长(小时)
            
        Returns:
            bool: 是否成功
        """
        try:
            # 检查是否已在黑名单中
            if ip_address in self.blacklist_ips:
                return True
                
            # 设置过期时间
            expiry = None
            if not permanent:
                expiry = timezone.now() + timedelta(hours=duration)
            
            # 添加到数据库
            IPBlacklist.objects.create(
                ip_address=ip_address,
                description=reason or "手动添加",
                added_at=timezone.now(),
                expiry=expiry,
                is_permanent=permanent
            )
            
            # 添加到内存中的黑名单
            self.blacklist_ips.add(ip_address)
            
            logger.info(f"IP {ip_address} 已添加到黑名单 {'(永久)' if permanent else f'(过期时间: {expiry})'}")
            return True
            
        except Exception as e:
            logger.error(f"添加IP到黑名单失败: {str(e)}")
            return False
    
    def unblock_ip(self, ip_address: str) -> bool:
        """
        从黑名单中移除IP
        
        Args:
            ip_address: 要解除阻止的IP
            
        Returns:
            bool: 是否成功
        """
        try:
            # 从数据库中删除
            removed = IPBlacklist.objects.filter(ip_address=ip_address).delete()[0] > 0
            
            # 如果成功删除，从内存中也移除
            if removed and ip_address in self.blacklist_ips:
                self.blacklist_ips.remove(ip_address)
                logger.info(f"IP {ip_address} 已从黑名单中移除")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"从黑名单移除IP失败: {str(e)}")
            return False
    
    def add_to_whitelist(self, ip_address: str, reason: str = "") -> bool:
        """
        将IP添加到白名单
        
        Args:
            ip_address: 要添加的IP
            reason: 添加原因
            
        Returns:
            bool: 是否成功
        """
        try:
            # 检查是否已在白名单中
            if ip_address in self.whitelist_ips:
                return True
                
            # 添加到数据库
            IPWhitelist.objects.create(
                ip_address=ip_address,
                description=reason or "手动添加",
                added_at=timezone.now()
            )
            
            # 添加到内存中的白名单
            self.whitelist_ips.add(ip_address)
            
            logger.info(f"IP {ip_address} 已添加到白名单")
            return True
            
        except Exception as e:
            logger.error(f"添加IP到白名单失败: {str(e)}")
            return False
    
    def remove_from_whitelist(self, ip_address: str) -> bool:
        """
        从白名单中移除IP
        
        Args:
            ip_address: 要移除的IP
            
        Returns:
            bool: 是否成功
        """
        try:
            # 从数据库中删除
            removed = IPWhitelist.objects.filter(ip_address=ip_address).delete()[0] > 0
            
            # 如果成功删除，从内存中也移除
            if removed and ip_address in self.whitelist_ips:
                self.whitelist_ips.remove(ip_address)
                logger.info(f"IP {ip_address} 已从白名单中移除")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"从白名单移除IP失败: {str(e)}")
            return False
    
    def get_status(self) -> Dict:
        """
        获取防火墙状态信息
        
        Returns:
            Dict: 状态信息
        """
        try:
            return {
                'running': self._running,
                'rules_count': len(self.rules) if hasattr(self, 'rules') else 0,
                'blacklist_count': len(self.blacklist_ips) if hasattr(self, 'blacklist_ips') else 0,
                'whitelist_count': len(self.whitelist_ips) if hasattr(self, 'whitelist_ips') else 0,
                'stats': {
                    'inbound_packets': self.stats.get('inbound_packets', 0) if hasattr(self, 'stats') else 0,
                    'outbound_packets': self.stats.get('outbound_packets', 0) if hasattr(self, 'stats') else 0,
                    'inbound_bytes': self.stats.get('inbound_bytes', 0) if hasattr(self, 'stats') else 0,
                    'outbound_bytes': self.stats.get('outbound_bytes', 0) if hasattr(self, 'stats') else 0,
                    'blocked_packets': self.stats.get('blocked_packets', 0) if hasattr(self, 'stats') else 0,
                    'suspicious_packets': self.stats.get('suspicious_packets', 0) if hasattr(self, 'stats') else 0,
                },
                'sessions': len(self.active_sessions) if hasattr(self, 'active_sessions') else 0,
            }
        except Exception as e:
            logger.error(f"获取防火墙状态时出错: {str(e)}")
            # 返回默认状态
            return {
                'running': False,
                'rules_count': 0,
                'blacklist_count': 0,
                'whitelist_count': 0,
                'stats': {
                    'inbound_packets': 0,
                    'outbound_packets': 0,
                    'inbound_bytes': 0,
                    'outbound_bytes': 0,
                    'blocked_packets': 0,
                    'suspicious_packets': 0,
                },
                'sessions': 0,
                'error': str(e)
            }
    
    def _create_packet_log(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                          protocol_name: str, packet, direction: str, status: str) -> PacketLog:
        """创建数据包日志记录"""
        try:
            # 获取或创建协议对象
            protocol_obj = self.protocol_cache.get(protocol_name.lower())
            if not protocol_obj:
                protocol_obj, _ = Protocol.objects.get_or_create(
                    name=protocol_name,
                    defaults={'description': f'{protocol_name}协议'}
                )
                self.protocol_cache[protocol_name.lower()] = protocol_obj
            
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
                status=status
            )
            
            return packet_log
        except Exception as e:
            logger.error(f"创建数据包日志失败: {str(e)}")
            return None
    
    def _create_waf_alert(self, waf_result: WAFDetectionResult, src_ip: str, dst_ip: str, protocol: str):
        """创建WAF检测告警"""
        try:
            level = "info"
            if waf_result.risk_level == "high":
                level = "critical"
            elif waf_result.risk_level == "medium":
                level = "warning"
            
            title = f"WAF检测 - {waf_result.attack_type.upper()} 攻击"
            description = f"检测到Web应用攻击: {waf_result.description}\n"
            description += f"源IP: {src_ip}\n"
            description += f"目标IP: {dst_ip}\n"
            description += f"协议: {protocol}\n"
            description += f"置信度: {waf_result.confidence * 100:.1f}%\n"
            if waf_result.matched_patterns:
                description += f"匹配模式: {', '.join(waf_result.matched_patterns[:3])}\n"
            
            AlertLog.objects.create(
                timestamp=timezone.now(),
                level=level,
                title=title,
                description=description,
                source_ip=src_ip
            )
            
        except Exception as e:
            logger.error(f"创建WAF告警失败: {str(e)}") 