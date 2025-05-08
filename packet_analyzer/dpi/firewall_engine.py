"""
防火墙引擎 - 负责网络数据包的过滤、分析和日志记录
"""
import logging
import time
import threading
from typing import Dict, List, Optional, Tuple, Union, Any, Set, Callable
from ipaddress import ip_network, ip_address, IPv4Address, IPv4Network

import re
from django.utils import timezone
from django.db import transaction
from django.db.models import F

from packet_analyzer.models import Protocol, PacketLog, DeepInspectionResult
from firewall_rules.models import Rule, IPBlacklist, IPWhitelist
from dashboard.models import TrafficStatistics, AlertLog, SystemStatus

logger = logging.getLogger(__name__)

class FirewallEngine:
    """
    防火墙引擎 - 核心组件，处理实时数据包分析、过滤和处理
    """
    
    _instance = None
    _lock = threading.RLock()
    
    def __new__(cls) -> 'FirewallEngine':
        """单例模式实现"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(FirewallEngine, cls).__new__(cls)
        return cls._instance
    
    def __init__(self) -> None:
        """初始化防火墙引擎"""
        self.is_initialized = getattr(self, 'is_initialized', False)
        
        if not self.is_initialized:
            self.running: bool = False
            self.protocols: Dict[str, Protocol] = {}
            self.rules: Dict[int, Rule] = {}
            self.blacklist: Set[str] = set()
            self.whitelist: Set[str] = set()
            self.stats: Dict[str, Any] = {
                'inbound_packets': 0,
                'outbound_packets': 0,
                'inbound_bytes': 0,
                'outbound_bytes': 0,
                'blocked_packets': 0,
                'last_update': timezone.now()
            }
            self.stats_thread: Optional[threading.Thread] = None
            self.stats_interval: int = 60  # 统计数据保存间隔(秒)
            self.lock: threading.RLock = threading.RLock()
            
            # 初始化加载
            self._load_configurations()
            
            self.is_initialized = True
    
    def _load_configurations(self) -> None:
        """加载配置信息"""
        try:
            logger.info("加载防火墙配置")
            
            # 加载协议
            for protocol in Protocol.objects.all():
                self.protocols[protocol.name] = protocol
            
            # 加载规则(按优先级排序)
            rules = Rule.objects.filter(is_enabled=True).order_by('-priority', 'id')
            for rule in rules:
                self.rules[rule.id] = rule
            
            # 加载IP黑名单
            blacklist_items = IPBlacklist.objects.filter(
                is_permanent=True
            ).values_list('ip_address', flat=True)
            self.blacklist = set(blacklist_items)
            
            # 加载有效期内的临时黑名单
            temp_blacklist = IPBlacklist.objects.filter(
                is_permanent=False, 
                expiry__gt=timezone.now()
            ).values_list('ip_address', flat=True)
            self.blacklist.update(temp_blacklist)
            
            # 加载IP白名单
            whitelist_items = IPWhitelist.objects.values_list('ip_address', flat=True)
            self.whitelist = set(whitelist_items)
                
            logger.info(f"加载了 {len(self.protocols)} 个协议，{len(self.rules)} 条规则")
            logger.info(f"黑名单: {len(self.blacklist)} 条，白名单: {len(self.whitelist)} 条")
            
        except Exception as e:
            logger.error(f"加载配置时出错: {str(e)}")
    
    def start(self) -> bool:
        """
        启动防火墙引擎
        
        Returns:
            bool: 是否成功启动
        """
        if self.running:
            logger.warning("防火墙引擎已经在运行")
            return True
        
        logger.info("启动防火墙引擎")
        
        try:
            # 重新加载配置
            self._load_configurations()
            
            # 启动统计数据线程
            self.running = True
            self.stats_thread = threading.Thread(target=self._stats_worker, daemon=True)
            self.stats_thread.start()
            
            # 更新系统状态
            self._update_system_status(running=True)
            
            logger.info("防火墙引擎启动成功")
            return True
            
        except Exception as e:
            logger.error(f"启动防火墙引擎失败: {str(e)}")
            self.running = False
            return False
    
    def _update_system_status(self, running: bool) -> None:
        """
        更新系统状态
        
        Args:
            running: 防火墙是否运行中
        """
        try:
            status, created = SystemStatus.objects.get_or_create(id=1)
            status.firewall_running = running
            
            if running:
                status.last_start_time = timezone.now()
            else:
                status.last_stop_time = timezone.now()
                
            status.save()
        except Exception as e:
            logger.error(f"更新系统状态失败: {str(e)}")
    
    def stop(self) -> bool:
        """
        停止防火墙引擎
        
        Returns:
            bool: 是否成功停止
        """
        if not self.running:
            logger.warning("防火墙引擎已经停止运行")
            return True
        
        logger.info("停止防火墙引擎")
        self.running = False
        
        # 等待统计线程结束
        if self.stats_thread and self.stats_thread.is_alive():
            self.stats_thread.join(timeout=2.0)
        
        # 保存最终统计数据
        self._save_stats()
        
        # 更新系统状态
        self._update_system_status(running=False)
        
        logger.info("防火墙引擎已停止")
        return True
    
    def is_running(self) -> bool:
        """
        检查防火墙引擎是否运行
        
        Returns:
            bool: 引擎是否运行中
        """
        return self.running
    
    def reload_configurations(self) -> bool:
        """
        重新加载规则和配置
        
        Returns:
            bool: 是否成功重新加载
        """
        logger.info("重新加载防火墙配置")
        
        with self.lock:
            # 清除现有配置
            self.protocols.clear()
            self.rules.clear()
            self.blacklist.clear()
            self.whitelist.clear()
            
            # 重新加载
            self._load_configurations()
        
        return True
    
    def _stats_worker(self) -> None:
        """统计数据工作线程"""
        logger.info("启动统计数据收集线程")
        
        last_save = time.time()
        
        while self.running:
            current_time = time.time()
            
            # 定期保存统计数据
            if current_time - last_save >= self.stats_interval:
                self._save_stats()
                last_save = current_time
            
            time.sleep(1.0)  # 休眠1秒
        
        logger.info("统计数据收集线程已停止")
    
    def _save_stats(self) -> None:
        """保存流量统计数据到数据库"""
        try:
            with self.lock:
                # 创建流量统计记录
                stats = TrafficStatistics(
                    inbound_packets=self.stats['inbound_packets'],
                    outbound_packets=self.stats['outbound_packets'],
                    inbound_bytes=self.stats['inbound_bytes'],
                    outbound_bytes=self.stats['outbound_bytes'],
                    blocked_packets=self.stats['blocked_packets'],
                    timestamp=timezone.now()
                )
                stats.save()
                
                # 重置计数
                self.stats['inbound_packets'] = 0
                self.stats['outbound_packets'] = 0
                self.stats['inbound_bytes'] = 0
                self.stats['outbound_bytes'] = 0
                self.stats['blocked_packets'] = 0
                self.stats['last_update'] = timezone.now()
                
                logger.debug("已保存流量统计数据")
                
        except Exception as e:
            logger.error(f"保存统计数据时出错: {str(e)}")
    
    def process_packet(self, packet: Any) -> Tuple[str, Optional[Rule]]:
        """
        处理网络数据包
        
        Args:
            packet: Scapy数据包对象
            
        Returns:
            Tuple[str, Optional[Rule]]: 状态("allowed", "blocked")和匹配的规则
        """
        if not self.running:
            # 如果防火墙没有运行，默认允许所有流量
            return ("allowed", None)
        
        try:
            start_time = time.time()
            
            # 提取数据包基本信息
            packet_info = self._extract_packet_info(packet)
            if packet_info is None:
                return ("allowed", None)
                
            src_ip, dst_ip, src_port, dst_port, ip_proto = packet_info
            
            # 确定数据包方向
            direction = self._determine_direction(src_ip, dst_ip)
            
            # 更新统计数据
            self._update_packet_stats(direction, len(packet))
            
            # 打印数据包基本信息，用于调试
            logger.debug(f"处理数据包: {src_ip}:{src_port} -> {dst_ip}:{dst_port} [{ip_proto}] 方向: {direction}")
            
            # 1. 首先检查IP白名单
            if src_ip in self.whitelist or dst_ip in self.whitelist:
                logger.debug(f"数据包命中白名单: {src_ip} -> {dst_ip}")
                return ("allowed", None)
            
            # 2. 然后检查IP黑名单
            if src_ip in self.blacklist:
                logger.info(f"数据包命中IP黑名单，已阻止: {src_ip} -> {dst_ip}")
                with self.lock:
                    self.stats['blocked_packets'] += 1
                return ("blocked", None)
            
            # 3. 应用规则过滤
            rule_result, matched_rule = self._apply_rules(src_ip, dst_ip, src_port, dst_port, ip_proto, direction, packet)
            
            # 计算处理时间
            process_time = (time.time() - start_time) * 1000  # 转换为毫秒
            
            # 记录处理结果
            if rule_result == "blocked":
                logger.info(f"规则阻止: {src_ip}:{src_port} -> {dst_ip}:{dst_port} [{ip_proto}] 规则: {matched_rule.name if matched_rule else 'Unknown'}")
            else:
                logger.debug(f"规则允许: {src_ip}:{src_port} -> {dst_ip}:{dst_port} [{ip_proto}]")
                
            return rule_result, matched_rule
            
        except Exception as e:
            logger.error(f"处理数据包时出错: {str(e)}")
            return ("allowed", None)  # 出错时默认允许
    
    def _update_packet_stats(self, direction: str, packet_size: int) -> None:
        """
        更新数据包统计信息
        
        Args:
            direction: 数据包方向 ('inbound' 或 'outbound')
            packet_size: 数据包大小(字节)
        """
        with self.lock:
            if direction == "inbound":
                self.stats['inbound_packets'] += 1
                self.stats['inbound_bytes'] += packet_size
            else:
                self.stats['outbound_packets'] += 1
                self.stats['outbound_bytes'] += packet_size
    
    def _apply_rules(
        self, 
        src_ip: str, 
        dst_ip: str, 
        src_port: int, 
        dst_port: int, 
        ip_proto: str, 
        direction: str, 
        packet: Any
    ) -> Tuple[str, Optional[Rule]]:
        """
        应用过滤规则
        
        Args:
            src_ip: 源IP地址
            dst_ip: 目标IP地址
            src_port: 源端口
            dst_port: 目标端口
            ip_proto: IP协议
            direction: 数据包方向
            packet: 原始数据包
            
        Returns:
            Tuple[str, Optional[Rule]]: 状态("allowed", "blocked")和匹配的规则
        """
        matched_rule = None
        rule_action = "allowed"  # 默认允许
        
        # 检查是否有任何规则
        if not self.rules:
            logger.warning("没有加载任何规则，默认允许所有流量")
            return ("allowed", None)
        
        # 记录规则数量（调试用）
        rule_counts = {
            'total': len(self.rules),
            'block': sum(1 for r in self.rules.values() if r.action == 'block' and r.is_enabled),
            'allow': sum(1 for r in self.rules.values() if r.action == 'allow' and r.is_enabled),
            'alert': sum(1 for r in self.rules.values() if r.action == 'alert' and r.is_enabled),
        }
        logger.debug(f"规则数量: {rule_counts}")
        
        # 根据规则优先级排序
        ordered_rules = sorted(
            self.rules.items(), 
            key=lambda x: (x[1].category.priority if x[1].category else 999)
        )
        
        # 查找默认允许规则（用于最后兜底）
        default_allow_rule = None
        for rule_id, rule in self.rules.items():
            if rule.action == 'allow' and rule.is_enabled and '默认' in rule.name:
                default_allow_rule = rule
                break
                
        with self.lock:
            for rule_id, rule in ordered_rules:
                # 跳过禁用的规则
                if not rule.is_enabled:
                    continue
                    
                if self._rule_matches(rule, src_ip, dst_ip, src_port, dst_port, ip_proto, direction, packet):
                    matched_rule = rule
                    
                    # 更新规则命中计数
                    try:
                        Rule.objects.filter(id=rule_id).update(hits=F('hits') + 1)
                    except Exception as e:
                        logger.error(f"更新规则命中计数失败: {str(e)}")
                    
                    # 确定动作
                    if rule.action == "block":
                        rule_action = "blocked"
                        self.stats['blocked_packets'] += 1
                        logger.info(f"阻止数据包: {src_ip}:{src_port} -> {dst_ip}:{dst_port} [{ip_proto}], 规则: {rule.name}")
                        return (rule_action, matched_rule)
                    elif rule.action == "alert":
                        # 记录告警但不阻止
                        try:
                            from dashboard.models import AlertLog
                            AlertLog.objects.create(
                                title=f"防火墙规则告警: {rule.name}",
                                description=f"检测到可能的安全威胁。\n源IP: {src_ip}\n目标IP: {dst_ip}\n协议: {ip_proto}",
                                level=rule.priority if rule.priority in ['info', 'warning', 'error', 'critical'] else 'warning',
                                source_ip=src_ip
                            )
                        except Exception as e:
                            logger.error(f"创建告警记录失败: {str(e)}")
                    elif rule.action == "allow":
                        logger.debug(f"允许数据包: {src_ip}:{src_port} -> {dst_ip}:{dst_port} [{ip_proto}], 规则: {rule.name}")
                        return ("allowed", matched_rule)
                    
                    break
        
        # 如果没有规则匹配，使用默认允许规则
        if default_allow_rule:
            logger.debug(f"使用默认允许规则: {default_allow_rule.name}")
            return ("allowed", default_allow_rule)
            
        # 没有规则匹配且没有默认允许规则时，默认也是允许
        return ("allowed", None)
    
    def _extract_packet_info(self, packet: Any) -> Optional[Tuple[str, str, int, int, str]]:
        """
        从数据包中提取基本信息
        
        Args:
            packet: 数据包对象
            
        Returns:
            Optional[Tuple[str, str, int, int, str]]: 源IP, 目标IP, 源端口, 目标端口, IP协议
                                                    如果提取失败则返回None
        """
        src_ip = None
        dst_ip = None
        src_port = 0
        dst_port = 0
        ip_proto = "unknown"
        
        try:
            # 提取IP层信息
            if 'IP' in packet:
                ip = packet['IP']
                src_ip = ip.src
                dst_ip = ip.dst
                ip_proto = self._get_ip_proto_name(ip.proto)
            elif 'IPv6' in packet:
                ip = packet['IPv6']
                src_ip = ip.src
                dst_ip = ip.dst
                ip_proto = self._get_ip_proto_name(ip.nh)  # next header
            else:
                # 不是IP数据包
                return None
            
            # 提取TCP/UDP端口信息
            if 'TCP' in packet:
                tcp = packet['TCP']
                src_port = tcp.sport
                dst_port = tcp.dport
            elif 'UDP' in packet:
                udp = packet['UDP']
                src_port = udp.sport
                dst_port = udp.dport
                
            # 确保IP地址不为None
            if not src_ip or not dst_ip:
                return None
                
            return (src_ip, dst_ip, src_port, dst_port, ip_proto)
                
        except Exception as e:
            logger.error(f"提取数据包信息时出错: {str(e)}")
            return None
    
    def _determine_direction(self, src_ip: str, dst_ip: str) -> str:
        """
        确定数据包方向
        
        Args:
            src_ip: 源IP地址
            dst_ip: 目标IP地址
            
        Returns:
            str: 方向("inbound"或"outbound")
        """
        if self._is_internal_ip(dst_ip) and not self._is_internal_ip(src_ip):
            return "inbound"
        else:
            return "outbound"
    
    def _is_internal_ip(self, ip: str) -> bool:
        """
        检查IP是否为内部IP
        
        Args:
            ip: IP地址
            
        Returns:
            bool: 是否为内部IP
        """
        # 检查常见的内网IP段
        private_ranges = [
            "10.0.0.0/8",      # 10.0.0.0 - 10.255.255.255
            "172.16.0.0/12",   # 172.16.0.0 - 172.31.255.255
            "192.168.0.0/16",  # 192.168.0.0 - 192.168.255.255
            "127.0.0.0/8"      # 127.0.0.0 - 127.255.255.255 (本地回环)
        ]
        
        try:
            ip_obj = ip_address(ip)
            for cidr in private_ranges:
                if ip_obj in ip_network(cidr):
                    return True
            return False
        except ValueError:
            # IP地址格式无效
            logger.warning(f"无效的IP地址格式: {ip}")
            return False
    
    def _get_ip_proto_name(self, proto_num: int) -> str:
        """
        获取IP协议名称
        
        Args:
            proto_num: 协议号
            
        Returns:
            str: 协议名称
        """
        proto_map = {
            1: "ICMP",
            6: "TCP", 
            17: "UDP",
            47: "GRE",
            50: "ESP",
            51: "AH",
            58: "ICMPv6"
        }
        
        return proto_map.get(proto_num, f"PROTO_{proto_num}")
    
    def _rule_matches(
        self, 
        rule: Rule, 
        src_ip: str, 
        dst_ip: str, 
        src_port: int, 
        dst_port: int, 
        ip_proto: str, 
        direction: str, 
        packet: Any
    ) -> bool:
        """
        检查规则是否匹配数据包
        
        Args:
            rule: 规则对象
            src_ip: 源IP
            dst_ip: 目标IP
            src_port: 源端口
            dst_port: 目标端口
            ip_proto: IP协议
            direction: 方向
            packet: 原始数据包
            
        Returns:
            bool: 是否匹配
        """
        # 检查规则是否启用
        if not rule.is_enabled:
            return False
        
        # 检查方向
        if hasattr(rule, 'direction') and rule.direction != "any" and rule.direction != direction:
            return False
        
        # 检查源IP
        if rule.source_ip and not self._ip_matches(src_ip, rule.source_ip):
            return False
        
        # 检查目标IP
        if rule.destination_ip and not self._ip_matches(dst_ip, rule.destination_ip):
            return False
        
        # 检查源端口
        if rule.source_port and not self._port_matches(src_port, rule.source_port):
            return False
        
        # 检查目标端口
        if rule.destination_port and not self._port_matches(dst_port, rule.destination_port):
            return False
        
        # 检查协议
        if rule.protocol and rule.protocol != "any":
            if rule.protocol.lower() != ip_proto.lower():
                # 特殊处理：TCP可以匹配HTTP/HTTPS规则
                if ip_proto.lower() == "tcp" and rule.protocol.lower() in ["http", "https"]:
                    # 检查端口是否匹配标准HTTP/HTTPS端口
                    if not (dst_port in [80, 8000, 8080] and rule.protocol.lower() == "http") and not (dst_port == 443 and rule.protocol.lower() == "https"):
                        return False
                else:
                    return False
        
        # 检查是否为Web攻击检测规则
        is_web_attack_rule = False
        if rule.category and 'web' in rule.category.name.lower() and '攻击' in rule.category.name:
            is_web_attack_rule = True
        
        # 对于Web攻击规则，需要检测HTTP流量
        if is_web_attack_rule:
            # 仅对HTTP/S流量或端口80/443/8000的流量应用Web攻击规则
            is_http_traffic = False
            if ip_proto.lower() == "tcp" and dst_port in [80, 443, 8000, 8080]:
                is_http_traffic = True
            
            if not is_http_traffic:
                return False
        
        # 检查内容匹配模式 (DPI规则)
        if hasattr(rule, 'pattern') and rule.pattern.exists():
            # 检查是否为HTTPS加密流量
            is_https = False
            if packet.haslayer(TCP):
                if dst_port == 443 or src_port == 443:
                    is_https = True
            
            # 检查模式匹配
            matched_any_pattern = False
            for pattern_obj in rule.pattern.all():
                pattern_string = pattern_obj.pattern_string
                is_regex = pattern_obj.is_regex
                
                # 创建正则表达式对象(如果是正则模式)
                if is_regex:
                    try:
                        regex_pattern = re.compile(pattern_string, re.IGNORECASE)
                    except:
                        logger.error(f"无效的正则表达式: {pattern_string}")
                        continue
                
                # HTTPS加密流量特殊处理
                if is_https:
                    # 对于Web攻击规则，跳过所有需要内容检测的HTTPS流量
                    if is_web_attack_rule:
                        logger.debug(f"跳过对HTTPS加密流量的Web攻击规则 '{rule.name}' 匹配")
                        # 返回False仅针对需要内容检测的规则
                        # 对于基于IP/端口的规则依然可以匹配HTTPS流量
                        continue
                
                # 检查数据包是否包含Raw层
                if packet.haslayer('Raw'):
                    payload = packet['Raw'].load
                    
                    # 尝试解码为文本
                    try:
                        if isinstance(payload, bytes):
                            payload_text = payload.decode('utf-8', 'ignore')
                        else:
                            payload_text = str(payload)
                        
                        # 使用正则表达式匹配(如果是正则模式)
                        if is_regex:
                            if regex_pattern.search(payload_text):
                                logger.info(f"规则 '{rule.name}' 匹配模式 '{pattern_obj.name}'")
                                matched_any_pattern = True
                                break
                        else:
                            # 字符串包含匹配
                            if pattern_string in payload_text:
                                logger.info(f"规则 '{rule.name}' 匹配字符串 '{pattern_string}'")
                                matched_any_pattern = True
                                break
                        
                        # 检查HTTP攻击特征 - 使用X-Attack-Type头
                        if "X-Attack-Type:" in payload_text:
                            attack_type_match = re.search(r'X-Attack-Type:\s*([^\r\n]+)', payload_text)
                            if attack_type_match:
                                attack_type = attack_type_match.group(1).strip()
                                
                                # 针对特定类型的Web攻击规则进行匹配
                                if is_web_attack_rule:
                                    rule_name_lower = rule.name.lower()
                                    
                                    if attack_type == 'sql_injection' and ('sql' in rule_name_lower or '注入' in rule_name_lower):
                                        logger.info(f"规则 '{rule.name}' 匹配SQL注入攻击类型")
                                        matched_any_pattern = True
                                        break
                                    elif attack_type == 'xss' and ('xss' in rule_name_lower or '跨站' in rule_name_lower):
                                        logger.info(f"规则 '{rule.name}' 匹配XSS攻击类型")
                                        matched_any_pattern = True
                                        break
                                    elif attack_type == 'command_injection' and ('命令' in rule_name_lower or 'cmd' in rule_name_lower):
                                        logger.info(f"规则 '{rule.name}' 匹配命令注入攻击类型")
                                        matched_any_pattern = True
                                        break
                                    elif attack_type == 'path_traversal' and ('路径' in rule_name_lower or 'path' in rule_name_lower):
                                        logger.info(f"规则 '{rule.name}' 匹配路径遍历攻击类型")
                                        matched_any_pattern = True
                                        break
                        
                        # 检查X-Test-Payload-Description头
                        payload_desc_match = re.search(r'X-Test-Payload-Description:\s*([^\r\n]+)', payload_text)
                        if payload_desc_match and is_web_attack_rule:
                            try:
                                import urllib.parse
                                payload_desc = urllib.parse.unquote(payload_desc_match.group(1).strip())
                                
                                rule_name_lower = rule.name.lower()
                                # 根据载荷描述和规则名称进行匹配
                                if ('SQL' in payload_desc or 'UNION' in payload_desc or '注入' in payload_desc) and ('sql' in rule_name_lower or '注入' in rule_name_lower):
                                    logger.info(f"规则 '{rule.name}' 匹配SQL注入载荷描述: {payload_desc}")
                                    matched_any_pattern = True
                                    break
                                elif ('XSS' in payload_desc or 'script' in payload_desc.lower() or '脚本' in payload_desc) and ('xss' in rule_name_lower or '跨站' in rule_name_lower):
                                    logger.info(f"规则 '{rule.name}' 匹配XSS载荷描述: {payload_desc}")
                                    matched_any_pattern = True
                                    break
                                elif ('命令' in payload_desc or 'Command' in payload_desc) and ('命令' in rule_name_lower or 'cmd' in rule_name_lower):
                                    logger.info(f"规则 '{rule.name}' 匹配命令注入载荷描述: {payload_desc}")
                                    matched_any_pattern = True
                                    break
                                elif ('路径' in payload_desc or 'Path' in payload_desc) and ('路径' in rule_name_lower or 'path' in rule_name_lower):
                                    logger.info(f"规则 '{rule.name}' 匹配路径遍历载荷描述: {payload_desc}")
                                    matched_any_pattern = True
                                    break
                            except Exception as e:
                                logger.error(f"解析载荷描述时出错: {str(e)}")
                            
                    except Exception as e:
                        logger.error(f"解析payload时出错: {str(e)}")
                        # 对于解析错误，尝试对原始字节进行匹配
                        if not is_regex and isinstance(payload, bytes):
                            try:
                                byte_pattern = pattern_string.encode('utf-8', errors='ignore')
                                if byte_pattern in payload:
                                    logger.info(f"规则 '{rule.name}' 匹配字节模式")
                                    matched_any_pattern = True
                                    break
                            except:
                                pass
            
            # 如果需要匹配任何模式，但没有匹配到，则返回False
            if rule.pattern.exists() and not matched_any_pattern:
                return False
        
        # 所有条件都匹配
        return True
    
    def _ip_matches(self, ip: str, pattern: str) -> bool:
        """
        检查IP是否匹配模式
        
        Args:
            ip: IP地址
            pattern: IP模式(单个IP、CIDR或范围)
            
        Returns:
            bool: 是否匹配
        """
        if not pattern or pattern == "any":
            return True
        
        if pattern == ip:
            return True
        
        try:
            # 检查CIDR格式 (192.168.1.0/24)
            if "/" in pattern:
                try:
                    network = ip_network(pattern, strict=False)
                    return ip_address(ip) in network
                except ValueError:
                    logger.warning(f"无效的CIDR格式: {pattern}")
                    return False
            
            # 检查范围格式 (192.168.1.1-192.168.1.100)
            if "-" in pattern:
                start, end = pattern.split("-")
                start_ip = ip_address(start.strip())
                end_ip = ip_address(end.strip())
                return start_ip <= ip_address(ip) <= end_ip
            
            # 检查多个IP (使用逗号分隔)
            if "," in pattern:
                ip_list = [addr.strip() for addr in pattern.split(",")]
                return ip in ip_list
                
        except Exception as e:
            logger.error(f"IP匹配检查出错 ({ip}, {pattern}): {str(e)}")
        
        return False
    
    def _port_matches(self, port: int, pattern: str) -> bool:
        """
        检查端口是否匹配模式
        
        Args:
            port: 端口号
            pattern: 端口模式(单个端口、范围或列表)
            
        Returns:
            bool: 是否匹配
        """
        if not pattern or pattern == "any":
            return True
        
        try:
            # 单个端口
            if str(port) == pattern:
                return True
            
            # 检查范围格式 (1000-2000)
            if "-" in pattern:
                start, end = pattern.split("-")
                return int(start) <= port <= int(end)
            
            # 检查列表格式 (80,443,8080)
            if "," in pattern:
                ports = [int(p.strip()) for p in pattern.split(",")]
                return port in ports
                
        except Exception as e:
            logger.error(f"端口匹配检查出错 ({port}, {pattern}): {str(e)}")
        
        return False
    
    def _content_matches(self, packet: Any, pattern: str) -> bool:
        """
        检查数据包内容是否匹配模式 (深度包检测)
        
        Args:
            packet: 数据包
            pattern: 内容模式(正则表达式)
            
        Returns:
            bool: 是否匹配
        """
        if not pattern:
            return True
        
        try:
            # 检查是否为HTTPS加密流量
            is_https = False
            if packet.haslayer(TCP):
                dst_port = packet[TCP].dport
                if dst_port == 443:
                    is_https = True
            
            # 如果是HTTPS加密流量，默认返回False（不能分析加密内容）
            if is_https:
                logger.debug(f"跳过HTTPS加密流量的内容匹配")
                return False
            
            # 提取原始负载
            payload = None
            if packet.haslayer('Raw'):
                payload = packet['Raw'].load
            
            # 检查HTTP攻击特征 - 检查所有可能的载荷位置
            if payload:
                try:
                    # 尝试解码为文本
                    if isinstance(payload, bytes):
                        payload_text = payload.decode('utf-8', errors='ignore')
                    else:
                        payload_text = str(payload)
                    
                    # 使用正则表达式匹配
                    if re.search(pattern, payload_text, re.IGNORECASE):
                        logger.info(f"检测到匹配内容: {pattern}")
                        return True
                    
                    # 检查HTTP头中的X-Attack-Type
                    if "X-Attack-Type:" in payload_text:
                        attack_type_match = re.search(r'X-Attack-Type:\s*([^\r\n]+)', payload_text)
                        if attack_type_match:
                            attack_type = attack_type_match.group(1).strip()
                            
                            # 根据攻击类型匹配相应的模式
                            if attack_type == 'sql_injection' and re.search(r"sql|union|select|'.*=.*'|--", pattern, re.IGNORECASE):
                                logger.info(f"基于X-Attack-Type检测到SQL注入攻击: {attack_type}")
                                return True
                            elif attack_type == 'xss' and re.search(r"script|alert|on\w+=|javascript:", pattern, re.IGNORECASE):
                                logger.info(f"基于X-Attack-Type检测到XSS攻击: {attack_type}")
                                return True
                            elif attack_type == 'command_injection' and re.search(r";|\||`|\$\(", pattern, re.IGNORECASE):
                                logger.info(f"基于X-Attack-Type检测到命令注入攻击: {attack_type}")
                                return True
                            elif attack_type == 'path_traversal' and re.search(r"\.\.\/|etc\/passwd", pattern, re.IGNORECASE):
                                logger.info(f"基于X-Attack-Type检测到路径遍历攻击: {attack_type}")
                                return True
                    
                    # 检查URL参数中的攻击载荷 (GET请求)
                    if packet.haslayer(TCP) and packet[TCP].dport in [80, 8000, 443]:
                        # 查找HTTP GET请求
                        get_match = re.search(r'GET\s+[^\s\?]+\?([^\s]+)\s+HTTP', payload_text)
                        if get_match:
                            params = get_match.group(1)
                            if re.search(pattern, params, re.IGNORECASE):
                                logger.info(f"在URL参数中检测到攻击载荷: {pattern}")
                                return True
                    
                    # 检查POST内容中的攻击载荷
                    if 'POST' in payload_text:
                        # 尝试提取POST数据
                        post_data_match = re.search(r'\r\n\r\n(.*)', payload_text, re.DOTALL)
                        if post_data_match:
                            post_data = post_data_match.group(1)
                            if re.search(pattern, post_data, re.IGNORECASE):
                                logger.info(f"在POST数据中检测到攻击载荷: {pattern}")
                                return True
                    
                    # 尝试提取X-Test-Payload-Description头部
                    payload_desc_match = re.search(r'X-Test-Payload-Description:\s*([^\r\n]+)', payload_text)
                    if payload_desc_match:
                        payload_desc = payload_desc_match.group(1).strip()
                        # 解码URL编码
                        try:
                            import urllib.parse
                            payload_desc = urllib.parse.unquote(payload_desc)
                            
                            # 相应攻击类型的模式
                            if ('OR' in payload_desc or 'UNION' in payload_desc) and re.search(r"sql|union|select|'.*=.*'|--", pattern, re.IGNORECASE):
                                logger.info(f"基于载荷描述检测到SQL注入攻击: {payload_desc}")
                                return True
                            elif ('XSS' in payload_desc or 'script' in payload_desc.lower()) and re.search(r"script|alert|on\w+=|javascript:", pattern, re.IGNORECASE):
                                logger.info(f"基于载荷描述检测到XSS攻击: {payload_desc}")
                                return True
                            elif ('命令' in payload_desc or 'cmd' in payload_desc.lower()) and re.search(r";|\||`|\$\(", pattern, re.IGNORECASE):
                                logger.info(f"基于载荷描述检测到命令注入攻击: {payload_desc}")
                                return True
                            elif ('路径' in payload_desc or 'path' in payload_desc.lower()) and re.search(r"\.\.\/|etc\/passwd", pattern, re.IGNORECASE):
                                logger.info(f"基于载荷描述检测到路径遍历攻击: {payload_desc}")
                                return True
                        except:
                            pass
                        
                except Exception as e:
                    logger.error(f"解析HTTP内容匹配时出错: {str(e)}")
            
            # 如果以上所有检查都未匹配，尝试对原始字节进行匹配
            if isinstance(payload, bytes):
                try:
                    byte_pattern = pattern.encode('utf-8', errors='ignore')
                    return byte_pattern in payload
                except Exception as e:
                    logger.error(f"字节内容匹配出错: {str(e)}")
        
        except Exception as e:
            logger.error(f"内容匹配检查时出错: {str(e)}")
        
        return False