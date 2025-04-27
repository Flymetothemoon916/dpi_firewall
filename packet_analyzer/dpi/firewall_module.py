import os
import logging
import time
import threading
import re
import ipaddress
from typing import Dict, List, Optional, Tuple, Any, Set

from scapy.all import IP, TCP, UDP, ICMP, ARP, send, conf, get_if_addr, get_if_list
from scapy.layers.inet import IP, TCP, UDP
from django.utils import timezone

from packet_analyzer.models import Protocol, PacketLog, DeepInspectionResult
from firewall_rules.models import Rule, IPBlacklist, IPWhitelist
from dashboard.models import TrafficStatistics, AlertLog

logger = logging.getLogger(__name__)

class FirewallModule:
    """防火墙核心模块，负责过滤和阻断恶意数据包"""
    
    def __init__(self):
        self.initialized = False
        self.rules = []
        self.blacklist_ips = set()
        self.whitelist_ips = set()
        self.local_ips = set()
        self.is_running = False
        self.lock = threading.Lock()
        self.last_stats_update = timezone.now()
        self.last_stats_time = timezone.now()
        self.stats = {
            'inbound_packets': 0,
            'outbound_packets': 0,
            'inbound_bytes': 0,
            'outbound_bytes': 0,
            'blocked_packets': 0,
        }
        self._init_local_network()
    
    def _init_local_network(self):
        """初始化本地网络信息"""
        try:
            # 获取本机IP地址
            for iface in get_if_list():
                try:
                    ip = get_if_addr(iface)
                    if ip != '0.0.0.0' and ip != '127.0.0.1':
                        self.local_ips.add(ip)
                except:
                    pass
            
            logger.info(f"本地IP地址: {self.local_ips}")
        except Exception as e:
            logger.error(f"初始化本地网络信息失败: {str(e)}")
    
    def initialize(self):
        """初始化防火墙，加载规则和IP名单"""
        if self.initialized:
            return True
        
        try:
            # 从数据库加载规则
            self._load_rules()
            
            # 从数据库加载IP黑白名单
            self._load_ip_lists()
            
            self.initialized = True
            logger.info("防火墙初始化完成")
            return True
        except Exception as e:
            logger.error(f"防火墙初始化失败: {str(e)}")
            return False
    
    def _load_rules(self):
        """从数据库加载防火墙规则"""
        self.rules = []
        active_rules = Rule.objects.filter(is_enabled=True).order_by('category__priority')
        
        for rule in active_rules:
            rule_patterns = list(rule.pattern.all())
            compiled_patterns = []
            
            for pattern in rule_patterns:
                if pattern.is_regex:
                    try:
                        compiled_patterns.append(re.compile(pattern.pattern_string))
                    except:
                        logger.error(f"正则表达式编译失败: {pattern.pattern_string}")
                else:
                    compiled_patterns.append(pattern.pattern_string)
            
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
            self.blacklist_ips.add(entry.ip_address)
        
        # 加载白名单
        self.whitelist_ips = set()
        for entry in IPWhitelist.objects.all():
            self.whitelist_ips.add(entry.ip_address)
        
        logger.info(f"已加载 {len(self.blacklist_ips)} 个黑名单IP和 {len(self.whitelist_ips)} 个白名单IP")
    
    def start(self):
        """启动防火墙"""
        if not self.initialized:
            if not self.initialize():
                return False
        
        with self.lock:
            self.is_running = True
        
        logger.info("防火墙已启动")
        return True
    
    def stop(self):
        """停止防火墙"""
        with self.lock:
            self.is_running = False
        
        logger.info("防火墙已停止")
        return True
    
    def is_active(self):
        """检查防火墙是否处于活动状态"""
        with self.lock:
            return self.is_running
    
    def reload_rules(self):
        """重新加载防火墙规则"""
        with self.lock:
            self._load_rules()
            self._load_ip_lists()
        
        logger.info("防火墙规则已重新加载")
        return True
    
    def process_packet(self, packet):
        """处理网络数据包
        
        Args:
            packet: scapy捕获的数据包
            
        Returns:
            Tuple[str, Optional[Rule]]: (决策, 匹配的规则)
        """
        if not self.is_active():
            return "allowed", None
        
        if not packet.haslayer(IP):
            return "allowed", None
        
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        # 检查黑白名单
        if src_ip in self.blacklist_ips:
            self._update_stats("blocked", len(packet))
            return "blocked", None
        
        if src_ip in self.whitelist_ips:
            self._update_stats("allowed", len(packet))
            return "allowed", None
        
        # 提取端口信息
        src_port = 0
        dst_port = 0
        protocol = "UNKNOWN"
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            protocol = "TCP"
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
        
        # 应用规则
        for rule in self.rules:
            # 检查IP匹配
            if rule['source_ip'] and not self._ip_matches(src_ip, rule['source_ip']):
                continue
            
            if rule['destination_ip'] and not self._ip_matches(dst_ip, rule['destination_ip']):
                continue
            
            # 检查端口匹配
            if rule['source_port'] and src_port > 0 and not self._port_matches(src_port, rule['source_port']):
                continue
            
            if rule['destination_port'] and dst_port > 0 and not self._port_matches(dst_port, rule['destination_port']):
                continue
            
            # 检查协议匹配
            if rule['protocol'] and protocol != rule['protocol']:
                continue
            
            # 检查DPI模式匹配
            if rule['patterns'] and packet.haslayer(TCP) or packet.haslayer(UDP):
                raw_data = bytes(packet.payload)
                match_found = False
                
                for pattern in rule['patterns']:
                    if isinstance(pattern, re.Pattern):
                        if pattern.search(str(raw_data)):
                            match_found = True
                            break
                    else:  # 字符串模式
                        if pattern in str(raw_data):
                            match_found = True
                            break
                
                if not match_found and rule['patterns']:
                    continue
            
            # 规则匹配，更新命中次数
            rule['rule_obj'].hits += 1
            rule['rule_obj'].save()
            
            # 根据规则动作决定
            action = rule['action']
            if action == 'block':
                self._update_stats("blocked", len(packet))
                return "blocked", rule['rule_obj']
            elif action == 'alert':
                self._create_alert(rule['rule_obj'], src_ip, packet)
                self._update_stats("allowed", len(packet))
                return "allowed", rule['rule_obj']
            elif action == 'log':
                self._update_stats("allowed", len(packet))
                return "allowed", rule['rule_obj']
        
        # 如果没有匹配规则，默认允许
        self._update_stats("allowed", len(packet))
        return "allowed", None
    
    def _ip_matches(self, ip: str, rule_ip: str) -> bool:
        """检查IP是否匹配规则
        
        Args:
            ip: 要检查的IP地址
            rule_ip: 规则中的IP表达式（可能包含CIDR或逗号分隔列表）
            
        Returns:
            bool: 是否匹配
        """
        if not rule_ip:
            return True
        
        # 处理逗号分隔的多个IP
        if ',' in rule_ip:
            ip_list = rule_ip.split(',')
            return any(self._ip_matches(ip, single_ip.strip()) for single_ip in ip_list)
        
        # 处理CIDR表示法
        if '/' in rule_ip:
            try:
                network = ipaddress.ip_network(rule_ip, strict=False)
                return ipaddress.ip_address(ip) in network
            except:
                return False
        
        # 完全匹配
        return ip == rule_ip
    
    def _port_matches(self, port: int, rule_port: str) -> bool:
        """检查端口是否匹配规则
        
        Args:
            port: 要检查的端口
            rule_port: 规则中的端口表达式（可能包含范围或逗号分隔列表）
            
        Returns:
            bool: 是否匹配
        """
        if not rule_port:
            return True
        
        # 处理逗号分隔的多个端口
        if ',' in rule_port:
            port_list = rule_port.split(',')
            return any(self._port_matches(port, single_port.strip()) for single_port in port_list)
        
        # 处理端口范围
        if '-' in rule_port:
            try:
                start, end = map(int, rule_port.split('-'))
                return start <= port <= end
            except:
                return False
        
        # 单个端口匹配
        try:
            return port == int(rule_port)
        except:
            return False
    
    def _update_stats(self, action: str, packet_size: int):
        """更新统计信息
        
        Args:
            action: 数据包动作（allowed/blocked）
            packet_size: 数据包大小
        """
        with self.lock:
            if action == "blocked":
                self.stats['blocked_packets'] += 1
            
            # 确定方向并更新统计
            direction = "inbound"  # 简化处理，实际应根据本机IP判断
            
            if direction == "inbound":
                self.stats['inbound_packets'] += 1
                self.stats['inbound_bytes'] += packet_size
            else:
                self.stats['outbound_packets'] += 1
                self.stats['outbound_bytes'] += packet_size
            
            # 每5分钟保存一次统计数据
            now = timezone.now()
            if (now - self.last_stats_update).total_seconds() > 300:
                self._save_stats()
                self.last_stats_update = now
    
    def _save_stats(self):
        """保存流量统计到数据库"""
        try:
            with self.lock:
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
                
                # 重置计数器
                self.stats['inbound_packets'] = 0
                self.stats['outbound_packets'] = 0
                self.stats['inbound_bytes'] = 0
                self.stats['outbound_bytes'] = 0
                self.stats['blocked_packets'] = 0
                
                logger.info("流量统计已保存到数据库")
        except Exception as e:
            logger.error(f"保存流量统计失败: {str(e)}")
    
    def _create_alert(self, rule: Rule, src_ip: str, packet):
        """创建告警记录
        
        Args:
            rule: 匹配的规则
            src_ip: 源IP地址
            packet: 数据包
        """
        try:
            # 决定告警级别
            level = 'info'
            if rule.priority == 'critical':
                level = 'critical'
            elif rule.priority == 'high':
                level = 'warning'
            
            AlertLog.objects.create(
                timestamp=timezone.now(),
                level=level,
                title=f"防火墙规则触发: {rule.name}",
                description=f"从 {src_ip} 的流量触发了规则 '{rule.name}'。{rule.description}",
                source_ip=src_ip,
                is_read=False
            )
            
            logger.info(f"已创建告警 - 规则: {rule.name}, IP: {src_ip}")
        except Exception as e:
            logger.error(f"创建告警失败: {str(e)}") 