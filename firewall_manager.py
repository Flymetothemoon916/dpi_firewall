#!/usr/bin/env python
import os
import sys
import argparse
import django
import logging
import subprocess
import time

# 设置Django环境
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'DPI_Firewall.settings')
django.setup()

from django.utils import timezone
from django.db.models import Count, Sum

from dashboard.models import SystemStatus, TrafficStatistics, AlertLog
from firewall_rules.models import Rule, RuleCategory, IPBlacklist, IPWhitelist
from packet_analyzer.models import Protocol, PacketLog, DeepInspectionResult
from packet_analyzer.scripts import PacketCaptureManager
from packet_analyzer.dpi.firewall_engine import FirewallEngine
from packet_analyzer.dpi.packet_analyzer import DPIPacketAnalyzer

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger('firewall_manager')

# 获取防火墙引擎实例
firewall_engine = FirewallEngine()

def list_rules():
    """列出所有防火墙规则"""
    print("\n防火墙规则列表:")
    print("-" * 80)
    print(f"{'ID':<4} {'状态':<6} {'名称':<20} {'动作':<8} {'优先级':<8} {'分类':<15} {'命中次数':<8}")
    print("-" * 80)
    
    rules = Rule.objects.all().select_related('category')
    
    for rule in rules:
        status = "启用" if rule.is_enabled else "禁用"
        action = "允许" if rule.action == 'allow' else "阻止" if rule.action == 'block' else "记录" if rule.action == 'log' else "告警"
        priority = "严重" if rule.priority == 'critical' else "高" if rule.priority == 'high' else "中" if rule.priority == 'medium' else "低"
        category = rule.category.name if rule.category else "无分类"
        
        print(f"{rule.id:<4} {status:<6} {rule.name[:20]:<20} {action:<8} {priority:<8} {category[:15]:<15} {rule.hits:<8}")


def add_rule(name, description, action, priority, category_name, protocol=None, src_ip=None, dst_ip=None, src_port=None, dst_port=None):
    """添加新规则"""
    try:
        # 获取或创建分类
        category, created = RuleCategory.objects.get_or_create(
            name=category_name,
            defaults={'description': f'{category_name}分类', 'priority': 100}
        )
        
        # 创建规则
        rule = Rule.objects.create(
            name=name,
            description=description,
            category=category,
            source_ip=src_ip or '',
            destination_ip=dst_ip or '',
            source_port=src_port or '',
            destination_port=dst_port or '',
            protocol=protocol or '',
            action=action,
            priority=priority,
            is_enabled=True
        )
        
        print(f"规则 '{name}' 已成功创建，ID: {rule.id}")
        return True
    except Exception as e:
        print(f"创建规则失败: {str(e)}")
        return False


def enable_disable_rule(rule_id, enable=True):
    """启用或禁用规则"""
    try:
        rule = Rule.objects.get(id=rule_id)
        rule.is_enabled = enable
        rule.save()
        
        status = "启用" if enable else "禁用"
        print(f"规则 '{rule.name}' 已{status}")
        return True
    except Rule.DoesNotExist:
        print(f"错误: 规则ID {rule_id} 不存在")
        return False
    except Exception as e:
        print(f"操作失败: {str(e)}")
        return False


def delete_rule(rule_id):
    """删除规则"""
    try:
        rule = Rule.objects.get(id=rule_id)
        name = rule.name
        rule.delete()
        
        print(f"规则 '{name}' 已删除")
        return True
    except Rule.DoesNotExist:
        print(f"错误: 规则ID {rule_id} 不存在")
        return False
    except Exception as e:
        print(f"删除失败: {str(e)}")
        return False


def manage_blacklist(action, ip_address=None, description=None):
    """管理IP黑名单"""
    if action == 'list':
        print("\nIP黑名单:")
        print("-" * 60)
        print(f"{'IP地址':<20} {'是否永久':<8} {'描述':<30}")
        print("-" * 60)
        
        for entry in IPBlacklist.objects.all():
            permanent = "是" if entry.is_permanent else "否"
            print(f"{entry.ip_address:<20} {permanent:<8} {entry.description[:30]:<30}")
        
    elif action == 'add':
        if not ip_address:
            print("错误: 添加黑名单需要指定IP地址")
            return False
        
        try:
            # 检查是否已存在
            if IPBlacklist.objects.filter(ip_address=ip_address).exists():
                print(f"IP {ip_address} 已在黑名单中")
                return False
            
            # 创建黑名单项
            IPBlacklist.objects.create(
                ip_address=ip_address,
                description=description or '手动添加',
                added_at=timezone.now(),
                is_permanent=True
            )
            
            print(f"IP {ip_address} 已添加到黑名单")
            return True
        except Exception as e:
            print(f"添加黑名单失败: {str(e)}")
            return False
    
    elif action == 'remove':
        if not ip_address:
            print("错误: 移除黑名单需要指定IP地址")
            return False
        
        try:
            # 查找并删除
            entries = IPBlacklist.objects.filter(ip_address=ip_address)
            if entries.exists():
                entries.delete()
                print(f"IP {ip_address} 已从黑名单中移除")
                return True
            else:
                print(f"IP {ip_address} 不在黑名单中")
                return False
        except Exception as e:
            print(f"移除黑名单失败: {str(e)}")
            return False
    
    else:
        print(f"错误: 未知的黑名单操作 '{action}'")
        return False


def manage_whitelist(action, ip_address=None, description=None):
    """管理IP白名单"""
    if action == 'list':
        print("\nIP白名单:")
        print("-" * 60)
        print(f"{'IP地址':<20} {'描述':<40}")
        print("-" * 60)
        
        for entry in IPWhitelist.objects.all():
            print(f"{entry.ip_address:<20} {entry.description[:40]:<40}")
        
    elif action == 'add':
        if not ip_address:
            print("错误: 添加白名单需要指定IP地址")
            return False
        
        try:
            # 检查是否已存在
            if IPWhitelist.objects.filter(ip_address=ip_address).exists():
                print(f"IP {ip_address} 已在白名单中")
                return False
            
            # 创建白名单项
            IPWhitelist.objects.create(
                ip_address=ip_address,
                description=description or '手动添加',
                added_at=timezone.now()
            )
            
            print(f"IP {ip_address} 已添加到白名单")
            return True
        except Exception as e:
            print(f"添加白名单失败: {str(e)}")
            return False
    
    elif action == 'remove':
        if not ip_address:
            print("错误: 移除白名单需要指定IP地址")
            return False
        
        try:
            # 查找并删除
            entries = IPWhitelist.objects.filter(ip_address=ip_address)
            if entries.exists():
                entries.delete()
                print(f"IP {ip_address} 已从白名单中移除")
                return True
            else:
                print(f"IP {ip_address} 不在白名单中")
                return False
        except Exception as e:
            print(f"移除白名单失败: {str(e)}")
            return False
    
    else:
        print(f"错误: 未知的白名单操作 '{action}'")
        return False


def show_stats():
    """显示系统统计信息"""
    try:
        # 获取系统状态
        system_status = SystemStatus.objects.first()
        if not system_status:
            print("系统状态未初始化")
            return
        
        # 获取流量统计
        try:
            latest_stats = TrafficStatistics.objects.latest('timestamp')
        except TrafficStatistics.DoesNotExist:
            latest_stats = None
        
        total_stats = TrafficStatistics.objects.aggregate(
            total_in=Sum('inbound_packets'),
            total_out=Sum('outbound_packets'),
            total_blocked=Sum('blocked_packets')
        )
        
        # 获取数据包和告警统计
        packet_stats = {
            'total': PacketLog.objects.count(),
            'allowed': PacketLog.objects.filter(status='allowed').count(),
            'blocked': PacketLog.objects.filter(status='blocked').count(),
            'suspicious': PacketLog.objects.filter(status='suspicious').count(),
        }
        
        alert_stats = {
            'total': AlertLog.objects.count(),
            'unread': AlertLog.objects.filter(is_read=False).count(),
            'critical': AlertLog.objects.filter(level='critical').count(),
            'warning': AlertLog.objects.filter(level='warning').count(),
            'info': AlertLog.objects.filter(level='info').count(),
        }
        
        # 显示统计信息
        print("\n系统统计信息")
        print("=" * 60)
        
        # 系统状态
        status_map = {
            'running': '运行中',
            'stopped': '已停止',
            'paused': '已暂停',
            'error': '错误'
        }
        print(f"系统状态: {status_map.get(system_status.status, system_status.status)}")
        if system_status.started_at:
            print(f"启动时间: {system_status.started_at.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"CPU使用率: {system_status.cpu_usage}%")
        print(f"内存使用率: {system_status.memory_usage}%")
        
        # 流量统计
        print("\n流量统计:")
        if latest_stats:
            print(f"  最近更新: {latest_stats.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"  入站数据包: {latest_stats.inbound_packets} 包")
            print(f"  出站数据包: {latest_stats.outbound_packets} 包")
            print(f"  入站流量: {latest_stats.inbound_bytes/1024:.2f} KB")
            print(f"  出站流量: {latest_stats.outbound_bytes/1024:.2f} KB")
            print(f"  拦截数据包: {latest_stats.blocked_packets} 包")
        
        if total_stats['total_in']:
            print("\n累计流量:")
            print(f"  入站总数据包: {total_stats['total_in']} 包")
            print(f"  出站总数据包: {total_stats['total_out']} 包")
            print(f"  总拦截数据包: {total_stats['total_blocked']} 包")
        
        # 数据包统计
        print("\n数据包统计:")
        print(f"  总数据包: {packet_stats['total']} 包")
        print(f"  已允许: {packet_stats['allowed']} 包")
        print(f"  已阻止: {packet_stats['blocked']} 包")
        print(f"  可疑: {packet_stats['suspicious']} 包")
        
        # 告警统计
        print("\n告警统计:")
        print(f"  总告警: {alert_stats['total']} 条")
        print(f"  未读告警: {alert_stats['unread']} 条")
        print(f"  严重告警: {alert_stats['critical']} 条")
        print(f"  警告告警: {alert_stats['warning']} 条")
        print(f"  信息告警: {alert_stats['info']} 条")
        
        # 规则统计
        print("\n规则统计:")
        print(f"  总规则数: {Rule.objects.count()} 条")
        print(f"  启用规则: {Rule.objects.filter(is_enabled=True).count()} 条")
        print(f"  禁用规则: {Rule.objects.filter(is_enabled=False).count()} 条")
        
        # 命中最多的规则
        top_rules = Rule.objects.filter(hits__gt=0).order_by('-hits')[:5]
        if top_rules.exists():
            print("\n命中最多的规则:")
            for rule in top_rules:
                print(f"  {rule.name}: {rule.hits} 次命中")
    
    except Exception as e:
        print(f"获取统计信息失败: {str(e)}")


def control_firewall(action):
    """控制防火墙状态"""
    try:
        # 获取当前状态
        status_obj = SystemStatus.objects.first()
        current_status = status_obj.status if status_obj else 'stopped'
        
        if action == 'start':
            if current_status == 'running':
                print("防火墙已经在运行中")
                return False
            
            # 使用新的防火墙引擎启动
            if firewall_engine.start():
                print("防火墙已成功启动")
                
                # 在后台启动防火墙服务命令
                subprocess.Popen(
                    [sys.executable, "manage.py", "firewall_service", "--foreground"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                print("防火墙服务已在后台启动")
                return True
            else:
                print("启动防火墙失败")
                return False
                
        elif action == 'stop':
            if current_status != 'running':
                print("防火墙未运行")
                return False
            
            # 使用新的防火墙引擎停止
            if firewall_engine.stop():
                print("防火墙已停止")
                return True
            else:
                print("停止防火墙失败")
                return False
                
        elif action == 'restart':
            # 无论当前状态如何，都尝试重启
            firewall_engine.stop()
            time.sleep(1)  # 等待资源释放
            
            if firewall_engine.start():
                print("防火墙已重新启动")
                
                # 在后台启动防火墙服务命令
                subprocess.Popen(
                    [sys.executable, "manage.py", "firewall_service", "--foreground"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                print("防火墙服务已在后台启动")
                return True
            else:
                print("重启防火墙失败")
                return False
                
        elif action == 'status':
            if current_status == 'running':
                print("防火墙状态: 运行中")
            elif current_status == 'stopped':
                print("防火墙状态: 已停止")
            elif current_status == 'paused':
                print("防火墙状态: 已暂停")
            else:
                print(f"防火墙状态: {current_status}")
            
            # 获取统计信息
            status = firewall_engine.get_status()
            print(f"已加载规则数: {status['rules_count']}")
            print(f"黑名单IP数: {status['blacklist_count']}")
            print(f"白名单IP数: {status['whitelist_count']}")
            print(f"活动会话数: {status['sessions']}")
            
            # 打印流量统计
            stats = status['stats']
            print(f"入站数据包: {stats['inbound_packets']}")
            print(f"出站数据包: {stats['outbound_packets']}")
            print(f"入站流量: {stats['inbound_bytes']} 字节")
            print(f"出站流量: {stats['outbound_bytes']} 字节")
            print(f"阻断数据包: {stats['blocked_packets']}")
            
            return True
            
        else:
            print(f"未知的防火墙操作: {action}")
            return False
            
    except Exception as e:
        print(f"控制防火墙时出错: {str(e)}")
        return False


def clear_logs(log_type=None, days=None):
    """清除日志"""
    if log_type == 'packets' or log_type is None:
        if days:
            cutoff_date = timezone.now() - timezone.timedelta(days=int(days))
            count, _ = PacketLog.objects.filter(timestamp__lt=cutoff_date).delete()
            print(f"已删除 {count} 条超过 {days} 天的数据包日志")
        else:
            count, _ = PacketLog.objects.all().delete()
            print(f"已删除所有数据包日志 ({count} 条)")
    
    if log_type == 'alerts' or log_type is None:
        if days:
            cutoff_date = timezone.now() - timezone.timedelta(days=int(days))
            count, _ = AlertLog.objects.filter(timestamp__lt=cutoff_date).delete()
            print(f"已删除 {count} 条超过 {days} 天的告警日志")
        else:
            count, _ = AlertLog.objects.all().delete()
            print(f"已删除所有告警日志 ({count} 条)")
    
    if log_type == 'traffic' or log_type is None:
        if days:
            cutoff_date = timezone.now() - timezone.timedelta(days=int(days))
            count, _ = TrafficStatistics.objects.filter(timestamp__lt=cutoff_date).delete()
            print(f"已删除 {count} 条超过 {days} 天的流量统计")
        else:
            count, _ = TrafficStatistics.objects.all().delete()
            print(f"已删除所有流量统计 ({count} 条)")


def start_attack_detection_firewall():
    """专门用于HTTP攻击测试的防火墙启动函数"""
    print("\n启动专用HTTP攻击检测防火墙...")
    
    # 确保Web攻击规则已启用
    web_attack_rules = Rule.objects.filter(name__in=[
        'SQL注入攻击检测', 'XSS攻击检测', '命令注入攻击检测', '路径遍历攻击检测'
    ])
    for rule in web_attack_rules:
        if not rule.is_enabled:
            rule.is_enabled = True
            rule.save()
            print(f"已启用规则: {rule.name}")
        else:
            print(f"规则已启用: {rule.name}")
    
    # 启动防火墙引擎
    engine = FirewallEngine()
    if not engine.is_running():
        success = engine.start()
        if success:
            print("防火墙引擎启动成功")
            
            # 更新系统状态
            SystemStatus.objects.update_or_create(
                defaults={
                    'status': 'running',
                    'firewall_running': True,
                    'last_start_time': timezone.now()
                }
            )
        else:
            print("防火墙引擎启动失败")
            return False
    else:
        print("防火墙引擎已经在运行")
    
    # 启动数据包分析器，监听localhost流量
    try:
        print("启动数据包分析器，准备捕获HTTP攻击流量...")
        print("请在另一个终端窗口运行攻击测试脚本...")
        analyzer = DPIPacketAnalyzer()
        analyzer.start_packet_capture(timeout=120)  # 设置2分钟超时
        return True
    except Exception as e:
        print(f"启动数据包分析器失败: {str(e)}")
        return False


def main():
    """主函数，处理命令行参数"""
    parser = argparse.ArgumentParser(description='DPI防火墙管理工具')
    subparsers = parser.add_subparsers(dest='command', help='子命令')
    
    # 规则命令
    rule_parser = subparsers.add_parser('rule', help='管理防火墙规则')
    rule_subparsers = rule_parser.add_subparsers(dest='rule_action', help='规则操作')
    
    # 列出规则
    rule_subparsers.add_parser('list', help='列出所有规则')
    
    # 添加规则
    add_rule_parser = rule_subparsers.add_parser('add', help='添加新规则')
    add_rule_parser.add_argument('--name', required=True, help='规则名称')
    add_rule_parser.add_argument('--desc', help='规则描述')
    add_rule_parser.add_argument('--action', choices=['allow', 'block', 'log', 'alert'], required=True, help='规则动作')
    add_rule_parser.add_argument('--priority', choices=['low', 'medium', 'high', 'critical'], required=True, help='规则优先级')
    add_rule_parser.add_argument('--category', required=True, help='规则分类')
    add_rule_parser.add_argument('--protocol', help='协议 (如TCP, UDP)')
    add_rule_parser.add_argument('--src-ip', help='源IP地址')
    add_rule_parser.add_argument('--dst-ip', help='目标IP地址')
    add_rule_parser.add_argument('--src-port', help='源端口')
    add_rule_parser.add_argument('--dst-port', help='目标端口')
    
    # 启用规则
    enable_rule_parser = rule_subparsers.add_parser('enable', help='启用规则')
    enable_rule_parser.add_argument('rule_id', type=int, help='规则ID')
    
    # 禁用规则
    disable_rule_parser = rule_subparsers.add_parser('disable', help='禁用规则')
    disable_rule_parser.add_argument('rule_id', type=int, help='规则ID')
    
    # 删除规则
    delete_rule_parser = rule_subparsers.add_parser('delete', help='删除规则')
    delete_rule_parser.add_argument('rule_id', type=int, help='规则ID')
    
    # IP黑名单命令
    blacklist_parser = subparsers.add_parser('blacklist', help='管理IP黑名单')
    blacklist_subparsers = blacklist_parser.add_subparsers(dest='blacklist_action', help='黑名单操作')
    
    # 列出黑名单
    blacklist_subparsers.add_parser('list', help='列出所有黑名单IP')
    
    # 添加黑名单
    add_blacklist_parser = blacklist_subparsers.add_parser('add', help='添加IP到黑名单')
    add_blacklist_parser.add_argument('ip_address', help='IP地址')
    add_blacklist_parser.add_argument('--desc', help='描述')
    
    # 移除黑名单
    remove_blacklist_parser = blacklist_subparsers.add_parser('remove', help='从黑名单移除IP')
    remove_blacklist_parser.add_argument('ip_address', help='IP地址')
    
    # IP白名单命令
    whitelist_parser = subparsers.add_parser('whitelist', help='管理IP白名单')
    whitelist_subparsers = whitelist_parser.add_subparsers(dest='whitelist_action', help='白名单操作')
    
    # 列出白名单
    whitelist_subparsers.add_parser('list', help='列出所有白名单IP')
    
    # 添加白名单
    add_whitelist_parser = whitelist_subparsers.add_parser('add', help='添加IP到白名单')
    add_whitelist_parser.add_argument('ip_address', help='IP地址')
    add_whitelist_parser.add_argument('--desc', help='描述')
    
    # 移除白名单
    remove_whitelist_parser = whitelist_subparsers.add_parser('remove', help='从白名单移除IP')
    remove_whitelist_parser.add_argument('ip_address', help='IP地址')
    
    # 统计命令
    subparsers.add_parser('stats', help='显示系统统计信息')
    
    # 控制命令
    control_parser = subparsers.add_parser('control', help='控制防火墙')
    control_parser.add_argument('action', choices=['start', 'stop', 'status'], help='控制动作')
    
    # 清除日志命令
    clear_parser = subparsers.add_parser('clear', help='清除日志')
    clear_parser.add_argument('--type', choices=['packets', 'alerts', 'traffic'], help='日志类型 (不指定则清除所有)')
    clear_parser.add_argument('--days', type=int, help='清除多少天前的日志 (不指定则清除所有)')
    
    # 攻击检测命令
    parser.add_argument('--attack-detection', action='store_true', help='启动专用于HTTP攻击检测的防火墙')
    
    # 解析参数
    args = parser.parse_args()
    
    if args.attack_detection:
        start_attack_detection_firewall()
        return
        
    # 处理命令
    if args.command == 'rule':
        if args.rule_action == 'list':
            list_rules()
        elif args.rule_action == 'add':
            add_rule(
                args.name, args.desc, args.action, args.priority, args.category,
                args.protocol, args.src_ip, args.dst_ip, args.src_port, args.dst_port
            )
        elif args.rule_action == 'enable':
            enable_disable_rule(args.rule_id, True)
        elif args.rule_action == 'disable':
            enable_disable_rule(args.rule_id, False)
        elif args.rule_action == 'delete':
            delete_rule(args.rule_id)
        else:
            parser.print_help()
    
    elif args.command == 'blacklist':
        if args.blacklist_action == 'list':
            manage_blacklist('list')
        elif args.blacklist_action == 'add':
            manage_blacklist('add', args.ip_address, args.desc)
        elif args.blacklist_action == 'remove':
            manage_blacklist('remove', args.ip_address)
        else:
            parser.print_help()
    
    elif args.command == 'whitelist':
        if args.whitelist_action == 'list':
            manage_whitelist('list')
        elif args.whitelist_action == 'add':
            manage_whitelist('add', args.ip_address, args.desc)
        elif args.whitelist_action == 'remove':
            manage_whitelist('remove', args.ip_address)
        else:
            parser.print_help()
    
    elif args.command == 'stats':
        show_stats()
    
    elif args.command == 'control':
        control_firewall(args.action)
    
    elif args.command == 'clear':
        clear_logs(args.type, args.days)
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main() 