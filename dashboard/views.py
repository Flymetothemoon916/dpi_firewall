from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.utils import timezone
import psutil

from .models import SystemStatus, TrafficStatistics, AlertLog
from packet_analyzer.models import PacketLog
from firewall_rules.models import Rule
from packet_analyzer.scripts import PacketCaptureManager
from packet_analyzer.dpi.firewall_engine import FirewallEngine
from scapy.all import get_if_list

@login_required
def dashboard(request):
    """显示系统仪表盘首页"""
    try:
        system_status = SystemStatus.objects.first()
        if not system_status:
            system_status = SystemStatus.objects.create()
            
        # 更新CPU和内存使用率
        cpu_usage = psutil.cpu_percent(interval=0.5)
        memory = psutil.virtual_memory()
        memory_usage = memory.percent
        
        system_status.cpu_usage = cpu_usage
        system_status.memory_usage = memory_usage
        system_status.save()
            
        # 添加提示信息，指导用户使用命令行
        cli_instructions = {
            'show_interfaces': 'python manage.py firewall_service',
            'start_service': 'python manage.py firewall_service --interface <接口索引>',
            'examples': [
                'python manage.py firewall_service --interface 0',
                'python manage.py firewall_service -i 2'
            ]
        }
    except:
        system_status = None
        cli_instructions = {}
    
    # 获取最近的流量统计
    traffic_stats = TrafficStatistics.objects.order_by('-timestamp').first()
    
    # 获取未读告警数量
    unread_alerts_count = AlertLog.objects.filter(is_read=False).count()
    
    # 获取最近的告警
    recent_alerts = AlertLog.objects.order_by('-timestamp')[:5]
    
    # 获取数据包统计信息
    total_packets = PacketLog.objects.count()
    allowed_packets = PacketLog.objects.filter(status='allowed').count()
    blocked_packets = PacketLog.objects.filter(status='blocked').count()
    suspicious_packets = PacketLog.objects.filter(status='suspicious').count()
    
    # 获取最常用的规则
    top_rules = Rule.objects.order_by('-hits')[:5]
    
    context = {
        'system_status': system_status,
        'traffic_stats': traffic_stats,
        'unread_alerts_count': unread_alerts_count,
        'recent_alerts': recent_alerts,
        'total_packets': total_packets,
        'allowed_packets': allowed_packets,
        'blocked_packets': blocked_packets,
        'suspicious_packets': suspicious_packets,
        'top_rules': top_rules,
        'cli_instructions': cli_instructions,
    }
    
    return render(request, 'dashboard/dashboard.html', context)


@login_required
def alerts(request):
    """显示告警页面"""
    alerts_list = AlertLog.objects.order_by('-timestamp')
    return render(request, 'dashboard/alerts.html', {'alerts': alerts_list})


@login_required
def mark_alert_as_read(request, alert_id):
    """将告警标记为已读"""
    try:
        alert = AlertLog.objects.get(id=alert_id)
        alert.is_read = True
        alert.save()
        return JsonResponse({'status': 'success'})
    except AlertLog.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': '告警不存在'}, status=404)


@login_required
def traffic_stats(request):
    """显示流量统计页面"""
    # 获取时间范围参数
    start_time = request.GET.get('start_time')
    if start_time:
        try:
            start_time = timezone.datetime.fromisoformat(start_time.replace('Z', '+00:00'))
            stats = TrafficStatistics.objects.filter(timestamp__gte=start_time).order_by('-timestamp')
        except ValueError:
            stats = TrafficStatistics.objects.order_by('-timestamp')[:24]  # 最近24小时的统计
    else:
        stats = TrafficStatistics.objects.order_by('-timestamp')[:24]  # 最近24小时的统计
    
    # 如果是AJAX请求，返回JSON数据
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        data = [{
            'timestamp': stat.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'inbound_packets': stat.inbound_packets,
            'outbound_packets': stat.outbound_packets,
            'inbound_bytes': stat.inbound_bytes,
            'outbound_bytes': stat.outbound_bytes,
            'inbound_bytes_per_sec': stat.inbound_bytes_per_sec,
            'outbound_bytes_per_sec': stat.outbound_bytes_per_sec,
            'blocked_packets': stat.blocked_packets
        } for stat in stats]
        return JsonResponse(data, safe=False)
    
    return render(request, 'dashboard/traffic_stats.html', {'stats': stats})


@login_required
def get_dashboard_data(request):
    """API端点，返回仪表盘最新数据，用于AJAX实时更新"""
    try:
        import psutil
        
        # 获取系统状态
        system_status = SystemStatus.objects.first()
        
        # 更新CPU和内存使用率
        if system_status:
            cpu_usage = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            memory_usage = memory.percent
            
            system_status.cpu_usage = cpu_usage
            system_status.memory_usage = memory_usage
            system_status.save()
        
        # 获取最近的流量统计
        traffic_stats = TrafficStatistics.objects.order_by('-timestamp').first()
        
        # 获取未读告警数量和最近告警
        unread_alerts_count = AlertLog.objects.filter(is_read=False).count()
        recent_alerts = []
        for alert in AlertLog.objects.order_by('-timestamp')[:5]:
            recent_alerts.append({
                'id': alert.id,
                'timestamp': alert.timestamp.strftime('%Y-%m-%d %H:%M'),
                'title': alert.title,
                'is_read': alert.is_read,
                'level': alert.level
            })
        
        # 获取数据包统计信息 - 使用正确的状态名称
        total_packets = PacketLog.objects.count()
        allowed_packets = PacketLog.objects.filter(status='allowed').count()
        blocked_packets = PacketLog.objects.filter(status='blocked').count()
        suspicious_packets = PacketLog.objects.filter(status='suspicious').count()
        
        # 获取最近的数据包
        recent_packets = []
        for packet in PacketLog.objects.order_by('-timestamp')[:10]:
            recent_packets.append({
                'id': packet.id,
                'timestamp': packet.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'src_ip': packet.source_ip,
                'dst_ip': packet.destination_ip,
                'src_port': packet.source_port,
                'dst_port': packet.destination_port,
                'protocol': packet.protocol.name if packet.protocol else 'Unknown',
                'status': packet.status.upper(),
                'size': packet.packet_size
            })
        
        # 获取最常用的规则
        top_rules = []
        for rule in Rule.objects.order_by('-hits')[:5]:
            top_rules.append({
                'id': rule.id,
                'name': rule.name,
                'hits': rule.hits
            })
        
        # 尝试获取实时流量数据
        real_stats = None
        try:
            # 尝试获取防火墙引擎实例
            firewall = FirewallEngine()
            if firewall._running:  # 检查防火墙是否正在运行
                status = firewall.get_status()
                
                # 计算每秒的流量
                current_time = timezone.now()
                if traffic_stats:
                    time_diff = (current_time - traffic_stats.timestamp).total_seconds()
                    if time_diff > 0:
                        inbound_bytes_per_sec = status['stats']['inbound_bytes'] / time_diff
                        outbound_bytes_per_sec = status['stats']['outbound_bytes'] / time_diff
                    else:
                        inbound_bytes_per_sec = status['stats']['inbound_bytes']
                        outbound_bytes_per_sec = status['stats']['outbound_bytes']
                else:
                    inbound_bytes_per_sec = status['stats']['inbound_bytes']
                    outbound_bytes_per_sec = status['stats']['outbound_bytes']
                
                real_stats = {
                    'inbound_packets': status['stats']['inbound_packets'],
                    'outbound_packets': status['stats']['outbound_packets'],
                    'inbound_bytes': inbound_bytes_per_sec,  # 每秒入站流量
                    'outbound_bytes': outbound_bytes_per_sec,  # 每秒出站流量
                    'blocked_packets': status['stats']['blocked_packets'],
                    'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S')
                }
        except Exception as e:
            # 记录错误但不中断处理
            real_stats = None
        
        # 构建返回数据
        data = {
            'system_status': {
                'status': system_status.status if system_status else 'unknown',
                'cpu_usage': system_status.cpu_usage if system_status else 0,
                'memory_usage': system_status.memory_usage if system_status else 0,
                'started_at': system_status.started_at.strftime('%Y-%m-%d %H:%M:%S') if system_status and system_status.started_at else None
            },
            'traffic_stats': {
                'inbound_packets': traffic_stats.inbound_packets if traffic_stats else 0,
                'outbound_packets': traffic_stats.outbound_packets if traffic_stats else 0,
                'inbound_bytes': traffic_stats.inbound_bytes if traffic_stats else 0,
                'outbound_bytes': traffic_stats.outbound_bytes if traffic_stats else 0,
                'inbound_bytes_per_sec': traffic_stats.inbound_bytes_per_sec if traffic_stats else 0,
                'outbound_bytes_per_sec': traffic_stats.outbound_bytes_per_sec if traffic_stats else 0,
                'blocked_packets': traffic_stats.blocked_packets if traffic_stats else 0,
                'timestamp': traffic_stats.timestamp.strftime('%Y-%m-%d %H:%M:%S') if traffic_stats else None
            },
            'real_time_stats': real_stats,
            'alerts': {
                'unread_count': unread_alerts_count,
                'recent': recent_alerts
            },
            'packets': {
                'total': total_packets,
                'allowed': allowed_packets,
                'blocked': blocked_packets,
                'suspicious': suspicious_packets
            },
            'top_rules': top_rules,
            'recent_packets': recent_packets
        }
        
        return JsonResponse(data)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def performance_monitor(request):
    """显示性能监控页面"""
    return render(request, 'dashboard/performance.html')


@login_required
def get_performance_data(request):
    """API端点，返回性能监控数据，用于实时更新"""
    try:
        import psutil
        import time
        from django.db.models import Count, Sum, Avg
        from datetime import timedelta
        
        # 获取系统状态
        system_status = SystemStatus.objects.first()
        if not system_status:
            system_status = SystemStatus.objects.create()
        
        # 获取最近的流量统计
        traffic_stats = TrafficStatistics.objects.order_by('-timestamp').first()
        if not traffic_stats:
            traffic_stats = TrafficStatistics.objects.create()
        
        # 获取进程性能指标
        process = psutil.Process()
        
        # 使用全局系统CPU和内存使用率，而不是仅进程使用率
        cpu_usage = psutil.cpu_percent(interval=0.5)  # 获取系统总体CPU使用率
        memory = psutil.virtual_memory()
        memory_usage = memory.percent  # 获取系统总体内存使用率
        
        process_stats = {
            'cpu_usage': process.cpu_percent(interval=0.1),  # 进程CPU使用率
            'memory_usage': process.memory_percent(),  # 进程内存使用率
            'threads': len(process.threads()),
            'open_files': len(process.open_files()),
            'connections': len(process.connections()),
        }
        
        # 更新系统状态中的CPU和内存使用率
        system_status.cpu_usage = cpu_usage
        system_status.memory_usage = memory_usage
        system_status.save()
        
        # 获取系统网络接口统计信息
        net_io_counters = psutil.net_io_counters()
        
        # 测量网络延迟
        # 这里使用简化的方法，实际项目中可能需要更复杂的测量
        packet_processing_stats = {}
        try:
            from packet_analyzer.dpi.firewall_engine import FirewallEngine
            firewall = FirewallEngine()
            if hasattr(firewall, 'get_performance_stats'):
                packet_processing_stats = firewall.get_performance_stats()
            else:
                # 如果没有专门的性能统计方法，尝试从状态中推断
                status = firewall.get_status()
                active_sessions = status.get('sessions', 0)
                
                # 从数据库获取数据包处理统计信息
                from packet_analyzer.models import PacketLog
                now = timezone.now()
                one_minute_ago = now - timedelta(minutes=1)
                
                # 计算最近一分钟的每秒处理包数
                recent_packets = PacketLog.objects.filter(timestamp__gte=one_minute_ago).count()
                packets_per_second = recent_packets / 60.0 if recent_packets > 0 else 0
                
                # 计算平均处理时间（如果记录了处理时间）
                avg_processing_time = 0
                if hasattr(PacketLog, 'processing_time'):
                    avg_processing_time = PacketLog.objects.filter(
                        timestamp__gte=one_minute_ago
                    ).aggregate(avg_time=Avg('processing_time'))['avg_time'] or 0
                
                packet_processing_stats = {
                    'packets_per_second': packets_per_second,
                    'avg_processing_time': avg_processing_time,
                    'active_sessions': active_sessions
                }
        except Exception as e:
            # 记录异常但继续处理
            packet_processing_stats = {
                'packets_per_second': 0,
                'avg_processing_time': 0,
                'active_sessions': 0
            }
        
        # 获取网络性能指标
        # 实际项目中，这些值应该从网络监控组件获取
        network_stats = {
            'avg_latency': 0.5,  # 示例值，实际应从监控系统获取
            'packet_loss': 0.01,  # 示例值，实际应从监控系统获取
            'total_bytes_sent': net_io_counters.bytes_sent,
            'total_bytes_recv': net_io_counters.bytes_recv,
            'packets_sent': net_io_counters.packets_sent,
            'packets_recv': net_io_counters.packets_recv,
            'err_in': net_io_counters.errin,
            'err_out': net_io_counters.errout,
            'drop_in': net_io_counters.dropin,
            'drop_out': net_io_counters.dropout
        }
        
        # 获取规则性能统计
        from firewall_rules.models import Rule
        total_rules = Rule.objects.count()
        enabled_rules = Rule.objects.filter(is_enabled=True).count()
        total_hits = Rule.objects.aggregate(total=Sum('hits'))['total'] or 0
        
        # 计算阻断率
        from packet_analyzer.models import PacketLog
        total_packets = PacketLog.objects.count()
        blocked_packets = PacketLog.objects.filter(status='block').count()
        block_rate = (blocked_packets / total_packets * 100) if total_packets > 0 else 0
        
        # 计算规则命中率
        total_packets = PacketLog.objects.count() or 1  # 避免除以零
        packets_with_rule_hits = PacketLog.objects.exclude(matched_rule__isnull=True).count()
        rule_hit_rate = (packets_with_rule_hits / total_packets * 100)
        
        rules_stats = {
            'total': total_rules,
            'enabled': enabled_rules,
            'total_hits': total_hits,
            'block_rate': block_rate,
            'hit_rate': rule_hit_rate
        }
        
        # 获取DPI性能统计
        dpi_stats = {
            'total_inspections': 0,
            'deep_inspections': 0,
            'efficiency': 0
        }
        
        try:
            from packet_analyzer.models import DeepInspectionResult
            
            # 统计DPI扫描的总数和有效数
            total_inspections = DeepInspectionResult.objects.count() or 1  # 避免除以零
            positive_inspections = DeepInspectionResult.objects.filter(matched_pattern__isnull=False).count()
            
            dpi_stats = {
                'total_inspections': total_inspections,
                'deep_inspections': positive_inspections,
                'efficiency': (positive_inspections / total_inspections * 100)
            }
        except:
            # 如果无法获取DPI统计，使用默认值
            pass
        
        # 构建返回数据
        data = {
            'system_status': {
                'status': system_status.status,
                'cpu_usage': system_status.cpu_usage,
                'memory_usage': system_status.memory_usage,
                'started_at': system_status.started_at.isoformat() if system_status.started_at else None
            },
            'process_stats': process_stats,
            'traffic_stats': {
                'inbound_packets': traffic_stats.inbound_packets,
                'outbound_packets': traffic_stats.outbound_packets,
                'inbound_bytes': traffic_stats.inbound_bytes,
                'outbound_bytes': traffic_stats.outbound_bytes,
                'inbound_bytes_per_sec': traffic_stats.inbound_bytes_per_sec,
                'outbound_bytes_per_sec': traffic_stats.outbound_bytes_per_sec,
                'blocked_packets': traffic_stats.blocked_packets,
                'timestamp': traffic_stats.timestamp.isoformat()
            },
            'network_stats': network_stats,
            'packet_stats': packet_processing_stats,
            'rules_stats': rules_stats,
            'dpi_stats': dpi_stats,
            'active_sessions': packet_processing_stats.get('active_sessions', 0)
        }
        
        return JsonResponse(data)
    except Exception as e:
        return JsonResponse({
            'error': str(e)
        }, status=500)


@login_required
def reset_packet_stats(request):
    """清除所有数据包统计并重新开始计数"""
    if request.method == 'POST':
        try:
            # 清除PacketLog表中的所有记录
            from packet_analyzer.models import PacketLog
            PacketLog.objects.all().delete()
            
            # 重置流量统计
            from .models import TrafficStatistics
            TrafficStatistics.objects.all().update(
                inbound_packets=0,
                outbound_packets=0,
                inbound_bytes=0,
                outbound_bytes=0,
                inbound_bytes_per_sec=0,
                outbound_bytes_per_sec=0,
                blocked_packets=0
            )
            
            return JsonResponse({'status': 'success', 'message': '数据包统计已清除'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': f'清除数据包统计时出错: {str(e)}'}, status=500)
    else:
        return JsonResponse({'status': 'error', 'message': '仅支持POST请求'}, status=405)
