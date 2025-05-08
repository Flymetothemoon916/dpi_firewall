from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.core.paginator import Paginator
from django.db.models import Q
from django.urls import reverse

from .models import Protocol, PacketLog, DeepInspectionResult
from .scripts import PacketCaptureManager

@login_required
def packet_list(request):
    """显示数据包列表页面"""
    packets = PacketLog.objects.all().order_by('-timestamp')
    
    # 筛选条件
    search_query = request.GET.get('q', '')
    status_filter = request.GET.get('status', '')
    direction_filter = request.GET.get('direction', '')
    protocol_filter = request.GET.get('protocol', '')
    
    if search_query:
        packets = packets.filter(
            Q(source_ip__icontains=search_query) | 
            Q(destination_ip__icontains=search_query)
        )
    
    if status_filter:
        packets = packets.filter(status=status_filter)
    
    if direction_filter:
        packets = packets.filter(direction=direction_filter)
    
    if protocol_filter:
        packets = packets.filter(protocol__name=protocol_filter)
    
    # 分页
    paginator = Paginator(packets, 50)  # 每页显示50条
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # 获取协议列表用于筛选
    protocols = Protocol.objects.all()
    
    context = {
        'page_obj': page_obj,
        'protocols': protocols,
        'search_query': search_query,
        'status_filter': status_filter,
        'direction_filter': direction_filter,
        'protocol_filter': protocol_filter,
    }
    
    return render(request, 'packet_analyzer/packet_list.html', context)


@login_required
def packet_detail(request, packet_id):
    """显示数据包详情页面"""
    packet = get_object_or_404(PacketLog, id=packet_id)
    
    # 尝试获取DPI分析结果
    try:
        dpi_result = DeepInspectionResult.objects.get(packet=packet)
    except DeepInspectionResult.DoesNotExist:
        dpi_result = None
    
    # 预处理数据包载荷内容
    packet_payload = {
        'info': '',
        'raw': '',
        'hex': '',
        'structure': '',
        'http_request': ''  # HTTP请求内容
    }
    
    # 如果有原始HTTP请求，优先展示
    if packet.raw_request:
        packet_payload['http_request'] = packet.raw_request
        
        # 格式化HTTP请求用于高亮显示
        if packet.attack_type != 'normal':
            packet_payload['http_request'] += f"\n\n# 检测到的攻击类型: {packet.attack_type}"
    
    if packet.payload:
        payload = packet.payload
        
        # 提取基本信息部分
        if "=== PACKET INFO ===" in payload:
            info_index = payload.find("=== PACKET INFO ===")
            raw_index = payload.find("=== RAW PAYLOAD ===")
            if raw_index > info_index:
                packet_payload['info'] = payload[info_index:raw_index].strip()
                
                # 提取原始载荷部分
                hex_index = payload.find("=== HEXDUMP ===")
                if hex_index > raw_index:
                    packet_payload['raw'] = payload[raw_index:hex_index].strip()
                    
                    # 提取十六进制部分
                    structure_index = payload.find("=== PACKET STRUCTURE ===")
                    if structure_index > hex_index:
                        packet_payload['hex'] = payload[hex_index:structure_index].strip()
                        
                        # 提取数据包结构部分
                        if structure_index > 0:
                            packet_payload['structure'] = payload[structure_index:].strip()
        else:
            # 如果没有格式化的部分，将整个载荷作为结构信息
            packet_payload['structure'] = payload
    
    # 强调HTTP请求内容
    if packet.raw_request and not packet_payload['http_request']:
        packet_payload['http_request'] = packet.raw_request
    
    # 添加攻击类型分析
    context = {
        'packet': packet,
        'dpi_result': dpi_result,
        'packet_payload': packet_payload,
        'attack_detected': packet.attack_type != 'normal',
        'attack_type': packet.attack_type,
    }
    
    return render(request, 'packet_analyzer/packet_detail.html', context)


@login_required
def capture_packets(request):
    """数据包捕获页面"""
    manager = PacketCaptureManager()
    status = manager.get_status()
    
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'start':
            interface = request.POST.get('interface', '')
            count = int(request.POST.get('count', 0))
            timeout = int(request.POST.get('timeout', 0) or 0)
            
            success, message = manager.start_capture(
                interface if interface else None,
                count,
                timeout if timeout > 0 else None
            )
            
            return JsonResponse({
                'success': success,
                'message': message,
                'status': manager.get_status()
            })
            
        elif action == 'stop':
            success, message = manager.stop_capture()
            
            return JsonResponse({
                'success': success,
                'message': message,
                'status': manager.get_status()
            })
        
        # AJAX请求状态更新
        elif action == 'status':
            return JsonResponse({
                'success': True,
                'status': manager.get_status()
            })
    
    # 获取可用接口
    available_interfaces = get_available_interfaces()
    
    context = {
        'status': status,
        'interfaces': available_interfaces
    }
    
    return render(request, 'packet_analyzer/capture.html', context)


@login_required
def protocols(request):
    """协议管理页面"""
    protocol_list = Protocol.objects.all().order_by('name')
    return render(request, 'packet_analyzer/protocols.html', {'protocols': protocol_list})


def get_available_interfaces():
    """获取可用的网络接口列表
    
    Returns:
        list: 网络接口列表
    """
    # 这里简化实现，实际应使用netifaces或类似库获取
    # 由于我们使用的是Web界面，这个列表可以是静态的
    interfaces = [
        {'name': 'eth0', 'description': '以太网适配器'},
        {'name': 'wlan0', 'description': '无线网络适配器'},
        {'name': 'lo', 'description': '本地回环接口'}
    ]
    
    # Windows系统的常见接口名称
    if 'win' in __import__('platform').system().lower():
        interfaces = [
            {'name': 'Ethernet', 'description': '以太网适配器'},
            {'name': 'Wi-Fi', 'description': '无线网络适配器'},
            {'name': 'Loopback', 'description': '本地回环接口'}
        ]
    
    return interfaces


def get_latest_packets(request):
    """获取最新的数据包列表，用于前端实时更新"""
    # 获取查询参数
    search_query = request.GET.get('q', '')
    status_filter = request.GET.get('status', '')
    direction_filter = request.GET.get('direction', '')
    protocol_filter = request.GET.get('protocol', '')
    
    # 过滤数据包
    packets = PacketLog.objects.all().order_by('-timestamp')
    
    if search_query:
        packets = packets.filter(
            Q(source_ip__icontains=search_query) | 
            Q(destination_ip__icontains=search_query)
        )
    
    if status_filter:
        packets = packets.filter(status=status_filter)
    
    if direction_filter:
        packets = packets.filter(direction=direction_filter)
    
    if protocol_filter:
        packets = packets.filter(protocol__name=protocol_filter)
    
    # 获取最新的20个数据包
    latest_packets = packets[:20]
    
    # 准备响应数据
    packets_data = []
    for packet in latest_packets:
        packets_data.append({
            'id': packet.id,
            'timestamp': packet.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'source_ip': packet.source_ip,
            'source_port': packet.source_port,
            'destination_ip': packet.destination_ip,
            'destination_port': packet.destination_port,
            'protocol': packet.protocol.name if packet.protocol else '未知',
            'direction': packet.direction,
            'status': packet.status,
            'packet_size': packet.packet_size,
            'detail_url': reverse('packet_detail', args=[packet.id])
        })
    
    return JsonResponse({
        'packets': packets_data,
        'total_count': packets.count()
    })
