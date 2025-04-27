import time
import logging
import os
from django.core.management.base import BaseCommand
from packet_analyzer.dpi.packet_analyzer import DPIPacketAnalyzer
from packet_analyzer.dpi.firewall_engine import FirewallEngine
from scapy.all import get_if_list, conf

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = '启动数据包捕获和DPI分析'

    def add_arguments(self, parser):
        parser.add_argument(
            '--interface', '-i',
            type=str,
            help='要监听的网络接口索引或名称'
        )
        parser.add_argument(
            '--count', '-c',
            type=int,
            default=0,
            help='要捕获的数据包数量 (0 表示无限制)'
        )
        parser.add_argument(
            '--timeout', '-t',
            type=int,
            default=None,
            help='捕获超时时间(秒)'
        )
        parser.add_argument(
            '--verbose', '-V',
            action='store_true',
            help='输出详细日志'
        )
        parser.add_argument(
            '--engine', '-e',
            action='store_true',
            help='使用新的防火墙引擎分析数据包'
        )

    def handle(self, *args, **options):
        try:
            interface = options['interface']
            count = options['count']
            timeout = options['timeout']
            verbose = options['verbose']
            use_engine = options['engine']

            # 设置日志级别
            if verbose:
                logging.basicConfig(level=logging.DEBUG)
            else:
                logging.basicConfig(level=logging.INFO)

            # 获取网络接口列表
            interfaces = get_if_list()
            
            # 如果提供了接口索引，找到对应的接口名称
            if interface and interface.isdigit():
                index = int(interface)
                if 0 <= index < len(interfaces):
                    interface_name = interfaces[index]
                else:
                    raise ValueError(f"找不到索引为 {index} 的网络接口")
            else:
                interface_name = interface

            # 在 Windows 上，如果接口名称是 GUID 格式，添加 NPF_ 前缀
            if os.name == 'nt' and interface_name and interface_name.startswith('{') and interface_name.endswith('}'):
                interface_name = f"\\Device\\NPF_{interface_name}"

            print(f"使用网络接口: {interface_name}")
            print(f"数据包数量: {count}")
            print("开始捕获数据包，按 Ctrl+C 停止...")

            if use_engine:
                # 使用新的防火墙引擎
                self.stdout.write("使用防火墙引擎处理数据包...")
                firewall = FirewallEngine()
                if not firewall.start():
                    self.stderr.write(self.style.ERROR("启动防火墙引擎失败"))
                    return
                
                # 创建一个新的数据包分析器实例
                analyzer = DPIPacketAnalyzer()
                
                # 定义数据包处理回调
                def packet_callback(packet):
                    # 先使用防火墙引擎处理数据包
                    action, rule = firewall.process_packet(packet)
                    
                    # 如果允许通过，进一步分析
                    if action == "allowed":
                        analyzer.process_packet(packet)
                    
                    return action
                
                # 导入scapy模块
                from scapy.all import sniff
                
                # 开始数据包捕获和分析
                sniff(
                    iface=interface_name,
                    prn=packet_callback,
                    count=count,
                    timeout=timeout,
                    store=False
                )
                
                # 停止防火墙引擎
                firewall.stop()
                
            else:
                # 使用旧的分析器
                self.stdout.write("使用传统DPI分析器处理数据包...")
                sniffer = DPIPacketAnalyzer()
                sniffer.start_packet_capture(
                    interface=interface_name,
                    packet_count=count,
                    timeout=timeout
                )

        except KeyboardInterrupt:
            print("\n捕获已停止")
        except Exception as e:
            print(f"数据包捕获错误: {str(e)}")
            # 更新系统状态为错误
            try:
                from dashboard.models import SystemStatus
                SystemStatus.objects.update_or_create(
                    defaults={
                        'status': 'error',
                    }
                )
            except:
                pass 