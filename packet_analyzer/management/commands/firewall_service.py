import time
import logging
import signal
import sys
from django.core.management.base import BaseCommand
from packet_analyzer.dpi.firewall_engine import FirewallEngine
from packet_analyzer.dpi.packet_analyzer import DPIPacketAnalyzer
from scapy.all import get_if_list, conf

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = '启动防火墙服务，捕获并分析网络数据包'

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
            help='要处理的数据包数量 (0 表示无限制)'
        )
        parser.add_argument(
            '--timeout', '-t',
            type=int,
            default=None,
            help='服务运行超时时间(秒)'
        )
        parser.add_argument(
            '--verbose', '-V',
            action='store_true',
            help='输出详细日志'
        )
        parser.add_argument(
            '--foreground', '-f',
            action='store_true',
            help='前台运行，不后台执行'
        )

    def handle(self, *args, **options):
        interface = options['interface']
        count = options['count']
        timeout = options['timeout']
        verbose = options['verbose']
        foreground = options['foreground']

        # 设置日志级别
        if verbose:
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)

        self.stdout.write("正在初始化防火墙引擎...")

        # 初始化防火墙引擎
        try:
            firewall = FirewallEngine()
            if not firewall.start():
                self.stderr.write(self.style.ERROR("启动防火墙引擎失败"))
                return
        except Exception as e:
            self.stderr.write(self.style.ERROR(f"防火墙引擎初始化失败: {str(e)}"))
            return

        # 获取网络接口列表
        try:
            interfaces = get_if_list()
            
            # 输出可用接口
            self.stdout.write(self.style.SUCCESS("可用网络接口:"))
            for i, iface in enumerate(interfaces):
                self.stdout.write(f"  [{i}] {iface}")
                
            # 如果提供了接口索引，找到对应的接口名称
            if interface and interface.isdigit():
                index = int(interface)
                if 0 <= index < len(interfaces):
                    interface = interfaces[index]
                else:
                    raise ValueError(f"找不到索引为 {index} 的网络接口")
                    
            self.stdout.write(self.style.SUCCESS(f"使用网络接口: {interface or '默认'}"))
        except Exception as e:
            self.stderr.write(self.style.ERROR(f"获取网络接口列表失败: {str(e)}"))
            return

        # 设置信号处理器，用于优雅退出
        def signal_handler(sig, frame):
            self.stdout.write(self.style.SUCCESS("\n正在停止防火墙服务..."))
            firewall.stop()
            self.stdout.write(self.style.SUCCESS("防火墙服务已停止"))
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # 创建一个新的数据包分析器实例
        self.stdout.write("初始化DPI数据包分析器...")
        analyzer = DPIPacketAnalyzer()

        # 集成防火墙和分析器
        def packet_callback(packet):
            # 初始化变量
            action = "allowed"
            matched_rule = None
            
            try:
                # 先使用防火墙引擎处理数据包
                result = firewall.process_packet(packet)
                if isinstance(result, tuple) and len(result) == 2:
                    action, matched_rule = result
                else:
                    logger.error(f"防火墙处理结果格式错误: {result}")
                    action = "blocked"
                
                # 如果允许通过，进一步分析
                if action == "allowed":
                    analyzer.process_packet(packet)
                    
            except Exception as e:
                logger.error(f"处理数据包时出错: {str(e)}")
                action = "blocked"  # 出错时默认阻止
                matched_rule = None
                
            return action

        try:
            # 输出开始信息
            self.stdout.write(self.style.SUCCESS(f"防火墙服务已启动"))
            self.stdout.write(f"数据包数量限制: {count if count > 0 else '无限制'}")
            self.stdout.write(f"超时时间: {timeout if timeout else '无限制'}")
            self.stdout.write("按 Ctrl+C 停止服务")

            # 导入scapy模块
            from scapy.all import sniff
            
            # 开始数据包捕获和实时分析
            sniff(
                iface=interface,
                prn=packet_callback,
                count=count,
                timeout=timeout,
                store=False
            )
            
            # 如果设置了count或timeout并正常结束，停止防火墙服务
            self.stdout.write(self.style.SUCCESS("数据包捕获完成"))
            firewall.stop()
            self.stdout.write(self.style.SUCCESS("防火墙服务已停止"))
            
        except KeyboardInterrupt:
            self.stdout.write(self.style.SUCCESS("\n接收到中断信号"))
            firewall.stop()
            self.stdout.write(self.style.SUCCESS("防火墙服务已停止"))
        except Exception as e:
            self.stderr.write(self.style.ERROR(f"防火墙服务运行时错误: {str(e)}"))
            firewall.stop() 