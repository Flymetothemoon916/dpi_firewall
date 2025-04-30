import logging
import re
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.db import transaction

from packet_analyzer.models import PacketLog, DeepInspectionResult

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = '为缺少DPI分析结果的可疑或阻止的数据包生成DPI分析结果'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--limit',
            type=int,
            default=0,
            help='限制处理的数据包数量，0表示处理所有'
        )
        
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='只显示将要生成的DPI结果数量，不实际执行'
        )
    
    def handle(self, *args, **options):
        limit = options.get('limit', 0)
        dry_run = options.get('dry_run', False)
        
        self.stdout.write('开始修复DPI分析结果...')
        
        # 获取所有可疑或阻止的数据包，但没有对应的DPI分析结果
        packets_needing_dpi = PacketLog.objects.filter(
            status__in=['suspicious', 'blocked']
        ).exclude(
            id__in=DeepInspectionResult.objects.values_list('packet_id', flat=True)
        )
        
        if limit > 0:
            packets_needing_dpi = packets_needing_dpi[:limit]
        
        total_packets = packets_needing_dpi.count()
        
        self.stdout.write(f'找到 {total_packets} 条需要生成DPI分析结果的数据包')
        
        if dry_run:
            self.stdout.write(self.style.SUCCESS('仅显示统计，未执行实际操作'))
            return
        
        created_count = 0
        
        try:
            with transaction.atomic():
                for packet_log in packets_needing_dpi:
                    try:
                        # 提取应用层协议
                        app_protocol = "UNKNOWN"
                        if packet_log.protocol:
                            app_protocol = packet_log.protocol.name
                        
                        # 根据端口推断应用层协议
                        dst_port = packet_log.destination_port
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
                        elif dst_port == 53:
                            app_protocol = "DNS"
                        
                        # 提取内容类型和检测模式
                        content_type = ""
                        detected_patterns = ""
                        is_malicious = False
                        risk_level = "low"
                        metadata = {}
                        
                        # 根据状态设置风险级别
                        if packet_log.status == 'blocked':
                            risk_level = "high"
                            is_malicious = True
                            detected_patterns = "自动阻止的流量"
                        elif packet_log.status == 'suspicious':
                            risk_level = "medium"
                            detected_patterns = "可疑流量模式"
                        
                        # 提取更多元数据
                        metadata = {
                            'source_ip': packet_log.source_ip,
                            'destination_ip': packet_log.destination_ip,
                            'source_port': packet_log.source_port,
                            'destination_port': packet_log.destination_port,
                            'direction': packet_log.direction,
                            'status': packet_log.status,
                            'generated_by': 'fix_dpi_results',
                            'timestamp': timezone.now().isoformat()
                        }
                        
                        # 创建DPI分析结果
                        DeepInspectionResult.objects.create(
                            packet=packet_log,
                            application_protocol=app_protocol,
                            content_type=content_type,
                            detected_patterns=detected_patterns,
                            risk_level=risk_level,
                            is_malicious=is_malicious,
                            metadata=metadata
                        )
                        
                        created_count += 1
                        
                        if created_count % 100 == 0:
                            self.stdout.write(f'已处理 {created_count}/{total_packets} 条数据包')
                            
                    except Exception as e:
                        self.stdout.write(self.style.WARNING(f'处理数据包 {packet_log.id} 时出错: {str(e)}'))
                        logger.error(f'处理数据包 {packet_log.id} 时出错: {str(e)}')
            
            self.stdout.write(self.style.SUCCESS(f'成功为 {created_count}/{total_packets} 条数据包生成DPI分析结果'))
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'修复过程中出错: {str(e)}'))
            logger.error(f'修复DPI分析结果时出错: {str(e)}') 