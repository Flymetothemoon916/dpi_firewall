import logging
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.db import transaction
from django.db.models import Q

from packet_analyzer.models import PacketLog
from dashboard.models import TrafficStatistics, AlertLog

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = '修复数据库中的无效日期时间值问题'
    
    def handle(self, *args, **options):
        self.stdout.write('开始修复数据库中的日期时间值...')
        
        try:
            with transaction.atomic():
                # 修复 PacketLog 的时间戳
                invalid_packets = self._fix_packetlog_timestamps()
                self.stdout.write(f'已修复 {invalid_packets} 条无效的数据包日志记录')
                
                # 修复 TrafficStatistics 的时间戳
                invalid_stats = self._fix_trafficstatistics_timestamps()
                self.stdout.write(f'已修复 {invalid_stats} 条无效的流量统计记录')
                
                # 修复 AlertLog 的时间戳
                invalid_alerts = self._fix_alertlog_timestamps()
                self.stdout.write(f'已修复 {invalid_alerts} 条无效的告警日志记录')
                
            self.stdout.write(self.style.SUCCESS('数据库日期时间值修复完成!'))
        
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'修复过程中出错: {e}'))
            logger.error(f'修复日期时间值时出错: {e}')
    
    def _fix_packetlog_timestamps(self):
        """修复 PacketLog 中的无效时间戳"""
        try:
            # 尝试发现无效的日期时间值
            problematic_packets = PacketLog.objects.filter(
                Q(timestamp__isnull=True) | 
                Q(timestamp__year__lt=2020) |  # 假设2020年之前的记录为无效
                Q(timestamp__gt=timezone.now() + timezone.timedelta(days=1))  # 未来日期
            )
            
            count = problematic_packets.count()
            
            # 更新为当前时间
            if count > 0:
                now = timezone.now()
                problematic_packets.update(timestamp=now)
            
            return count
        
        except Exception as e:
            logger.error(f'修复 PacketLog 时间戳时出错: {e}')
            return 0
    
    def _fix_trafficstatistics_timestamps(self):
        """修复 TrafficStatistics 中的无效时间戳"""
        try:
            # 尝试发现无效的日期时间值
            problematic_stats = TrafficStatistics.objects.filter(
                Q(timestamp__isnull=True) | 
                Q(timestamp__year__lt=2020) |  # 假设2020年之前的记录为无效
                Q(timestamp__gt=timezone.now() + timezone.timedelta(days=1))  # 未来日期
            )
            
            count = problematic_stats.count()
            
            # 更新为当前时间
            if count > 0:
                now = timezone.now()
                problematic_stats.update(timestamp=now)
            
            return count
        
        except Exception as e:
            logger.error(f'修复 TrafficStatistics 时间戳时出错: {e}')
            return 0
    
    def _fix_alertlog_timestamps(self):
        """修复 AlertLog 中的无效时间戳"""
        try:
            # 尝试发现无效的日期时间值
            problematic_alerts = AlertLog.objects.filter(
                Q(timestamp__isnull=True) | 
                Q(timestamp__year__lt=2020) |  # 假设2020年之前的记录为无效
                Q(timestamp__gt=timezone.now() + timezone.timedelta(days=1))  # 未来日期
            )
            
            count = problematic_alerts.count()
            
            # 更新为当前时间
            if count > 0:
                now = timezone.now()
                problematic_alerts.update(timestamp=now)
            
            return count
        
        except Exception as e:
            logger.error(f'修复 AlertLog 时间戳时出错: {e}')
            return 0 