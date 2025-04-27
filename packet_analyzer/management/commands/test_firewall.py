from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import datetime
import time

class Command(BaseCommand):
    help = '测试时间戳处理和防火墙功能'

    def handle(self, *args, **options):
        self.stdout.write('开始时间戳测试...')
        
        # 使用timezone.now()
        now_tz = timezone.now()
        self.stdout.write(f"timezone.now(): {now_tz} (类型: {type(now_tz)})")
        
        # 使用datetime.now()
        now_naive = datetime.now()
        self.stdout.write(f"datetime.now(): {now_naive} (类型: {type(now_naive)})")
        
        # 使用两种方式计算时间差
        try:
            time_diff_invalid = (now_tz - now_naive).total_seconds()
            self.stdout.write(f"无效时间差 (timezone.now - datetime.now): {time_diff_invalid}")
        except Exception as e:
            self.stdout.write(f"无效时间差计算错误: {str(e)}")
        
        # 创建相同类型的时间戳测试有效计算
        time.sleep(1)
        later_tz = timezone.now()
        time_diff_valid = (later_tz - now_tz).total_seconds()
        self.stdout.write(f"有效时间差 (timezone.now - timezone.now): {time_diff_valid}")
        
        self.stdout.write(self.style.SUCCESS('\n结论：始终使用 timezone.now() 而不是 datetime.now()'))
        
        # 现在测试修复后的防火墙引擎
        from packet_analyzer.dpi.firewall_engine import FirewallEngine
        from packet_analyzer.dpi.packet_analyzer import DPIPacketAnalyzer
        
        self.stdout.write("\n开始防火墙引擎测试...")
        
        # 初始化防火墙引擎
        try:
            engine = FirewallEngine()
            self.stdout.write(self.style.SUCCESS("防火墙引擎初始化成功"))
            
            # 尝试访问 stats 来测试时间戳
            last_update = engine.stats['last_update']
            self.stdout.write(f"引擎最后更新时间: {last_update} (类型: {type(last_update)})")
            
            # 更新并测试时间差计算
            now = timezone.now()
            time_diff = (now - last_update).total_seconds()
            self.stdout.write(f"引擎初始化到现在的时间差: {time_diff} 秒")
            
            # 测试 _update_stats 方法
            engine._update_stats("inbound", 1000)
            self.stdout.write(self.style.SUCCESS("更新统计数据成功"))
            
            # 测试 _save_stats 方法
            engine._save_stats()
            self.stdout.write(self.style.SUCCESS("保存统计数据成功"))
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"防火墙引擎测试失败: {str(e)}"))
            import traceback
            self.stdout.write(traceback.format_exc())
        
        # 测试DPI分析器
        try:
            self.stdout.write("\n开始DPI分析器测试...")
            analyzer = DPIPacketAnalyzer()
            self.stdout.write(self.style.SUCCESS("DPI分析器初始化成功"))
            
            # 检查 stats
            last_update = analyzer.stats['last_update']
            self.stdout.write(f"分析器最后更新时间: {last_update} (类型: {type(last_update)})")
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"DPI分析器测试失败: {str(e)}"))
            import traceback
            self.stdout.write(traceback.format_exc()) 