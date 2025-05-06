from django.contrib import admin
from .models import SystemStatus, TrafficStatistics, AlertLog

# 注释掉SystemStatus模型的注册
# @admin.register(SystemStatus)
# class SystemStatusAdmin(admin.ModelAdmin):
#     list_display = ('status', 'cpu_usage', 'memory_usage', 'started_at', 'updated_at')
#     list_filter = ('status',)
#     readonly_fields = ('updated_at',)
#     search_fields = ('status',)
    
#     def has_add_permission(self, request):
#         # 限制只能有一个系统状态实例
#         if self.model.objects.count() >= 1:
#             return False
#         return super().has_add_permission(request)


@admin.register(TrafficStatistics)
class TrafficStatisticsAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'inbound_packets', 'outbound_packets', 
                   'inbound_bytes', 'outbound_bytes', 'blocked_packets')
    list_filter = ('timestamp',)
    date_hierarchy = 'timestamp'
    ordering = ('-timestamp',)


@admin.register(AlertLog)
class AlertLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'level', 'title', 'source_ip', 'is_read')
    list_filter = ('level', 'is_read', 'timestamp')
    search_fields = ('title', 'description', 'source_ip')
    date_hierarchy = 'timestamp'
    list_editable = ('is_read',)
    ordering = ('-timestamp',)
