from django.contrib import admin
from .models import Protocol, PacketLog, DeepInspectionResult

@admin.register(Protocol)
class ProtocolAdmin(admin.ModelAdmin):
    list_display = ('name', 'port', 'description')
    search_fields = ('name', 'description')
    list_filter = ('name',)
    ordering = ('name',)


class DeepInspectionResultInline(admin.StackedInline):
    model = DeepInspectionResult
    can_delete = False
    verbose_name_plural = 'DPI分析结果'
    extra = 0


@admin.register(PacketLog)
class PacketLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'source_ip', 'source_port', 'destination_ip', 
                   'destination_port', 'protocol', 'direction', 'status', 'packet_size')
    list_filter = ('status', 'direction', 'protocol', 'timestamp')
    search_fields = ('source_ip', 'destination_ip', 'payload')
    date_hierarchy = 'timestamp'
    readonly_fields = ('timestamp', 'matched_rule')
    inlines = [DeepInspectionResultInline]
    ordering = ('-timestamp',)
    
    def has_change_permission(self, request, obj=None):
        # 防止修改历史数据包记录
        return False


@admin.register(DeepInspectionResult)
class DeepInspectionResultAdmin(admin.ModelAdmin):
    list_display = ('packet', 'application_protocol', 'content_type', 'risk_level', 'is_malicious')
    list_filter = ('risk_level', 'is_malicious', 'application_protocol')
    search_fields = ('application_protocol', 'content_type', 'detected_patterns')
    readonly_fields = ('packet',)
    
    def has_change_permission(self, request, obj=None):
        # 防止修改历史DPI结果
        return False
