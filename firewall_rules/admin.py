from django.contrib import admin
from .models import RuleCategory, RulePattern, Rule, IPBlacklist, IPWhitelist

@admin.register(RuleCategory)
class RuleCategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'priority', 'description')
    search_fields = ('name', 'description')
    ordering = ('priority', 'name')
    list_filter = ('priority',)


@admin.register(RulePattern)
class RulePatternAdmin(admin.ModelAdmin):
    list_display = ('name', 'is_regex', 'pattern_preview')
    search_fields = ('name', 'pattern_string', 'description')
    list_filter = ('is_regex',)
    
    def pattern_preview(self, obj):
        """显示模式字符串的预览"""
        if len(obj.pattern_string) > 50:
            return f"{obj.pattern_string[:50]}..."
        return obj.pattern_string
    
    pattern_preview.short_description = '模式预览'


class RulePatternInline(admin.TabularInline):
    model = Rule.pattern.through
    extra = 1
    verbose_name = '检测模式'
    verbose_name_plural = '检测模式列表'


@admin.register(Rule)
class RuleAdmin(admin.ModelAdmin):
    list_display = ('name', 'category', 'get_applicable_protocols', 'action', 'priority', 'hits', 'is_enabled')
    list_filter = ('category', 'application_protocol', 'action', 'priority', 'is_enabled')
    search_fields = ('name', 'description', 'source_ip', 'destination_ip')
    readonly_fields = ('hits', 'created_at', 'updated_at', 'get_applicable_protocols')
    filter_horizontal = ('pattern',)
    
    fieldsets = (
        ('基本信息', {
            'fields': ('name', 'description', 'category', 'application_protocol', 'get_applicable_protocols', 'is_enabled')
        }),
        ('匹配条件', {
            'fields': ('source_ip', 'destination_ip', 'source_port', 'destination_port', 'protocol')
        }),
        ('动作和优先级', {
            'fields': ('action', 'priority', 'log_prefix')
        }),
        ('统计信息', {
            'fields': ('hits', 'created_at', 'updated_at')
        }),
    )
    
    inlines = [RulePatternInline]
    exclude = ('pattern',)
    
    def get_applicable_protocols(self, obj):
        """获取规则适用的协议列表"""
        # 导入时可能还没准备好，放在函数内部导入
        try:
            from packet_analyzer.dpi.protocol_rule_manager import protocol_rule_manager
            
            # 确保协议规则管理器已初始化
            protocol_rule_manager.reload_if_needed()
            
            # 获取适用协议
            protocols = protocol_rule_manager.classify_rule(obj)
            
            if not protocols:
                return "无适用协议"
            
            return ", ".join(protocols)
        except ImportError:
            return "未知"
    
    get_applicable_protocols.short_description = '适用协议'
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('category').prefetch_related('pattern')


@admin.register(IPBlacklist)
class IPBlacklistAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'is_permanent', 'expiry', 'description', 'added_at')
    list_filter = ('is_permanent', 'added_at')
    search_fields = ('ip_address', 'description')
    readonly_fields = ('added_at',)
    
    fieldsets = (
        ('IP信息', {
            'fields': ('ip_address', 'description')
        }),
        ('有效期', {
            'fields': ('is_permanent', 'expiry')
        }),
        ('添加时间', {
            'fields': ('added_at',)
        }),
    )


@admin.register(IPWhitelist)
class IPWhitelistAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'description', 'added_at')
    search_fields = ('ip_address', 'description')
    readonly_fields = ('added_at',)
    
    fieldsets = (
        ('IP信息', {
            'fields': ('ip_address', 'description', 'added_at')
        }),
    )
