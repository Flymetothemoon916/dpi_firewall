from django.contrib import admin
from .models import RuleCategory, RulePattern, Rule, IPBlacklist, IPWhitelist

@admin.register(RuleCategory)
class RuleCategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'priority', 'description')
    search_fields = ('name', 'description')
    list_editable = ('priority',)
    ordering = ('priority', 'name')


@admin.register(RulePattern)
class RulePatternAdmin(admin.ModelAdmin):
    list_display = ('name', 'is_regex', 'description')
    list_filter = ('is_regex',)
    search_fields = ('name', 'pattern_string', 'description')


class RulePatternInline(admin.TabularInline):
    model = Rule.pattern.through
    extra = 1


@admin.register(Rule)
class RuleAdmin(admin.ModelAdmin):
    list_display = ('name', 'category', 'protocol', 'action', 'priority', 
                   'is_enabled', 'hits', 'created_at')
    list_filter = ('is_enabled', 'action', 'priority', 'category', 'protocol')
    search_fields = ('name', 'description', 'source_ip', 'destination_ip')
    readonly_fields = ('hits', 'created_at', 'updated_at')
    date_hierarchy = 'created_at'
    list_editable = ('is_enabled', 'priority')
    fieldsets = (
        ('基本信息', {
            'fields': ('name', 'description', 'category', 'is_enabled')
        }),
        ('匹配条件', {
            'fields': ('source_ip', 'destination_ip', 'source_port', 
                      'destination_port', 'protocol', 'application_protocol')
        }),
        ('行为设置', {
            'fields': ('action', 'priority', 'log_prefix')
        }),
        ('统计信息', {
            'fields': ('hits', 'created_at', 'updated_at')
        }),
    )
    inlines = [RulePatternInline]
    exclude = ('pattern',)


@admin.register(IPBlacklist)
class IPBlacklistAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'description', 'added_at', 'expiry', 'is_permanent')
    list_filter = ('is_permanent', 'added_at')
    search_fields = ('ip_address', 'description')
    date_hierarchy = 'added_at'
    list_editable = ('is_permanent',)
    readonly_fields = ('added_at',)


@admin.register(IPWhitelist)
class IPWhitelistAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'description', 'added_at')
    search_fields = ('ip_address', 'description')
    date_hierarchy = 'added_at'
    readonly_fields = ('added_at',)
