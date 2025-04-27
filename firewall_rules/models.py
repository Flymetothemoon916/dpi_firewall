from django.db import models
from django.utils import timezone

class RuleCategory(models.Model):
    """规则分类模型，对防火墙规则进行分类"""
    name = models.CharField(verbose_name='分类名称', max_length=50, unique=True)
    description = models.TextField(verbose_name='分类描述', blank=True)
    priority = models.IntegerField(verbose_name='优先级', default=0)
    
    def __str__(self):
        return self.name
    
    class Meta:
        verbose_name = '规则分类'
        verbose_name_plural = '规则分类'
        ordering = ['priority', 'name']


class RulePattern(models.Model):
    """规则模式模型，定义DPI检测模式"""
    name = models.CharField(verbose_name='模式名称', max_length=100)
    pattern_string = models.TextField(verbose_name='检测模式字符串')
    description = models.TextField(verbose_name='模式描述', blank=True)
    is_regex = models.BooleanField(verbose_name='是否正则表达式', default=False)
    
    def __str__(self):
        return self.name
    
    class Meta:
        verbose_name = '检测模式'
        verbose_name_plural = '检测模式'


class Rule(models.Model):
    """防火墙规则模型，定义网络流量过滤规则"""
    ALLOW = 'allow'
    BLOCK = 'block'
    LOG = 'log'
    ALERT = 'alert'
    
    ACTION_CHOICES = [
        (ALLOW, '允许'),
        (BLOCK, '阻止'),
        (LOG, '仅记录'),
        (ALERT, '告警'),
    ]
    
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'
    
    PRIORITY_CHOICES = [
        (LOW, '低'),
        (MEDIUM, '中'),
        (HIGH, '高'),
        (CRITICAL, '严重'),
    ]
    
    name = models.CharField(verbose_name='规则名称', max_length=100)
    description = models.TextField(verbose_name='规则描述', blank=True)
    category = models.ForeignKey(RuleCategory, on_delete=models.SET_NULL, null=True, verbose_name='规则分类')
    
    # 基本匹配条件
    source_ip = models.CharField(verbose_name='源IP', max_length=50, blank=True, help_text='可使用CIDR格式')
    destination_ip = models.CharField(verbose_name='目标IP', max_length=50, blank=True, help_text='可使用CIDR格式')
    source_port = models.CharField(verbose_name='源端口', max_length=50, blank=True, help_text='单个端口或端口范围，如 80 或 1000-2000')
    destination_port = models.CharField(verbose_name='目标端口', max_length=50, blank=True, help_text='单个端口或端口范围，如 80 或 1000-2000')
    protocol = models.CharField(verbose_name='协议', max_length=10, blank=True, help_text='如TCP, UDP, ICMP等')
    
    # DPI相关配置
    pattern = models.ManyToManyField(RulePattern, blank=True, verbose_name='检测模式')
    application_protocol = models.CharField(verbose_name='应用层协议', max_length=50, blank=True, help_text='如HTTP, FTP, DNS等')
    
    # 规则行为
    action = models.CharField(
        max_length=10,
        choices=ACTION_CHOICES,
        default=LOG,
        verbose_name='动作'
    )
    priority = models.CharField(
        max_length=10,
        choices=PRIORITY_CHOICES,
        default=MEDIUM,
        verbose_name='优先级'
    )
    log_prefix = models.CharField(verbose_name='日志前缀', max_length=50, blank=True)
    
    # 规则状态
    is_enabled = models.BooleanField(verbose_name='是否启用', default=True)
    created_at = models.DateTimeField(verbose_name='创建时间', default=timezone.now)
    updated_at = models.DateTimeField(verbose_name='更新时间', auto_now=True)
    hits = models.IntegerField(verbose_name='命中次数', default=0)
    
    def __str__(self):
        return f"{self.name} ({self.get_action_display()})"
    
    class Meta:
        verbose_name = '防火墙规则'
        verbose_name_plural = '防火墙规则'
        ordering = ['-is_enabled', 'category__priority']


class IPBlacklist(models.Model):
    """IP黑名单模型，记录被禁止访问的IP地址"""
    ip_address = models.GenericIPAddressField(verbose_name='IP地址', unique=True)
    description = models.TextField(verbose_name='禁止原因', blank=True)
    added_at = models.DateTimeField(verbose_name='添加时间', default=timezone.now)
    expiry = models.DateTimeField(verbose_name='过期时间', null=True, blank=True)
    is_permanent = models.BooleanField(verbose_name='永久禁止', default=False)
    
    def __str__(self):
        return f"{self.ip_address} {'(永久)' if self.is_permanent else ''}"
    
    class Meta:
        verbose_name = 'IP黑名单'
        verbose_name_plural = 'IP黑名单'
        ordering = ['-added_at']


class IPWhitelist(models.Model):
    """IP白名单模型，记录受信任的IP地址"""
    ip_address = models.GenericIPAddressField(verbose_name='IP地址', unique=True)
    description = models.TextField(verbose_name='信任原因', blank=True)
    added_at = models.DateTimeField(verbose_name='添加时间', default=timezone.now)
    
    def __str__(self):
        return self.ip_address
    
    class Meta:
        verbose_name = 'IP白名单'
        verbose_name_plural = 'IP白名单'
        ordering = ['ip_address']
