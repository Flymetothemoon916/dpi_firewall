from django.db import models
from django.utils import timezone

class SystemStatus(models.Model):
    """系统状态模型，记录防火墙系统的运行状态"""
    RUNNING = 'running'
    STOPPED = 'stopped'
    PAUSED = 'paused'
    ERROR = 'error'
    
    STATUS_CHOICES = [
        (RUNNING, '运行中'),
        (STOPPED, '已停止'),
        (PAUSED, '已暂停'),
        (ERROR, '错误'),
    ]
    
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default=STOPPED,
        verbose_name='系统状态'
    )
    cpu_usage = models.FloatField(verbose_name='CPU使用率', default=0.0)
    memory_usage = models.FloatField(verbose_name='内存使用率', default=0.0)
    started_at = models.DateTimeField(verbose_name='启动时间', null=True, blank=True)
    updated_at = models.DateTimeField(verbose_name='更新时间', auto_now=True)
    
    def __str__(self):
        return f"系统状态: {self.get_status_display()}"
    
    class Meta:
        verbose_name = '系统状态'
        verbose_name_plural = '系统状态'


class TrafficStatistics(models.Model):
    """流量统计模型，记录网络流量统计信息"""
    timestamp = models.DateTimeField(verbose_name='统计时间', default=timezone.now)
    inbound_packets = models.BigIntegerField(verbose_name='入站数据包数', default=0)
    outbound_packets = models.BigIntegerField(verbose_name='出站数据包数', default=0)
    inbound_bytes = models.BigIntegerField(verbose_name='入站流量(字节)', default=0)
    outbound_bytes = models.BigIntegerField(verbose_name='出站流量(字节)', default=0)
    blocked_packets = models.IntegerField(verbose_name='拦截数据包数', default=0)
    inbound_bytes_per_sec = models.FloatField(verbose_name='入站流量(字节/秒)', default=0)
    outbound_bytes_per_sec = models.FloatField(verbose_name='出站流量(字节/秒)', default=0)
    
    def __str__(self):
        return f"流量统计 - {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
    
    class Meta:
        verbose_name = '流量统计'
        verbose_name_plural = '流量统计'
        ordering = ['-timestamp']


class AlertLog(models.Model):
    """告警日志模型，记录系统告警信息"""
    INFO = 'info'
    WARNING = 'warning'
    ERROR = 'error'
    CRITICAL = 'critical'
    
    LEVEL_CHOICES = [
        (INFO, '信息'),
        (WARNING, '警告'),
        (ERROR, '错误'),
        (CRITICAL, '严重'),
    ]
    
    timestamp = models.DateTimeField(verbose_name='告警时间', default=timezone.now)
    level = models.CharField(
        max_length=10,
        choices=LEVEL_CHOICES,
        default=INFO,
        verbose_name='告警级别'
    )
    title = models.CharField(verbose_name='告警标题', max_length=100)
    description = models.TextField(verbose_name='告警内容')
    source_ip = models.GenericIPAddressField(verbose_name='源IP地址', null=True, blank=True)
    is_read = models.BooleanField(verbose_name='是否已读', default=False)
    
    def __str__(self):
        return f"{self.get_level_display()} - {self.title}"
    
    class Meta:
        verbose_name = '告警日志'
        verbose_name_plural = '告警日志'
        ordering = ['-timestamp']
