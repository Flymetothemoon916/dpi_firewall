from django.db import models
from django.utils import timezone

class Protocol(models.Model):
    """协议模型，记录不同的网络协议"""
    name = models.CharField(verbose_name='协议名称', max_length=50, unique=True)
    description = models.TextField(verbose_name='协议描述', blank=True)
    port = models.IntegerField(verbose_name='默认端口', null=True, blank=True)
    
    def __str__(self):
        return self.name
    
    class Meta:
        verbose_name = '协议'
        verbose_name_plural = '协议'
        ordering = ['name']


class PacketLog(models.Model):
    """数据包日志模型，记录网络数据包信息"""
    INBOUND = 'inbound'
    OUTBOUND = 'outbound'
    
    DIRECTION_CHOICES = [
        (INBOUND, '入站'),
        (OUTBOUND, '出站'),
    ]
    
    ALLOWED = 'allowed'
    BLOCKED = 'blocked'
    SUSPICIOUS = 'suspicious'
    
    STATUS_CHOICES = [
        (ALLOWED, '已允许'),
        (BLOCKED, '已阻止'),
        (SUSPICIOUS, '可疑'),
    ]
    
    timestamp = models.DateTimeField(verbose_name='捕获时间', default=timezone.now, db_index=True)
    source_ip = models.GenericIPAddressField(verbose_name='源IP地址')
    source_port = models.IntegerField(verbose_name='源端口')
    destination_ip = models.GenericIPAddressField(verbose_name='目标IP地址')
    destination_port = models.IntegerField(verbose_name='目标端口')
    protocol = models.ForeignKey(Protocol, on_delete=models.SET_NULL, null=True, verbose_name='协议')
    payload = models.TextField(verbose_name='数据内容', blank=True)
    packet_size = models.IntegerField(verbose_name='数据包大小(字节)', default=0)
    processing_time = models.FloatField(verbose_name='处理时间(毫秒)', default=0.0)
    direction = models.CharField(
        max_length=10,
        choices=DIRECTION_CHOICES,
        default=INBOUND,
        verbose_name='方向'
    )
    status = models.CharField(
        max_length=10,
        choices=STATUS_CHOICES,
        default=ALLOWED,
        verbose_name='状态'
    )
    matched_rule = models.ForeignKey(
        'firewall_rules.Rule',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name='匹配规则',
        related_name='matched_packets'
    )
    
    def __str__(self):
        return f"{self.source_ip}:{self.source_port} → {self.destination_ip}:{self.destination_port} ({self.get_status_display()})"
    
    class Meta:
        verbose_name = '数据包日志'
        verbose_name_plural = '数据包日志'
        ordering = ['-timestamp']


class DeepInspectionResult(models.Model):
    """深度包检测结果模型，记录DPI分析结果"""
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    
    RISK_LEVEL_CHOICES = [
        (LOW, '低'),
        (MEDIUM, '中'),
        (HIGH, '高'),
    ]
    
    packet = models.OneToOneField(PacketLog, on_delete=models.CASCADE, verbose_name='关联数据包')
    application_protocol = models.CharField(verbose_name='应用层协议', max_length=50)
    content_type = models.CharField(verbose_name='内容类型', max_length=100, blank=True)
    detected_patterns = models.TextField(verbose_name='检测到的模式', blank=True)
    risk_level = models.CharField(
        max_length=10,
        choices=RISK_LEVEL_CHOICES,
        default=LOW,
        verbose_name='风险等级'
    )
    is_malicious = models.BooleanField(verbose_name='是否恶意', default=False)
    decoded_content = models.TextField(verbose_name='解码内容', blank=True, null=True)
    metadata = models.JSONField(verbose_name='元数据', default=dict, blank=True)
    
    def __str__(self):
        return f"DPI结果 - {self.application_protocol} ({self.get_risk_level_display()}风险)"
    
    class Meta:
        verbose_name = 'DPI分析结果'
        verbose_name_plural = 'DPI分析结果'
