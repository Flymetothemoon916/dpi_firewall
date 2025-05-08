import logging
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from .models import Rule, RuleCategory, RulePattern

logger = logging.getLogger(__name__)

@receiver([post_save, post_delete], sender=Rule)
def rule_changed(sender, instance, **kwargs):
    """当规则被保存或删除时，重新加载协议规则管理器"""
    try:
        from packet_analyzer.dpi.protocol_rule_manager import protocol_rule_manager
        protocol_rule_manager.reload_if_needed(force=True)
        logger.info(f"规则变更，已重新加载协议规则管理器: {instance.name if hasattr(instance, 'name') else 'Unknown'}")
    except Exception as e:
        logger.error(f"重新加载协议规则管理器失败: {str(e)}")

@receiver([post_save, post_delete], sender=RuleCategory)
def category_changed(sender, instance, **kwargs):
    """当规则类别被保存或删除时，重新加载协议规则管理器"""
    try:
        from packet_analyzer.dpi.protocol_rule_manager import protocol_rule_manager
        protocol_rule_manager.reload_if_needed(force=True)
        logger.info(f"规则类别变更，已重新加载协议规则管理器: {instance.name if hasattr(instance, 'name') else 'Unknown'}")
    except Exception as e:
        logger.error(f"重新加载协议规则管理器失败: {str(e)}")

@receiver([post_save, post_delete], sender=RulePattern)
def pattern_changed(sender, instance, **kwargs):
    """当规则模式被保存或删除时，重新加载协议规则管理器"""
    try:
        from packet_analyzer.dpi.protocol_rule_manager import protocol_rule_manager
        protocol_rule_manager.reload_if_needed(force=True)
        logger.info(f"规则模式变更，已重新加载协议规则管理器: {instance.name if hasattr(instance, 'name') else 'Unknown'}")
    except Exception as e:
        logger.error(f"重新加载协议规则管理器失败: {str(e)}")

# 初始化时记录一条日志
logger.info("防火墙规则信号处理器已注册") 