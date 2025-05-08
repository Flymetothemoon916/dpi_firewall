from django.apps import AppConfig


class FirewallRulesConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'firewall_rules'
    verbose_name = '防火墙规则'
    
    def ready(self):
        """当应用程序准备好时初始化协议规则管理器"""
        # 导入协议规则管理器
        try:
            from packet_analyzer.dpi.protocol_rule_manager import protocol_rule_manager
            
            # 在应用程序启动时初始化
            protocol_rule_manager.reload_if_needed()
        except Exception as e:
            # 防止在初始化时可能出现的导入错误
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"协议规则管理器初始化失败: {str(e)}")
        
        # 导入信号处理器
        import firewall_rules.signals
