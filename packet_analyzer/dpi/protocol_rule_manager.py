"""
协议规则管理器 - 针对不同协议应用不同的规则集
"""
import logging
from typing import Dict, List, Set, Optional, Tuple, Any

from django.utils import timezone
from firewall_rules.models import Rule, RulePattern, RuleCategory

logger = logging.getLogger(__name__)

class ProtocolRuleManager:
    """
    协议规则管理器
    
    负责为不同协议（HTTP/HTTPS）管理和应用不同的规则集：
    - HTTP: 应用完整的内容检测规则
    - HTTPS: 仅应用不依赖于内容检测的规则
    """
    
    def __init__(self):
        self.initialized = False
        self.last_update = None
        self.http_rules = []
        self.https_rules = []
        self.content_inspection_categories = set()
        
    def initialize(self):
        """初始化协议规则管理器"""
        logger.info("初始化协议规则管理器")
        
        # 设置内容检测类别
        self.content_inspection_categories = {
            'SQL注入', 
            '跨站脚本', 
            '命令注入', 
            '文件访问', 
            'Web攻击'
        }
        
        # 从数据库加载规则
        self._load_protocol_rules()
        
        self.initialized = True
        self.last_update = timezone.now()
        logger.info(f"协议规则管理器初始化完成，HTTP规则：{len(self.http_rules)}，HTTPS规则：{len(self.https_rules)}")
        
    def reload_if_needed(self, force=False):
        """检查是否需要重新加载规则"""
        if not self.initialized or force:
            self.initialize()
            return True
        
        # 检查最后加载时间，定期刷新规则
        current_time = timezone.now()
        if (current_time - self.last_update).total_seconds() > 300:  # 5分钟刷新一次
            logger.info("协议规则管理器定期刷新")
            self.initialize()
            return True
            
        return False
        
    def _load_protocol_rules(self):
        """从数据库加载不同协议的规则"""
        # 清空现有规则
        self.http_rules = []
        self.https_rules = []
        
        # 加载所有启用的规则
        active_rules = Rule.objects.filter(is_enabled=True).select_related('category').prefetch_related('pattern')
        
        for rule in active_rules:
            # 对HTTP规则：所有规则都适用
            if not rule.application_protocol or rule.application_protocol.upper() == 'HTTP':
                self.http_rules.append(rule)
            
            # 对HTTPS规则：只有不依赖内容检测的规则适用
            if not rule.application_protocol or rule.application_protocol.upper() == 'HTTPS':
                # 检查该规则是否依赖于内容检测
                is_content_dependent = False
                
                # 检查规则类别
                if rule.category and rule.category.name in self.content_inspection_categories:
                    is_content_dependent = True
                
                # 检查规则是否有检测模式
                has_patterns = rule.pattern.exists()
                
                # 如果不依赖内容检测，或者是基于IP/端口的规则，加入HTTPS规则集
                if not is_content_dependent or not has_patterns:
                    self.https_rules.append(rule)
    
    def get_rules_for_protocol(self, protocol: str) -> List[Rule]:
        """
        获取适用于指定协议的规则列表
        
        Args:
            protocol: 协议名称 ('HTTP' 或 'HTTPS')
            
        Returns:
            List[Rule]: 适用的规则列表
        """
        if not self.initialized:
            self.initialize()
            
        protocol = protocol.upper()
        
        if protocol == 'HTTP':
            return self.http_rules
        elif protocol == 'HTTPS':
            return self.https_rules
        else:
            # 默认情况，返回HTTP规则
            return self.http_rules
    
    def is_content_inspection_rule(self, rule: Rule) -> bool:
        """
        检查规则是否依赖于内容检测
        
        Args:
            rule: 要检查的规则
            
        Returns:
            bool: 是否依赖内容检测
        """
        # 检查规则是否有检测模式
        has_patterns = rule.pattern.exists()
        
        # 检查规则类别
        category_dependent = False
        if rule.category and rule.category.name in self.content_inspection_categories:
            category_dependent = True
            
        return has_patterns or category_dependent
    
    def is_applicable_to_https(self, rule: Rule) -> bool:
        """
        检查规则是否适用于HTTPS流量
        
        Args:
            rule: 要检查的规则
            
        Returns:
            bool: 是否适用于HTTPS
        """
        # 如果规则明确指定为HTTP而非HTTPS，则不适用
        if rule.application_protocol and rule.application_protocol.upper() == 'HTTP':
            return False
            
        # 检查规则是否依赖内容检测
        return not self.is_content_inspection_rule(rule)
            
    def classify_rule(self, rule: Rule) -> List[str]:
        """
        分析规则并返回其适用的协议列表
        
        Args:
            rule: 要分类的规则
            
        Returns:
            List[str]: 适用的协议列表
        """
        protocols = []
        
        # 检查是否适用于HTTP
        if not rule.application_protocol or rule.application_protocol.upper() == 'HTTP':
            protocols.append('HTTP')
            
        # 检查是否适用于HTTPS
        if self.is_applicable_to_https(rule):
            protocols.append('HTTPS')
            
        return protocols

# 全局单例
protocol_rule_manager = ProtocolRuleManager() 