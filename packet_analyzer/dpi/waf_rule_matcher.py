"""
WAF规则匹配器 - 用于优化Web应用防火墙规则匹配过程
"""
import re
import logging
from typing import Dict, List, Set, Tuple, Optional, Any, Union

from django.utils import timezone
from firewall_rules.models import Rule, RulePattern
from packet_analyzer.dpi.protocol_rule_manager import protocol_rule_manager

logger = logging.getLogger(__name__)

class WafRuleMatcher:
    """
    WAF规则匹配器 - 优化Web应用防火墙规则的匹配
    """
    def __init__(self):
        self.rules_by_category: Dict[str, List[Rule]] = {}
        self.compiled_patterns: Dict[int, re.Pattern] = {}
        self.initialized = False
        self.last_update = None
        
    def initialize(self):
        """初始化规则匹配器"""
        logger.info("初始化WAF规则匹配器")
        self._load_rules()
        self._compile_patterns()
        self.initialized = True
        self.last_update = timezone.now()
        logger.info(f"WAF规则匹配器初始化完成，共加载{sum(len(rules) for rules in self.rules_by_category.values())}条规则")
    
    def reload_if_needed(self, force=False):
        """检查是否需要重新加载规则"""
        if not self.initialized or force:
            self.initialize()
            return True
        
        # 检查最后加载时间，定期刷新规则
        current_time = timezone.now()
        if (current_time - self.last_update).total_seconds() > 300:  # 5分钟刷新一次
            logger.info("WAF规则匹配器定期刷新")
            self.initialize()
            return True
            
        return False
    
    def _load_rules(self):
        """从数据库加载规则"""
        self.rules_by_category = {}
        
        # 加载所有已启用的规则
        rules = Rule.objects.filter(
            is_enabled=True, 
            application_protocol__in=['HTTP', 'HTTPS', '']
        ).select_related('category').prefetch_related('pattern')
        
        # 按类别组织规则
        for rule in rules:
            category_name = rule.category.name if rule.category else "未分类"
            
            if category_name not in self.rules_by_category:
                self.rules_by_category[category_name] = []
                
            self.rules_by_category[category_name].append(rule)
            
    def _compile_patterns(self):
        """预编译正则表达式模式"""
        self.compiled_patterns = {}
        
        # 遍历所有规则的检测模式
        for category_rules in self.rules_by_category.values():
            for rule in category_rules:
                for pattern in rule.pattern.filter(is_regex=True):
                    try:
                        # 编译正则表达式
                        self.compiled_patterns[pattern.id] = re.compile(
                            pattern.pattern_string, 
                            re.IGNORECASE | re.DOTALL
                        )
                    except re.error as e:
                        logger.error(f"正则表达式编译错误 - 规则ID: {rule.id}, 模式ID: {pattern.id}, 错误: {str(e)}")
    
    def match_content(self, content: str, categories: Optional[List[str]] = None, protocol: str = 'HTTP') -> List[Tuple[Rule, RulePattern]]:
        """
        检查内容是否匹配任何规则
        
        Args:
            content: 要检查的内容
            categories: 可选的类别列表，用于限制要检查的规则
            protocol: 协议类型，默认为'HTTP'
            
        Returns:
            List[Tuple[Rule, RulePattern]]: 匹配的规则和对应的模式列表
        """
        if not self.initialized:
            self.initialize()
            
        matches = []
        
        # 确保协议规则管理器已初始化
        protocol_rule_manager.reload_if_needed()
        
        # 获取适用于指定协议的规则
        applicable_rules = protocol_rule_manager.get_rules_for_protocol(protocol)
        applicable_rule_ids = {rule.id for rule in applicable_rules}
        
        # 确定要检查的类别
        categories_to_check = categories or list(self.rules_by_category.keys())
        
        # 遍历指定类别中的规则
        for category in categories_to_check:
            if category not in self.rules_by_category:
                continue
                
            for rule in self.rules_by_category[category]:
                # 检查规则是否适用于当前协议
                if rule.id not in applicable_rule_ids:
                    continue
                    
                # HTTPS流量跳过内容检测规则
                if protocol == 'HTTPS' and protocol_rule_manager.is_content_inspection_rule(rule):
                    continue
                
                for pattern in rule.pattern.all():
                    # 尝试匹配
                    if self._pattern_matches(pattern, content):
                        matches.append((rule, pattern))
                        # 如果只需要知道是否匹配，可以提前返回
                        # return matches
        
        return matches
    
    def _pattern_matches(self, pattern: RulePattern, content: str) -> bool:
        """
        检查内容是否匹配指定的模式
        
        Args:
            pattern: 检测模式
            content: 要检查的内容
            
        Returns:
            bool: 是否匹配
        """
        if pattern.is_regex:
            # 使用预编译的正则表达式
            if pattern.id in self.compiled_patterns:
                regex = self.compiled_patterns[pattern.id]
                return bool(regex.search(content))
            else:
                # 如果模式未预编译，临时编译
                try:
                    regex = re.compile(pattern.pattern_string, re.IGNORECASE | re.DOTALL)
                    return bool(regex.search(content))
                except re.error as e:
                    logger.error(f"正则表达式匹配错误 - 模式ID: {pattern.id}, 错误: {str(e)}")
                    return False
        else:
            # 非正则表达式，直接搜索
            return pattern.pattern_string.lower() in content.lower()
    
    def get_rules_for_protocol(self, protocol: str) -> List[Rule]:
        """
        获取适用于指定协议的规则
        
        Args:
            protocol: 协议名称
            
        Returns:
            List[Rule]: 适用的规则列表
        """
        # 直接使用协议规则管理器
        return protocol_rule_manager.get_rules_for_protocol(protocol)
    
    def get_blocked_rule(self, content: str, categories: Optional[List[str]] = None, protocol: str = 'HTTP') -> Optional[Tuple[Rule, RulePattern]]:
        """
        获取匹配内容且动作为阻止的第一个规则
        
        Args:
            content: 要检查的内容
            categories: 可选的类别列表，用于限制要检查的规则
            protocol: 协议类型，默认为'HTTP'
            
        Returns:
            Optional[Tuple[Rule, RulePattern]]: 匹配且阻止的规则和模式，如果没有则返回None
        """
        matches = self.match_content(content, categories, protocol)
        
        # 按优先级排序
        matches.sort(key=lambda x: self._get_rule_priority_value(x[0]), reverse=True)
        
        # 寻找需要阻止的规则
        for rule, pattern in matches:
            if rule.action == 'block':
                return (rule, pattern)
                
        return None
    
    def _get_rule_priority_value(self, rule: Rule) -> int:
        """
        获取规则优先级的数值表示
        
        Args:
            rule: 防火墙规则
            
        Returns:
            int: 优先级数值
        """
        priority_map = {
            'critical': 400,
            'high': 300,
            'medium': 200,
            'low': 100
        }
        
        return priority_map.get(rule.priority, 0)

# 全局单例
waf_rule_matcher = WafRuleMatcher() 