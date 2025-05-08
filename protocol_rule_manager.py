"""
协议规则管理器 - 针对不同协议应用不同的规则集
"""
import os
import logging
import time
from typing import Dict, List, Set, Optional, Tuple, Any

from django.utils import timezone
from django.db.models import Q
from django.core.cache import cache
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
        self.update_interval = 300  # 5分钟更新一次
        self.http_rules = []
        self.https_rules = []
        self.content_inspection_categories = {
            'SQL注入', 
            'XSS攻击',
            '命令注入', 
            '路径遍历', 
            '文件访问',
            'Web攻击'
        }
        self.content_inspection_rules = set()  # 需要内容检测的规则ID
        
    def initialize(self):
        """初始化协议规则管理器"""
        logger.info("初始化协议规则管理器")
        
        # 从数据库加载规则
        self._load_protocol_rules()
        
        # 设置默认允许规则的优先级
        self._ensure_rule_priorities()
          
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
        if (current_time - self.last_update).total_seconds() > self.update_interval:
            logger.info("协议规则管理器定期刷新")
            self.initialize()
            return True
            
        return False
    
    def _load_protocol_rules(self):
        """加载协议相关规则"""
        try:
            # 清除之前的数据
            self.http_rules = []
            self.https_rules = []
            self.content_inspection_rules = set()
            
            # 加载所有启用的规则
            active_rules = Rule.objects.filter(is_enabled=True)
            
            # 将规则分类为HTTP和HTTPS
            for rule in active_rules:
                # 检查是否需要内容检测
                if self.is_content_inspection_rule(rule):
                    self.content_inspection_rules.add(rule.id)
                
                # HTTP规则：所有规则都适用于HTTP
                self.http_rules.append(rule)
                
                # HTTPS规则：只有不依赖内容检测的规则适用于HTTPS
                if not self.is_content_inspection_rule(rule):
                    self.https_rules.append(rule)
                    
            logger.info(f"加载规则完成: 内容检测规则 {len(self.content_inspection_rules)}个")
                    
        except Exception as e:
            logger.error(f"加载协议规则失败: {str(e)}")
    
    def _ensure_rule_priorities(self):
        """确保规则优先级设置正确
        - 特殊规则：默认允许规则优先级最低（数字最大）
        """
        try:
            # 查找所有默认允许规则
            default_allow_rules = Rule.objects.filter(
                action='allow',
                name__icontains='默认'
            )
            
            # 设置它们的优先级为最低
            for rule in default_allow_rules:
                if rule.category:
                    # 设置类别优先级为最低，确保规则最后才匹配
                    if rule.category.priority < 900:
                        rule.category.priority = 999  # 极低优先级
                        rule.category.save()
                        logger.info(f"设置规则分类 '{rule.category.name}' 的优先级为 {rule.category.priority}")
            
            logger.info(f"已确保规则优先级设置正确")
        except Exception as e:
            logger.error(f"设置规则优先级时出错: {str(e)}")
    
    def is_content_inspection_rule(self, rule: Rule) -> bool:
        """
        检查规则是否依赖内容检测
        
        Args:
            rule: 防火墙规则对象
            
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
            rule: 防火墙规则对象
            
        Returns:
            bool: 是否适用于HTTPS
        """
        # 默认允许规则总是适用于所有协议
        if rule.action == 'allow' and '默认' in rule.name:
            return True
            
        # 其他规则，只有不依赖内容检测的才适用于HTTPS
        return not self.is_content_inspection_rule(rule)
    
    def is_applicable_to_http(self, rule: Rule) -> bool:
        """
        检查规则是否适用于HTTP流量
        
        Args:
            rule: 防火墙规则对象
            
        Returns:
            bool: 是否适用于HTTP
        """
        # 所有规则都适用于HTTP
        return True
    
    def is_applicable_to_protocol(self, rule: Rule, protocol: str) -> bool:
        """
        检查规则是否适用于特定协议
        
        Args:
            rule: 防火墙规则对象
            protocol: 协议名称 ('HTTP' 或 'HTTPS')
            
        Returns:
            bool: 是否适用于该协议
        """
        if protocol == 'HTTP':
            return self.is_applicable_to_http(rule)
        elif protocol == 'HTTPS':
            return self.is_applicable_to_https(rule)
        else:
            # 对于其他协议，只应用不依赖内容检测的规则
            return not self.is_content_inspection_rule(rule)

# 全局单例
protocol_rule_manager = ProtocolRuleManager() 