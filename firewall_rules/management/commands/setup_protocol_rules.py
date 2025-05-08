import logging
from django.core.management.base import BaseCommand
from django.db import transaction
from firewall_rules.models import Rule, RuleCategory, RulePattern

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = '设置针对HTTP和HTTPS协议的不同规则集'
    
    def handle(self, *args, **options):
        self.stdout.write('开始设置协议规则...')
        
        # 创建或更新规则类别
        categories = self._setup_categories()
        
        # 创建或更新模式
        patterns = self._setup_patterns()
        
        # 创建HTTP规则
        http_rules = self._setup_http_rules(categories, patterns)
        
        # 创建HTTPS规则
        https_rules = self._setup_https_rules(categories, patterns)
        
        # 创建通用规则（适用于所有协议）
        common_rules = self._setup_common_rules(categories, patterns)
        
        total_rules = len(http_rules) + len(https_rules) + len(common_rules)
        self.stdout.write(self.style.SUCCESS(f'协议规则设置完成，共创建/更新 {total_rules} 条规则'))
    
    def _setup_categories(self):
        """创建或更新规则类别"""
        categories = {}
        
        category_data = [
            {'name': 'Web攻击', 'description': '通用Web攻击检测', 'priority': 10},
            {'name': 'SQL注入', 'description': 'SQL注入攻击检测', 'priority': 20},
            {'name': '跨站脚本', 'description': 'XSS攻击检测', 'priority': 30},
            {'name': '命令注入', 'description': '命令注入攻击检测', 'priority': 40},
            {'name': '文件访问', 'description': '非法文件访问检测', 'priority': 50},
            {'name': '协议异常', 'description': '协议规范违规检测', 'priority': 60},
            {'name': '网络攻击', 'description': '网络层攻击检测', 'priority': 70},
            {'name': '资源限制', 'description': '资源滥用限制', 'priority': 80},
        ]
        
        for data in category_data:
            category, created = RuleCategory.objects.update_or_create(
                name=data['name'],
                defaults={
                    'description': data['description'],
                    'priority': data['priority']
                }
            )
            categories[data['name']] = category
            action = '创建' if created else '更新'
            self.stdout.write(f'{action}规则类别: {data["name"]}')
            
        return categories
    
    def _setup_patterns(self):
        """创建或更新规则模式"""
        patterns = {}
        
        # SQL注入检测模式
        sql_patterns = [
            {'name': 'SQL注入-基础', 'pattern': "('|\")(\\s*)(;|--|#|\\*|union|select|insert|update|delete|substr|hex|unhex|drop)\\b", 'is_regex': True},
            {'name': 'SQL注入-联合查询', 'pattern': "union(\\s+|/**/)select", 'is_regex': True},
            {'name': 'SQL注入-布尔盲注', 'pattern': "(\\b|\\*|')\\s*(AND|OR)\\s*\\d+=\\d+", 'is_regex': True},
            {'name': 'SQL注入-时间盲注', 'pattern': "(sleep\\(|benchmark\\(|pg_sleep\\(|WAITFOR DELAY)", 'is_regex': True},
        ]
        
        # XSS攻击检测模式
        xss_patterns = [
            {'name': 'XSS-基础', 'pattern': "<(script|iframe|embed|object|style|form|input|img)[^>]*?>", 'is_regex': True},
            {'name': 'XSS-事件', 'pattern': "(\\b|'|\")on\\w+\\s*=", 'is_regex': True},
            {'name': 'XSS-JavaScript', 'pattern': "(\\b|'|\")javascript:\\s*", 'is_regex': True},
            {'name': 'XSS-数据', 'pattern': "data:text/html", 'is_regex': True},
        ]
        
        # 命令注入检测模式
        cmd_patterns = [
            {'name': '命令注入-基础', 'pattern': "(;|\\||&)\\s*(ls|cat|pwd|wget|curl|bash|sh|chmod|chown|rm|cp|mv)", 'is_regex': True},
            {'name': '命令注入-反弹Shell', 'pattern': "(nc|netcat|ncat)\\s+-e", 'is_regex': True},
        ]
        
        # 文件访问检测模式
        file_patterns = [
            {'name': '文件包含', 'pattern': "\\.\\.(/|\\\\)|\\.\\.%2f", 'is_regex': True},
            {'name': '敏感文件访问', 'pattern': "/(etc|var|proc|usr)/(passwd|shadow|hosts|group)", 'is_regex': True},
        ]
        
        # HTTP协议异常检测模式
        http_patterns = [
            {'name': 'HTTP头注入', 'pattern': "\\r\\n(?:[A-Za-z0-9-]+):\\s*", 'is_regex': True},
            {'name': 'HTTP请求走私', 'pattern': "Content-Length:\\s*\\d+\\s*\\r\\n\\s*Content-Length:\\s*\\d+", 'is_regex': True},
        ]
        
        # 共同创建所有模式
        all_patterns = sql_patterns + xss_patterns + cmd_patterns + file_patterns + http_patterns
        
        for data in all_patterns:
            pattern, created = RulePattern.objects.update_or_create(
                name=data['name'],
                defaults={
                    'pattern_string': data['pattern'],
                    'is_regex': data['is_regex'],
                    'description': data.get('description', '')
                }
            )
            patterns[data['name']] = pattern
            action = '创建' if created else '更新'
            self.stdout.write(f'{action}规则模式: {data["name"]}')
            
        return patterns
    
    @transaction.atomic
    def _setup_http_rules(self, categories, patterns):
        """设置HTTP特定规则"""
        rules = []
        
        # SQL注入规则 - 仅适用于HTTP
        sql_rule, created = Rule.objects.update_or_create(
            name='SQL注入检测 - HTTP',
            defaults={
                'description': '检测HTTP请求中的SQL注入攻击',
                'category': categories['SQL注入'],
                'application_protocol': 'HTTP',
                'action': 'block',
                'priority': 'high',
                'log_prefix': 'SQL_INJECTION',
                'is_enabled': True
            }
        )
        
        # 添加模式
        sql_rule.pattern.set([
            patterns['SQL注入-基础'],
            patterns['SQL注入-联合查询'],
            patterns['SQL注入-布尔盲注'],
            patterns['SQL注入-时间盲注']
        ])
        
        rules.append(sql_rule)
        action = '创建' if created else '更新'
        self.stdout.write(f'{action}规则: SQL注入检测 - HTTP')
        
        # XSS攻击规则 - 仅适用于HTTP
        xss_rule, created = Rule.objects.update_or_create(
            name='XSS攻击检测 - HTTP',
            defaults={
                'description': '检测HTTP请求中的跨站脚本攻击',
                'category': categories['跨站脚本'],
                'application_protocol': 'HTTP',
                'action': 'block',
                'priority': 'high',
                'log_prefix': 'XSS_ATTACK',
                'is_enabled': True
            }
        )
        
        # 添加模式
        xss_rule.pattern.set([
            patterns['XSS-基础'],
            patterns['XSS-事件'],
            patterns['XSS-JavaScript'],
            patterns['XSS-数据']
        ])
        
        rules.append(xss_rule)
        action = '创建' if created else '更新'
        self.stdout.write(f'{action}规则: XSS攻击检测 - HTTP')
        
        # 命令注入规则 - 仅适用于HTTP
        cmd_rule, created = Rule.objects.update_or_create(
            name='命令注入检测 - HTTP',
            defaults={
                'description': '检测HTTP请求中的命令注入攻击',
                'category': categories['命令注入'],
                'application_protocol': 'HTTP',
                'action': 'block',
                'priority': 'critical',
                'log_prefix': 'CMD_INJECTION',
                'is_enabled': True
            }
        )
        
        # 添加模式
        cmd_rule.pattern.set([
            patterns['命令注入-基础'],
            patterns['命令注入-反弹Shell']
        ])
        
        rules.append(cmd_rule)
        action = '创建' if created else '更新'
        self.stdout.write(f'{action}规则: 命令注入检测 - HTTP')
        
        # 文件访问规则 - 仅适用于HTTP
        file_rule, created = Rule.objects.update_or_create(
            name='文件访问检测 - HTTP',
            defaults={
                'description': '检测HTTP请求中的非法文件访问尝试',
                'category': categories['文件访问'],
                'application_protocol': 'HTTP',
                'action': 'block',
                'priority': 'medium',
                'log_prefix': 'FILE_ACCESS',
                'is_enabled': True
            }
        )
        
        # 添加模式
        file_rule.pattern.set([
            patterns['文件包含'],
            patterns['敏感文件访问']
        ])
        
        rules.append(file_rule)
        action = '创建' if created else '更新'
        self.stdout.write(f'{action}规则: 文件访问检测 - HTTP')
        
        # HTTP协议异常规则 - 仅适用于HTTP
        http_rule, created = Rule.objects.update_or_create(
            name='HTTP协议异常检测',
            defaults={
                'description': '检测HTTP协议异常和滥用',
                'category': categories['协议异常'],
                'application_protocol': 'HTTP',
                'action': 'block',
                'priority': 'medium',
                'log_prefix': 'HTTP_ANOMALY',
                'is_enabled': True
            }
        )
        
        # 添加模式
        http_rule.pattern.set([
            patterns['HTTP头注入'],
            patterns['HTTP请求走私']
        ])
        
        rules.append(http_rule)
        action = '创建' if created else '更新'
        self.stdout.write(f'{action}规则: HTTP协议异常检测')
        
        return rules
    
    @transaction.atomic
    def _setup_https_rules(self, categories, patterns):
        """设置HTTPS特定规则"""
        rules = []
        
        # HTTPS流量限制规则 - 不依赖内容检测
        https_limit_rule, created = Rule.objects.update_or_create(
            name='HTTPS流量限制',
            defaults={
                'description': '限制HTTPS流量的异常行为（不依赖内容检测）',
                'category': categories['资源限制'],
                'application_protocol': 'HTTPS',
                'destination_port': '443',
                'protocol': 'TCP',
                'action': 'alert',
                'priority': 'low',
                'log_prefix': 'HTTPS_LIMIT',
                'is_enabled': True
            }
        )
        
        rules.append(https_limit_rule)
        action = '创建' if created else '更新'
        self.stdout.write(f'{action}规则: HTTPS流量限制')
        
        # HTTPS异常连接规则 - 不依赖内容检测
        https_conn_rule, created = Rule.objects.update_or_create(
            name='HTTPS异常连接检测',
            defaults={
                'description': '检测HTTPS异常连接模式（不依赖内容检测）',
                'category': categories['网络攻击'],
                'application_protocol': 'HTTPS',
                'destination_port': '443',
                'protocol': 'TCP',
                'action': 'alert',
                'priority': 'medium',
                'log_prefix': 'HTTPS_CONN',
                'is_enabled': True
            }
        )
        
        rules.append(https_conn_rule)
        action = '创建' if created else '更新'
        self.stdout.write(f'{action}规则: HTTPS异常连接检测')
        
        return rules
    
    @transaction.atomic
    def _setup_common_rules(self, categories, patterns):
        """设置通用规则（适用于HTTP和HTTPS）"""
        rules = []
        
        # HTTP/HTTPS端口扫描规则
        port_scan_rule, created = Rule.objects.update_or_create(
            name='Web端口扫描检测',
            defaults={
                'description': '检测针对Web服务端口的扫描活动',
                'category': categories['网络攻击'],
                'destination_port': '80,443,8080,8443',
                'protocol': 'TCP',
                'action': 'alert',
                'priority': 'medium',
                'log_prefix': 'PORT_SCAN',
                'is_enabled': True
            }
        )
        
        rules.append(port_scan_rule)
        action = '创建' if created else '更新'
        self.stdout.write(f'{action}规则: Web端口扫描检测')
        
        # 基于IP的速率限制规则
        rate_limit_rule, created = Rule.objects.update_or_create(
            name='Web请求速率限制',
            defaults={
                'description': '限制单个IP对Web服务的请求速率',
                'category': categories['资源限制'],
                'destination_port': '80,443',
                'protocol': 'TCP',
                'action': 'alert',
                'priority': 'low',
                'log_prefix': 'RATE_LIMIT',
                'is_enabled': True
            }
        )
        
        rules.append(rate_limit_rule)
        action = '创建' if created else '更新'
        self.stdout.write(f'{action}规则: Web请求速率限制')
        
        return rules 