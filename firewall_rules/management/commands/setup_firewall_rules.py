from django.core.management.base import BaseCommand
from django.utils import timezone
from django.db import transaction
from firewall_rules.models import RuleCategory, RulePattern, Rule

class Command(BaseCommand):
    help = '设置基本的防火墙规则集，用于Web攻击防御'

    def handle(self, *args, **options):
        self.stdout.write('开始设置防火墙规则...')
        
        with transaction.atomic():
            # 确保规则分类存在
            categories = self._setup_categories()
            
            # 设置检测模式
            patterns = self._setup_patterns()
            
            # 设置规则
            self._setup_rules(categories, patterns)
        
        self.stdout.write(self.style.SUCCESS('防火墙规则设置完成！'))
    
    def _setup_categories(self):
        """设置规则分类"""
        categories = {}
        
        # 基本分类
        web_attacks = self._get_or_create_category(
            name="Web攻击",
            description="防御各类Web应用攻击的规则",
            priority=10
        )
        
        sql_injection = self._get_or_create_category(
            name="SQL注入",
            description="防御SQL注入攻击的规则",
            priority=20
        )
        
        xss = self._get_or_create_category(
            name="跨站脚本",
            description="防御XSS攻击的规则",
            priority=30
        )
        
        command_injection = self._get_or_create_category(
            name="命令注入",
            description="防御命令注入攻击的规则",
            priority=40
        )
        
        file_access = self._get_or_create_category(
            name="文件访问",
            description="防御路径遍历和文件包含攻击的规则",
            priority=50
        )
        
        protocol = self._get_or_create_category(
            name="协议异常",
            description="处理协议异常的规则",
            priority=60
        )
        
        # 存储分类引用
        categories = {
            'web_attacks': web_attacks,
            'sql_injection': sql_injection,
            'xss': xss,
            'command_injection': command_injection,
            'file_access': file_access,
            'protocol': protocol,
        }
        
        return categories
    
    def _get_or_create_category(self, name, description, priority):
        """获取或创建规则分类"""
        category, created = RuleCategory.objects.get_or_create(
            name=name,
            defaults={
                'description': description,
                'priority': priority
            }
        )
        
        if created:
            self.stdout.write(f'创建规则分类: {name}')
        else:
            self.stdout.write(f'使用已有规则分类: {name}')
        
        return category
    
    def _setup_patterns(self):
        """设置检测模式"""
        patterns = {}
        
        # SQL注入检测模式
        sql_basic = self._get_or_create_pattern(
            name="SQL注入-基础语法",
            pattern_string=r"('|\")?\s*(OR|AND)\s*\d+\s*=\s*\d+(\s*--|\s*#|\s*\/\*|\s*;)?",
            description="检测常见的SQL注入基础语法，如OR 1=1",
            is_regex=True
        )
        
        sql_union = self._get_or_create_pattern(
            name="SQL注入-UNION",
            pattern_string=r"UNION\s+(ALL\s+)?SELECT\s+",
            description="检测UNION SELECT语法",
            is_regex=True
        )
        
        sql_error = self._get_or_create_pattern(
            name="SQL注入-错误特征",
            pattern_string=r"(SQL syntax|mysql_fetch|mysql_num_rows|mysql_query|pg_query|ORA-\d+|Microsoft SQL|ODBC Driver)",
            description="检测SQL错误信息",
            is_regex=True
        )
        
        # XSS检测模式
        xss_script = self._get_or_create_pattern(
            name="XSS-脚本标签",
            pattern_string=r"<\s*script[\s\S]*?>[\s\S]*?<\s*\/script\s*>",
            description="检测<script>标签",
            is_regex=True
        )
        
        xss_event = self._get_or_create_pattern(
            name="XSS-事件属性",
            pattern_string=r"(on\w+)\s*=\s*(\"|\')?(javascript|alert|confirm|prompt)",
            description="检测HTML事件属性如onclick",
            is_regex=True
        )
        
        xss_url = self._get_or_create_pattern(
            name="XSS-JavaScript协议",
            pattern_string=r"(javascript|vbscript|data):\s*",
            description="检测JavaScript URL协议",
            is_regex=True
        )
        
        # 命令注入检测模式
        cmd_basic = self._get_or_create_pattern(
            name="命令注入-基础",
            pattern_string=r"(;|\||&|\$\(|\`)\s*(ls|dir|cat|wget|curl|bash|sh|nc|python|perl|php|powershell|cmd\.exe)",
            description="检测基本命令注入",
            is_regex=True
        )
        
        # 路径遍历检测模式
        path_traversal = self._get_or_create_pattern(
            name="路径遍历",
            pattern_string=r"(\.\.\/|\.\.\\|%2e%2e\/|%2e%2e\\|\.\.%c0%af|\.\.%252f)",
            description="检测路径遍历尝试",
            is_regex=True
        )
        
        # 文件包含检测模式
        file_inclusion = self._get_or_create_pattern(
            name="文件包含",
            pattern_string=r"(php|file|zip|data|phar|glob|ssh2|rar|ogg|expect)://",
            description="检测文件包含攻击",
            is_regex=True
        )
        
        # 异常HTTP协议检测模式
        http_unusual = self._get_or_create_pattern(
            name="HTTP协议异常",
            pattern_string=r"(Content-Length:\s*-\d+|Transfer-Encoding:\s*chunked.*?Content-Length)",
            description="检测HTTP协议异常",
            is_regex=True
        )
        
        # 存储模式引用
        patterns = {
            'sql_basic': sql_basic,
            'sql_union': sql_union,
            'sql_error': sql_error,
            'xss_script': xss_script,
            'xss_event': xss_event,
            'xss_url': xss_url,
            'cmd_basic': cmd_basic,
            'path_traversal': path_traversal,
            'file_inclusion': file_inclusion,
            'http_unusual': http_unusual
        }
        
        return patterns
    
    def _get_or_create_pattern(self, name, pattern_string, description, is_regex=True):
        """获取或创建检测模式"""
        pattern, created = RulePattern.objects.get_or_create(
            name=name,
            defaults={
                'pattern_string': pattern_string,
                'description': description,
                'is_regex': is_regex
            }
        )
        
        if created:
            self.stdout.write(f'创建检测模式: {name}')
        else:
            # 更新模式
            pattern.pattern_string = pattern_string
            pattern.description = description
            pattern.is_regex = is_regex
            pattern.save()
            self.stdout.write(f'更新检测模式: {name}')
        
        return pattern
    
    def _setup_rules(self, categories, patterns):
        """设置防火墙规则"""
        # 基本SQL注入防护规则
        sql_rule = self._get_or_create_rule(
            name="SQL注入检测",
            description="检测并阻止SQL注入攻击",
            category=categories['sql_injection'],
            application_protocol="HTTP",
            destination_port="80,443,8080,8443",
            protocol="TCP",
            action=Rule.BLOCK,
            priority=Rule.HIGH
        )
        
        # 添加模式到规则
        sql_rule.pattern.add(patterns['sql_basic'])
        sql_rule.pattern.add(patterns['sql_union'])
        sql_rule.pattern.add(patterns['sql_error'])
        
        # XSS防护规则
        xss_rule = self._get_or_create_rule(
            name="XSS攻击检测",
            description="检测并阻止跨站脚本攻击",
            category=categories['xss'],
            application_protocol="HTTP",
            destination_port="80,443,8080,8443",
            protocol="TCP",
            action=Rule.BLOCK,
            priority=Rule.HIGH
        )
        
        # 添加模式到规则
        xss_rule.pattern.add(patterns['xss_script'])
        xss_rule.pattern.add(patterns['xss_event'])
        xss_rule.pattern.add(patterns['xss_url'])
        
        # 命令注入防护规则
        cmd_rule = self._get_or_create_rule(
            name="命令注入检测",
            description="检测并阻止命令注入攻击",
            category=categories['command_injection'],
            application_protocol="HTTP",
            destination_port="80,443,8080,8443",
            protocol="TCP",
            action=Rule.BLOCK,
            priority=Rule.CRITICAL
        )
        
        # 添加模式到规则
        cmd_rule.pattern.add(patterns['cmd_basic'])
        
        # 路径遍历防护规则
        path_rule = self._get_or_create_rule(
            name="路径遍历检测",
            description="检测并阻止路径遍历攻击",
            category=categories['file_access'],
            application_protocol="HTTP",
            destination_port="80,443,8080,8443",
            protocol="TCP",
            action=Rule.BLOCK,
            priority=Rule.HIGH
        )
        
        # 添加模式到规则
        path_rule.pattern.add(patterns['path_traversal'])
        
        # 文件包含防护规则
        file_rule = self._get_or_create_rule(
            name="文件包含检测",
            description="检测并阻止文件包含攻击",
            category=categories['file_access'],
            application_protocol="HTTP",
            destination_port="80,443,8080,8443",
            protocol="TCP",
            action=Rule.BLOCK,
            priority=Rule.HIGH
        )
        
        # 添加模式到规则
        file_rule.pattern.add(patterns['file_inclusion'])
        
        # HTTP协议异常规则
        http_rule = self._get_or_create_rule(
            name="HTTP协议异常检测",
            description="检测HTTP协议异常",
            category=categories['protocol'],
            application_protocol="HTTP",
            destination_port="80,443,8080,8443",
            protocol="TCP",
            action=Rule.ALERT,
            priority=Rule.MEDIUM
        )
        
        # 添加模式到规则
        http_rule.pattern.add(patterns['http_unusual'])
    
    def _get_or_create_rule(self, name, description, category, application_protocol=None, 
                           source_ip=None, destination_ip=None, source_port=None, 
                           destination_port=None, protocol=None, action=Rule.BLOCK, 
                           priority=Rule.MEDIUM):
        """获取或创建规则"""
        rule, created = Rule.objects.get_or_create(
            name=name,
            defaults={
                'description': description,
                'category': category,
                'application_protocol': application_protocol or '',
                'source_ip': source_ip or '',
                'destination_ip': destination_ip or '',
                'source_port': source_port or '',
                'destination_port': destination_port or '',
                'protocol': protocol or '',
                'action': action,
                'priority': priority,
                'is_enabled': True,
                'created_at': timezone.now(),
            }
        )
        
        if created:
            self.stdout.write(f'创建规则: {name}')
        else:
            # 更新规则
            rule.description = description
            rule.category = category
            rule.application_protocol = application_protocol or ''
            rule.source_ip = source_ip or ''
            rule.destination_ip = destination_ip or ''
            rule.source_port = source_port or ''
            rule.destination_port = destination_port or ''
            rule.protocol = protocol or ''
            rule.action = action
            rule.priority = priority
            rule.is_enabled = True
            rule.save()
            self.stdout.write(f'更新规则: {name}')
        
        return rule 