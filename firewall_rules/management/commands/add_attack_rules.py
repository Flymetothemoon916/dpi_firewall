from django.core.management.base import BaseCommand
from django.utils import timezone
from firewall_rules.models import Rule, RuleCategory, RulePattern

class Command(BaseCommand):
    help = '添加HTTP攻击检测规则'

    def handle(self, *args, **options):
        # 创建或获取Web攻击类别
        web_attack_category, created = RuleCategory.objects.get_or_create(
            name='Web攻击',
            defaults={
                'description': 'Web应用攻击检测规则',
                'priority': 50  # 高优先级
            }
        )
        
        if created:
            self.stdout.write(self.style.SUCCESS(f'创建规则分类: Web攻击'))
        
        # 创建SQL注入规则模式
        sql_injection_patterns = [
            ('SQL注入-OR语句', "'\\s*OR\\s*'\\s*=\\s*'", '检测常见的OR条件注入'),
            ('SQL注入-联合查询', "UNION\\s+SELECT", '检测UNION SELECT注入'),
            ('SQL注入-注释', "--\\s+|#\\s*|/\\*", '检测SQL注释注入'),
            ('SQL注入-系统表', "information_schema|sys\\.user|all_tables", '检测系统表查询'),
            ('SQL注入-函数调用', "sleep\\s*\\(|benchmark\\s*\\(|waitfor\\s+delay", '检测基于时间的盲注'),
        ]
        
        sql_patterns = []
        for name, pattern, desc in sql_injection_patterns:
            pattern_obj, created = RulePattern.objects.get_or_create(
                name=name,
                defaults={
                    'pattern_string': pattern,
                    'description': desc,
                    'is_regex': True
                }
            )
            sql_patterns.append(pattern_obj)
            if created:
                self.stdout.write(self.style.SUCCESS(f'创建规则模式: {name}'))
        
        # 创建XSS攻击规则模式
        xss_patterns = [
            ('XSS-脚本标签', "<script[^>]*>[\\s\\S]*?</script>", '检测脚本标签'),
            ('XSS-事件属性', "on(load|error|click|mouseover|focus)\\s*=", '检测事件属性'),
            ('XSS-JS协议', "javascript:", '检测JavaScript协议'),
            ('XSS-alert函数', "alert\\s*\\(", '检测alert函数调用'),
            ('XSS-document操作', "document\\.cookie|document\\.location", '检测文档对象操作'),
        ]
        
        xss_rule_patterns = []
        for name, pattern, desc in xss_patterns:
            pattern_obj, created = RulePattern.objects.get_or_create(
                name=name,
                defaults={
                    'pattern_string': pattern,
                    'description': desc,
                    'is_regex': True
                }
            )
            xss_rule_patterns.append(pattern_obj)
            if created:
                self.stdout.write(self.style.SUCCESS(f'创建规则模式: {name}'))
        
        # 创建命令注入规则模式
        cmd_patterns = [
            ('命令注入-分隔符', ";\\s*\\w+|\\|\\s*\\w+|`\\w+`", '检测命令分隔符'),
            ('命令注入-系统命令', "cat\\s+/etc|ls\\s+-la|ping\\s+-c|wget\\s+http|curl\\s+http", '检测常见系统命令'),
            ('命令注入-反引号', "`[^`]*`", '检测反引号命令执行'),
            ('命令注入-环境变量', "\\$\\([^)]*\\)|\\$\\{[^}]*\\}", '检测环境变量和子命令'),
        ]
        
        cmd_rule_patterns = []
        for name, pattern, desc in cmd_patterns:
            pattern_obj, created = RulePattern.objects.get_or_create(
                name=name,
                defaults={
                    'pattern_string': pattern,
                    'description': desc,
                    'is_regex': True
                }
            )
            cmd_rule_patterns.append(pattern_obj)
            if created:
                self.stdout.write(self.style.SUCCESS(f'创建规则模式: {name}'))
        
        # 创建路径遍历规则模式
        path_patterns = [
            ('路径遍历-点点斜杠', "\\.\\./|\\.\\.\\\\" , '检测目录跳转'),
            ('路径遍历-系统文件', "/etc/passwd|/etc/shadow|c:\\\\windows\\\\win.ini|boot\\.ini", '检测敏感系统文件'),
            ('路径遍历-编码', "\\.\\.%2f|\\.\\.%5c", '检测URL编码的目录跳转'),
            ('路径遍历-Unicode编码', "\\.\\.%u002f", '检测Unicode编码的目录跳转'),
        ]
        
        path_rule_patterns = []
        for name, pattern, desc in path_patterns:
            pattern_obj, created = RulePattern.objects.get_or_create(
                name=name,
                defaults={
                    'pattern_string': pattern,
                    'description': desc,
                    'is_regex': True
                }
            )
            path_rule_patterns.append(pattern_obj)
            if created:
                self.stdout.write(self.style.SUCCESS(f'创建规则模式: {name}'))
        
        # 创建SQL注入攻击规则
        sql_rule, created = Rule.objects.get_or_create(
            name='SQL注入攻击检测',
            defaults={
                'description': '检测常见的SQL注入攻击',
                'category': web_attack_category,
                'protocol': 'TCP',
                'destination_port': '80,443,8000',
                'action': 'block',
                'priority': 'high',
                'is_enabled': True,
                'created_at': timezone.now(),
                'log_prefix': 'SQL_INJECTION'
            }
        )
        
        if created:
            # 添加模式
            for pattern in sql_patterns:
                sql_rule.pattern.add(pattern)
            self.stdout.write(self.style.SUCCESS(f'创建规则: SQL注入攻击检测'))
        
        # 创建XSS攻击规则
        xss_rule, created = Rule.objects.get_or_create(
            name='XSS攻击检测',
            defaults={
                'description': '检测跨站脚本攻击',
                'category': web_attack_category,
                'protocol': 'TCP',
                'destination_port': '80,443,8000',
                'action': 'block',
                'priority': 'high',
                'is_enabled': True,
                'created_at': timezone.now(),
                'log_prefix': 'XSS_ATTACK'
            }
        )
        
        if created:
            # 添加模式
            for pattern in xss_rule_patterns:
                xss_rule.pattern.add(pattern)
            self.stdout.write(self.style.SUCCESS(f'创建规则: XSS攻击检测'))
        
        # 创建命令注入攻击规则
        cmd_rule, created = Rule.objects.get_or_create(
            name='命令注入攻击检测',
            defaults={
                'description': '检测命令注入攻击',
                'category': web_attack_category,
                'protocol': 'TCP',
                'destination_port': '80,443,8000',
                'action': 'block',
                'priority': 'high',
                'is_enabled': True,
                'created_at': timezone.now(),
                'log_prefix': 'COMMAND_INJECTION'
            }
        )
        
        if created:
            # 添加模式
            for pattern in cmd_rule_patterns:
                cmd_rule.pattern.add(pattern)
            self.stdout.write(self.style.SUCCESS(f'创建规则: 命令注入攻击检测'))
        
        # 创建路径遍历攻击规则
        path_rule, created = Rule.objects.get_or_create(
            name='路径遍历攻击检测',
            defaults={
                'description': '检测路径遍历攻击',
                'category': web_attack_category,
                'protocol': 'TCP',
                'destination_port': '80,443,8000',
                'action': 'block',
                'priority': 'high',
                'is_enabled': True,
                'created_at': timezone.now(),
                'log_prefix': 'PATH_TRAVERSAL'
            }
        )
        
        if created:
            # 添加模式
            for pattern in path_rule_patterns:
                path_rule.pattern.add(pattern)
            self.stdout.write(self.style.SUCCESS(f'创建规则: 路径遍历攻击检测'))
        
        self.stdout.write(self.style.SUCCESS('所有HTTP攻击检测规则已添加完成')) 