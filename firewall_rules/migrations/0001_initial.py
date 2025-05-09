# Generated by Django 4.2.7 on 2025-04-25 07:50

from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='IPBlacklist',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip_address', models.GenericIPAddressField(unique=True, verbose_name='IP地址')),
                ('description', models.TextField(blank=True, verbose_name='禁止原因')),
                ('added_at', models.DateTimeField(default=django.utils.timezone.now, verbose_name='添加时间')),
                ('expiry', models.DateTimeField(blank=True, null=True, verbose_name='过期时间')),
                ('is_permanent', models.BooleanField(default=False, verbose_name='永久禁止')),
            ],
            options={
                'verbose_name': 'IP黑名单',
                'verbose_name_plural': 'IP黑名单',
                'ordering': ['-added_at'],
            },
        ),
        migrations.CreateModel(
            name='IPWhitelist',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip_address', models.GenericIPAddressField(unique=True, verbose_name='IP地址')),
                ('description', models.TextField(blank=True, verbose_name='信任原因')),
                ('added_at', models.DateTimeField(default=django.utils.timezone.now, verbose_name='添加时间')),
            ],
            options={
                'verbose_name': 'IP白名单',
                'verbose_name_plural': 'IP白名单',
                'ordering': ['ip_address'],
            },
        ),
        migrations.CreateModel(
            name='RuleCategory',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=50, unique=True, verbose_name='分类名称')),
                ('description', models.TextField(blank=True, verbose_name='分类描述')),
                ('priority', models.IntegerField(default=0, verbose_name='优先级')),
            ],
            options={
                'verbose_name': '规则分类',
                'verbose_name_plural': '规则分类',
                'ordering': ['priority', 'name'],
            },
        ),
        migrations.CreateModel(
            name='RulePattern',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, verbose_name='模式名称')),
                ('pattern_string', models.TextField(verbose_name='检测模式字符串')),
                ('description', models.TextField(blank=True, verbose_name='模式描述')),
                ('is_regex', models.BooleanField(default=False, verbose_name='是否正则表达式')),
            ],
            options={
                'verbose_name': '检测模式',
                'verbose_name_plural': '检测模式',
            },
        ),
        migrations.CreateModel(
            name='Rule',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, verbose_name='规则名称')),
                ('description', models.TextField(blank=True, verbose_name='规则描述')),
                ('source_ip', models.CharField(blank=True, help_text='可使用CIDR格式', max_length=50, verbose_name='源IP')),
                ('destination_ip', models.CharField(blank=True, help_text='可使用CIDR格式', max_length=50, verbose_name='目标IP')),
                ('source_port', models.CharField(blank=True, help_text='单个端口或端口范围，如 80 或 1000-2000', max_length=50, verbose_name='源端口')),
                ('destination_port', models.CharField(blank=True, help_text='单个端口或端口范围，如 80 或 1000-2000', max_length=50, verbose_name='目标端口')),
                ('protocol', models.CharField(blank=True, help_text='如TCP, UDP, ICMP等', max_length=10, verbose_name='协议')),
                ('application_protocol', models.CharField(blank=True, help_text='如HTTP, FTP, DNS等', max_length=50, verbose_name='应用层协议')),
                ('action', models.CharField(choices=[('allow', '允许'), ('block', '阻止'), ('log', '仅记录'), ('alert', '告警')], default='log', max_length=10, verbose_name='动作')),
                ('priority', models.CharField(choices=[('low', '低'), ('medium', '中'), ('high', '高'), ('critical', '严重')], default='medium', max_length=10, verbose_name='优先级')),
                ('log_prefix', models.CharField(blank=True, max_length=50, verbose_name='日志前缀')),
                ('is_enabled', models.BooleanField(default=True, verbose_name='是否启用')),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now, verbose_name='创建时间')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='更新时间')),
                ('hits', models.IntegerField(default=0, verbose_name='命中次数')),
                ('category', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='firewall_rules.rulecategory', verbose_name='规则分类')),
                ('pattern', models.ManyToManyField(blank=True, to='firewall_rules.rulepattern', verbose_name='检测模式')),
            ],
            options={
                'verbose_name': '防火墙规则',
                'verbose_name_plural': '防火墙规则',
                'ordering': ['-is_enabled', 'category__priority'],
            },
        ),
    ]
