# HTTP攻击测试指南

本文档说明如何使用DPI防火墙系统测试HTTP攻击检测功能。

## 主要功能

我们提供了多种工具来测试DPI防火墙对HTTP攻击的检测和阻止能力：

1. **直接HTTP攻击测试**：直接向防火墙注入攻击数据包
2. **强制攻击数据包注入**：支持多种攻击类型，包括SQL注入、XSS、命令注入和路径遍历
3. **实时攻击数据包捕获**：可以实时捕获网络中的攻击流量
4. **攻击日志查看**：查看已捕获的攻击数据包详情

## 如何使用

### 1. 设置攻击检测规则

在使用任何测试工具之前，请确保已设置攻击检测规则：

```bash
python test_firewall_rules.py --setup
```

这将创建并启用SQL注入、XSS、命令注入和路径遍历攻击的检测规则。

### 2. 启动防火墙和Web服务器

在一个终端中启动Django开发服务器：

```bash
python manage.py runserver
```

### 3. 执行攻击测试

**方法1：使用全能攻击测试工具**

这是最简单的方法，能测试所有类型的攻击：

```bash
python force_http_attack.py
```

支持的选项：
- `--attacks sql_injection xss command_injection path_traversal`：指定要测试的攻击类型（默认为所有类型）
- `--db-insert`：直接在数据库中创建数据包记录（无需网络交互）
- `--no-force`：不强制阻止，使用常规匹配过程

**方法2：使用特定攻击测试工具**

SQL注入测试：
```bash
python test_sql_injection.py http://localhost:8000 -v
```

直接注入攻击测试：
```bash
python direct_attack_tester.py
```

原始套接字攻击测试：
```bash
python send_raw_attack.py --host localhost --port 8000 -v
```

**方法3：启动专用防火墙捕获测试**

```bash
python start_firewall_capture.py
```

然后在另一个终端中运行攻击测试工具。

### 4. 检查攻击日志

测试完成后，检查捕获的攻击日志：

```bash
python test_firewall_rules.py --check-logs
```

## 查看Web界面结果

访问DPI防火墙Web界面查看攻击数据包：

- 数据包列表：http://localhost:8000/packets/
- 被阻止的数据包：http://localhost:8000/packets/?status=blocked
- 攻击数据包：http://localhost:8000/packets/?attack_type=sql_injection

## 数据包详情

在数据包详情页面中，您可以查看：

1. 攻击载荷：如 `' OR '1'='1'`
2. 匹配的攻击规则
3. 原始HTTP请求内容
4. 拦截原因

## 故障排除

如果测试中没有看到被阻止的数据包，可以尝试：

1. 确认所有攻击规则已启用：`python test_firewall_rules.py --setup`
2. 使用强制攻击测试：`python force_http_attack.py --db-insert`
3. 检查Django服务器是否正在运行
4. 确认防火墙引擎已启动

## 实现原理

1. 本解决方案直接调用了防火墙的核心组件（DPIPacketAnalyzer和FirewallEngine）
2. 创建带有明确攻击特征的HTTP请求数据包
3. 使用规则匹配机制确保攻击被正确识别
4. 记录完整的攻击载荷和请求内容 