# DPI-Firewall
基于深度包检测（DPI）的智能防火墙系统，使用Django框架开发。
## 功能特点
- 深度包检测（DPI）技术
- 实时流量监控和分析
- 智能规则管理
- IP黑白名单管理
- 详细的日志记录和告警系统
- 直观的Web管理界面
## 系统要求
- Python 3.8+
- Django 4.2.7
- MySQL 5.7+

## 安装步骤
1. 克隆项目
bash
git clone [项目地址]
cd DPI-Firewall

2. 创建并激活虚拟环境
bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

3. 安装依赖
pip install -r requirements.txt

4. 配置数据库
- 创建MySQL数据库
- 修改 settings.py 中的数据库配置

5. 初始化数据库
python manage.py migrate
python manage.py createsuperuser

6. 启动服务
1.python manage.py runserver
new cmd/bash：
2.python manage.py firewall_service --interface [网卡]   (WLAN)本机
python manage.py firewall_service --foreground  默认设置启动
## 项目结构
DPI-Firewall/
├── dashboard/          # 仪表盘应用
├── packet_analyzer/    # 数据包分析应用
├── firewall_rules/     # 防火墙规则管理
├── accounts/          # 用户认证
├── templates/         # 前端模板
├── static/           # 静态文件
└── tests/            # 测试文件


## 主要功能模块
### 1. 数据包分析
- 实时捕获和分析网络数据包
- 协议识别和分类
- 深度包检测

### 2. 防火墙规则
- 自定义规则管理
- 规则优先级设置
- 规则分类管理

### 3. 访问控制
- IP黑白名单
- 基于协议的访问控制
- 端口访问控制

### 4. 监控和告警
- 实时流量监控
- 异常行为检测
- 告警通知

