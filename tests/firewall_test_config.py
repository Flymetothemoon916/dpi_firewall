# 测试配置

# 目标IP地址
TARGET_IP = "127.0.0.1"  # 默认测试本地

# 测试端口配置
TEST_PORTS = {
    # 应该被阻止的端口
    'blocked': {
        'tcp': [22, 23, 445, 3389],  # SSH, Telnet, SMB, RDP
        'udp': [137, 138, 139, 445]  # NetBIOS, SMB
    },
    
    # 应该允许的端口
    'allowed': {
        'tcp': [80, 443, 53],  # HTTP, HTTPS, DNS
        'udp': [53, 67, 68]    # DNS, DHCP
    }
}

# 测试超时设置（秒）
TEST_TIMEOUT = 2

# 日志配置
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# 测试报告配置
REPORT_FILE = "firewall_test_report.txt" 