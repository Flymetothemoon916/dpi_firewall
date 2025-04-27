import os
import subprocess
import threading
import logging
import signal
import sys
import time
from pathlib import Path
from typing import Optional, Tuple, Dict

from django.conf import settings
from django.utils import timezone

from dashboard.models import SystemStatus

logger = logging.getLogger(__name__)

class PacketCaptureManager:
    """管理数据包捕获进程"""
    
    _instance = None
    _process = None
    _process_lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(PacketCaptureManager, cls).__new__(cls)
        return cls._instance
    
    def is_running(self) -> bool:
        """检查捕获进程是否正在运行"""
        with self._process_lock:
            return self._process is not None and self._process.poll() is None
    
    def start_capture(self, interface: Optional[str] = None, count: int = 0, timeout: Optional[int] = None) -> Tuple[bool, str]:
        """启动数据包捕获
        
        Args:
            interface: 网络接口
            count: 数据包数量限制
            timeout: 超时时间
            
        Returns:
            Tuple[bool, str]: (是否成功, 消息)
        """
        if self.is_running():
            return False, "捕获已在运行中"
        
        try:
            # 构建命令
            cmd = [sys.executable, "manage.py", "capture_packets"]
            
            if interface:
                cmd.extend(["--interface", interface])
            
            if count > 0:
                cmd.extend(["--count", str(count)])
                
            if timeout:
                cmd.extend(["--timeout", str(timeout)])
            
            # 启动进程
            with self._process_lock:
                if os.name == 'nt':  # Windows
                    self._process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        universal_newlines=True,
                        creationflags=subprocess.CREATE_NEW_CONSOLE
                    )
                else:  # Linux/Unix
                    self._process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        universal_newlines=True
                    )
            
            # 更新系统状态
            try:
                SystemStatus.objects.update_or_create(
                    defaults={
                        'status': 'running',
                        'started_at': timezone.now()
                    }
                )
            except Exception as e:
                logger.error(f"更新系统状态失败: {str(e)}")
            
            logger.info(f"数据包捕获已启动，进程ID: {self._process.pid}")
            return True, f"捕获已启动，进程ID: {self._process.pid}"
            
        except Exception as e:
            logger.error(f"启动数据包捕获失败: {str(e)}")
            return False, f"启动失败: {str(e)}"
    
    def stop_capture(self) -> Tuple[bool, str]:
        """停止数据包捕获
        
        Returns:
            Tuple[bool, str]: (是否成功, 消息)
        """
        if not self.is_running():
            return False, "没有运行中的捕获进程"
        
        try:
            with self._process_lock:
                if self._process:
                    pid = self._process.pid
                    
                    # Windows上使用taskkill
                    if os.name == 'nt':
                        subprocess.call(['taskkill', '/F', '/T', '/PID', str(pid)])
                    # Linux/Unix上使用SIGTERM信号
                    else:
                        os.kill(pid, signal.SIGTERM)
                    
                    # 等待进程结束
                    self._process.wait(timeout=5)
                    self._process = None
            
            # 更新系统状态
            try:
                SystemStatus.objects.update_or_create(
                    defaults={
                        'status': 'stopped',
                    }
                )
            except Exception as e:
                logger.error(f"更新系统状态失败: {str(e)}")
            
            logger.info(f"数据包捕获已停止，进程ID: {pid}")
            return True, f"捕获已停止，进程ID: {pid}"
            
        except subprocess.TimeoutExpired:
            # 进程未在超时时间内退出，强制结束
            with self._process_lock:
                if self._process:
                    self._process.kill()
                    self._process = None
            return True, "捕获进程已强制终止"
            
        except Exception as e:
            logger.error(f"停止数据包捕获失败: {str(e)}")
            return False, f"停止失败: {str(e)}"
    
    def get_status(self) -> Dict:
        """获取捕获状态信息
        
        Returns:
            Dict: 状态信息
        """
        with self._process_lock:
            running = self._process is not None and self._process.poll() is None
            pid = self._process.pid if self._process else None
            
            # 尝试获取输出
            output = ""
            if self._process:
                try:
                    # 非阻塞读取
                    output = self._process.stdout.read()
                except:
                    pass
            
            return {
                "running": running,
                "process_id": pid,
                "output": output
            } 