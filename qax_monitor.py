#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
QAX安全设备日志监控脚本
自动监控并导出安全设备日志文件
"""

import argparse
import json
import logging
import os
import platform
import signal
import sys
import time
import warnings
from datetime import datetime, timedelta

import requests

# 全局停止标志
stop_monitoring = False


# 颜色输出支持
class Colors:
    """终端颜色输出类"""
    # 基本颜色
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'

    # 背景颜色
    BG_RED = '\033[101m'
    BG_GREEN = '\033[102m'
    BG_YELLOW = '\033[103m'

    # 样式
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    # 重置
    RESET = '\033[0m'

    @staticmethod
    def disable():
        """禁用颜色输出"""
        Colors.RED = ''
        Colors.GREEN = ''
        Colors.YELLOW = ''
        Colors.BLUE = ''
        Colors.MAGENTA = ''
        Colors.CYAN = ''
        Colors.WHITE = ''
        Colors.BG_RED = ''
        Colors.BG_GREEN = ''
        Colors.BG_YELLOW = ''
        Colors.BOLD = ''
        Colors.UNDERLINE = ''
        Colors.RESET = ''


# 全局颜色开关
enable_colors = True


def colored_print(text, color=None, style=None, use_global_setting=True):
    """
    带颜色的打印函数

    Args:
        text (str): 要打印的文本
        color (str): 颜色名称
        style (str): 样式名称
        use_global_setting (bool): 是否使用全局颜色设置
    """
    if use_global_setting and not enable_colors:
        print(text)
        return

    colors = []
    if style == 'bold':
        colors.append(Colors.BOLD)
    if style == 'underline':
        colors.append(Colors.UNDERLINE)

    if color == 'red':
        colors.append(Colors.RED)
    elif color == 'green':
        colors.append(Colors.GREEN)
    elif color == 'yellow':
        colors.append(Colors.YELLOW)
    elif color == 'blue':
        colors.append(Colors.BLUE)
    elif color == 'magenta':
        colors.append(Colors.MAGENTA)
    elif color == 'cyan':
        colors.append(Colors.CYAN)
    elif color == 'white':
        colors.append(Colors.WHITE)

    color_code = ''.join(colors)
    reset_code = Colors.RESET if color_code else ''

    print(f"{color_code}{text}{reset_code}")


def print_separator(char="=", length=60, color=None):
    """打印分隔线"""
    colored_print(char * length, color=color)


def signal_handler(signum, frame):
    """处理Ctrl+C信号"""
    global stop_monitoring
    colored_print("\n[STOP] 收到停止信号，正在安全停止监控...", color='yellow')
    stop_monitoring = True


# 根据操作系统选择语音库
if platform.system() == 'Windows':
    try:
        import win32com.client
        import pythoncom

        VOICE_AVAILABLE = True
    except ImportError:
        VOICE_AVAILABLE = False
        print("警告: 未安装pywin32库，无法使用语音报警功能")
else:
    # 对于非Windows系统，使用其他语音方案
    try:
        import subprocess

        VOICE_AVAILABLE = True
    except ImportError:
        VOICE_AVAILABLE = False

# 禁用SSL警告
warnings.filterwarnings('ignore', message='Unverified HTTPS request')


class DeviceConfig:
    """设备配置类"""

    def __init__(self, name, ip, token, cookie, interval_minutes=None):
        self.name = name  # 设备名称
        self.ip = ip  # 设备IP
        self.token = token  # 认证令牌
        self.cookie = cookie  # 会话Cookie
        self.interval_minutes = interval_minutes  # 设备特定的监控间隔（分钟）


class QAXMonitor:
    def __init__(self, device_config, interval_minutes=None, log_name_format=None):
        """
        初始化QAX监控器

        Args:
            device_config (DeviceConfig): 设备配置对象
            interval_minutes (int): 默认监控间隔（分钟），会被设备特定间隔覆盖
            log_name_format (str): 自定义日志文件名格式
        """
        self.device_config = device_config
        self.device_ip = device_config.ip
        self.device_name = device_config.name
        self.token = device_config.token
        self.cookie = device_config.cookie
        self.base_url = f"https://{device_config.ip}"
        self.api_endpoint = "/data.html"
        self.log_name_format = log_name_format or "{设备名}-{日期}-{时间}"

        # 使用设备特定的间隔时间，如果没有则使用默认间隔时间
        if device_config.interval_minutes is not None:
            self.interval_minutes = device_config.interval_minutes
            self.is_custom_interval = True
        else:
            self.interval_minutes = interval_minutes or 10  # 默认10分钟
            self.is_custom_interval = False

        # 设置请求头（匹配实际请求格式）
        self.headers = {
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Accept-Language': 'zh-CN,zh;q=0.9,zh-TW;q=0.8',
            'Content-Type': 'application/json; charset=UTF-8',
            'Host': self.device_ip,
            'Origin': self.base_url,
            'Referer': self.base_url + '/',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'token': self.token,
            'Cookie': self.cookie,
            'sec-ch-ua': '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors'
        }

        # 设置日志
        self.setup_logging()

        # 创建下载目录（每个设备一个子目录）
        self.download_dir = os.path.join("downloaded_logs", self.device_name)
        if not os.path.exists(self.download_dir):
            os.makedirs(self.download_dir)

        # 重试计数器
        self.retry_count = 0
        self.max_retries = 3

    def setup_logging(self):
        """设置日志记录"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('qax_monitor.log', encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)

    def format_log_filename(self, start_time, end_time):
        """
        根据格式模板生成文件名

        Args:
            start_time (datetime): 开始时间
            end_time (datetime): 结束时间

        Returns:
            str: 格式化后的文件名（不含扩展名）
        """
        # 准备替换变量
        replacements = {
            '{设备名}': self.device_name,
            '{设备IP}': self.device_ip,
            '{日期}': start_time.strftime('%Y%m%d'),
            '{时间}': end_time.strftime('%H%M'),
            '{开始日期}': start_time.strftime('%Y%m%d'),
            '{结束日期}': end_time.strftime('%Y%m%d'),
            '{开始时间}': start_time.strftime('%H%M'),
            '{结束时间}': end_time.strftime('%H%M'),
            '{开始日期时间}': start_time.strftime('%Y%m%d_%H%M'),
            '{结束日期时间}': end_time.strftime('%Y%m%d_%H%M'),
            '{时间范围}': f"{start_time.strftime('%H%M')}-{end_time.strftime('%H%M')}",
            '{完整时间范围}': f"{start_time.strftime('%H%M%S')}-{end_time.strftime('%H%M%S')}",
            '{年}': start_time.strftime('%Y'),
            '{月}': start_time.strftime('%m'),
            '{日}': start_time.strftime('%d'),
            '{开始小时}': start_time.strftime('%H'),
            '{开始分钟}': start_time.strftime('%M'),
            '{结束小时}': end_time.strftime('%H'),
            '{结束分钟}': end_time.strftime('%M'),
        }

        # 应用替换
        formatted_name = self.log_name_format
        for placeholder, value in replacements.items():
            formatted_name = formatted_name.replace(placeholder, str(value))

        # 清理文件名中的非法字符
        import re
        # 替换Windows不允许的字符
        formatted_name = re.sub(r'[<>:"/\\|?*]', '_', formatted_name)
        # 移除多余的空格和点
        formatted_name = re.sub(r'\.+', '.', formatted_name)
        formatted_name = formatted_name.strip(' .')

        # 确保文件名不为空
        if not formatted_name:
            formatted_name = f"log_{start_time.strftime('%Y%m%d_%H%M')}"

        self.logger.debug(f"生成的文件名: {formatted_name}")
        return formatted_name

    def get_next_target_time(self):
        """
        计算下一个目标时间点（根据间隔时间计算）

        Returns:
            datetime: 下一个目标时间点
        """
        now = datetime.now()

        # 计算当前时间从00:00开始的总分钟数
        total_minutes = now.hour * 60 + now.minute

        # 计算下一个目标时间点的总分钟数
        next_target_minutes = ((total_minutes // self.interval_minutes) + 1) * self.interval_minutes

        # 转换为小时和分钟
        next_hour = next_target_minutes // 60
        next_minute = next_target_minutes % 60

        # 处理跨天的情况
        if next_hour >= 24:
            next_hour = next_hour % 24
            next_target = now.replace(day=now.day + 1, hour=next_hour, minute=next_minute, second=0, microsecond=0)
        else:
            next_target = now.replace(hour=next_hour, minute=next_minute, second=0, microsecond=0)

        self.logger.debug(f"下一个目标时间点: {next_target.strftime('%Y-%m-%d %H:%M:%S')}")
        return next_target

    def get_time_range_for_period(self, end_time):
        """
        根据结束时间计算对应的时间范围

        Args:
            end_time (datetime): 结束时间

        Returns:
            tuple: (start_time, end_time) 格式化的时间字符串
        """
        start_time = end_time - timedelta(minutes=self.interval_minutes)

        start_str = start_time.strftime('%Y-%m-%d %H:%M:%S')
        end_str = end_time.strftime('%Y-%m-%d %H:%M:%S')

        self.logger.debug(f"计算时间范围: {start_str} 到 {end_str}")
        return start_str, end_str

    def is_target_time_reached(self, target_time):
        """
        检查是否到达目标时间

        Args:
            target_time (datetime): 目标时间

        Returns:
            bool: 是否到达或超过目标时间
        """
        now = datetime.now()
        return now >= target_time

    def get_optimized_time_range(self):
        """
        获取优化的时间范围，自动选择最近的10分钟的整数时间作为开始时间

        Returns:
            tuple: (start_time, end_time) 格式化的时间字符串
        """
        now = datetime.now()

        # 计算最近的10分钟整数倍时间点
        minutes = now.minute
        rounded_minutes = (minutes // 10) * 10

        # 如果当前时间不是10分钟的整数倍，使用上一个10分钟时间点
        if minutes % 10 != 0:
            start_time = now.replace(minute=rounded_minutes, second=0, microsecond=0)
        else:
            # 如果正好是10分钟整数倍，往前推一个间隔
            start_time = now - timedelta(minutes=self.interval_minutes)

        # 确保时间范围不超过设定的间隔
        if (now - start_time).total_seconds() > self.interval_minutes * 60:
            start_time = now - timedelta(minutes=self.interval_minutes)

        start_str = start_time.strftime('%Y-%m-%d %H:%M:%S')
        end_str = now.strftime('%Y-%m-%d %H:%M:%S')

        self.logger.debug(f"计算时间范围: {start_str} 到 {end_str}")
        return start_str, end_str

    def play_voice_alert(self, message="发生报错，请人工排除"):
        """
        播放语音报警

        Args:
            message (str): 报警消息
        """
        if not VOICE_AVAILABLE:
            return

        try:
            if platform.system() == 'Windows':
                # 初始化COM（每个线程都需要单独初始化）
                try:
                    import pythoncom
                    # 检查当前线程是否已初始化COM
                    pythoncom.CoInitialize()
                    com_initialized = True
                except Exception:
                    # 如果已经初始化过，使用CoInitializeEx
                    try:
                        pythoncom.CoInitializeEx(pythoncom.COINIT_APARTMENTTHREADED)
                        com_initialized = True
                    except Exception:
                        com_initialized = False
                        self.logger.warning("COM初始化失败，跳过语音报警")
                        return

                try:
                    speaker = win32com.client.Dispatch("SAPI.SpVoice")
                    for i in range(3):  # 播放三次
                        speaker.Speak(message)
                        time.sleep(1)  # 间隔1秒
                finally:
                    # 清理COM
                    if com_initialized:
                        pythoncom.CoUninitialize()
            else:
                # 对于Linux/Mac系统使用espeak或其他TTS工具
                for i in range(3):
                    try:
                        subprocess.run(['espeak', message], check=True, capture_output=True)
                    except (subprocess.CalledProcessError, FileNotFoundError):
                        # 如果espeak不可用，尝试使用say命令（Mac）
                        try:
                            subprocess.run(['say', message], check=True, capture_output=True)
                        except (subprocess.CalledProcessError, FileNotFoundError):
                            self.logger.warning("语音报警不可用，请安装espeak或使用系统TTS")
                            break
                    time.sleep(1)

            self.logger.info("语音报警已触发")
        except Exception as e:
            self.logger.error(f"语音报警失败: {str(e)}")

    def export_logs(self, start_time, end_time, retry_count=0):
        """
        导出日志文件，包含重试机制

        Args:
            start_time (str): 开始时间
            end_time (str): 结束时间
            retry_count (int): 当前重试次数

        Returns:
            str: 导出文件名，失败返回None
        """
        try:
            # 构建导出请求
            export_payload = [{
                "head": {
                    "function": "export_log_threat",
                    "module": "stored",
                    "page_index": 1,
                    "page_size": 10000
                },
                "body": {
                    "log_show": {
                        "filter": "((threat_type eq '全部威胁类型'))",
                        "time_start": start_time,
                        "time_end": end_time,
                        "order": "descend",
                        "password": ""
                    }
                }
            }]

            self.logger.info(
                f"正在导出日志: {start_time} 到 {end_time} (尝试 {retry_count + 1}/{self.max_retries + 1})")

            # 发送导出请求
            response = requests.post(
                self.base_url + self.api_endpoint,
                headers=self.headers,
                json=export_payload,
                verify=False,  # 忽略SSL证书验证
                timeout=30
            )

            # 记录响应信息用于调试
            self.logger.debug(f"响应状态码: {response.status_code}")
            self.logger.debug(f"响应头: {dict(response.headers)}")

            if response.status_code == 200:
                # 检查响应内容
                response_text = response.text.strip()
                self.logger.debug(f"响应内容: {response_text[:200]}...")  # 只记录前200个字符

                if not response_text:
                    self.logger.error("响应内容为空")
                    return self._handle_export_failure(start_time, end_time, retry_count, "响应内容为空")

                try:
                    response_data = response.json()
                except json.JSONDecodeError as e:
                    self.logger.error(f"JSON解析失败: {str(e)}")
                    self.logger.error(f"原始响应: {response_text}")
                    return self._handle_export_failure(start_time, end_time, retry_count, f"JSON解析失败: {str(e)}")

                if response_data.get('head', {}).get('error_code') == 0:
                    filter_value = response_data.get('data', {}).get('filter', '')
                    if filter_value:
                        self.logger.info(f"日志导出成功，文件名: {filter_value}")
                        # 重置重试计数器
                        self.retry_count = 0
                        return filter_value
                    else:
                        self.logger.error("导出响应中没有找到文件名")
                        return self._handle_export_failure(start_time, end_time, retry_count,
                                                           "导出响应中没有找到文件名")
                else:
                    error_msg = response_data.get('head', {}).get('error_string', '未知错误')
                    self.logger.error(f"导出日志失败: {error_msg}")
                    return self._handle_export_failure(start_time, end_time, retry_count, error_msg)
            else:
                error_msg = f"导出请求失败，状态码: {response.status_code}, 响应: {response.text[:200]}"
                self.logger.error(error_msg)
                return self._handle_export_failure(start_time, end_time, retry_count, error_msg)

        except requests.exceptions.RequestException as e:
            error_msg = f"网络请求异常: {str(e)}"
            self.logger.error(error_msg)
            return self._handle_export_failure(start_time, end_time, retry_count, error_msg)
        except Exception as e:
            error_msg = f"导出日志时发生未知异常: {str(e)}"
            self.logger.error(error_msg)
            return self._handle_export_failure(start_time, end_time, retry_count, error_msg)

    def _handle_export_failure(self, start_time, end_time, retry_count, error_msg):
        """
        处理导出失败的情况

        Args:
            start_time (str): 开始时间
            end_time (str): 结束时间
            retry_count (int): 当前重试次数
            error_msg (str): 错误消息

        Returns:
            None: 表示失败
        """
        if retry_count < self.max_retries:
            self.retry_count = retry_count + 1
            self.logger.info(f"第 {self.retry_count} 次重试导出，等待 5 秒...")
            time.sleep(5)
            return self.export_logs(start_time, end_time, self.retry_count)
        else:
            self.logger.error(f"导出失败，已达到最大重试次数 ({self.max_retries + 1})")
            self.logger.error(f"最终错误: {error_msg}")

            # 触发语音报警
            self.play_voice_alert("发生报错，请人工排除")

            # 重置重试计数器
            self.retry_count = 0
            return None

    def download_log_file(self, original_filename, custom_filename, retry_count=0):
        """
        下载导出的日志文件，包含重试机制

        Args:
            original_filename (str): 服务器返回的原始文件名
            custom_filename (str): 自定义的文件名（不含扩展名）
            retry_count (int): 当前重试次数

        Returns:
            str: 下载的文件路径，失败返回None
        """
        try:
            # 构建下载URL
            download_url = f"{self.base_url}/getDownLoad/{original_filename}/refer/{self.token}.html"

            self.logger.info(
                f"正在下载文件: {original_filename} -> {custom_filename}.csv (尝试 {retry_count + 1}/{self.max_retries + 1})")
            self.logger.debug(f"下载URL: {download_url}")

            # 为下载请求设置专门的头部（包含Cookie）
            download_headers = {
                'Accept': '*/*',
                'Accept-Encoding': 'gzip, deflate, br, zstd',
                'Accept-Language': 'zh-CN,zh;q=0.9,zh-TW;q=0.8',
                'Host': self.device_ip,
                'Origin': self.base_url,
                'Referer': self.base_url + '/',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
                'Cookie': self.cookie,
                'sec-ch-ua': '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors'
            }

            # 发送下载请求
            response = requests.get(
                download_url,
                headers=download_headers,
                verify=False,  # 忽略SSL证书验证
                timeout=60,
                stream=True,  # 流式下载大文件
                allow_redirects=False  # 不自动重定向，以便处理认证问题
            )

            # 记录响应信息用于调试
            self.logger.debug(f"下载响应状态码: {response.status_code}")
            self.logger.debug(f"下载响应头: {dict(response.headers)}")

            # 检查是否需要重定向（可能需要重新认证）
            if response.status_code in [302, 303, 307, 308]:
                redirect_url = response.headers.get('Location', '')
                self.logger.warning(f"下载请求被重定向到: {redirect_url}")
                self.logger.warning("可能需要重新登录获取新的Cookie和Token")
                return self._handle_download_failure(original_filename, retry_count, "下载请求被重定向，可能认证已过期")

            # 检查响应内容类型
            content_type = response.headers.get('content-type', '').lower()
            if 'text/html' in content_type:
                self.logger.warning(f"下载返回HTML内容而不是文件，可能认证失败")
                self.logger.debug(f"响应内容: {response.text[:200]}...")
                return self._handle_download_failure(original_filename, retry_count,
                                                     "下载返回HTML而不是文件，可能认证失败")

            if response.status_code == 200:
                # 检查响应内容大小
                content_length = response.headers.get('content-length')
                if content_length and int(content_length) == 0:
                    self.logger.error("下载文件大小为0")
                    return self._handle_download_failure(original_filename, retry_count, "下载文件大小为0")

                # 确定最终文件名（保持CSV扩展名）
                final_filename = f"{custom_filename}.csv"
                file_path = os.path.join(self.download_dir, final_filename)

                # 如果文件已存在，添加时间戳避免覆盖
                counter = 1
                while os.path.exists(file_path):
                    name_part, ext_part = os.path.splitext(final_filename)
                    final_filename = f"{name_part}_{counter}{ext_part}"
                    file_path = os.path.join(self.download_dir, final_filename)
                    counter += 1

                total_size = 0
                with open(file_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            total_size += len(chunk)

                self.logger.info(f"文件下载成功: {file_path} (大小: {total_size} 字节)")
                return file_path
            else:
                error_msg = f"下载失败，状态码: {response.status_code}, 响应: {response.text[:200]}"
                self.logger.error(error_msg)
                return self._handle_download_failure(original_filename, retry_count, error_msg)

        except requests.exceptions.RequestException as e:
            error_msg = f"下载请求异常: {str(e)}"
            self.logger.error(error_msg)
            return self._handle_download_failure(original_filename, retry_count, error_msg)
        except Exception as e:
            error_msg = f"下载文件时发生未知异常: {str(e)}"
            self.logger.error(error_msg)
            return self._handle_download_failure(original_filename, retry_count, error_msg)

    def _handle_download_failure(self, filename, retry_count, error_msg):
        """
        处理下载失败的情况

        Args:
            filename (str): 文件名
            retry_count (int): 当前重试次数
            error_msg (str): 错误消息

        Returns:
            None: 表示失败
        """
        if retry_count < self.max_retries:
            self.retry_count = retry_count + 1
            self.logger.info(f"第 {self.retry_count} 次重试下载，等待 5 秒...")
            time.sleep(5)
            return self.download_log_file(filename, self.retry_count)
        else:
            self.logger.error(f"下载失败，已达到最大重试次数 ({self.max_retries + 1})")
            self.logger.error(f"最终错误: {error_msg}")

            # 触发语音报警
            self.play_voice_alert("文件下载失败，请人工排除")

            # 重置重试计数器
            self.retry_count = 0
            return None

    def monitor_at_target_time(self, target_time):
        """
        在目标时间点执行监控流程

        Args:
            target_time (datetime): 目标时间点

        Returns:
            bool: 是否成功
        """
        try:
            # 计算实际的开始和结束时间（datetime对象）
            start_time_dt = target_time - timedelta(minutes=self.interval_minutes)
            end_time_dt = target_time

            # 获取格式化的时间字符串（用于API请求）
            start_time_str = start_time_dt.strftime('%Y-%m-%d %H:%M:%S')
            end_time_str = end_time_dt.strftime('%Y-%m-%d %H:%M:%S')

            self.logger.info(f"执行监控周期: {start_time_str} 到 {end_time_str}")

            # 导出日志（使用字符串格式的时间）
            original_filename = self.export_logs(start_time_str, end_time_str)
            if not original_filename:
                return False

            # 生成自定义文件名（使用datetime对象）
            custom_filename = self.format_log_filename(start_time_dt, end_time_dt)
            self.logger.info(f"自定义文件名: {custom_filename}.csv")

            # 等待一段时间让服务器准备文件
            time.sleep(5)

            # 下载文件
            downloaded_file = self.download_log_file(original_filename, custom_filename)
            if not downloaded_file:
                return False

            self.logger.info(f"监控周期完成，文件已保存: {downloaded_file}")
            return True

        except Exception as e:
            self.logger.error(f"监控周期中发生异常: {str(e)}")
            return False

    def monitor_once(self):
        """执行一次监控流程（保持兼容性）"""
        try:
            # 获取优化的时间范围
            start_time, end_time = self.get_optimized_time_range()

            # 输出时间段信息（使用彩色输出）
            start_str = start_time.strftime('%Y-%m-%d %H:%M:%S')
            end_str = end_time.strftime('%Y-%m-%d %H:%M:%S')

            colored_print(f"\n{'=' * 20} 监控周期开始 {'=' * 20}", color='cyan')
            colored_print(f"[DEVICE] 设备: {self.device_name}", color='blue', style='bold')
            colored_print(f"[TIME] 时间段: {start_str} → {end_str}", color='yellow', style='bold')
            colored_print(f"[IP] 地址: {self.device_ip}", color='blue')
            print_separator("-", color='cyan')

            self.logger.info(f"开始监控周期: {start_str} 到 {end_str}")

            # 导出日志
            filename = self.export_logs(start_time, end_time)
            if not filename:
                return False

            # 等待一段时间让服务器准备文件
            time.sleep(5)

            # 下载文件
            downloaded_file = self.download_log_file(filename)
            if not downloaded_file:
                colored_print("[ERROR] 文件下载失败", color='red')
                return False

            # 输出监控完成信息
            colored_print("[SUCCESS] 文件下载成功", color='green')
            colored_print(f"[SAVE] 保存位置: {downloaded_file}", color='blue')
            print_separator("=", color='green')

            self.logger.info(f"监控周期完成，文件已保存: {downloaded_file}")
            return True

        except Exception as e:
            colored_print(f"[ERROR] 监控异常: {str(e)}", color='red')
            self.logger.error(f"监控周期中发生异常: {str(e)}")
            return False

    def start_monitoring(self):
        """开始监控循环"""
        self.logger.info(f"开始监控设备 {self.device_ip}，间隔 {self.interval_minutes} 分钟")
        self.logger.info("监控逻辑: 每10秒检查一次是否到达10分钟整数倍时间点")
        self.logger.info("按 Ctrl+C 停止监控")

        try:
            while not stop_monitoring:
                # 获取下一个目标时间点
                next_target_time = self.get_next_target_time()

                self.logger.info(f"===== 等待目标时间点: {next_target_time.strftime('%Y-%m-%d %H:%M:%S')} =====")

                # 每10秒检查一次是否到达目标时间
                while not self.is_target_time_reached(next_target_time):
                    current_time = datetime.now()
                    remaining_seconds = (next_target_time - current_time).total_seconds()

                    if remaining_seconds > 10:
                        self.logger.debug(f"距离目标时间还有 {int(remaining_seconds)} 秒，等待10秒后检查...")
                        time.sleep(10)
                    else:
                        # 最后10秒内每秒检查一次
                        self.logger.info(f"即将到达目标时间，剩余 {int(remaining_seconds)} 秒")
                        time.sleep(1)

                # 到达目标时间，执行监控
                self.logger.info(
                    f"===== 到达目标时间点 {next_target_time.strftime('%Y-%m-%d %H:%M:%S')}，开始执行监控 =====")

                success = self.monitor_at_target_time(next_target_time)

                if success:
                    self.logger.info("监控周期成功完成")
                else:
                    self.logger.error("监控周期失败，继续等待下一个时间点")

        except KeyboardInterrupt:
            self.logger.info("监控已停止")
        except Exception as e:
            self.logger.error(f"监控过程中发生严重异常: {str(e)}")

    def start_monitoring_old(self):
        """旧的监控循环（保持兼容性）"""
        self.logger.info(f"开始监控设备 {self.device_ip}，间隔 {self.interval_minutes} 分钟")
        self.logger.info("按 Ctrl+C 停止监控")

        try:
            while not stop_monitoring:
                start_time = datetime.now()
                self.logger.info(f"===== 开始监控周期 {start_time.strftime('%Y-%m-%d %H:%M:%S')} =====")

                success = self.monitor_once()

                if success:
                    self.logger.info("监控周期成功完成")
                else:
                    self.logger.error("监控周期失败，将在下次间隔后重试")

                # 计算下次等待时间
                elapsed = (datetime.now() - start_time).total_seconds()
                wait_time = self.interval_minutes * 60 - elapsed

                if wait_time > 0:
                    self.logger.info(f"等待 {int(wait_time)} 秒后开始下次监控...")
                    time.sleep(wait_time)
                else:
                    self.logger.warning("监控周期耗时超过间隔时间，立即开始下次监控")

        except KeyboardInterrupt:
            self.logger.info("监控已停止")
        except Exception as e:
            self.logger.error(f"监控过程中发生严重异常: {str(e)}")


class MultiDeviceMonitor:
    """多设备监控管理器"""

    def __init__(self, device_configs, default_interval_minutes=None, log_name_format=None):
        """
        初始化多设备监控器

        Args:
            device_configs (list): 设备配置列表
            default_interval_minutes (int): 默认监控间隔（分钟）
            log_name_format (str): 自定义日志文件名格式
        """
        self.device_configs = device_configs
        self.default_interval_minutes = default_interval_minutes or 10
        self.log_name_format = log_name_format
        self.monitors = []

        # 为每个设备创建监控器
        for config in device_configs:
            monitor = QAXMonitor(config, self.default_interval_minutes, log_name_format)
            self.monitors.append(monitor)

        # 设置主日志记录器
        self.setup_main_logging()

        # 检查是否有设备特定的间隔时间
        self.has_custom_intervals = any(config.interval_minutes is not None for config in device_configs)

    def setup_main_logging(self):
        """设置主日志记录器"""
        self.logger = logging.getLogger("MultiDeviceMonitor")
        self.logger.setLevel(logging.INFO)

        # 避免重复添加handler
        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - [主控制器] - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def get_next_target_time(self):
        """计算下一个目标时间点"""
        now = datetime.now()

        # 计算当前时间从00:00开始的总分钟数
        total_minutes = now.hour * 60 + now.minute

        # 计算下一个目标时间点的总分钟数
        next_target_minutes = ((total_minutes // self.interval_minutes) + 1) * self.interval_minutes

        # 转换为小时和分钟
        next_hour = next_target_minutes // 60
        next_minute = next_target_minutes % 60

        # 处理跨天的情况
        if next_hour >= 24:
            next_hour = next_hour % 24
            next_target = now.replace(day=now.day + 1, hour=next_hour, minute=next_minute, second=0, microsecond=0)
        else:
            next_target = now.replace(hour=next_hour, minute=next_minute, second=0, microsecond=0)

        return next_target

    def monitor_device_independently(self, monitor):
        """独立监控单个设备"""
        device_name = monitor.device_name
        self.logger.info(f"设备 {device_name} ({monitor.interval_minutes}分钟间隔) 开始独立监控")

        try:
            while not stop_monitoring:
                # 计算设备的下一个目标时间点
                next_target_time = monitor.get_next_target_time()
                self.logger.debug(
                    f"设备 {device_name} 下一个目标时间: {next_target_time.strftime('%Y-%m-%d %H:%M:%S')}")

                # 等待到达目标时间
                while not stop_monitoring:
                    current_time = datetime.now()
                    remaining_seconds = (next_target_time - current_time).total_seconds()

                    if remaining_seconds <= 0:
                        break

                    if remaining_seconds > 10:
                        time.sleep(10)
                    else:
                        time.sleep(1)

                # 到达目标时间，执行监控
                self.logger.info(f"设备 {device_name} 开始监控: {next_target_time.strftime('%Y-%m-%d %H:%M:%S')}")
                success = monitor.monitor_at_target_time(next_target_time)

                if success:
                    self.logger.info(f"设备 {device_name} 监控成功")
                else:
                    self.logger.error(f"设备 {device_name} 监控失败，等待下次监控")

        except Exception as e:
            self.logger.error(f"设备 {device_name} 监控线程异常: {str(e)}")

    def monitor_all_devices(self, target_time):
        """同时监控所有设备（用于兼容相同的间隔时间）"""
        import threading

        self.logger.info(f"===== 开始监控所有设备，目标时间: {target_time.strftime('%Y-%m-%d %H:%M:%S')} =====")

        # 创建线程列表
        threads = []
        results = {}

        def monitor_device(monitor):
            """监控单个设备的线程函数"""
            device_name = monitor.device_name
            try:
                success = monitor.monitor_at_target_time(target_time)
                results[device_name] = success
                if success:
                    colored_print(f"[SUCCESS] 设备 {device_name} 监控成功", color='green')
                else:
                    colored_print(f"[ERROR] 设备 {device_name} 监控失败", color='red')
            except Exception as e:
                colored_print(f"[ERROR] 设备 {device_name} 监控异常: {str(e)}", color='red')
                results[device_name] = False

        # 为每个设备创建线程
        for monitor in self.monitors:
            thread = threading.Thread(target=monitor_device, args=(monitor,))
            thread.daemon = True
            threads.append(thread)
            thread.start()
            self.logger.info(f"设备 {monitor.device_name} 监控线程已启动")

        # 等待所有线程完成
        for thread in threads:
            thread.join()

        # 汇总结果
        success_count = sum(1 for success in results.values() if success)
        total_count = len(results)

        self.logger.info(f"===== 本次监控完成: {success_count}/{total_count} 个设备成功 =====")

        for device_name, success in results.items():
            status = "成功" if success else "失败"
            self.logger.info(f"  设备 {device_name}: {status}")

        return success_count, total_count

    def start_monitoring(self):
        """开始多设备监控循环"""
        device_names = [config.name for config in self.device_configs]
        self.logger.info(f"开始多设备监控: {', '.join(device_names)}")

        # 显示设备间隔时间信息
        interval_info = []
        for monitor in self.monitors:
            if monitor.is_custom_interval:
                interval_info.append(f"{monitor.device_name}({monitor.interval_minutes}分钟)")
            else:
                interval_info.append(f"{monitor.device_name}(默认{monitor.interval_minutes}分钟)")

        self.logger.info(f"设备间隔时间: {', '.join(interval_info)}")

        if self.has_custom_intervals:
            self.logger.info("检测到设备特定的间隔时间，将启用独立监控模式")
            self.logger.info("每个设备将按照自己的间隔时间独立监控")
        else:
            self.logger.info(f"监控间隔: {self.default_interval_minutes} 分钟")
            self.logger.info("监控逻辑: 每10秒检查一次是否到达目标时间点")

        self.logger.info("按 Ctrl+C 停止监控")

        # 注册信号处理器
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        try:
            if self.has_custom_intervals:
                # 独立监控模式：每个设备有自己的监控线程
                self.logger.info("===== 启动独立监控模式 =====")
                import threading

                threads = []
                for monitor in self.monitors:
                    thread = threading.Thread(target=self.monitor_device_independently, args=(monitor,))
                    thread.daemon = True
                    threads.append(thread)
                    thread.start()

                # 等待所有线程或停止信号
                while not stop_monitoring:
                    time.sleep(1)
                    # 检查是否有线程已经停止
                    for i, thread in enumerate(threads):
                        if not thread.is_alive():
                            self.logger.warning(f"设备线程 {self.monitors[i].device_name} 意外停止")

                # 等待所有线程完全停止
                for thread in threads:
                    thread.join(timeout=2)

            else:
                # 同步监控模式：所有设备使用相同的间隔时间
                while not stop_monitoring:
                    # 获取下一个目标时间点
                    next_target_time = self.monitors[0].get_next_target_time()

                    self.logger.info(f"===== 等待目标时间点: {next_target_time.strftime('%Y-%m-%d %H:%M:%S')} =====")

                    # 每10秒检查一次是否到达目标时间
                    while not stop_monitoring:
                        current_time = datetime.now()
                        remaining_seconds = (next_target_time - current_time).total_seconds()

                        if remaining_seconds <= 0:
                            break

                        if remaining_seconds > 10:
                            self.logger.debug(f"距离目标时间还有 {int(remaining_seconds)} 秒，等待10秒后检查...")
                            time.sleep(10)
                        else:
                            # 最后10秒内每秒检查一次
                            self.logger.info(f"即将到达目标时间，剩余 {int(remaining_seconds)} 秒")
                            time.sleep(1)

                    # 到达目标时间，同时监控所有设备
                    self.monitor_all_devices(next_target_time)

        except KeyboardInterrupt:
            self.logger.info("多设备监控已停止")
        except Exception as e:
            self.logger.error(f"多设备监控过程中发生严重异常: {str(e)}")
        finally:
            if stop_monitoring:
                self.logger.info("监控已安全停止")


def parse_device_config(config_str):
    """
    解析设备配置字符串

    格式: 设备名:IP:Token:Cookie
    """
    parts = config_str.split(':')
    if len(parts) != 4:
        raise ValueError(f"设备配置格式错误，应为: 设备名:IP:Token:Cookie，实际为: {config_str}")

    return DeviceConfig(parts[0].strip(), parts[1].strip(), parts[2].strip(), parts[3].strip())


def parse_config_file(file_path):
    """
    从请求包文件中解析设备配置

    Args:
        file_path (str): 配置文件路径

    Returns:
        DeviceConfig: 设备配置对象
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # 提取设备名称和间隔时间（从文件名）
        file_name = os.path.splitext(os.path.basename(file_path))[0]

        # 解析文件名格式：设备名-间隔时间
        if '-' in file_name:
            parts = file_name.split('-')
            device_name = parts[0]

            # 尝试解析间隔时间
            try:
                interval_minutes = int(parts[-1])
            except (ValueError, IndexError):
                interval_minutes = None
                device_name = file_name  # 如果解析失败，使用完整文件名
        else:
            device_name = file_name
            interval_minutes = None

        # 解析请求内容
        ip = None
        token = None
        cookie = None

        lines = content.strip().split('\n')

        for line in lines:
            line = line.strip()

            # 处理HTTP请求头格式
            if ':' in line:
                header_name = line.split(':', 1)[0].strip().lower()
                header_value = line.split(':', 1)[1].strip()

                # 提取IP地址（从Host头）
                if header_name in ['host', ':authority']:
                    ip = header_value

                # 提取Token
                elif header_name == 'token':
                    token = header_value

                # 提取Cookie
                elif header_name == 'cookie':
                    cookie = header_value

            # 处理旧格式（向后兼容）
            elif line.startswith(':authority:'):
                # IP在下一行
                current_index = lines.index(line)
                if current_index + 1 < len(lines):
                    ip = lines[current_index + 1].strip()

            elif line.startswith('token:'):
                # Token在下一行
                current_index = lines.index(line)
                if current_index + 1 < len(lines):
                    token = lines[current_index + 1].strip()

            elif line.startswith('cookie:'):
                # Cookie可能在同一行（如果有内容）或下一行
                cookie_value = line.split(':', 1)[1].strip()
                if cookie_value:
                    cookie = cookie_value
                else:
                    current_index = lines.index(line)
                    if current_index + 1 < len(lines):
                        cookie = lines[current_index + 1].strip()

        # 验证必要字段
        if not ip or not token or not cookie:
            raise ValueError(f"配置文件 {file_path} 缺少必要字段: IP={ip}, Token={bool(token)}, Cookie={bool(cookie)}")

        return DeviceConfig(device_name, ip, token, cookie, interval_minutes)

    except FileNotFoundError:
        raise FileNotFoundError(f"配置文件不存在: {file_path}")
    except Exception as e:
        raise Exception(f"解析配置文件 {file_path} 时发生错误: {str(e)}")


def load_configs_from_directory(config_dir="configs"):
    """
    从configs目录加载所有设备配置

    Args:
        config_dir (str): 配置目录路径

    Returns:
        list: 设备配置列表
    """
    device_configs = []

    # 检查配置目录是否存在
    if not os.path.exists(config_dir):
        raise FileNotFoundError(f"配置目录不存在: {config_dir}")

    # 查找所有.txt文件
    txt_files = []
    for file_name in os.listdir(config_dir):
        if file_name.endswith('.txt'):
            txt_files.append(file_name)

    if not txt_files:
        raise ValueError(f"配置目录 {config_dir} 中没有找到.txt文件")

    # 解析每个配置文件
    for file_name in txt_files:
        file_path = os.path.join(config_dir, file_name)
        try:
            config = parse_config_file(file_path)
            device_configs.append(config)

            # 显示配置信息
            if config.interval_minutes is not None:
                print(f"✓ 成功加载配置: {config.name} ({config.ip}) - 间隔时间: {config.interval_minutes} 分钟")
            else:
                print(f"✓ 成功加载配置: {config.name} ({config.ip}) - 使用默认间隔时间")
        except Exception as e:
            print(f"✗ 加载配置文件 {file_name} 失败: {str(e)}")

    if not device_configs:
        raise ValueError("没有成功加载任何设备配置")

    return device_configs


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='QAX安全设备日志监控脚本')

    # 创建互斥的参数组
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--devices', help='设备配置列表，格式: 设备名1:IP1:Token1:Cookie1,设备名2:IP2:Token2:Cookie2')
    group.add_argument('--auto-config', help='从configs目录自动加载所有设备配置')

    parser.add_argument('--interval', type=int, help='默认监控间隔（分钟），当设备文件未指定间隔时间时使用')
    parser.add_argument('--log-name', help='自定义日志文件名格式，例如: "某某项目-{日期}-{时间范围}"')
    parser.add_argument('--debug', action='store_true', help='启用调试模式，显示详细日志')
    parser.add_argument('--no-color', action='store_true', help='禁用彩色输出')

    args = parser.parse_args()

    # 设置颜色开关
    global enable_colors
    if args.no_color:
        enable_colors = False
        Colors.disable()

    # 解析设备配置
    try:
        device_configs = []

        if args.auto_config:
            # 自动从configs目录加载配置
            colored_print(f"正在从 {args.auto_config} 目录自动加载设备配置...", color='blue')
            device_configs = load_configs_from_directory(args.auto_config)
        else:
            # 手动解析设备配置字符串
            for config_str in args.devices.split(','):
                config = parse_device_config(config_str)
                device_configs.append(config)

        # 验证设备数量
        if len(device_configs) == 0:
            colored_print("[ERROR] 错误: 至少需要配置一个设备", color='red')
            sys.exit(1)

        print_separator(color='cyan')
        colored_print(f"[SUCCESS] 成功加载 {len(device_configs)} 个设备配置:", color='green', style='bold')
        for config in device_configs:
            if config.interval_minutes is not None:
                colored_print(f"  [DEVICE] {config.name}: {config.ip} (间隔: {config.interval_minutes}分钟)",
                              color='blue')
            else:
                colored_print(f"  [DEVICE] {config.name}: {config.ip} (使用默认间隔)", color='blue')

    except (ValueError, FileNotFoundError, Exception) as e:
        print(f"错误: {str(e)}")
        sys.exit(1)

    # 输出程序标题
    print_separator(color='cyan')
    colored_print("[SYSTEM] QAX安全设备日志监控系统", color='cyan', style='bold')
    colored_print(f"[INFO] 监控设备数量: {len(device_configs)}", color='blue')
    colored_print(f"[INFO] 彩色输出: {'关闭' if args.no_color else '开启'}", color='yellow')
    colored_print(f"[INFO] 调试模式: {'开启' if args.debug else '关闭'}", color='yellow')
    print_separator(color='cyan')

    # 创建多设备监控器并开始监控
    multi_monitor = MultiDeviceMonitor(device_configs, args.interval, args.log_name)

    # 如果启用调试模式，设置所有监控器的日志级别为DEBUG
    if args.debug:
        for monitor in multi_monitor.monitors:
            monitor.logger.setLevel(logging.DEBUG)
            for handler in monitor.logger.handlers:
                handler.setLevel(logging.DEBUG)
        colored_print("[DEBUG] 调试模式已启用", color='yellow')

    if args.log_name:
        colored_print(f"[INFO] 使用自定义文件名格式: {args.log_name}", color='blue')

    colored_print("[START] 开始监控...", color='green', style='bold')
    multi_monitor.start_monitoring()


def main_single():
    """单设备监控（保持向后兼容）"""
    parser = argparse.ArgumentParser(description='QAX安全设备日志监控脚本（单设备）')
    parser.add_argument('--ip', required=True, help='设备IP地址')
    parser.add_argument('--interval', type=int, required=True, help='监控间隔（分钟）')
    parser.add_argument('--token', required=True, help='认证令牌')
    parser.add_argument('--cookie', required=True, help='会话Cookie')
    parser.add_argument('--log-name', help='自定义日志文件名格式，例如: "某某项目-{日期}-{时间范围}"')
    parser.add_argument('--debug', action='store_true', help='启用调试模式，显示详细日志')
    parser.add_argument('--no-color', action='store_true', help='禁用彩色输出')

    args = parser.parse_args()

    # 设置颜色开关
    global enable_colors
    if args.no_color:
        enable_colors = False
        Colors.disable()

    # 创建设备配置
    device_config = DeviceConfig("SingleDevice", args.ip, args.token, args.cookie, args.interval)

    # 创建监控器并开始监控
    monitor = QAXMonitor(device_config, args.interval, args.log_name)

    # 如果启用调试模式，设置日志级别为DEBUG
    if args.debug:
        monitor.logger.setLevel(logging.DEBUG)
        for handler in monitor.logger.handlers:
            handler.setLevel(logging.DEBUG)
        monitor.logger.info("调试模式已启用")

    if args.log_name:
        monitor.logger.info(f"使用自定义文件名格式: {args.log_name}")

    monitor.logger.info(f"监控间隔: {args.interval} 分钟")
    monitor.start_monitoring()


if __name__ == "__main__":
    # 注册信号处理器
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # 检查是否使用单设备模式
    if len(sys.argv) > 1 and '--ip' in sys.argv:
        main_single()
    else:
        main()
