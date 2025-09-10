#!/usr/bin/env python
# -*- coding: utf-8 -*-
# license:  AGPL-V3

"""
Dr.COM 校园网认证客户端 Python 实现 (图形用户界面版)

核心功能:
- 提供完整的图形用户界面(GUI)。
- 自动检测并提示终止占用认证端口的进程。
- 可选的详细网络日志输出，便于调试。
- 记住用户配置，并支持自动登录。
- 配置文件与主程序在同一目录，方便移植。
- 关闭窗口时最小化到系统托盘，后台运行。
- Windows 系统下支持设置开机自启动。
"""

import os
import sys
import json
import queue
import socket
import struct
import time
import random
import platform
import logging
import threading
from hashlib import md5
from dataclasses import dataclass

# --- 依赖库导入 ---
try:
    import psutil
    from PIL import Image
    import pystray
except ImportError as e:
    print(f"错误: 缺少必要的依赖库。请先运行 'pip install psutil Pillow pystray' 进行安装。")
    print(f"具体错误信息: {e}")
    sys.exit(1)

# --- Windows 平台专属库导入 ---
if platform.system() == "Windows":
    try:
        import winreg
    except ImportError:
        print("警告: 'winreg' 模块导入失败。开机自启功能将无法使用。")

# --- Tkinter GUI 相关导入 ---
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText

# --- 全局常量与路径定义 ---

# SCRIPT_DIR 用于定位脚本所在的目录，以确保配置文件和图标能被正确找到。
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE_PATH = os.path.join(SCRIPT_DIR, 'config.json')
ICON_FILE_PATH = os.path.join(SCRIPT_DIR, 'icon.png')

# Dr.COM 协议相关常量
AUTH_PORT = 61440           # 认证服务器端口
AUTH_VERSION = b'\x68\00'       # 认证版本号
KEEP_ALIVE_VERSION = b'\xdc\02' # 心跳版本号

# --- 新增协议常量，提升可读性 ---
# 包类型或前缀
PACKET_PREFIX_LOGIN = b'\x03\x01\x00'
PACKET_PREFIX_CHALLENGE = b'\x01\x02'
PACKET_PREFIX_KEEPALIVE = b'\x07'
PACKET_PREFIX_INITIAL_KEEPALIVE = b'\xff'

# MD5 计算时使用的盐值或前缀
MD5_SALT_PREFIX_1 = b'\x03\x01'
MD5_SALT_PREFIX_2 = b'\x01'

# 固定的协议字段
CONTROL_CHECK_STATUS = b'\x20'
ADAPTER_NUM = b'\x03'
IP_DOG = b'\x01'

# 用于校验和计算的固定值
CHECKSUM_MAGIC_1 = b'\x14\x00\x07\x0b'
CHECKSUM_MAGIC_2 = b'\x01\x26\x07\x11\x00\x00'

# 其他固定字节串
MISC_BYTES_1 = b'\x94\x00\x00\x00\x06\x00\x00\x00\x02\x00\x00\x00\xf0\x23\x00\x00\x02\x00\x00\x00'
MISC_BYTES_2 = b'DrCOM\x00\xcf\x07\x68'
MISC_BYTES_3 = b'3dc79f5212e8170acfa9ec95f1d74916542be7b1'
MISC_BYTES_4 = b'\x02\x0c'
MISC_BYTES_5 = b'\x60\xa2'


# --- 数据结构与自定义异常 ---

@dataclass
class Config:
    """用于存储所有用户配置信息的数据类。"""
    server: str = '10.100.61.3'
    username: str = ''
    password: str = ''
    host_ip: str = '192.168.1.100'
    mac_address: str = '112233AABBCC'
    host_name: str = 'My-Computer'
    remember: bool = True
    autologin: bool = False

class DrcomError(Exception):
    """Dr.COM 客户端所有自定义错误的基类。"""
    pass

class ChallengeError(DrcomError):
    """当获取 Challenge (盐值) 失败时抛出此异常。"""
    pass

class LoginError(DrcomError):
    """当登录认证失败时抛出此异常。"""
    pass


# --- Dr.COM 核心网络逻辑 ---

class DrcomClient:
    """封装了 Dr.COM 认证协议的核心网络通信逻辑。"""

    def __init__(self, config: Config):
        # 从配置对象初始化客户端参数
        self.config = config
        self.username_bytes = self.config.username.encode('utf-8')
        self.password_bytes = self.config.password.encode('utf-8')
        self.hostname_bytes = self.config.host_name.encode('utf-8')
        self.mac_address_int = int(self.config.mac_address, 16)

        # 初始化 UDP Socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(5)
        self.server_address = (self.config.server, AUTH_PORT)
        
        # 状态变量，用于存储会话信息
        self.salt: bytes = b''
        self.package_tail: bytes = b''
        
        # 用于优雅地停止线程的事件标志
        self._stop_event = threading.Event()

    def stop(self):
        """设置停止事件标志，并关闭 socket，用于从外部安全地终止客户端循环。"""
        self._stop_event.set()
        self.sock.close()
        logging.info("客户端停止指令已发送。")

    def run_forever(self):
        """
        启动客户端的主循环。
        该循环会持续尝试登录，登录成功后则进入心跳维持阶段，并在连接断开或出错后自动重连。
        """
        logging.info(f"认证服务器: {self.config.server}, 用户名: {self.config.username}")

        if self.sock.fileno() == -1:
            logging.error("Socket 已被关闭，无法继续执行。")
            return

        while not self._stop_event.is_set():
            try:
                logging.info("开始登录流程...")
                self._login()
                logging.info("登录成功，开始维持心跳...")
                self._keep_alive_loop()
            except (LoginError, ChallengeError) as e:
                logging.error(f"认证失败: {e}，3秒后重试...")
                self._stop_event.wait(3)
            except socket.timeout:
                if not self._stop_event.is_set():
                    logging.warning("网络连接超时，将重新开始登录流程...")
            except Exception as e:
                if not self._stop_event.is_set():
                    logging.error(f"发生未知错误: {e}")
                break
        logging.info("客户端主循环已退出。")

    def _login(self):
        """执行完整的登录认证流程：获取 Challenge -> 构建并发送登录包 -> 处理响应。"""
        self.salt = self._get_challenge()
        logging.info(f"成功获取到 Salt: {self.salt.hex()}")

        login_packet = self._build_login_packet()
        logging.debug(f"[Login] 发送: {login_packet.hex()}")
        self.sock.sendto(login_packet, self.server_address)
        
        response, _ = self.sock.recvfrom(1024)
        logging.debug(f"[Login] 接收: {response.hex()}")

        if response[0] != 0x04:
            raise LoginError(f"服务器返回了非预期的响应码 {response[0]}")
        
        # 保存登录成功后返回的尾部数据，用于后续心跳包
        self.package_tail = response[23:39]

    def _get_challenge(self) -> bytes:
        """向服务器发送 Challenge 请求，以获取用于加密密码的 salt (盐值)。"""
        while not self._stop_event.is_set():
            # 构造 Challenge 请求包
            random_val = int(time.time()) + random.randint(0x0F, 0xFF)
            packet = PACKET_PREFIX_CHALLENGE + struct.pack("<H", random_val % 0xFFFF) + b"\x09\x00" * 8
            
            try:
                logging.debug(f"[Challenge] 发送: {packet.hex()}")
                self.sock.sendto(packet, self.server_address)
                response, addr = self.sock.recvfrom(1024)
                logging.debug(f"[Challenge] 接收: {response.hex()}")

                # 验证响应的合法性
                if addr == self.server_address and response[0] == 0x02:
                    return response[4:8] # 返回盐值
            except socket.timeout:
                logging.warning("[Challenge] 请求超时，正在重试...")
                continue
        
        raise ChallengeError("客户端在获取 Challenge 期间被停止。")

    def _keep_alive_loop(self):
        """登录成功后，循环发送心跳包以维持在线状态，直到客户端被停止。"""
        # 发送一个初始心跳包
        self._perform_initial_keep_alive()
        self._empty_socket_buffer()
        
        svr_num, tail = 0, b''
        
        # 心跳协议需要一个三次握手的过程
        for i in range(3):
            packet_type = 3 if i == 2 else 1
            is_first = (i == 0)
            current_tail = tail if i > 0 else b'\x00' * 4
            
            packet = self._build_keep_alive_packet(svr_num, current_tail, packet_type, is_first)
            logging.debug(f"[KeepAlive-Handshake-{i+1}] 发送: {packet.hex()}")
            self.sock.sendto(packet, self.server_address)
            
            response, _ = self.sock.recvfrom(1024)
            logging.debug(f"[KeepAlive-Handshake-{i+1}] 接收: {response.hex()}")
            tail = response[16:20] # 更新尾部数据
            svr_num += 1

        logging.info("心跳握手完成，进入稳定维持阶段。")
        i = svr_num
        while not self._stop_event.is_set():
            # 稳定阶段，每20秒交替发送两种类型的心跳包
            packet1 = self._build_keep_alive_packet(i, tail, 1)
            logging.debug(f"[KeepAlive-Loop] 发送 ({i}): {packet1.hex()}")
            self.sock.sendto(packet1, self.server_address)
            response1, _ = self.sock.recvfrom(1024)
            logging.debug(f"[KeepAlive-Loop] 接收: {response1.hex()}")
            tail = response1[16:20]
            
            packet2 = self._build_keep_alive_packet(i + 1, tail, 3)
            logging.debug(f"[KeepAlive-Loop] 发送 ({i+1}): {packet2.hex()}")
            self.sock.sendto(packet2, self.server_address)
            response2, _ = self.sock.recvfrom(1024)
            logging.debug(f"[KeepAlive-Loop] 接收: {response2.hex()}")
            tail = response2[16:20]
            
            i = (i + 2) % 0xFF
            
            # 使用可中断的等待，确保能及时响应停止事件
            self._stop_event.wait(20)

    # --- 协议数据包构建与辅助函数 ---
    
    def _perform_initial_keep_alive(self):
        """
        发送登录成功后的第一个特殊心跳包。
        此函数现在只负责发送和接收，构建逻辑已移至 _build_initial_keep_alive_packet。
        """
        packet = self._build_initial_keep_alive_packet()
        logging.debug(f"[KeepAlive-Initial] 发送: {packet.hex()}")
        self.sock.sendto(packet, self.server_address)
        
        response, _ = self.sock.recvfrom(1024)
        logging.debug(f"[KeepAlive-Initial] 接收: {response.hex()}")

    def _build_initial_keep_alive_packet(self) -> bytes:
        """构建登录成功后的第一个特殊心跳包。"""
        # 1. 计算 MD5
        md5_content = MD5_SALT_PREFIX_1 + self.salt + self.password_bytes
        md5_hash = self.md5sum(md5_content)
        
        # 2. 获取当前时间戳的低16位
        timestamp = struct.pack('!H', int(time.time()) % 0xFFFF)
        
        # 3. 组装数据包
        packet_parts = [
            PACKET_PREFIX_INITIAL_KEEPALIVE, # 包头 (0xff)
            md5_hash,                        # MD5 值
            b'\x00\x00\x00',                 # 3字节分隔符
            self.package_tail,               # 登录成功后服务器返回的尾部数据
            timestamp,                       # 时间戳
            b'\x00\x00\x00\x00'              # 4字节空值
        ]
        
        return b''.join(packet_parts)

    def _build_login_packet(self) -> bytes:
        """
        构建包含所有认证信息的登录请求包。
        此版本将一行代码分解为多个逻辑块，以提高可读性。
        """
        # --- 步骤 1: 计算所有需要的 MD5 哈希值 ---
        # MD5 #1: 用于主认证和MAC地址异或
        md5_pass_salt = self.md5sum(MD5_SALT_PREFIX_1 + self.salt + self.password_bytes)
        
        # MD5 #2: 用于次要认证
        md5_pass_salt_alt = self.md5sum(MD5_SALT_PREFIX_2 + self.password_bytes + self.salt + b'\x00' * 4)
        
        # --- 步骤 2: 构建数据包主体（校验和之前的部分） ---
        packet_parts = []
        
        # 包头和长度
        packet_parts.append(PACKET_PREFIX_LOGIN)
        packet_parts.append((len(self.username_bytes) + 20).to_bytes(1, 'big'))
        
        # 认证信息
        packet_parts.append(md5_pass_salt)
        packet_parts.append(self.username_bytes.ljust(36, b'\x00'))
        
        # 控制与适配器信息
        packet_parts.append(CONTROL_CHECK_STATUS)
        packet_parts.append(ADAPTER_NUM)
        
        # MAC 地址与 MD5 的异或结果
        mac_xor_md5_val = int(md5_pass_salt[:6].hex(), 16) ^ self.mac_address_int
        packet_parts.append(self.dump_hex(mac_xor_md5_val).rjust(6, b'\x00'))
        
        # 第二个 MD5 和 IP 地址
        packet_parts.append(md5_pass_salt_alt)
        packet_parts.append(b'\x01')
        packet_parts.append(socket.inet_aton(self.config.host_ip))
        packet_parts.append(b'\x00' * 12)
        
        # --- 步骤 3: 计算包中部的 MD5 校验和 ---
        pre_checksum_packet = b''.join(packet_parts)
        md5_checksum_content = pre_checksum_packet + CHECKSUM_MAGIC_1
        md5_checksum = self.md5sum(md5_checksum_content)[:8] # 只取前8字节
        packet_parts.append(md5_checksum)

        # --- 步骤 4: 构建数据包剩余部分（最终校验和之前） ---
        packet_parts.append(IP_DOG)
        packet_parts.append(b'\x00' * 4)
        packet_parts.append(self.hostname_bytes.ljust(32, b'\x00'))
        packet_parts.append(socket.inet_aton('10.10.10.10')) # 可能是 DNS 或其他信息
        packet_parts.append(socket.inet_aton('0.0.0.0'))   # 子网掩码
        packet_parts.append(b'\x00' * 28)
        
        # 一些固定的、意义不明的字节
        packet_parts.append(MISC_BYTES_1)
        packet_parts.append(MISC_BYTES_2)
        packet_parts.append(b'\x00' * 55)
        packet_parts.append(MISC_BYTES_3)
        packet_parts.append(b'\x00' * 24)
        
        # 认证版本、密码长度和加密后的密码
        packet_parts.append(AUTH_VERSION)
        packet_parts.append(b'\x00')
        packet_parts.append(len(self.password_bytes).to_bytes(1, 'big'))
        packet_parts.append(self.ror(md5_pass_salt, self.password_bytes))
        packet_parts.append(MISC_BYTES_4)

        # --- 步骤 5: 计算最终的 4 字节校验和 ---
        pre_final_checksum_packet = b''.join(packet_parts)
        final_checksum_content = pre_final_checksum_packet + CHECKSUM_MAGIC_2 + self.dump_hex(self.mac_address_int)
        final_checksum = self.checksum(final_checksum_content)
        packet_parts.append(final_checksum)

        # --- 步骤 6: 组装数据包的最后部分 ---
        packet_parts.append(b'\x00\x00')
        packet_parts.append(self.dump_hex(self.mac_address_int))
        
        # 最后的动态填充和固定尾部
        if (len(self.password_bytes) // 4) != 4:
            packet_parts.append(b'\x00' * (len(self.password_bytes) // 4))
        
        packet_parts.append(MISC_BYTES_5)
        packet_parts.append(b'\x00' * 28)

        return b''.join(packet_parts)

    def _build_keep_alive_packet(self, number: int, tail: bytes, packet_type: int, first: bool = False) -> bytes:
        """
        构建心跳维持包。
        此版本将逻辑拆分，使其更易于理解。
        """
        packet_parts = []

        # 1. 包头和类型
        packet_parts.append(PACKET_PREFIX_KEEPALIVE)         # 0x07
        packet_parts.append(number.to_bytes(1, 'big'))
        packet_parts.append(b'\x28\x00\x0b')
        packet_parts.append(packet_type.to_bytes(1, 'big'))
        
        # 2. 版本号 (首次握手时为特殊值)
        version = b'\x0f\x27' if first else KEEP_ALIVE_VERSION
        packet_parts.append(version)
        
        # 3. 固定字节和尾部数据
        packet_parts.append(b'\x2f\x12' + b'\x00' * 6)
        packet_parts.append(tail)
        packet_parts.append(b'\x00' * 4)
        
        # 4. 主体内容 (根据包类型不同)
        if packet_type == 3:
            # 类型3的包包含本机IP地址
            payload = b'\x00' * 4 + socket.inet_aton(self.config.host_ip) + b'\x00' * 8
        else:
            # 其他类型的包为空
            payload = b'\x00' * 16
        packet_parts.append(payload)

        return b''.join(packet_parts)

    def _empty_socket_buffer(self):
        """清空 socket 接收缓冲区，防止旧数据干扰后续通信。"""
        try: self.sock.setblocking(False)
        except Exception: pass
        try:
            while True: self.sock.recv(1024)
        except (BlockingIOError, socket.error): pass
        finally:
            try: self.sock.setblocking(True)
            except Exception: pass

    @staticmethod
    def md5sum(d: bytes) -> bytes:
        """计算字节串的 MD5 摘要。"""
        return md5(d).digest()

    @staticmethod
    def dump_hex(n: int) -> bytes:
        """将整数转换为十六进制字节串。"""
        s = f'{n:x}'; s = '0'+s if len(s)%2 else s; return bytes.fromhex(s)

    @staticmethod
    def ror(md5_h: bytes, pwd: bytes) -> bytes:
        """实现一种特定的循环右移加密算法。"""
        r = bytearray(); [r.append(((x<<3)&0xFF)+(x>>5)) for x in [h^p for h,p in zip(md5_h,pwd)]]; return bytes(r)

    @staticmethod
    def checksum(data: bytes) -> bytes:
        """计算数据包的校验和。"""
        ret = 1234; data += b'\x00' * ((4 - len(data) % 4) % 4);
        for i in range(0, len(data), 4): ret ^= struct.unpack('<I', data[i:i+4])[0]
        return struct.pack('<I', (1968 * ret) & 0xFFFFFFFF)

# --- GUI 图形用户界面 ---

class QueueHandler(logging.Handler):
    """自定义日志处理器，将日志记录写入队列，以供GUI线程安全地读取和显示。"""
    def __init__(self, log_queue: queue.Queue):
        super().__init__()
        self.log_queue = log_queue
    def emit(self, record):
        self.log_queue.put(self.format(record))

class DrcomApp:
    """Dr.COM 客户端的图形用户界面(GUI)主程序类。"""

    def __init__(self, master: tk.Tk):
        self.master = master
        self.master.title("Dr.COM 客户端")
        self.master.geometry("550x580")

        # 初始化状态变量和客户端实例
        self.client_thread: threading.Thread = None
        self.drcom_client: DrcomClient = None
        self.tray_icon: pystray.Icon = None

        # 构建UI界面
        self._setup_styles()
        main_frame = ttk.Frame(master, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        self.entries, self.check_vars, self.checkboxes = {}, {}, {}
        self._create_config_widgets(main_frame)
        self._create_button_widgets(main_frame)
        self._create_log_widgets(main_frame)

        # 初始化日志系统并绑定窗口事件
        self._setup_logging()
        self._bind_events()

        # 加载保存的配置
        self._load_config()
        # 启动日志队列轮询
        self.master.after(100, self.poll_log_queue)
        # 如果设置了自动登录，则在程序启动后自动开始连接
        if self.check_vars["自动登录"].get():
            self.master.after(200, self.start_client)

    # --- UI 界面构建方法 ---
    def _setup_styles(self):
        """配置 ttk 组件的样式。"""
        style = ttk.Style()
        style.theme_use('clam')

    def _create_config_widgets(self, parent):
        """创建所有配置相关的UI组件，如输入框和标签。"""
        config_frame = ttk.LabelFrame(parent, text="认证配置", padding="10")
        config_frame.pack(fill=tk.X, pady=(0, 5))
        
        fields = {"服务器IP": "", "用户名": "", "密码": "", "本机IP": "", "MAC地址": "", "主机名": ""}
        for i, text in enumerate(fields):
            label = ttk.Label(config_frame, text=text + ":")
            label.grid(row=i, column=0, sticky=tk.W, padx=5, pady=3)
            entry = ttk.Entry(config_frame, width=30)
            entry.grid(row=i, column=1, sticky=tk.EW, padx=5, pady=3)
            if text == "密码": entry.config(show="*")
            self.entries[text] = entry
        
        config_frame.columnconfigure(1, weight=1)

        # 创建“选项”部分的复选框
        options_frame = ttk.LabelFrame(parent, text="选项", padding="10")
        options_frame.pack(fill=tk.X, pady=5)
        
        check_texts = ["记住配置", "自动登录", "显示详细网络日志"]
        if platform.system() == "Windows":
            check_texts.append("开机启动")
            
        for text in check_texts:
            var = tk.BooleanVar()
            chk = ttk.Checkbutton(options_frame, text=text, variable=var)
            chk.pack(side=tk.LEFT, padx=10, pady=2)
            self.check_vars[text] = var
            self.checkboxes[text] = chk

        self.checkboxes["显示详细网络日志"].config(command=self._toggle_detailed_logs)
        if "开机启动" in self.checkboxes:
            self.checkboxes["开机启动"].config(command=self._toggle_startup)

    def _create_button_widgets(self, parent):
        """创建“连接”和“断开连接”按钮。"""
        button_frame = ttk.Frame(parent, padding="5")
        button_frame.pack(fill=tk.X, pady=5)
        self.connect_button = ttk.Button(button_frame, text="连接", command=self.start_client)
        self.connect_button.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        self.disconnect_button = ttk.Button(button_frame, text="断开连接", command=self.stop_client, state=tk.DISABLED)
        self.disconnect_button.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)

    def _create_log_widgets(self, parent):
        """创建用于显示日志的文本框。"""
        log_frame = ttk.LabelFrame(parent, text="日志", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        self.log_display = ScrolledText(log_frame, state='disabled', wrap=tk.WORD, height=10)
        self.log_display.pack(fill=tk.BOTH, expand=True)

    # --- 核心逻辑与事件处理 ---
    def _bind_events(self):
        """绑定窗口关闭事件，使其最小化到系统托盘而不是直接退出。"""
        self.master.protocol("WM_DELETE_WINDOW", self.hide_window)

    def start_client(self):
        """
        “连接”按钮的响应函数。
        负责检查端口占用、读取UI配置、启动认证客户端线程。
        """
        if not self._check_and_free_port():
            return
        
        try:
            config = Config(
                server=self.entries["服务器IP"].get(),
                username=self.entries["用户名"].get(),
                password=self.entries["密码"].get(),
                host_ip=self.entries["本机IP"].get(),
                mac_address=self.entries["MAC地址"].get(),
                host_name=self.entries["主机名"].get()
            )
            # 简单验证MAC地址格式
            int(config.mac_address, 16)
        except ValueError:
            messagebox.showerror("配置错误", "MAC地址格式不正确，应为12位十六进制字符（例如 112233AABBCC）。")
            return
        
        if not config.username or not config.password:
            messagebox.showerror("配置错误", "用户名和密码不能为空。")
            return

        # 如果用户勾选了“记住配置”，则保存当前配置
        if self.check_vars["记住配置"].get():
            self._save_config()

        self.toggle_controls(is_running=True)
        self.drcom_client = DrcomClient(config)
        
        try:
            # 绑定本地端口，这是Dr.COM协议要求的
            self.drcom_client.sock.bind(('0.0.0.0', AUTH_PORT))
        except OSError as e:
            messagebox.showerror("绑定错误", f"无法绑定到端口 {AUTH_PORT}，请检查端口是否被占用。\n错误: {e}")
            self.toggle_controls(is_running=False)
            return

        self.client_thread = threading.Thread(target=self.drcom_client.run_forever, daemon=True)
        self.client_thread.start()

    def stop_client(self):
        """“断开连接”按钮的响应函数。负责停止认证客户端线程并更新UI状态。"""
        if self.drcom_client:
            self.drcom_client.stop()
            self.drcom_client = None
            self.client_thread = None
        self.toggle_controls(is_running=False)

    def toggle_controls(self, is_running: bool):
        """根据客户端的运行状态，启用或禁用界面上的控件，防止用户误操作。"""
        state = tk.DISABLED if is_running else tk.NORMAL
        
        for entry in self.entries.values():
            entry.config(state=state)
        # “记住配置”和“自动登录”在连接时不可更改
        for key in ["记住配置", "自动登录"]:
            if key in self.checkboxes:
                self.checkboxes[key].config(state=state)
            
        self.connect_button.config(state=tk.DISABLED if is_running else tk.NORMAL)
        self.disconnect_button.config(state=tk.NORMAL if is_running else tk.DISABLED)
        
        # 日志级别和开机启动选项允许在任何时候切换
        self.checkboxes["显示详细网络日志"].config(state=tk.NORMAL)
        if "开机启动" in self.checkboxes:
            self.checkboxes["开机启动"].config(state=tk.NORMAL)

    # --- 系统托盘相关方法 ---
    def hide_window(self):
        """隐藏主窗口并在系统托盘创建图标。"""
        self.master.withdraw()
        if not self.tray_icon or not self.tray_icon.visible:
            # 在后台线程中运行托盘图标，避免阻塞GUI主线程
            threading.Thread(target=self.run_tray_icon, daemon=True).start()

    def show_window(self, icon=None, item=None):
        """从系统托盘恢复并显示主窗口。"""
        if self.tray_icon:
            self.tray_icon.stop()
        self.master.after(0, self.master.deiconify)

    def run_tray_icon(self):
        """创建并运行系统托盘图标及其菜单。"""
        try:
            image = Image.open(ICON_FILE_PATH)
        except FileNotFoundError:
            logging.error(f"系统托盘图标文件 '{ICON_FILE_PATH}' 未找到！")
            messagebox.showwarning("资源缺失", f"图标文件 'icon.png' 未找到，无法创建托盘图标。")
            self.show_window() # 无法创建图标时，直接显示主窗口
            return

        menu = (pystray.MenuItem('显示', self.show_window, default=True),
                pystray.MenuItem('退出', self.exit_app))
        
        self.tray_icon = pystray.Icon("Dr.COM客户端", image, "Dr.COM 客户端", menu)
        self.tray_icon.run()
        self.tray_icon = None # 托盘图标退出后，重置变量

    # --- 程序退出与资源清理 ---
    def exit_app(self, icon=None, item=None):
        """响应托盘菜单的“退出”命令。"""
        self.on_closing()

    def on_closing(self):
        """
        处理程序关闭事件，负责保存配置、停止后台线程和销毁窗口，确保程序干净地退出。
        """
        if self.check_vars.get("记住配置") and self.check_vars["记住配置"].get():
            self._save_config()
        if self.client_thread and self.client_thread.is_alive():
            self.stop_client()
        if self.tray_icon:
            self.tray_icon.stop()
        self.master.destroy()

    # --- 日志与配置文件读写 ---
    def _setup_logging(self):
        """配置日志系统，将日志信息重定向到队列中，以便GUI安全地显示。"""
        self.log_queue = queue.Queue()
        self.queue_handler = QueueHandler(self.log_queue)
        formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s', datefmt='%H:%M:%S')
        self.queue_handler.setFormatter(formatter)
        
        root_logger = logging.getLogger()
        root_logger.addHandler(self.queue_handler)
        root_logger.setLevel(logging.INFO) # 默认日志级别

    def poll_log_queue(self):
        """定时从日志队列中获取消息，并将其显示在GUI的日志文本框中。"""
        while True:
            try:
                record = self.log_queue.get(block=False)
                self.log_display.config(state='normal')
                self.log_display.insert(tk.END, record + '\n')
                self.log_display.see(tk.END) # 自动滚动到最新日志
                self.log_display.config(state='disabled')
            except queue.Empty:
                break
        self.master.after(100, self.poll_log_queue) # 每100毫秒检查一次
    
    def _load_config(self):
        """从 JSON 配置文件加载用户设置到UI界面。"""
        try:
            with open(CONFIG_FILE_PATH, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            self.entries["服务器IP"].insert(0, data.get("server", ""))
            self.entries["用户名"].insert(0, data.get("username", ""))
            self.entries["密码"].insert(0, data.get("password", ""))
            self.entries["本机IP"].insert(0, data.get("host_ip", ""))
            self.entries["MAC地址"].insert(0, data.get("mac_address", ""))
            self.entries["主机名"].insert(0, data.get("host_name", ""))
            
            self.check_vars["记住配置"].set(data.get("remember", True))
            self.check_vars["自动登录"].set(data.get("autologin", False))

            if "开机启动" in self.check_vars:
                # 开机启动状态应从注册表实时读取，而不是依赖配置文件
                self.check_vars["开机启动"].set(self._is_startup_enabled())

            logging.info(f"已从 '{CONFIG_FILE_PATH}' 加载配置。")
        except (FileNotFoundError, json.JSONDecodeError):
            self.check_vars["记住配置"].set(True) # 默认记住配置
            if "开机启动" in self.check_vars:
                self.check_vars["开机启动"].set(self._is_startup_enabled())
            logging.info("未找到有效的配置文件，将使用默认设置。")
    
    def _save_config(self):
        """将UI界面上的用户配置保存到 JSON 文件。"""
        config_data = {
            "server": self.entries["服务器IP"].get(),
            "username": self.entries["用户名"].get(),
            "password": self.entries["密码"].get(),
            "host_ip": self.entries["本机IP"].get(),
            "mac_address": self.entries["MAC地址"].get(),
            "host_name": self.entries["主机名"].get(),
            "remember": self.check_vars["记住配置"].get(),
            "autologin": self.check_vars["自动登录"].get(),
        }
        try:
            with open(CONFIG_FILE_PATH, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=4)
            logging.info(f"配置已保存至 '{CONFIG_FILE_PATH}'。")
        except IOError as e:
            logging.error(f"无法写入配置文件: {e}")

    # --- 开机自启动相关方法 (Windows 平台专属) ---
    def _toggle_startup(self):
        """响应“开机启动”复选框的点击事件，添加或移除注册表项。"""
        if platform.system() != "Windows": return
            
        if self.check_vars["开机启动"].get():
            self._add_to_startup()
        else:
            self._remove_from_startup()

    def _get_startup_reg_info(self):
        """获取设置开机自启所需的注册表信息（路径、键名、键值）。"""
        app_name = "DrcomClientGUI"
        # 使用 pythonw.exe 可以在后台静默运行，不弹出命令行窗口
        pythonw_path = sys.executable.replace("python.exe", "pythonw.exe")
        script_path = os.path.abspath(__file__)
        
        # 为路径添加引号，以处理路径中可能存在的空格
        command = f'"{pythonw_path}" "{script_path}"'
        
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        return winreg.HKEY_CURRENT_USER, key_path, app_name, command
        
    def _is_startup_enabled(self) -> bool:
        """检查注册表中是否已存在本应用的自启动项。"""
        if platform.system() != "Windows": return False
            
        hkey, key_path, app_name, _ = self._get_startup_reg_info()
        try:
            with winreg.OpenKey(hkey, key_path, 0, winreg.KEY_READ) as key:
                winreg.QueryValueEx(key, app_name)
            return True # 如果能查询到值，说明已存在
        except FileNotFoundError:
            return False # 查询不到，说明不存在

    def _add_to_startup(self):
        """将本应用添加到 Windows 注册表的开机自启动项中。"""
        hkey, key_path, app_name, command = self._get_startup_reg_info()
        try:
            with winreg.OpenKey(hkey, key_path, 0, winreg.KEY_WRITE) as key:
                winreg.SetValueEx(key, app_name, 0, winreg.REG_SZ, command)
            logging.info("已成功添加到开机启动项。")
        except Exception as e:
            logging.error(f"添加到开机启动失败: {e}")
            messagebox.showerror("错误", f"添加到开机启动失败: {e}\n\n请尝试使用管理员权限运行本程序。")
            self.check_vars["开机启动"].set(False) # 操作失败后，将复选框恢复原状

    def _remove_from_startup(self):
        """从 Windows 注册表的开机自启动项中移除本应用。"""
        hkey, key_path, app_name, _ = self._get_startup_reg_info()
        try:
            with winreg.OpenKey(hkey, key_path, 0, winreg.KEY_WRITE) as key:
                winreg.DeleteValue(key, app_name)
            logging.info("已从开机启动项中移除。")
        except FileNotFoundError:
            logging.info("启动项不存在，无需移除。")
        except Exception as e:
            logging.error(f"从开机启动移除失败: {e}")
            messagebox.showerror("错误", f"从开机启动移除失败: {e}\n\n请尝试使用管理员权限运行本程序。")
            self.check_vars["开机启动"].set(True) # 操作失败后，将复选框恢复原状

    # --- 其他辅助方法 ---
    def _toggle_detailed_logs(self):
        """根据复选框状态，切换日志记录级别（INFO 或 DEBUG）。"""
        level = logging.DEBUG if self.check_vars["显示详细网络日志"].get() else logging.INFO
        logging.getLogger().setLevel(level)
        logging.info(f"日志级别已切换为 {'DEBUG' if level == logging.DEBUG else 'INFO'}")

    def _check_and_free_port(self) -> bool:
        """
        使用 psutil 检查认证所需的端口是否被占用。
        如果被占用，则弹窗询问用户是否需要终止占用进程。
        """
        for conn in psutil.net_connections(kind='udp'):
            if conn.laddr and conn.laddr.port == AUTH_PORT:
                try:
                    proc = psutil.Process(conn.pid)
                    msg = (f"端口 {AUTH_PORT} 已被进程 '{proc.name()}' (PID: {proc.pid}) 占用。\n\n"
                           f"是否需要强制终止该进程以继续认证？")
                    if messagebox.askyesno("端口冲突", msg):
                        proc.kill()
                        proc.wait(timeout=1) # 等待进程终止
                        logging.info(f"已终止进程 {proc.name()} (PID: {proc.pid})。")
                        return True
                    else:
                        logging.warning("用户取消了终止进程的操作，连接中止。")
                        return False
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    messagebox.showerror("错误", f"无法终止占用端口的进程: {e}")
                    return False
        return True # 端口未被占用


def main():
    """程序主入口函数，负责创建 Tkinter 根窗口和应用实例。"""
    root = tk.Tk()
    # 尝试让窗口居中显示
    root.eval('tk::PlaceWindow . center')
    app = DrcomApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()