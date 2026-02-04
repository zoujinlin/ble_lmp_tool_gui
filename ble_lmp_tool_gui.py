#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BLE设备LMP版本读取工具 - GUI版本（简化版，已移除内置 btmon 窗口）
跨平台支持：Windows 和 Linux (Ubuntu)
功能：扫描、连接BLE设备并读取LMP版本信息
"""

import asyncio
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
from typing import Optional, List, Dict
import platform
import sys
import re
import subprocess
import time
import os
import shutil

# 尝试导入 bleak 库
try:
    from bleak import BleakScanner, BleakClient
    from bleak.backends.device import BLEDevice
except ImportError:
    print("错误: 需要安装 bleak 库")
    print("安装命令: pip install bleak")
    sys.exit(1)


class BLELMPToolGUI:
    """BLE LMP 版本读取工具 GUI 类"""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("BLE设备LMP版本读取工具")
        self.root.geometry("850x620")

        # 数据存储
        self.devices: List[BLEDevice] = []
        self.filtered_devices: List[BLEDevice] = []
        self.device_rssi: Dict[str, int] = {}
        self.selected_device: Optional[BLEDevice] = None
        self.is_scanning = False
        self.client: Optional[BleakClient] = None
        self.btmon_process: Optional[subprocess.Popen] = None
        self.sudo_password: Optional[str] = None
        self.btmon_lmp_info: Optional[Dict[str, str]] = None

        # asyncio 事件循环
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.loop_thread: Optional[threading.Thread] = None

        # 创建UI
        self.create_widgets()

        # 启动btmon捕获（Linux），将输出集成到日志窗口
        if platform.system() == 'Linux':
            self.root.after(200, self.start_btmon_capture)

        # 启动事件循环
        self.start_event_loop()

    # ------------------------- 基础工具 -------------------------
    def start_event_loop(self):
        """在后台线程中启动 asyncio 事件循环"""

        def run_loop():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.loop.run_forever()

        self.loop_thread = threading.Thread(target=run_loop, daemon=True)
        self.loop_thread.start()
        time.sleep(0.1)

    def create_widgets(self):
        """创建GUI组件"""
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)

        # 标题
        title_label = ttk.Label(main_frame, text="BLE设备LMP版本读取工具", font=('Arial', 10, 'bold'))
        title_label.grid(row=0, column=0, pady=5)

        # 控制面板
        control_frame = ttk.LabelFrame(main_frame, text="控制面板", padding="5")
        control_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=3)
        control_frame.columnconfigure(1, weight=1)

        ttk.Label(control_frame, text="设备名称:", font=('Arial', 8)).grid(row=0, column=0, sticky=tk.W, pady=2)
        self.filter_var = tk.StringVar()
        self.filter_entry = ttk.Entry(control_frame, textvariable=self.filter_var, width=30, font=('Arial', 8))
        self.filter_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=3, pady=2)
        self.filter_var.trace('w', self.on_filter_changed)
        ttk.Button(control_frame, text="清除", command=self.clear_filter, width=8).grid(row=0, column=2, padx=3, pady=2)

        ttk.Label(control_frame, text="扫描时间:", font=('Arial', 8)).grid(row=1, column=0, sticky=tk.W, pady=2)
        self.scan_time_var = tk.IntVar(value=5)
        scan_time_spinbox = ttk.Spinbox(control_frame, from_=5, to=30, textvariable=self.scan_time_var, width=8, font=('Arial', 8))
        scan_time_spinbox.grid(row=1, column=1, sticky=tk.W, padx=3, pady=2)

        self.scan_button = ttk.Button(control_frame, text="扫描", command=self.start_scan, width=8)
        self.scan_button.grid(row=1, column=2, padx=3, pady=2)

        # 设备列表
        device_frame = ttk.LabelFrame(main_frame, text="设备列表", padding="5")
        device_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=3)
        device_frame.columnconfigure(0, weight=1)
        device_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)

        style = ttk.Style()
        style.configure('Small.Treeview', rowheight=18, font=('Arial', 8))
        style.configure('Small.Treeview.Heading', font=('Arial', 8, 'bold'))

        columns = ('name', 'address', 'rssi')
        self.device_tree = ttk.Treeview(device_frame, columns=columns, show='tree headings', height=5, style='Small.Treeview')
        self.device_tree.heading('#0', text='#')
        self.device_tree.heading('name', text='设备名称')
        self.device_tree.heading('address', text='MAC地址')
        self.device_tree.heading('rssi', text='RSSI')
        self.device_tree.column('#0', width=40)
        self.device_tree.column('name', width=200)
        self.device_tree.column('address', width=150)
        self.device_tree.column('rssi', width=80)

        scrollbar = ttk.Scrollbar(device_frame, orient=tk.VERTICAL, command=self.device_tree.yview)
        self.device_tree.configure(yscrollcommand=scrollbar.set)
        self.device_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.device_tree.bind('<<TreeviewSelect>>', self.on_device_selected)

        # 操作按钮
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, pady=3)
        self.connect_button = ttk.Button(button_frame, text="连接", command=self.connect_device, state=tk.DISABLED, width=10)
        self.connect_button.grid(row=0, column=0, padx=3)
        self.read_lmp_button = ttk.Button(button_frame, text="读LMP", command=self.read_lmp_version, state=tk.DISABLED, width=10)
        self.read_lmp_button.grid(row=0, column=1, padx=3)
        self.disconnect_button = ttk.Button(button_frame, text="断开", command=self.disconnect_device, state=tk.DISABLED, width=10)
        self.disconnect_button.grid(row=0, column=2, padx=3)

        # 日志
        log_frame = ttk.LabelFrame(main_frame, text="操作日志", padding="5")
        log_frame.grid(row=4, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=3)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(4, weight=3)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=20, wrap=tk.WORD, state=tk.DISABLED, font=('Consolas', 9))
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.log_text.tag_config('info', foreground='blue')
        self.log_text.tag_config('success', foreground='green')
        self.log_text.tag_config('error', foreground='red')
        self.log_text.tag_config('warning', foreground='orange')
        self.log_text.tag_config('btmon', foreground='#008800')

        log_btn_frame = ttk.Frame(log_frame)
        log_btn_frame.grid(row=1, column=0, sticky=tk.E, pady=3)
        ttk.Button(log_btn_frame, text="保存日志", width=10, command=self.save_log_to_file).grid(row=0, column=0, padx=2)

        # 状态栏
        self.status_var = tk.StringVar(value="就绪")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, font=('Arial', 8))
        status_bar.grid(row=5, column=0, sticky=(tk.W, tk.E), pady=2)

        # 初始化日志
        self.log_message(f"系统: {platform.system()} {platform.release()}", 'info')
        self.log_message("准备就绪，请点击'扫描'按钮扫描BLE设备", 'info')

    # ------------------------- btmon 终端 -------------------------
    def start_btmon_capture(self):
        """以 sudo 启动 btmon 并将输出写入日志窗口"""
        if platform.system() != 'Linux':
            return

        if self.btmon_process and self.btmon_process.poll() is None:
            return

        password = None
        try:
            test = subprocess.run(['sudo', '-n', 'true'], capture_output=True, text=True)
            if test.returncode != 0:
                password = self._ask_password()
                if not password:
                    self.log_message("已取消输入 sudo 密码，未启动 btmon", 'warning')
                    return
        except FileNotFoundError:
            self.log_message("未找到 sudo，无法自动启动 btmon，请手动运行: sudo btmon -t", 'warning')
            return

        try:
            base_cmd = ['btmon', '-t']
            # 强制行缓冲，确保通过管道及时输出
            cmd = (['sudo', '-S', 'stdbuf', '-oL', '-eL'] + base_cmd) if password else ['sudo', '-n', 'stdbuf', '-oL', '-eL'] + base_cmd
            if password:
                self.sudo_password = password
            self.btmon_process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE if password else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
            )

            if password and self.btmon_process.stdin:
                try:
                    self.btmon_process.stdin.write(password + "\n")
                    self.btmon_process.stdin.flush()
                except Exception:
                    pass

            threading.Thread(target=self._read_btmon_output, daemon=True).start()
            self.log_message("已启动 btmon 捕获 (sudo)", 'success')
        except Exception as exc:
            self.log_message(f"启动 btmon 失败: {exc}", 'error')

    def _ask_password(self) -> Optional[str]:
        """弹窗获取sudo密码，返回字符串或None"""
        pw_win = tk.Toplevel(self.root)
        pw_win.title("sudo 密码")
        pw_win.geometry("300x140")
        pw_win.grab_set()

        ttk.Label(pw_win, text="请输入sudo密码:").pack(pady=10)
        pwd_var = tk.StringVar()
        entry = ttk.Entry(pw_win, textvariable=pwd_var, show='*', width=28)
        entry.pack(pady=5)
        entry.focus_set()

        result = {'value': None}

        def on_ok():
            result['value'] = pwd_var.get()
            pw_win.destroy()

        def on_cancel():
            pw_win.destroy()

        btn_frame = ttk.Frame(pw_win)
        btn_frame.pack(pady=8)
        ttk.Button(btn_frame, text="确定", command=on_ok, width=8).grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text="取消", command=on_cancel, width=8).grid(row=0, column=1, padx=5)

        pw_win.wait_window()
        return result['value']

    def _read_btmon_output(self):
        """读取 btmon 标准输出并写入日志窗口，解析版本事件"""
        if not self.btmon_process or not self.btmon_process.stdout:
            return
        collecting = False
        tmp: Dict[str, str] = {}
        for line in self.btmon_process.stdout:
            line = line.rstrip('\n')
            if not line:
                continue
            stripped = line.strip()

            # 去重：如果和上一行内容完全相同，跳过，避免重复
            if hasattr(self, '_last_btmon_line') and self._last_btmon_line == stripped:
                continue
            self._last_btmon_line = stripped

            # 事件起点：只要包含 Read Remote Version 即开始收集
            if "Read Remote Version" in stripped:
                collecting = True
                tmp = {'raw': stripped}
            elif collecting:
                tmp['raw'] += " | " + stripped

            if collecting:
                status_match = re.search(r"Status:\s+\w+\s+\(0x([0-9a-fA-F]{2})\)", stripped)
                if status_match:
                    tmp['status'] = status_match.group(1)
                handle_match = re.search(r"Handle:\s*(\d+)", stripped)
                if handle_match:
                    tmp['handle'] = handle_match.group(1)
                ver_match = re.search(r"LMP version:\s*(.+?)\s*\(0x([0-9a-fA-F]+)\).*Subversion\s+([0-9]+)\s*\(0x([0-9a-fA-F]+)\)", stripped)
                if ver_match:
                    tmp['lmp_version_text'] = ver_match.group(1).strip()
                    tmp['lmp_version_raw'] = ver_match.group(2)
                    tmp['lmp_subversion'] = ver_match.group(3)
                    tmp['lmp_subversion_hex'] = ver_match.group(4)
                mfg_match = re.search(r"Manufacturer:\s*(.+?)\s*\((\d+)\)", stripped)
                if mfg_match:
                    tmp['manufacturer'] = mfg_match.group(1).strip()
                    tmp['manufacturer_code'] = mfg_match.group(2)

                # 如果已拿到版本和厂商则收尾
                if tmp.get('lmp_version_raw') and tmp.get('manufacturer_code'):
                    collecting = False
                    self.btmon_lmp_info = tmp.copy()
                    summary = (
                        f"btmon版本: {tmp.get('lmp_version_text', 'N/A')} "
                        f"(0x{tmp.get('lmp_version_raw', '??')}) / 厂商 {tmp.get('manufacturer', 'N/A')}"
                        f"(0x{tmp.get('manufacturer_code', '??')}) / 子版本 0x{tmp.get('lmp_subversion_hex', '??')}"
                    )
                    self.root.after(0, self.log_message, summary, 'btmon')

            self.root.after(0, self.log_message, f"[btmon] {line}", 'btmon')

    def _run_cmd_with_sudo(self, cmd: List[str], timeout: int = 5) -> subprocess.CompletedProcess:
        """在Linux上优先使用 sudo 运行命令，复用已输入的密码"""
        if platform.system() != 'Linux':
            return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        prefix: List[str]
        input_data = None
        if self.sudo_password:
            prefix = ['sudo', '-S']
            input_data = self.sudo_password + "\n"
        else:
            prefix = ['sudo', '-n']
        try:
            return subprocess.run(prefix + cmd, capture_output=True, text=True, timeout=timeout, input=input_data)
        except FileNotFoundError:
            raise
        except Exception as exc:
            return subprocess.CompletedProcess(cmd, returncode=1, stdout='', stderr=str(exc))

    def log_message(self, message: str, level: str = 'info'):
        try:
            max_length = 1000
            if len(message) > max_length:
                message = message[:max_length] + "..."
            self.log_text.configure(state=tk.NORMAL)
            timestamp = __import__('datetime').datetime.now().strftime('%H:%M:%S')
            log_line = f"[{timestamp}] {message}\n"
            self.log_text.insert(tk.END, log_line, level)
            lines = int(self.log_text.index('end-1c').split('.')[0])
            if lines > 2000:
                self.log_text.delete('1.0', '500.0')
            self.log_text.see(tk.END)
            self.log_text.configure(state=tk.DISABLED)
            self.log_text.update_idletasks()
        except Exception as exc:
            print(f"[{level}] {message}")
            print(f"日志写入错误: {exc}")

    def save_log_to_file(self):
        try:
            content = self.log_text.get('1.0', tk.END)
            if not content.strip():
                messagebox.showinfo("提示", "当前日志为空，无需保存")
                return
            default_name = time.strftime("ble_log_%Y%m%d_%H%M%S.txt")
            file_path = filedialog.asksaveasfilename(
                title="保存日志",
                defaultextension=".txt",
                initialfile=default_name,
                filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            )
            if not file_path:
                return
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            self.log_message(f"日志已保存: {file_path}", 'success')
        except Exception as exc:
            self.log_message(f"保存日志失败: {exc}", 'error')
            messagebox.showerror("保存失败", f"保存日志时出错:\n{exc}")

    def update_status(self, status: str):
        self.status_var.set(status)

    # ------------------------- 过滤与列表 -------------------------
    def on_filter_changed(self, *args):
        self.apply_filter()

    def clear_filter(self):
        self.filter_var.set("")

    def apply_filter(self):
        filter_text = self.filter_var.get().lower()
        if not filter_text:
            self.filtered_devices = self.devices.copy()
        else:
            self.filtered_devices = [
                dev for dev in self.devices
                if filter_text in (dev.name or '').lower() or filter_text in dev.address.lower()
            ]
        self.update_device_list()

    def update_device_list(self):
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
        for idx, device in enumerate(self.filtered_devices, 1):
            name = device.name if device.name else "(未知设备)"
            rssi = self.device_rssi.get(device.address, None)
            rssi_str = f"{rssi} dBm" if rssi is not None else "N/A"
            self.device_tree.insert('', tk.END, text=str(idx), values=(name, device.address, rssi_str))
        count = len(self.filtered_devices)
        total = len(self.devices)
        if count != total:
            self.log_message(f"显示 {count}/{total} 个设备（已过滤）", 'info')
        else:
            self.log_message(f"显示 {count} 个设备", 'info')

    # ------------------------- 扫描相关 -------------------------
    def start_scan(self):
        if self.is_scanning:
            self.log_message("正在扫描中，请稍候...", 'warning')
            return
        self.is_scanning = True
        self.scan_button.configure(state=tk.DISABLED, text="扫描中...")
        self.update_status("正在扫描BLE设备...")
        self.log_message("=" * 50, 'info')
        self.log_message(f"开始扫描BLE设备（扫描时间: {self.scan_time_var.get()}秒）", 'info')
        threading.Thread(target=self._scan_async, daemon=True).start()

    def _scan_async(self):
        try:
            future = asyncio.run_coroutine_threadsafe(self._scan_devices(), self.loop)
            devices, rssi_dict = future.result(timeout=self.scan_time_var.get() + 5)
            self.root.after(0, self._scan_complete, devices, rssi_dict)
        except Exception as exc:
            self.root.after(0, self._scan_error, str(exc))

    async def _scan_devices(self):
        devices = await BleakScanner.discover(timeout=self.scan_time_var.get(), return_adv=True)
        device_list = []
        rssi_dict = {}
        for device, adv_data in devices.values():
            device_list.append(device)
            rssi_dict[device.address] = adv_data.rssi
        device_list.sort(key=lambda d: rssi_dict.get(d.address, -100), reverse=True)
        return device_list, rssi_dict

    def _scan_complete(self, devices: List[BLEDevice], rssi_dict: Dict[str, int]):
        self.devices = devices
        self.filtered_devices = devices.copy()
        self.device_rssi = rssi_dict
        self.is_scanning = False
        self.scan_button.configure(state=tk.NORMAL, text="扫描")
        self.log_message(f"扫描完成！发现 {len(devices)} 个BLE设备", 'success')
        self.update_status(f"扫描完成，发现 {len(devices)} 个设备")
        self.update_device_list()

    def _scan_error(self, error: str):
        self.is_scanning = False
        self.scan_button.configure(state=tk.NORMAL, text="扫描")
        self.log_message(f"扫描失败: {error}", 'error')
        self.update_status("扫描失败")
        messagebox.showerror("扫描错误", f"扫描BLE设备时出错:\n{error}")

    # ------------------------- 连接与断开 -------------------------
    def on_device_selected(self, event):
        selection = self.device_tree.selection()
        if selection:
            item = self.device_tree.item(selection[0])
            idx = int(item['text']) - 1
            if 0 <= idx < len(self.filtered_devices):
                self.selected_device = self.filtered_devices[idx]
                self.log_message(f"已选择设备: {self.selected_device.name or '(未知)'} [{self.selected_device.address}]", 'success')
                self.connect_button.configure(state=tk.NORMAL)

    def connect_device(self):
        if not self.selected_device:
            messagebox.showwarning("提示", "请先选择一个设备")
            return
        self.log_message("=" * 50, 'info')
        self.log_message(f"正在连接设备: {self.selected_device.address}", 'info')
        self.update_status("正在连接...")
        self.connect_button.configure(state=tk.DISABLED)
        threading.Thread(target=self._connect_async, daemon=True).start()

    def _connect_async(self):
        try:
            future = asyncio.run_coroutine_threadsafe(self._connect_device(), self.loop)
            future.result(timeout=30)
            self.root.after(0, self._connect_complete)
        except Exception as exc:
            self.root.after(0, self._connect_error, str(exc))

    async def _connect_device(self):
        self.client = BleakClient(self.selected_device.address)
        await self.client.connect(timeout=20.0)

    def _connect_complete(self):
        self.log_message("设备连接成功！", 'success')
        self.update_status(f"已连接: {self.selected_device.address}")
        self.connect_button.configure(state=tk.DISABLED)
        self.read_lmp_button.configure(state=tk.NORMAL)
        self.disconnect_button.configure(state=tk.NORMAL)

    def _connect_error(self, error: str):
        self.log_message(f"连接失败: {error}", 'error')
        self.update_status("连接失败")
        self.connect_button.configure(state=tk.NORMAL)
        messagebox.showerror("连接错误", f"连接设备时出错:\n{error}")

    def disconnect_device(self):
        if not self.client:
            return
        try:
            asyncio.run_coroutine_threadsafe(self.client.disconnect(), self.loop).result(timeout=10)
        except Exception:
            pass
        self.client = None
        self.log_message("设备已断开", 'info')
        self.update_status("未连接")
        self.connect_button.configure(state=tk.NORMAL)
        self.read_lmp_button.configure(state=tk.DISABLED)
        self.disconnect_button.configure(state=tk.DISABLED)

    # ------------------------- 读取 LMP -------------------------
    def read_lmp_version(self):
        if not self.client or not self.client.is_connected:
            messagebox.showwarning("提示", "请先连接设备")
            return
        # 清空上次 btmon 缓存，准备等待新事件
        self.btmon_lmp_info = None
        self.log_message("正在读取LMP版本信息...", 'info')
        self.update_status("正在读取LMP版本...")
        self.read_lmp_button.configure(state=tk.DISABLED)
        threading.Thread(target=self._read_lmp_async, daemon=True).start()

    def _read_lmp_async(self):
        try:
            future = asyncio.run_coroutine_threadsafe(self._read_lmp_version(), self.loop)
            info = future.result(timeout=10)
            # 等待 btmon 捕获版本事件（最多 2 秒）
            wait_ms = 0
            while not self.btmon_lmp_info and wait_ms < 2000:
                time.sleep(0.05)
                wait_ms += 50
            self.root.after(0, self._read_lmp_complete, info)
        except Exception as exc:
            self.root.after(0, self._read_lmp_error, str(exc))

    def _read_windows_lmp_info(self) -> Dict[str, str]:
        info: Dict[str, str] = {}
        if platform.system() != 'Linux':
            info['hci_error'] = f"HCI 命令仅支持 Linux 系统，当前系统: {platform.system()}"
            return info
        try:
            mac_address = self.selected_device.address
            result = self._run_cmd_with_sudo(['hcitool', 'con'], timeout=5)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if mac_address.upper() in line.upper() or mac_address.lower() in line:
                        match = re.search(r'handle\s+(\d+)', line, re.IGNORECASE)
                        if match:
                            handle = int(match.group(1))
                            info['connection_handle'] = handle
                            info['connection_info'] = line.strip()
                            lmp_info = self._read_lmp_via_hci(handle)
                            info.update(lmp_info)
                        break
                if 'connection_handle' not in info:
                    info['hci_error'] = f"未找到设备 {mac_address} 的连接句柄"
            else:
                err = result.stderr or "hcitool 命令失败"
                if not self.sudo_password:
                    err += "（可能需要sudo权限）"
                info['hci_error'] = err
        except subprocess.TimeoutExpired:
            info['hci_error'] = "hcitool 命令超时"
        except FileNotFoundError:
            info['hci_error'] = "未找到 hcitool 命令，请安装 bluez 工具包: sudo apt-get install bluez"
        except Exception as exc:
            info['hci_error'] = f"HCI 命令错误: {str(exc)}"
        return info

    def _read_lmp_via_hci(self, handle: int) -> Dict[str, str]:
        info: Dict[str, str] = {}
        try:
            handle_low = handle & 0xFF
            handle_high = (handle >> 8) & 0xFF
            cmd = ['hcitool', 'cmd', '0x01', '0x001D', f'0x{handle_low:02X}', f'0x{handle_high:02X}']
            self.log_message(f"执行 HCI 命令: {' '.join(cmd)}", 'info')
            result = self._run_cmd_with_sudo(cmd, timeout=5)
            if result.returncode == 0:
                info['hci_command_success'] = True
                info['hci_response'] = result.stdout.strip()
                if info['hci_response']:
                    preview = info['hci_response'][:180].replace('\n', ' | ')
                    self.log_message(f"hcitool输出: {preview}", 'info')
                self.log_message("HCI 命令已发送，解析输出...", 'info')
                parsed = self._parse_hcitool_output(result.stdout)
                if parsed:
                    info.update(parsed)
                    info['lmp_source'] = 'hcitool'
                    self.log_message("✓ 已直接从hcitool输出解析到版本信息", 'success')
                else:
                    self.log_message("未能从hcitool输出解析到版本字段", 'warning')
            else:
                info['hci_command_error'] = result.stderr
        except subprocess.TimeoutExpired:
            info['hci_read_error'] = "HCI 命令超时"
        except FileNotFoundError:
            info['hci_read_error'] = "未找到 hcitool 命令"
        except Exception as exc:
            info['hci_read_error'] = str(exc)
        return info

    def _parse_hcitool_output(self, output: str) -> Dict[str, str]:
        parsed: Dict[str, str] = {}
        try:
            hex_lines = re.findall(r"(?:^|\n)[\s>]*((?:[0-9A-Fa-f]{2}[\s]+){6,}[0-9A-Fa-f]{2})", output)
            if not hex_lines:
                return parsed
            hex_str = hex_lines[-1]
            bytes_list = [int(b, 16) for b in hex_str.strip().split()]
            if len(bytes_list) < 8:
                return parsed
            payload = bytes_list[-8:]
            status, handle_l, handle_h, ver, mfg_l, mfg_h, sub_l, sub_h = payload
            if status != 0x00:
                parsed['hci_status'] = status
                return parsed
            handle = handle_l | (handle_h << 8)
            lmp_ver = ver
            manufacturer = mfg_l | (mfg_h << 8)
            subversion = sub_l | (sub_h << 8)
            parsed['connection_handle'] = handle
            parsed['lmp_version_raw'] = lmp_ver
            parsed['lmp_version'] = self._decode_lmp_version(lmp_ver)
            parsed['lmp_subversion'] = subversion
            parsed['manufacturer_from_hci'] = f"0x{manufacturer:04X}"
            parsed['hcitool_bytes'] = ' '.join(f"{b:02X}" for b in payload)
            return parsed
        except Exception as exc:
            print(f"[DEBUG] 解析hcitool输出失败: {exc}")
            return parsed

    async def _read_lmp_version(self) -> Dict[str, str]:
        info: Dict[str, str] = {}
        hci_info = self._read_windows_lmp_info()
        info.update(hci_info)
        try:
            services = self.client.services
            service_list = list(services)
            info['services'] = len(service_list)
            info['service_uuids'] = [str(s.uuid) for s in service_list[:10]]
            all_characteristics: Dict[str, List[Dict[str, str]]] = {}
            for service in service_list[:10]:
                service_uuid = str(service.uuid)
                chars = []
                for char in service.characteristics[:5]:
                    chars.append({'uuid': str(char.uuid), 'properties': char.properties})
                all_characteristics[service_uuid] = chars
            info['characteristics'] = all_characteristics
        except Exception as exc:
            info['services'] = 0
            info['service_uuids'] = []
            info['service_error'] = str(exc)

        characteristics = {
            'manufacturer': "00002a29-0000-1000-8000-00805f9b34fb",
            'model': "00002a24-0000-1000-8000-00805f9b34fb",
            'serial': "00002a25-0000-1000-8000-00805f9b34fb",
            'hardware': "00002a27-0000-1000-8000-00805f9b34fb",
            'firmware': "00002a26-0000-1000-8000-00805f9b34fb",
            'software': "00002a28-0000-1000-8000-00805f9b34fb",
        }
        for key, uuid in characteristics.items():
            try:
                value = await self.client.read_gatt_char(uuid)
                info[key] = value.decode('utf-8', errors='ignore').strip()
            except Exception:
                info[key] = 'N/A'

        try:
            PNP_ID_UUID = "00002a50-0000-1000-8000-00805f9b34fb"
            pnp_data = await self.client.read_gatt_char(PNP_ID_UUID)
            if len(pnp_data) >= 7:
                vendor_id = int.from_bytes(pnp_data[1:3], byteorder='little')
                product_id = int.from_bytes(pnp_data[3:5], byteorder='little')
                product_version = int.from_bytes(pnp_data[5:7], byteorder='little')
                info['pnp_vendor_id'] = f"0x{vendor_id:04X}"
                info['pnp_product_id'] = f"0x{product_id:04X}"
                info['pnp_product_version'] = f"0x{product_version:04X}"
                if 'lmp_version' not in info:
                    lmp_version = (product_version >> 8) & 0xFF
                    lmp_subversion = product_version & 0xFF
                    info['lmp_version_from_pnp'] = self._decode_lmp_version(lmp_version)
                    info['lmp_subversion_from_pnp'] = str(lmp_subversion)
        except Exception:
            info['pnp_vendor_id'] = 'N/A'
            info['pnp_product_id'] = 'N/A'
            info['pnp_product_version'] = 'N/A'
        return info

    def _decode_lmp_version(self, version: int) -> str:
        lmp_versions = {
            0: "Bluetooth 1.0b",
            1: "Bluetooth 1.1",
            2: "Bluetooth 1.2",
            3: "Bluetooth 2.0 + EDR",
            4: "Bluetooth 2.1 + EDR",
            5: "Bluetooth 3.0 + HS",
            6: "Bluetooth 4.0",
            7: "Bluetooth 4.1",
            8: "Bluetooth 4.2",
            9: "Bluetooth 5.0",
            10: "Bluetooth 5.1",
            11: "Bluetooth 5.2",
            12: "Bluetooth 5.3",
            13: "Bluetooth 5.4",
        }
        return lmp_versions.get(version, f"Unknown (0x{version:02X})")

    def _read_lmp_complete(self, info: Dict[str, str]):
        try:
            self.log_message("=" * 30, 'success')
            self.log_message("设备信息读取完成", 'success')
            if 'connection_handle' in info:
                self.log_message("【HCI 连接】", 'success')
                self.log_message(f"句柄: {info.get('connection_handle')}", 'info')
            if 'lmp_version' in info:
                self.log_message("【LMP 版本（HCI）】", 'success')
                self.log_message(f"✓ {info.get('lmp_version')}", 'success')
                self.log_message(f"版本号: {info.get('lmp_version_raw')}", 'info')
                self.log_message(f"子版本: {info.get('lmp_subversion')}", 'info')
                if info.get('manufacturer_from_hci'):
                    self.log_message(f"厂商: {info.get('manufacturer_from_hci')}", 'info')
                if info.get('hcitool_bytes'):
                    self.log_message(f"HCI原始: {info.get('hcitool_bytes')}", 'info')
            elif self.btmon_lmp_info:
                self.log_message("【LMP 版本（btmon捕获）】", 'success')
                b = self.btmon_lmp_info
                decoded = b.get('lmp_version_text', 'N/A')
                raw_hex = b.get('lmp_version_raw')
                if raw_hex:
                    try:
                        decoded = self._decode_lmp_version(int(raw_hex, 16))
                    except Exception:
                        pass
                self.log_message(f"✓ {decoded}", 'success')
                if raw_hex:
                    self.log_message(f"版本号: 0x{raw_hex}", 'info')
                if b.get('lmp_subversion_hex'):
                    self.log_message(f"子版本: 0x{b.get('lmp_subversion_hex')}", 'info')
                if b.get('manufacturer_code'):
                    self.log_message(f"厂商: {b.get('manufacturer')} (0x{b.get('manufacturer_code')})", 'info')
            elif info.get('hci_response'):
                raw_preview = str(info.get('hci_response'))[:180].replace('\n', ' | ')
                self.log_message(f"HCI原始输出: {raw_preview}", 'warning')
            if info.get('hci_command_error'):
                err = str(info.get('hci_command_error'))[:150]
                self.log_message(f"HCI命令失败: {err}", 'error')
            if 'hci_error' in info:
                error_msg = str(info.get('hci_error'))[:150]
                self.log_message(f"HCI错误: {error_msg}", 'error')
            self.log_message(f"服务数: {info.get('services', 0)}", 'info')
            if info.get('firmware', 'N/A') != 'N/A':
                self.log_message(f"固件: {info.get('firmware')[:50]}", 'success')
            if info.get('manufacturer', 'N/A') != 'N/A':
                self.log_message(f"制造商: {info.get('manufacturer')[:50]}", 'info')
            if info.get('pnp_vendor_id', 'N/A') != 'N/A':
                self.log_message(f"厂商ID: {info.get('pnp_vendor_id')}", 'info')
                if 'lmp_version_from_pnp' in info:
                    self.log_message("【LMP(PnP推断)】", 'info')
                    self.log_message(f"{info.get('lmp_version_from_pnp')}", 'info')
            self.log_message("=" * 30, 'success')
            if info.get('lmp_version') or self.btmon_lmp_info:
                self.log_message("✓ 读取成功", 'success')
            else:
                self.log_message("提示: 未拿到LMP信息（可能需要sudo或设备未返回）", 'warning')
            self.update_status("完成")
            self.read_lmp_button.configure(state=tk.NORMAL)
        except Exception as exc:
            print(f"显示结果出错: {exc}")
            try:
                self.log_message(f"显示错误: {str(exc)[:50]}", 'error')
                self.read_lmp_button.configure(state=tk.NORMAL)
            except Exception:
                pass

    def _read_lmp_error(self, error: str):
        self.log_message(f"读取LMP失败: {error}", 'error')
        self.update_status("读取失败")
        self.read_lmp_button.configure(state=tk.NORMAL)


def main():
    root = tk.Tk()
    app = BLELMPToolGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
