# BLE LMP Version Reader (GUI + CLI)

扫描、连接并读取 BLE 设备的 LMP 版本信息。GUI 基于 tkinter，自动拉起 `btmon` 并解析 `Read Remote Version Complete` 事件；附带简单 CLI 脚本用于快速命令行读取。

## 功能特性
- 设备扫描：名称/MAC 过滤，扫描时长可调，按 RSSI 排序
- 连接与读取：发送 HCI `Read_Remote_Version_Information`，解析 LMP 版本、子版本与厂商
- 自动 btmon：Linux 上 sudo 启动 `btmon -t` + `stdbuf` 行缓冲，日志去重并上屏
- 日志管理：日志窗口彩色分级，可一键保存为 txt
- GATT 补充：读取常见 Device Information 特征值、PnP ID 以辅助识别
- 跨平台：
	- Linux：完整 HCI + btmon 解析
	- Windows：可扫描/连接/GATT，HCI 命令不可用，仅保留 GATT 信息

## 目录
- ble_lmp_tool_gui.py：GUI 主程序
- ble_lmp_tool.sh：Linux CLI 辅助脚本（交互/直连）

## 运行环境
- Python 3.8+
- 依赖：`bleak`、`tkinter`（随标准库）、`asyncio`
- Linux 需：`bluez`、`bluez-tools`、`btmon`、`python3-dbus`，可用的蓝牙 4.0+ 适配器
- Windows 需：已配对/可连接的 BLE 适配器（仅 GATT 读取）

## 安装依赖
Linux：
```bash
sudo apt update
sudo apt install -y bluez bluez-tools btmon python3-dbus
python3 -m venv .venv && source .venv/bin/activate
pip install bleak
```

Windows：
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install bleak
```

## 启动 GUI
Linux（推荐）：
```bash
sudo .venv/bin/python ble_lmp_tool_gui.py
```

Windows：
```powershell
.\.venv\Scripts\python.exe ble_lmp_tool_gui.py
```

## 使用步骤（GUI）
1) 启动程序：首次在 Linux 会提示 sudo 密码，自动启动 btmon（行缓冲）。
2) 扫描：点击“扫描”，可在“设备名称”输入过滤关键字，扫描时长 5–30 秒可调（默认 5 秒）。
3) 选择设备：列表按 RSSI 排序，选中后“连接”按钮可用。
4) 连接：点击“连接”，成功后“读LMP”可用。
5) 读版本：点击“读LMP”。
	 - Linux：发送 HCI 命令，btmon 捕获 `Read Remote Version Complete`，解析 LMP 版本/子版本/厂商。
	 - Windows：HCI 不可用，仅显示 GATT 信息（制造商/固件/型号等，若设备提供）。
6) 保存日志：点击“保存日志”导出当前彩色日志为 txt。

## CLI 用法（Linux）
```bash
chmod +x ble_lmp_tool.sh
./ble_lmp_tool.sh            # 交互选择设备
./ble_lmp_tool.sh <MAC>      # 直连已知设备
```

## 权限与 sudo（Linux）
- 推荐直接用 sudo 运行 GUI，btmon/HCI 需要权限。
- 免密码选项：`visudo` 添加（替换为你的用户名）：
	```
	your_username ALL=(ALL) NOPASSWD: /usr/bin/btmon, /usr/bin/stdbuf
	```
- 也可为 `hcitool` 配置能力：`sudo setcap 'cap_net_raw,cap_net_admin+eip' $(which hcitool)`。

## 输出说明
- 日志分级：蓝色信息、绿色成功、橙色提示、红色错误、btmon 深绿。
- 关键字段：
	- `LMP 版本`：蓝牙核心规范对应名称（如 Bluetooth 5.2）
	- `子版本`：厂商自定义子版本号
	- `厂商`：厂商代码与名称（btmon/hcitool 解析）
	- `HCI原始`：若未能解析，显示原始 HCI 输出供排查
	- `PnP ID`：从 GATT 读取的厂商/产品/版本号

## 故障排查
- 读取不到 LMP：保持连接，等待 1–2 秒；确认 btmon 已启动且有输出。
- 权限不足：用 sudo 运行，或给 `hcitool` 配置 `cap_net_raw,cap_net_admin` 并将用户加入 `bluetooth` 组。
- 扫描/连接失败：
	- `sudo systemctl restart bluetooth`
	- `sudo hciconfig hci0 up`
	- 确认设备在广播且距离近
- `hcitool`/`btmon` 未找到：`sudo apt install bluez bluez-tools btmon`。
- btmon 无输出：确认已用 sudo，或按上方 visudo 配置免密码。
- Windows 无 LMP：属正常，Windows 无法发送 BlueZ HCI 命令，仅能看到 GATT 信息。

## LMP 版本对照
| 版本号 | 蓝牙规范 |
|-------|---------|
| 0 | Bluetooth 1.0b |
| 1 | Bluetooth 1.1 |
| 2 | Bluetooth 1.2 |
| 3 | Bluetooth 2.0 + EDR |
| 4 | Bluetooth 2.1 + EDR |
| 5 | Bluetooth 3.0 + HS |
| 6 | Bluetooth 4.0 |
| 7 | Bluetooth 4.1 |
| 8 | Bluetooth 4.2 |
| 9 | Bluetooth 5.0 |
| 10 | Bluetooth 5.1 |
| 11 | Bluetooth 5.2 |
| 12 | Bluetooth 5.3 |
| 13 | Bluetooth 5.4 |

## 许可证
仅供学习与研究使用。
