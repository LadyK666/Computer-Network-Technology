# 计算机网络实验项目代码

本项目按实验顺序组织计算机网络课程实验代码，包含 Wireshark 抓包观察、Npcap/Scapy 实时抓包、IPv4 协议控制信息解析、IP 流量统计和流量地图 Web 展示。

## 环境要求

推荐环境：

- Windows 10/11
- Python 3.10 或更高版本
- Npcap，用于实时抓包
- Wireshark，用于实验一抓包观察和保存 `.pcap` 文件

安装 Npcap 时建议勾选：

```text
Install Npcap in WinPcap API-compatible Mode
```

实时抓包通常需要使用“管理员 PowerShell”运行。

## 快速配置

在项目根目录执行。以下命令中的 `Code` 表示本仓库根目录，请按实际下载位置进入：

```powershell
cd Code
.\setup_env.ps1
```

脚本会检查 Python、Npcap、Wireshark，并创建 `.venv` 虚拟环境、安装 Python 依赖。

如果只想手动安装依赖：

```powershell
cd Code
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

后续命令建议先激活虚拟环境：

```powershell
cd Code
.\.venv\Scripts\Activate.ps1
```

也可以不激活，直接使用：

```powershell
.\.venv\Scripts\python.exe <脚本路径>
```

## 目录结构

```text
Code/
├─ README.md
├─ requirements.txt
├─ setup_env.ps1
├─ 实验一_Wireshark抓包工具使用/
├─ 实验二_Npcap抓包程序/
│  ├─ sniffer.py
│  └─ outputs/
└─ 实验三_IP协议分析与流量统计/
   ├─ capture_public_demo.py
   ├─ geo_overrides.csv
   ├─ ip_traffic_analyzer.py
   ├─ traffic_map.py
   ├─ outputs/
   │  ├─ demo_public_1000.pcap
   │  ├─ demo_public_1000/
   │  ├─ packet_pci.csv
   │  ├─ ip_stats.csv
   │  ├─ flows.csv
   │  ├─ map_flows.csv
   │  └─ traffic_map_data.json
   └─ web_app/
      ├─ server.py
      └─ static/
```

## 路径说明

一般不需要修改代码路径。

项目中的脚本默认使用相对于自身文件的目录：

- 实验二抓包输出默认写入 `实验二_Npcap抓包程序/outputs/`
- 实验三分析输出默认写入 `实验三_IP协议分析与流量统计/outputs/`
- Web 服务默认读取 `实验三_IP协议分析与流量统计/outputs/`
- IP 地理位置离线映射默认读取 `实验三_IP协议分析与流量统计/geo_overrides.csv`

只要保持当前目录结构不变，直接按下面命令运行即可。若移动项目目录，只需要重新进入新的项目根目录执行命令，不需要改源码。

## 实验一：Wireshark 抓包工具使用

实验一主要使用 Wireshark 图形界面完成。

启动 Wireshark：

```powershell
wireshark
```

如果 `wireshark` 不在 PATH 中，可以从 Windows 开始菜单启动 Wireshark。

建议演示流程：

1. 打开 Wireshark。
2. 选择当前联网网卡，例如 `WLAN`。
3. 设置显示过滤器，例如 `ip`、`tcp`、`udp`、`dns`。
4. 访问网页或执行网络命令产生流量。
5. 观察以太网帧、IP 数据报、TCP/UDP 报文结构。
6. 可将抓包结果保存为 `.pcap`，供实验三程序分析。

## 实验二：Npcap 抓包程序

实验二代码路径：

```text
实验二_Npcap抓包程序/sniffer.py
```

列出可用网卡：

```powershell
python .\实验二_Npcap抓包程序\sniffer.py --list
```

如果已经知道 Windows 网卡名，例如 `WLAN`，抓取 50 个 IP 包：

```powershell
python .\实验二_Npcap抓包程序\sniffer.py --iface "WLAN" --count 50 --timeout 20 --filter "ip"
```

如果 `WLAN` 名称无法被 Scapy/Npcap 识别，请使用 `--list` 输出的 NPF 设备路径，例如：

```powershell
python .\实验二_Npcap抓包程序\sniffer.py --iface "\Device\NPF_{网卡GUID}" --count 50 --timeout 20 --filter "ip"
```

指定输出文件：

```powershell
python .\实验二_Npcap抓包程序\sniffer.py `
  --iface "WLAN" `
  --count 50 `
  --timeout 20 `
  --filter "ip" `
  --pcap .\实验二_Npcap抓包程序\outputs\capture_demo.pcap `
  --csv .\实验二_Npcap抓包程序\outputs\packets_demo.csv
```

如果不指定 `--pcap` 和 `--csv`，程序会自动在 `实验二_Npcap抓包程序/outputs/` 下生成带时间戳的输出文件。

## 实验三：IPv4 协议分析与流量统计

实验三包括三个部分：IPv4 PCI 字段解析、IP/流向统计、流量地图生成。

### 1. 自检

```powershell
python .\实验三_IP协议分析与流量统计\ip_traffic_analyzer.py --self-test
```

### 2. 解析已有 PCAP

项目内置了脱敏演示数据：

```text
实验三_IP协议分析与流量统计/outputs/demo_public_1000.pcap
```

运行 IPv4 解析和统计：

```powershell
python .\实验三_IP协议分析与流量统计\ip_traffic_analyzer.py `
  --pcap .\实验三_IP协议分析与流量统计\outputs\demo_public_1000.pcap `
  --outdir .\实验三_IP协议分析与流量统计\outputs
```

输出文件：

- `packet_pci.csv`：每个 IPv4 包的 PCI 字段，包括 Version、IHL、TOS/DSCP、Total Length、Identification、Flags、Fragment Offset、TTL、Protocol、Header Checksum、Source IP、Destination IP 等。
- `ip_stats.csv`：按 IP 统计发送包数、接收包数、字节数。
- `flows.csv`：按源 IP、目的 IP、协议统计流量。
- `traffic_summary.json`：汇总结果。
- `traffic_dashboard.html`：可直接打开的统计页面。

在终端打印前 20 条 IPv4 PCI 字段：

```powershell
Import-Csv .\实验三_IP协议分析与流量统计\outputs\packet_pci.csv |
  Select-Object -First 20 packet_index,version,header_length,dscp_ecn,total_length,identification,flags,fragment_offset,ttl,protocol,header_checksum,src_ip,dst_ip |
  Format-Table -AutoSize
```

### 3. 生成流量地图数据

```powershell
python .\实验三_IP协议分析与流量统计\traffic_map.py `
  --flows .\实验三_IP协议分析与流量统计\outputs\flows.csv `
  --stats .\实验三_IP协议分析与流量统计\outputs\ip_stats.csv `
  --overrides .\实验三_IP协议分析与流量统计\geo_overrides.csv `
  --outdir .\实验三_IP协议分析与流量统计\outputs `
  --public-only
```

地图相关输出：

- `ip_geo.csv`：IP 到地点和经纬度的映射。
- `map_flows.csv`：按地点聚合后的流向统计。
- `traffic_map_data.json`：前端 ECharts 使用的数据。
- `traffic_map.html`：后端生成的备用 HTML 地图。

如果需要联网调用 ip-api 解析公网 IP，可增加：

```powershell
--resolve-online
```

注意：内网地址、保留地址、组播地址通常无法通过公网接口定位，需要在 `geo_overrides.csv` 中手工维护。

### 4. 分析实验二刚抓到的 PCAP

例如实验二保存了：

```text
实验二_Npcap抓包程序/outputs/capture_demo.pcap
```

则运行：

```powershell
python .\实验三_IP协议分析与流量统计\ip_traffic_analyzer.py `
  --pcap .\实验二_Npcap抓包程序\outputs\capture_demo.pcap `
  --outdir .\实验三_IP协议分析与流量统计\outputs

python .\实验三_IP协议分析与流量统计\traffic_map.py `
  --flows .\实验三_IP协议分析与流量统计\outputs\flows.csv `
  --stats .\实验三_IP协议分析与流量统计\outputs\ip_stats.csv `
  --overrides .\实验三_IP协议分析与流量统计\geo_overrides.csv `
  --outdir .\实验三_IP协议分析与流量统计\outputs `
  --public-only
```

## Web 前后端展示

Web 服务代码路径：

```text
实验三_IP协议分析与流量统计/web_app/server.py
```

启动服务：

```powershell
cd Code
.\.venv\Scripts\Activate.ps1
python .\实验三_IP协议分析与流量统计\web_app\server.py --host 127.0.0.1 --port 8088
```

浏览器访问：

```text
http://127.0.0.1:8088/
```

页面功能：

- 展示默认脱敏演示数据。
- 选择 `.pcap` 文件并触发协议分析。
- 查看每个包的 IPv4 PCI 字段。
- 查看每个 IP 的收发包统计。
- 查看源 IP 到目的 IP 的流量统计。
- 使用 ECharts 展示流量地图。
- 启动实时抓包，将最新满足条件的 IPv4 包显示在地图和表格中。

实时抓包建议参数：

```text
网卡：WLAN
数量：20
秒数：20
滑动窗口：100
过滤：ip
```

如果页面提示 `Scapy is not installed`，说明后端不是用 `.venv` 启动的。请停止旧服务，并使用上面的 Web 启动命令重新启动。

## 公网 IP 演示数据

仓库中包含一份脱敏静态 demo：

```text
实验三_IP协议分析与流量统计/outputs/demo_public_1000.pcap
实验三_IP协议分析与流量统计/outputs/demo_public_1000/
```

该数据用于课堂展示，不是真实网络抓包：

- 包数量：1000 个 IPv4 包
- MAC 地址：本地管理演示地址
- IP 地址：演示地址，通过 `geo_overrides.csv` 映射到地点
- 负载：合成零字节

## 常见问题

### 1. 运行 `python ...` 提示缺少 Scapy

先激活虚拟环境：

```powershell
.\.venv\Scripts\Activate.ps1
```

或直接使用：

```powershell
.\.venv\Scripts\python.exe .\实验二_Npcap抓包程序\sniffer.py --list
```

### 2. 实时抓包抓不到包

检查：

- 是否使用管理员 PowerShell 启动。
- Npcap 是否安装并运行。
- 网卡是否选对，优先选择当前联网的 `WLAN`。
- 过滤表达式是否过窄，建议先用 `ip`。
- 抓包时是否有网络活动。

### 3. 地图地点很少

原因通常是：

- 只有公网 IP 或已配置地理位置的 IP 才能定位。
- 内网 IP、广播、组播、保留地址无法直接定位。
- 可在 `geo_overrides.csv` 中手工补充 IP、城市、经纬度。
