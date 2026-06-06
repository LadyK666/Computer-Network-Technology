# 实验一：Wireshark 抓包工具使用

本实验使用 Wireshark 图形界面完成抓包观察，不包含必须运行的 Python 代码。

## 实验目的

- 熟悉 Wireshark 的网卡选择、抓包启动和停止流程。
- 观察以太网帧、IPv4 数据报、TCP/UDP 报文等协议结构。
- 使用显示过滤器筛选网络数据包。
- 将抓包结果保存为 `.pcap` 文件，供后续实验二、实验三分析。

## 启动方式

如果 Wireshark 已加入 PATH，可在 PowerShell 中运行：

```powershell
wireshark
```

如果命令不可用，可从 Windows 开始菜单启动 Wireshark。

## 建议演示流程

1. 打开 Wireshark。
2. 选择当前联网网卡，例如 `WLAN`。
3. 点击开始抓包。
4. 访问网页或执行网络命令产生流量。
5. 使用过滤器观察不同协议：

```text
ip
tcp
udp
dns
icmp
```

6. 展开数据包详情区，观察 Ethernet、IPv4、TCP/UDP 等首部字段。
7. 保存抓包文件为 `.pcap`，可作为实验三协议分析程序的输入。

## 与后续实验的关系

实验一保存的 `.pcap` 文件可以交给：

```text
实验三_IP协议分析与流量统计/ip_traffic_analyzer.py
```

用于解析 IPv4 PCI 字段和统计 IP 流量。
