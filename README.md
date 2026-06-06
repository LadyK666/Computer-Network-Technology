# 计算机网络实验项目代码

本目录按实验顺序组织代码与报告材料：

1. `实验一_Wireshark抓包工具使用/`：Wireshark 抓包观察记录模板和常用过滤表达式。
2. `实验二_Npcap抓包程序/`：基于 Python Scapy + Npcap 的实时抓包程序。
3. `实验三_IP协议分析与流量统计/`：离线 `.pcap` 解析、IP 首部 PCI 展示、IP 流量统计与 HTML 统计页面生成。
4. `实验报告初版.md`：按实验报告要求整理的 Markdown 初稿。

## 环境配置

推荐在 Windows 上使用：

- Python 3.10 或更高版本。
- Npcap，安装时勾选 `Install Npcap in WinPcap API-compatible Mode`。
- Wireshark，用于实验一抓包观察和保存 `.pcap` 文件。

执行环境检查与 Python 依赖安装：

```powershell
cd 计算机网络实验项目代码
.\setup_env.ps1
```

如果只做实验三离线解析，不需要先安装 Scapy/Npcap，可直接运行：

```powershell
python .\实验三_IP协议分析与流量统计\ip_traffic_analyzer.py --self-test
```

