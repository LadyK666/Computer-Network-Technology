# 实验二：WINPCAP（NPCAP）编程

## 程序说明

`sniffer.py` 使用 Python Scapy 调用系统底层抓包能力。在 Windows 上实时抓包依赖 Npcap，建议使用管理员 PowerShell 运行。

## 运行方式

列出网卡：

```powershell
python .\实验二_Npcap抓包程序\sniffer.py --list
```

抓取 50 个 IP 包：

```powershell
python .\实验二_Npcap抓包程序\sniffer.py --iface "网卡名称" --count 50 --filter "ip"
```

输出文件默认写入：

- `实验二_Npcap抓包程序\outputs\capture_*.pcap`
- `实验二_Npcap抓包程序\outputs\packets_*.csv`

抓到的 `.pcap` 文件可作为实验三输入。

