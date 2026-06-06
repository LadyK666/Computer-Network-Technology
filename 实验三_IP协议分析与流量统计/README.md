# 实验三：协议分析程序的编写

## 程序说明

`ip_traffic_analyzer.py` 可解析 Ethernet II + IPv4 的 `.pcap` 文件，输出每个 IP 包的 PCI 字段，并统计不同 IP 地址的发送/接收包数和字节数。

该程序的 `.pcap` 解析部分只使用 Python 标准库，因此即使未安装 Npcap，也可以分析由 Wireshark 或实验二保存的抓包文件。

## 运行方式

自检：

```powershell
python .\实验三_IP协议分析与流量统计\ip_traffic_analyzer.py --self-test
```

分析实验二抓到的 PCAP：

```powershell
python .\实验三_IP协议分析与流量统计\ip_traffic_analyzer.py --pcap .\实验二_Npcap抓包程序\outputs\capture_示例.pcap
```

输出文件默认写入 `实验三_IP协议分析与流量统计\outputs\`：

- `packet_pci.csv`：每个 IPv4 包的协议控制信息。
- `ip_stats.csv`：按 IP 地址统计发送/接收包数和字节数。
- `flows.csv`：按源 IP、目的 IP、协议统计流量。
- `traffic_summary.json`：汇总数据。
- `traffic_dashboard.html`：可直接打开查看的统计页面。

生成流量地图：

```powershell
python .\实验三_IP协议分析与流量统计\traffic_map.py
```

地图相关输出：

- `ip_geo.csv`：IP 地址与地理位置对应关系。
- `map_flows.csv`：按地点聚合后的流向统计。
- `traffic_map_data.json`：地图页面使用的数据。
- `traffic_map.html`：自包含 SVG 流量地图，可直接用浏览器打开。

公网 IP 可尝试通过 ip-api 自动解析：

```powershell
python .\实验三_IP协议分析与流量统计\traffic_map.py --resolve-online
```

内网 IP 无法通过公网接口定位，可在 `geo_overrides.csv` 中手工维护地点和经纬度。

## Web 前后端

启动本地 Web 应用：

```powershell
python .\实验三_IP协议分析与流量统计\web_app\server.py --host 127.0.0.1 --port 8088
```

浏览器访问：

```text
http://127.0.0.1:8088/
```

Web 页面支持：

- 选择已有 `.pcap` 文件并触发协议分析。
- 查看每个包的 PCI 字段。
- 查看不同 IP 的发送/接收包数量和字节数。
- 使用 ECharts 查看流量地图，圆点表示地点，动态箭头表示地点间流量。
- 启动实时抓包，地图和表格只显示最新 N 个包的滚动窗口，N 默认 1000。
- 编辑 IP 地理位置配置。
- 调用 Npcap 进行短时实时抓包。
