#!/usr/bin/env python3
"""
抓取与公网相关的 IPv4 流量并保存为固定 Demo 数据集。

用于课堂稳定展示流量地图：过滤掉纯内网、组播等流量后，
将 PCAP/CSV 保存到指定路径，供 ``ip_traffic_analyzer`` 与 ``traffic_map`` 分析。
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


PROJECT_DIR = Path(__file__).resolve().parents[1]
EXP2_DIR = PROJECT_DIR / "实验二_Npcap抓包程序"
sys.path.insert(0, str(EXP2_DIR))

try:
    from scapy.all import IP, conf, get_if_list, sniff, wrpcap
    from sniffer import packet_summary
except ImportError as exc:
    print("缺少 scapy。请先运行 setup_env.ps1。", file=sys.stderr)
    raise SystemExit(2) from exc


PUBLIC_BPF = (
    "ip "
    "and not (src net 10.0.0.0/8 and dst net 10.0.0.0/8) "
    "and not (src net 172.16.0.0/12 and dst net 172.16.0.0/12) "
    "and not (src net 192.168.0.0/16 and dst net 192.168.0.0/16) "
    "and not src net 224.0.0.0/4 and not dst net 224.0.0.0/4"
)


def is_public_endpoint(packet: Any) -> bool:
    """
    判断数据包是否至少有一端为可路由的公网（global）IPv4 地址。

    参数:
        packet: Scapy 数据包；无 IP 层时视为 False。

    返回:
        源或目的 IP 的 ``is_global`` 为真时返回 True。

    备注:
        用于抓包后二次过滤，剔除虽通过 BPF 但仍含私网/特殊地址的帧。
    """
    if IP not in packet:
        return False
    src = ipaddress.ip_address(packet[IP].src)
    dst = ipaddress.ip_address(packet[IP].dst)
    return src.is_global or dst.is_global


def main() -> int:
    """
    按命令行参数抓包、过滤公网相关帧并写出 PCAP/CSV。

    支持 ``--list`` 仅列出网卡。默认使用 ``PUBLIC_BPF`` 过滤表达式。

    返回:
        成功为 0；缺少依赖时为 2。
    """
    parser = argparse.ArgumentParser(description="Capture public-related packets for demo")
    parser.add_argument("--iface", help="Npcap interface name")
    parser.add_argument("--count", type=int, default=1000)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--filter", default=PUBLIC_BPF)
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()

    if args.list:
        for iface in get_if_list():
            print(iface)
        return 0

    args.pcap.parent.mkdir(parents=True, exist_ok=True)
    args.csv.parent.mkdir(parents=True, exist_ok=True)

    print(f"iface={args.iface or conf.iface}")
    print(f"count={args.count}, timeout={args.timeout}")
    print(f"filter={args.filter}")
    started = datetime.now()
    packets = sniff(iface=args.iface, count=args.count, timeout=args.timeout, filter=args.filter, store=True)
    packets = [packet for packet in packets if is_public_endpoint(packet)]
    wrpcap(str(args.pcap), packets)

    rows = [packet_summary(packet) for packet in packets]
    if rows:
        with args.csv.open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
    else:
        args.csv.write_text("", encoding="utf-8")

    print(f"captured={len(packets)}")
    print(f"pcap={args.pcap}")
    print(f"csv={args.csv}")
    print(f"elapsed_seconds={(datetime.now() - started).total_seconds():.1f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
