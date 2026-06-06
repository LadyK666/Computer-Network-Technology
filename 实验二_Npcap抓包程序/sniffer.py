#!/usr/bin/env python3
"""
实验二：基于 Npcap/WinPcap 的网卡抓包演示程序。

通过 Scapy 调用底层抓包接口，枚举网卡、按 BPF 过滤抓取数据包，
并将结果保存为 PCAP 与 CSV，供实验三离线分析使用。
"""

from __future__ import annotations

import argparse
import csv
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


try:
    from scapy.all import ICMP, IP, TCP, UDP, Ether, conf, get_if_list, sniff, wrpcap
except ImportError as exc:  # pragma: no cover - exercised on machines without scapy
    print("缺少依赖 scapy。请先在项目根目录运行 .\\setup_env.ps1，或执行 pip install -r requirements.txt。", file=sys.stderr)
    raise SystemExit(2) from exc


def list_interfaces() -> None:
    """
    列出本机 Scapy/Npcap 可见的全部网卡名称。

    输出到标准输出，编号从 1 开始，供用户在 ``--iface`` 参数中选用。
    不执行抓包，调用后立即返回。
    """
    print("可用网卡：")
    for index, iface in enumerate(get_if_list(), start=1):
        print(f"{index:2d}. {iface}")


def packet_summary(packet: Any) -> dict[str, str]:
    """
    将 Scapy 数据包对象转换为适合写入 CSV 的扁平字典。

    参数:
        packet: Scapy 解析后的分层数据包（通常含 Ether/IP/TCP/UDP 等层）。

    返回:
        包含时间、长度、MAC、IP、协议、端口、``info`` 摘要等字段的字典；
        缺失的层对应字段为空字符串。

    备注:
        协议名优先显示 TCP/UDP/ICMP 文本，否则为 IP 层 ``proto`` 数字。
    """
    row: dict[str, str] = {
        "time": datetime.fromtimestamp(float(packet.time)).strftime("%Y-%m-%d %H:%M:%S.%f"),
        "length": str(len(packet)),
        "eth_src": "",
        "eth_dst": "",
        "ip_src": "",
        "ip_dst": "",
        "protocol": "",
        "ttl": "",
        "src_port": "",
        "dst_port": "",
        "info": packet.summary(),
    }

    if Ether in packet:
        row["eth_src"] = packet[Ether].src
        row["eth_dst"] = packet[Ether].dst

    if IP in packet:
        ip = packet[IP]
        row["ip_src"] = ip.src
        row["ip_dst"] = ip.dst
        row["ttl"] = str(ip.ttl)
        row["protocol"] = str(ip.proto)

        if TCP in packet:
            row["protocol"] = "TCP"
            row["src_port"] = str(packet[TCP].sport)
            row["dst_port"] = str(packet[TCP].dport)
        elif UDP in packet:
            row["protocol"] = "UDP"
            row["src_port"] = str(packet[UDP].sport)
            row["dst_port"] = str(packet[UDP].dport)
        elif ICMP in packet:
            row["protocol"] = "ICMP"

    return row


def capture_packets(args: argparse.Namespace) -> None:
    """
    在指定网卡上执行一次短时抓包，并保存 PCAP 与 CSV。

    参数:
        args: 命令行命名空间，使用字段包括：
            ``iface`` 网卡名；``count`` 最多抓取包数；``timeout`` 超时秒数；
            ``filter`` BPF 表达式；``outdir``/``pcap``/``csv`` 输出路径。

    备注:
        Windows 上通常需管理员权限；无包时仅提示不生成文件。
        每抓到一包会通过 ``on_packet`` 回调打印一行摘要。
    """
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_path = Path(args.pcap) if args.pcap else outdir / f"capture_{stamp}.pcap"
    csv_path = Path(args.csv) if args.csv else outdir / f"packets_{stamp}.csv"

    rows: list[dict[str, str]] = []

    def on_packet(packet: Any) -> None:
        """Scapy 回调：每收到一包即汇总并打印进度。"""
        row = packet_summary(packet)
        rows.append(row)
        print(
            f"[{len(rows):04d}] {row['time']} len={row['length']} "
            f"{row['ip_src'] or '-'} -> {row['ip_dst'] or '-'} "
            f"{row['protocol'] or '-'} {row['info']}"
        )

    print("开始抓包。实时抓包在 Windows 上通常需要管理员权限和 Npcap。")
    print(f"iface={args.iface or conf.iface}, count={args.count}, timeout={args.timeout}, filter={args.filter or '(none)'}")

    try:
        packets = sniff(
            iface=args.iface,
            count=args.count,
            timeout=args.timeout,
            filter=args.filter,
            prn=on_packet,
            store=True,
        )
    except PermissionError:
        print("权限不足：请使用管理员 PowerShell 重新运行。", file=sys.stderr)
        raise SystemExit(1)
    except OSError as exc:
        print(f"抓包失败：{exc}", file=sys.stderr)
        print("请确认 Npcap 已安装，并勾选 WinPcap API-compatible Mode。", file=sys.stderr)
        raise SystemExit(1) from exc

    if packets:
        wrpcap(str(pcap_path), packets)
        fieldnames = list(rows[0].keys())
        with csv_path.open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        print(f"已保存 PCAP: {pcap_path}")
        print(f"已保存 CSV : {csv_path}")
    else:
        print("没有抓到数据包，请检查网卡、过滤条件或抓包时长。")


def build_parser() -> argparse.ArgumentParser:
    """
    构建实验二命令行参数解析器。

    返回:
        含 ``--list``、``--iface``、``--count``、``--filter`` 等选项的解析器。
    """
    parser = argparse.ArgumentParser(description="Experiment 2 Npcap/WinPcap sniffer")
    parser.add_argument("--list", action="store_true", help="列出可用网卡后退出")
    parser.add_argument("--iface", help="抓包网卡名称。不填时使用 Scapy 默认网卡")
    parser.add_argument("--count", type=int, default=20, help="抓包数量，默认 20")
    parser.add_argument("--timeout", type=int, default=30, help="最长抓包秒数，默认 30")
    parser.add_argument("--filter", default="ip", help="BPF 过滤表达式，默认 ip")
    parser.add_argument("--outdir", default=str(Path(__file__).with_name("outputs")), help="输出目录")
    parser.add_argument("--pcap", help="PCAP 输出路径")
    parser.add_argument("--csv", help="CSV 输出路径")
    return parser


def main() -> int:
    """
    程序入口：列出网卡或执行一次抓包。

    返回:
        退出码，正常为 0；权限/抓包失败时可能为 1 或 2。
    """
    parser = build_parser()
    args = parser.parse_args()
    if args.list:
        list_interfaces()
        return 0
    capture_packets(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
