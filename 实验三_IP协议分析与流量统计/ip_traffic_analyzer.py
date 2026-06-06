#!/usr/bin/env python3
"""
实验三：IPv4 协议 PCI 解析与 IP 流量统计。

本模块负责读取 PCAP 抓包文件，按 Ethernet II + IPv4 格式解析每个数据包的
协议控制信息（PCI），并统计各 IP 的发送/接收包数、字节数及源目流向。
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import struct
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Iterable


PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}

PROTOCOL_NAMES = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
}


@dataclass(frozen=True)
class PcapPacket:
    """PCAP 文件中的单个原始数据包记录。"""

    index: int
    timestamp: str
    captured_length: int
    original_length: int
    data: bytes


@dataclass(frozen=True)
class IPv4PCI:
    """单个 IPv4 数据包的协议控制信息（PCI）解析结果。"""

    packet_index: int
    timestamp: str
    frame_length: int
    ethernet_src: str
    ethernet_dst: str
    version: int
    header_length: int
    dscp_ecn: int
    total_length: int
    identification: int
    flags: str
    fragment_offset: int
    ttl: int
    protocol: str
    header_checksum: str
    src_ip: str
    dst_ip: str
    src_port: str
    dst_port: str
    payload_length: int


def format_mac(raw: bytes) -> str:
    """
    将 6 字节 MAC 地址格式化为冒号分隔的十六进制字符串。

    参数:
        raw: 原始 MAC 字节，长度应为 6。

    返回:
        形如 ``aa:bb:cc:dd:ee:ff`` 的字符串。
    """
    return ":".join(f"{byte:02x}" for byte in raw)


def format_ipv4(raw: bytes) -> str:
    """
    将 4 字节 IPv4 地址转换为点分十进制字符串。

    参数:
        raw: 网络字节序的 4 字节地址。

    返回:
        点分十进制 IP 字符串。
    """
    return str(ipaddress.IPv4Address(raw))


def flag_text(flags_and_offset: int) -> str:
    """
    从 IP 首部「标志 + 片偏移」字段中提取分片标志文本。

    参数:
        flags_and_offset: 16 位 flags/fragment offset 组合字段（网络序解包后的值）。

    返回:
        ``DF``、``MF``、``DF|MF`` 或 ``none``。
    """
    flags = flags_and_offset >> 13
    labels = []
    if flags & 0b010:
        labels.append("DF")
    if flags & 0b001:
        labels.append("MF")
    return "|".join(labels) if labels else "none"


def read_pcap(path: Path) -> tuple[int, list[PcapPacket]]:
    """
    读取 PCAP/PCAPNG 兼容的抓包文件并解析为数据包列表。

    参数:
        path: ``.pcap`` 文件路径。

    返回:
        ``(datalink, packets)`` 元组。``datalink`` 为链路类型（1 表示 Ethernet）；
        ``packets`` 为按文件顺序排列的 ``PcapPacket`` 列表。

    异常:
        ValueError: 文件格式不支持或记录不完整。
    """
    packets: list[PcapPacket] = []
    with path.open("rb") as handle:
        endian, divisor, network = read_pcap_header(handle)
        record_header = struct.Struct(f"{endian}IIII")
        index = 1
        while True:
            header = handle.read(record_header.size)
            if not header:
                break
            if len(header) != record_header.size:
                raise ValueError(f"PCAP 记录头不完整，packet_index={index}")
            ts_sec, ts_frac, incl_len, orig_len = record_header.unpack(header)
            data = handle.read(incl_len)
            if len(data) != incl_len:
                raise ValueError(f"PCAP 数据包内容不完整，packet_index={index}")
            timestamp = datetime.fromtimestamp(ts_sec + ts_frac / divisor, timezone.utc).astimezone().isoformat()
            packets.append(PcapPacket(index, timestamp, incl_len, orig_len, data))
            index += 1
    return network, packets


def read_pcap_header(handle: BinaryIO) -> tuple[str, int, int]:
    """
    解析 PCAP 全局文件头，确定字节序与时间戳精度。

    参数:
        handle: 已打开的二进制文件对象，读指针位于文件开头。

    返回:
        ``(endian, divisor, network)``：
        - ``endian``: ``'<'`` 或 ``'>'``，供后续 struct 使用；
        - ``divisor``: 时间戳小数部分的除数（微秒或纳秒）；
        - ``network``: 链路层类型编号。

    异常:
        ValueError: magic 不支持或头部长度不足。
    """
    magic = handle.read(4)
    if magic not in PCAP_MAGIC:
        raise ValueError("不支持的 PCAP 文件格式或 magic number")
    endian, divisor = PCAP_MAGIC[magic]
    rest = handle.read(20)
    if len(rest) != 20:
        raise ValueError("PCAP 全局头不完整")
    _major, _minor, _thiszone, _sigfigs, _snaplen, network = struct.unpack(f"{endian}HHIIII", rest)
    return endian, divisor, network


def parse_ipv4_packet(packet: PcapPacket, datalink: int) -> IPv4PCI | None:
    """
    从以太网帧中解析 IPv4 首部及常见传输层端口，生成 PCI 记录。

    参数:
        packet: 含原始帧数据的 ``PcapPacket``。
        datalink: PCAP 链路类型；当前仅支持 ``1``（Ethernet II）。

    返回:
        解析成功返回 ``IPv4PCI``；非 IPv4、带 VLAN 后非 0x0800、长度不足等返回 ``None``。

    异常:
        ValueError: ``datalink`` 不是 Ethernet II。

    备注:
        自动跳过 802.1Q / QinQ VLAN 标签；TCP/UDP 端口仅在首部完整时提取。
    """
    if datalink != 1:
        raise ValueError(f"当前只支持 Ethernet II PCAP，datalink={datalink}")

    frame = packet.data
    if len(frame) < 14:
        return None

    dst_mac = format_mac(frame[0:6])
    src_mac = format_mac(frame[6:12])
    ether_type = struct.unpack("!H", frame[12:14])[0]
    offset = 14

    # Skip one or more 802.1Q VLAN tags.
    while ether_type in (0x8100, 0x88A8):
        if len(frame) < offset + 4:
            return None
        ether_type = struct.unpack("!H", frame[offset + 2 : offset + 4])[0]
        offset += 4

    if ether_type != 0x0800:
        return None

    if len(frame) < offset + 20:
        return None

    first = frame[offset]
    version = first >> 4
    ihl = first & 0x0F
    header_length = ihl * 4
    if version != 4 or ihl < 5 or len(frame) < offset + header_length:
        return None

    fields = struct.unpack("!BBHHHBBH4s4s", frame[offset : offset + 20])
    _version_ihl, dscp_ecn, total_length, identification, flags_offset, ttl, proto, checksum, src, dst = fields

    transport_offset = offset + header_length
    payload_length = max(total_length - header_length, 0)
    src_port = ""
    dst_port = ""

    if proto in (6, 17) and len(frame) >= transport_offset + 4:
        src_port_num, dst_port_num = struct.unpack("!HH", frame[transport_offset : transport_offset + 4])
        src_port = str(src_port_num)
        dst_port = str(dst_port_num)

    return IPv4PCI(
        packet_index=packet.index,
        timestamp=packet.timestamp,
        frame_length=packet.original_length,
        ethernet_src=src_mac,
        ethernet_dst=dst_mac,
        version=version,
        header_length=header_length,
        dscp_ecn=dscp_ecn,
        total_length=total_length,
        identification=identification,
        flags=flag_text(flags_offset),
        fragment_offset=flags_offset & 0x1FFF,
        ttl=ttl,
        protocol=PROTOCOL_NAMES.get(proto, str(proto)),
        header_checksum=f"0x{checksum:04x}",
        src_ip=format_ipv4(src),
        dst_ip=format_ipv4(dst),
        src_port=src_port,
        dst_port=dst_port,
        payload_length=payload_length,
    )


def analyze_packets(datalink: int, packets: Iterable[PcapPacket]) -> tuple[list[IPv4PCI], dict[str, dict[str, int]], dict[tuple[str, str, str], dict[str, int]]]:
    """
    批量解析数据包并汇总 IP 级统计与三元组流向统计。

    参数:
        datalink: 链路层类型，传给 ``parse_ipv4_packet``。
        packets: 可迭代的 ``PcapPacket`` 集合。

    返回:
        三元组 ``(pci_rows, ip_stats, flows)``：
        - ``pci_rows``: 所有成功解析的 PCI 列表；
        - ``ip_stats``: 键为 IP，值为发送/接收包数与字节数；
        - ``flows``: 键为 ``(src_ip, dst_ip, protocol)``，值为包数与字节数。
    """
    pci_rows: list[IPv4PCI] = []
    ip_stats: dict[str, dict[str, int]] = defaultdict(lambda: {"sent_packets": 0, "received_packets": 0, "sent_bytes": 0, "received_bytes": 0})
    flows: dict[tuple[str, str, str], dict[str, int]] = defaultdict(lambda: {"packets": 0, "bytes": 0})

    for packet in packets:
        pci = parse_ipv4_packet(packet, datalink)
        if pci is None:
            continue
        pci_rows.append(pci)
        ip_stats[pci.src_ip]["sent_packets"] += 1
        ip_stats[pci.src_ip]["sent_bytes"] += pci.total_length
        ip_stats[pci.dst_ip]["received_packets"] += 1
        ip_stats[pci.dst_ip]["received_bytes"] += pci.total_length
        flows[(pci.src_ip, pci.dst_ip, pci.protocol)]["packets"] += 1
        flows[(pci.src_ip, pci.dst_ip, pci.protocol)]["bytes"] += pci.total_length

    return pci_rows, dict(ip_stats), dict(flows)


def write_csv(path: Path, rows: list[dict[str, object]], fieldnames: list[str]) -> None:
    """
    将字典行写入 UTF-8 BOM 编码的 CSV 文件。

    参数:
        path: 输出文件路径，父目录不存在时自动创建。
        rows: 每行一个字典，键与 ``fieldnames`` 对应。
        fieldnames: CSV 列名顺序。
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_outputs(outdir: Path, pcap_path: Path, pci_rows: list[IPv4PCI], ip_stats: dict[str, dict[str, int]], flows: dict[tuple[str, str, str], dict[str, int]]) -> None:
    """
    将分析结果写入实验三标准输出目录（CSV、JSON、HTML 看板）。

    参数:
        outdir: 输出根目录，例如 ``outputs/`` 或 ``outputs/_live/``。
        pcap_path: 源 PCAP 路径，写入 summary 供追溯。
        pci_rows: PCI 明细列表。
        ip_stats: IP 统计字典。
        flows: 流向统计字典。

    生成文件:
        ``packet_pci.csv``、``ip_stats.csv``、``flows.csv``、
        ``traffic_summary.json``、``traffic_dashboard.html``。
    """
    outdir.mkdir(parents=True, exist_ok=True)

    pci_dicts = [asdict(row) for row in pci_rows]
    if pci_dicts:
        write_csv(outdir / "packet_pci.csv", pci_dicts, list(pci_dicts[0].keys()))
    else:
        write_csv(outdir / "packet_pci.csv", [], [field.name for field in IPv4PCI.__dataclass_fields__.values()])

    stat_rows = [
        {"ip": ip, **stats, "total_packets": stats["sent_packets"] + stats["received_packets"], "total_bytes": stats["sent_bytes"] + stats["received_bytes"]}
        for ip, stats in sorted(ip_stats.items())
    ]
    write_csv(outdir / "ip_stats.csv", stat_rows, ["ip", "sent_packets", "received_packets", "sent_bytes", "received_bytes", "total_packets", "total_bytes"])

    flow_rows = [
        {"src_ip": src, "dst_ip": dst, "protocol": protocol, "packets": values["packets"], "bytes": values["bytes"]}
        for (src, dst, protocol), values in sorted(flows.items(), key=lambda item: item[1]["bytes"], reverse=True)
    ]
    write_csv(outdir / "flows.csv", flow_rows, ["src_ip", "dst_ip", "protocol", "packets", "bytes"])

    summary = {
        "pcap": str(pcap_path),
        "packet_count": len(pci_rows),
        "ip_count": len(ip_stats),
        "top_received_ips": sorted(stat_rows, key=lambda row: row["received_packets"], reverse=True)[:10],
        "top_flows": flow_rows[:20],
    }
    (outdir / "traffic_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    write_dashboard(outdir / "traffic_dashboard.html", summary, stat_rows, flow_rows[:50])


def write_dashboard(path: Path, summary: dict[str, object], stat_rows: list[dict[str, object]], flow_rows: list[dict[str, object]]) -> None:
    """
    生成自包含的 HTML 流量统计看板（内嵌 JSON 与简单表格脚本）。

    参数:
        path: 输出 HTML 路径。
        summary: 汇总信息，含包数、IP 数等。
        stat_rows: IP 统计行，用于 Top 接收表。
        flow_rows: 流向行，用于 Top Flow 表。

    备注:
        页面不依赖外部 CDN，适合离线打开；仅展示前 15~30 行以控制体积。
    """
    stats_json = json.dumps(stat_rows[:30], ensure_ascii=False)
    flows_json = json.dumps(flow_rows[:30], ensure_ascii=False)
    html = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>IP 流量统计</title>
  <style>
    body {{ font-family: Arial, "Microsoft YaHei", sans-serif; margin: 24px; color: #202124; }}
    h1 {{ font-size: 24px; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; }}
    .panel {{ border: 1px solid #d9dde3; border-radius: 8px; padding: 16px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th, td {{ border-bottom: 1px solid #eceff3; padding: 8px; text-align: left; }}
    th {{ background: #f6f8fa; }}
    .bar {{ height: 8px; background: #3367d6; border-radius: 4px; }}
  </style>
</head>
<body>
  <h1>IP 流量统计</h1>
  <p>IPv4 包数量：{summary["packet_count"]}；IP 地址数量：{summary["ip_count"]}</p>
  <div class="grid">
    <section class="panel">
      <h2>接收包数量 Top IP</h2>
      <div id="stats"></div>
    </section>
    <section class="panel">
      <h2>源到目的流量 Top Flow</h2>
      <div id="flows"></div>
    </section>
  </div>
  <script>
    const stats = {stats_json};
    const flows = {flows_json};
    function table(rows, columns) {{
      const html = ['<table><thead><tr>' + columns.map(c => `<th>${{c.title}}</th>`).join('') + '</tr></thead><tbody>'];
      for (const row of rows) {{
        html.push('<tr>' + columns.map(c => `<td>${{row[c.key] ?? ''}}</td>`).join('') + '</tr>');
      }}
      html.push('</tbody></table>');
      return html.join('');
    }}
    document.getElementById('stats').innerHTML = table(
      stats.sort((a, b) => b.received_packets - a.received_packets).slice(0, 15),
      [{{key: 'ip', title: 'IP'}}, {{key: 'received_packets', title: '接收包'}}, {{key: 'received_bytes', title: '接收字节'}}]
    );
    document.getElementById('flows').innerHTML = table(
      flows.slice(0, 15),
      [{{key: 'src_ip', title: '源 IP'}}, {{key: 'dst_ip', title: '目的 IP'}}, {{key: 'protocol', title: '协议'}}, {{key: 'bytes', title: '字节'}}]
    );
  </script>
</body>
</html>
"""
    path.write_text(html, encoding="utf-8")


def make_test_packet() -> bytes:
    """
    构造一帧用于自检的合成以太网 + IPv4 + UDP 数据包。

    返回:
        完整链路层帧字节串（42 字节左右）。
    """
    dst_mac = bytes.fromhex("001122334455")
    src_mac = bytes.fromhex("66778899aabb")
    eth_type = struct.pack("!H", 0x0800)
    version_ihl = 0x45
    dscp_ecn = 0
    total_length = 20 + 8
    identification = 0x1234
    flags_offset = 0x4000
    ttl = 64
    proto = 17
    checksum = 0
    src_ip = ipaddress.IPv4Address("192.168.1.10").packed
    dst_ip = ipaddress.IPv4Address("8.8.8.8").packed
    ip_header = struct.pack("!BBHHHBBH4s4s", version_ihl, dscp_ecn, total_length, identification, flags_offset, ttl, proto, checksum, src_ip, dst_ip)
    udp_header = struct.pack("!HHHH", 53000, 53, 8, 0)
    return dst_mac + src_mac + eth_type + ip_header + udp_header


def run_self_test() -> None:
    """
    运行内置单元自检：解析合成包并验证统计结果。

    异常:
        AssertionError: 任一断言失败时抛出。
    """
    packet = PcapPacket(1, "2026-05-20T00:00:00+08:00", 42, 42, make_test_packet())
    pci = parse_ipv4_packet(packet, 1)
    assert pci is not None
    assert pci.src_ip == "192.168.1.10"
    assert pci.dst_ip == "8.8.8.8"
    assert pci.protocol == "UDP"
    assert pci.dst_port == "53"
    rows, stats, flows = analyze_packets(1, [packet])
    assert len(rows) == 1
    assert stats["8.8.8.8"]["received_packets"] == 1
    assert flows[("192.168.1.10", "8.8.8.8", "UDP")]["packets"] == 1
    assert flows[("192.168.1.10", "8.8.8.8", "UDP")]["bytes"] == 28
    print("self-test passed")


def build_parser() -> argparse.ArgumentParser:
    """
    构建命令行参数解析器。

    返回:
        配置好 ``--pcap``、``--outdir``、``--self-test`` 等选项的 ``ArgumentParser``。
    """
    parser = argparse.ArgumentParser(description="Experiment 3 IPv4 PCI parser and traffic analyzer")
    parser.add_argument("--pcap", type=Path, help="输入 PCAP 文件路径")
    parser.add_argument("--outdir", type=Path, default=Path(__file__).with_name("outputs"), help="输出目录")
    parser.add_argument("--self-test", action="store_true", help="运行内置自检")
    return parser


def main() -> int:
    """
    程序入口：自检、读取 PCAP、分析并写出统计结果。

    返回:
        进程退出码，成功为 0。
    """
    args = build_parser().parse_args()
    if args.self_test:
        run_self_test()
        return 0
    if not args.pcap:
        raise SystemExit("请提供 --pcap，或使用 --self-test 运行自检。")

    datalink, packets = read_pcap(args.pcap)
    pci_rows, ip_stats, flows = analyze_packets(datalink, packets)
    write_outputs(args.outdir, args.pcap, pci_rows, ip_stats, flows)
    print(f"读取 PCAP 包数: {len(packets)}")
    print(f"解析 IPv4 包数: {len(pci_rows)}")
    print(f"统计 IP 数量 : {len(ip_stats)}")
    print(f"输出目录     : {args.outdir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
