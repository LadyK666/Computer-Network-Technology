#!/usr/bin/env python3
"""Local web app for packet capture, IPv4 PCI analysis, and traffic map viewing."""

from __future__ import annotations

import argparse
import csv
import json
import mimetypes
import sys
import threading
import time
from dataclasses import asdict
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse


APP_DIR = Path(__file__).resolve().parent
EXP3_DIR = APP_DIR.parent
PROJECT_DIR = EXP3_DIR.parent
EXP2_DIR = PROJECT_DIR / "实验二_Npcap抓包程序"
EXP2_OUTPUTS = EXP2_DIR / "outputs"
OUTPUTS_DIR = EXP3_DIR / "outputs"
STATIC_DIR = APP_DIR / "static"

sys.path.insert(0, str(EXP3_DIR))
sys.path.insert(0, str(EXP2_DIR))

from ip_traffic_analyzer import PcapPacket, analyze_packets, parse_ipv4_packet, read_pcap, write_outputs  # noqa: E402
from traffic_map import (  # noqa: E402
    GeoInfo,
    aggregate_map_data,
    geo_needs_online_retry,
    is_private_or_special,
    load_overrides,
    read_csv,
    resolve_geos,
    write_csv,
    write_map_html,
)


LIVE_WINDOW_LIMIT = 100
LIVE_OUTPUTS_DIR = OUTPUTS_DIR / "_live"
LIVE_PERSIST_INTERVAL = 3.0
LIVE_PCI_PREVIEW = 40
LIVE_TABLE_PREVIEW = 80
LIVE_ONLINE_RESOLVE_PER_BATCH = 6

LIVE_STATE: dict[str, Any] = {
    "running": False,
    "started_at": "",
    "last_update": "",
    "last_error": "",
    "last_result": {},
    "iface": "",
    "filter": "ip",
    "batch_count": 30,
    "interval": 5,
    "total_packets": 0,
    "max_packets": LIVE_WINDOW_LIMIT,
    "public_only": False,
    "map_revision": 0,
}
LIVE_STOP = threading.Event()
LIVE_THREAD: threading.Thread | None = None
LIVE_PACKETS: list[PcapPacket] = []
LIVE_SEQUENCE = 0
LIVE_DATA_CACHE: dict[str, Any] = {}
LIVE_GEOS_CACHE: dict[str, GeoInfo] = {}
LIVE_GEO_OVERRIDES: dict[str, GeoInfo] | None = None
LIVE_LAST_PERSIST = 0.0
LIVE_PACKETS_LOCK = threading.Lock()
LIVE_ANALYSIS_LOCK = threading.Lock()


def json_response(handler: BaseHTTPRequestHandler, payload: Any, status: int = 200, *, compact: bool = False) -> None:
    """
    功能说明：
        将 Python 对象序列化为 JSON，并通过 HTTP 响应写回浏览器或 API 调用方。
        用于本实验 Web 后端的统一 JSON 输出格式。

    参数：
        handler: BaseHTTPRequestHandler 实例，提供 send_response、send_header、wfile 等。
        payload: 任意可 JSON 序列化的对象（通常为 dict）。
        status: HTTP 状态码，默认 200。
        compact: 为 True 时使用紧凑分隔符、无缩进，适合实时轮询接口减小体积。

    返回值：
        无；响应体直接写入 handler.wfile。

    备注：
        由 AppHandler 的 do_GET / do_POST 在各 API 路由中调用；
        Content-Type 固定为 application/json; charset=utf-8。
    """
    data = json.dumps(payload, ensure_ascii=False, separators=(",", ":") if compact else None, indent=None if compact else 2).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def error_response(handler: BaseHTTPRequestHandler, message: str, status: int = 400) -> None:
    """
    功能说明：
        向客户端返回标准错误 JSON（ok=False），封装常见 4xx/5xx 场景。

    参数：
        handler: 当前 HTTP 请求处理器。
        message: 面向前端的错误说明字符串。
        status: HTTP 状态码，默认 400。

    返回值：
        无；内部调用 json_response。

    备注：
        与 json_response 配合，保证前端可用统一字段判断请求是否成功。
    """
    json_response(handler, {"ok": False, "error": message}, status)


def read_body(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    """
    功能说明：
        从 POST 请求体读取 JSON 并解析为字典，供 /api/* 接口使用。

    参数：
        handler: 当前 HTTP 请求处理器，从 rfile 读取正文。

    返回值：
        解析后的 dict；无正文或长度为 0 时返回空 dict {}。

    备注：
        假定客户端发送 application/json；非法 JSON 会向上抛出异常，
        由 AppHandler.do_POST 统一捕获并转为 500 错误响应。
    """
    length = int(handler.headers.get("Content-Length", "0") or "0")
    if length <= 0:
        return {}
    raw = handler.rfile.read(length)
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))


def csv_rows(path: Path) -> list[dict[str, str]]:
    """
    功能说明：
        安全读取 UTF-8-SIG 编码的 CSV 文件，返回字典行列表，供前端表格展示。

    参数：
        path: CSV 文件路径。

    返回值：
        每行一个 dict（键为表头）；文件不存在时返回空列表 []。

    备注：
        用于加载 packet_pci、ip_stats、flows、ip_geo 等实验输出；
        大文件在调用处通过切片限制返回条数。
    """
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def safe_project_path(value: str) -> Path:
    """
    功能说明：
        将用户提交的相对或绝对路径解析为项目目录内的绝对 Path，防止目录穿越。

    参数：
        value: 前端传来的 pcap 等文件路径字符串。

    返回值：
        位于 PROJECT_DIR 下的已 resolve 的 Path。

    备注：
        路径不在项目根下时抛出 ValueError；
        analyze_pcap 等接口在访问文件前必须先经此函数校验。
    """
    path = (PROJECT_DIR / value).resolve() if not Path(value).is_absolute() else Path(value).resolve()
    if not str(path).lower().startswith(str(PROJECT_DIR.resolve()).lower()):
        raise ValueError("path is outside project directory")
    return path


def rel(path: Path) -> str:
    """
    功能说明：
        将绝对路径转换为相对于项目根目录的正斜杠 URL 风格字符串。

    参数：
        path: 项目内任意文件或目录的 Path。

    返回值：
        如 "实验三_IP协议分析与流量统计/outputs/..." 的相对路径字符串。

    备注：
        供 API JSON 返回给前端，便于跨平台显示与再次提交分析请求。
    """
    return str(path.resolve().relative_to(PROJECT_DIR.resolve())).replace("\\", "/")


def outputs_rel(path: Path) -> str:
    """
    功能说明：
        将路径转换为相对于 OUTPUTS_DIR 的字符串，用于 /outputs/ 静态访问。

    参数：
        path: 通常位于 outputs 或 _live 子目录下的文件 Path。

    返回值：
        相对 outputs 的路径，正斜杠分隔。

    备注：
        与 AppHandler 中 /outputs/ 路由配合，前端通过 mapHtml 等字段打开地图 HTML。
    """
    return str(path.resolve().relative_to(OUTPUTS_DIR.resolve())).replace("\\", "/")


def normalize_iface(iface: str | None) -> str | None:
    """
    功能说明：
        将前端或配置中的网卡标识（含 Npcap GUID）规范化为 Scapy sniff 可用的接口名。

    参数：
        iface: 网卡名称或 GUID 字符串；None 或空串表示使用 Scapy 默认接口。

    返回值：
        匹配到的 Scapy 接口名；无法匹配时返回去空格后的原字符串；无输入时返回 None。

    备注：
        依赖 scapy.all.get_if_list；未安装 Scapy 时直接返回原值；
        live_capture_loop、capture_packets、start_live_capture 均会调用。
    """
    if not iface:
        return None
    cleaned = str(iface).strip()
    if not cleaned:
        return None
    try:
        from scapy.all import get_if_list
    except ImportError:
        return cleaned

    interfaces = list(get_if_list())
    if cleaned in interfaces:
        return cleaned

    key = cleaned.upper().replace("{", "").replace("}", "")
    for name in interfaces:
        normalized = name.upper().replace("{", "").replace("}", "")
        if key == normalized or key in normalized:
            return name
    return cleaned


def list_pcaps() -> list[dict[str, Any]]:
    """
    功能说明：
        扫描实验二 outputs、实验三 captures 与 outputs 目录，枚举可用 .pcap 文件。

    参数：
        无。

    返回值：
        字典列表，每项含 name、path（项目相对路径）、size、modified（ISO 时间）。

    备注：
        按路径去重；供 /api/pcaps 与 analyze 接口按 pcapIndex 选择文件。
    """
    roots = [EXP2_OUTPUTS, EXP3_DIR / "captures", OUTPUTS_DIR]
    results: list[dict[str, Any]] = []
    seen: set[Path] = set()
    for root in roots:
        if not root.exists():
            continue
        for path in sorted(root.glob("*.pcap")):
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            results.append(
                {
                    "name": path.name,
                    "path": rel(path),
                    "size": path.stat().st_size,
                    "modified": datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds"),
                }
            )
    return results


def read_outputs_data(outdir: Path) -> dict[str, Any]:
    """
    功能说明：
        从指定输出目录聚合 PCI、统计、流、地理与地图等数据，组装前端所需 payload。

    参数：
        outdir: 分析结果目录（通常为 OUTPUTS_DIR 或 LIVE_OUTPUTS_DIR）。

    返回值：
        含 pcaps、pci、ipStats、flows、ipGeo、mapFlows、summary、mapData、mapHtml 的字典。

    备注：
        pci 最多 500 行；缺失的 JSON 文件用空 dict 占位；
        get_data 与实时状态回退逻辑均依赖此结构。
    """
    return {
        "pcaps": list_pcaps(),
        "pci": csv_rows(outdir / "packet_pci.csv")[:500],
        "ipStats": csv_rows(outdir / "ip_stats.csv"),
        "flows": csv_rows(outdir / "flows.csv"),
        "ipGeo": csv_rows(outdir / "ip_geo.csv"),
        "mapFlows": csv_rows(outdir / "map_flows.csv"),
        "summary": json.loads((outdir / "traffic_summary.json").read_text(encoding="utf-8")) if (outdir / "traffic_summary.json").exists() else {},
        "mapData": json.loads((outdir / "traffic_map_data.json").read_text(encoding="utf-8")) if (outdir / "traffic_map_data.json").exists() else {},
        "mapHtml": outputs_rel(outdir / "traffic_map.html"),
    }


def flows_dict_to_rows(flows: dict[tuple[str, str, str], dict[str, int]]) -> list[dict[str, str]]:
    """
    功能说明：
        将 analyze_packets 产生的五元组流字典转为可写 CSV / 返回前端的行列表。

    参数：
        flows: 键为 (src_ip, dst_ip, protocol)，值为 packets、bytes 计数的字典。

    返回值：
        按 bytes 降序排列的 dict 行，字段均为字符串便于 CSV 写入。

    备注：
        实时分析与 persist_live_snapshot 在写 flows.csv 前调用。
    """
    return [
        {
            "src_ip": src,
            "dst_ip": dst,
            "protocol": protocol,
            "packets": str(values["packets"]),
            "bytes": str(values["bytes"]),
        }
        for (src, dst, protocol), values in sorted(flows.items(), key=lambda item: item[1]["bytes"], reverse=True)
    ]


def stats_dict_to_rows(ip_stats: dict[str, dict[str, int]]) -> list[dict[str, object]]:
    """
    功能说明：
        将 IP 维度的收发包/字节统计扩展为含 total_packets、total_bytes 的表格行。

    参数：
        ip_stats: 键为 IP 地址，值为 sent/received 包数与字节数的嵌套 dict。

    返回值：
        按 IP 排序的 dict 列表，数值字段保持 int 类型供前端与地图聚合使用。

    备注：
        与 flows_dict_to_rows 配合更新 LIVE_DATA_CACHE 与磁盘 CSV。
    """
    return [
        {
            "ip": ip,
            **stats,
            "total_packets": stats["sent_packets"] + stats["received_packets"],
            "total_bytes": stats["sent_bytes"] + stats["received_bytes"],
        }
        for ip, stats in sorted(ip_stats.items())
    ]


def map_flows_for_table(map_flows: list[dict[str, object]]) -> list[dict[str, object]]:
    """
    功能说明：
        将地图流数据中的 src_ips/dst_ips 列表压平为分号分隔字符串，并限制预览条数。

    参数：
        map_flows: aggregate_map_data 返回的流列表，可能含 list 型 IP 集合。

    返回值：
        最多 LIVE_TABLE_PREVIEW 行的 dict 列表，适合实时状态 JSON 体积控制。

    备注：
        仅用于 update_live_data_cache；完整 map_flows 仍写入 traffic_map_data.json。
    """
    rows: list[dict[str, object]] = []
    for flow in map_flows[:LIVE_TABLE_PREVIEW]:
        row = dict(flow)
        src_ips = row.get("src_ips", [])
        dst_ips = row.get("dst_ips", [])
        row["src_ips"] = ";".join(src_ips) if isinstance(src_ips, list) else src_ips
        row["dst_ips"] = ";".join(dst_ips) if isinstance(dst_ips, list) else dst_ips
        rows.append(row)
    return rows


def live_window_key() -> tuple[int, int, int]:
    """
    功能说明：
        描述当前实时抓包滑动窗口的规模与首尾包序号，写入 LIVE_STATE 供前端展示。

    参数：
        无（读取全局 LIVE_PACKETS，需在 LIVE_PACKETS_LOCK 外或已持锁上下文使用）。

    返回值：
        (窗口包数, 首包 index, 末包 index)；无包时为 (0, 0, 0)。

    备注：
        schedule_live_analysis 工作线程在分析完成后更新 window_first/window_last。
    """
    if not LIVE_PACKETS:
        return (0, 0, 0)
    return (len(LIVE_PACKETS), LIVE_PACKETS[0].index, LIVE_PACKETS[-1].index)


def resolve_geos_cached(ips: set[str], resolve_online: bool) -> dict[str, GeoInfo]:
    """
    功能说明：
        为实时分析批量解析 IP 地理位置，优先使用内存缓存与 geo_overrides，再按需在线查询。

    参数：
        ips: 待解析的 IP 地址集合（通常来自 ip_stats 与 flows）。
        resolve_online: 是否对公网 IP 调用在线 API（每批受 LIVE_ONLINE_RESOLVE_PER_BATCH 限制）。

    返回值：
        子集 dict，键为 IP，值为 GeoInfo；仅包含已成功缓存的条目。

    备注：
        使用全局 LIVE_GEOS_CACHE、LIVE_GEO_OVERRIDES；私网 IP 不走在线 API；
        超额公网 IP 暂用“排队等待在线解析”占位坐标，后续批次继续解析。
    """
    global LIVE_GEO_OVERRIDES
    if LIVE_GEO_OVERRIDES is None:
        LIVE_GEO_OVERRIDES = load_overrides(EXP3_DIR / "geo_overrides.csv")
    to_resolve: set[str] = set()
    for ip in ips:
        if ip in LIVE_GEO_OVERRIDES:
            continue
        cached = LIVE_GEOS_CACHE.get(ip)
        if cached is None or (resolve_online and geo_needs_online_retry(cached)):
            to_resolve.add(ip)
    if to_resolve:
        private_ips = {ip for ip in to_resolve if is_private_or_special(ip)}
        if private_ips:
            LIVE_GEOS_CACHE.update(resolve_geos(private_ips, LIVE_GEO_OVERRIDES, False, throttle_api=False))
        public_ips = [ip for ip in to_resolve if not is_private_or_special(ip)]
        if public_ips and resolve_online:
            budget = LIVE_ONLINE_RESOLVE_PER_BATCH
            LIVE_GEOS_CACHE.update(resolve_geos(set(public_ips[:budget]), LIVE_GEO_OVERRIDES, True, throttle_api=False))
            for ip in public_ips[budget:]:
                LIVE_GEOS_CACHE.setdefault(
                    ip,
                    GeoInfo(ip, "未知", 30.5928, 114.3055, "unknown", "排队等待在线解析"),
                )
        elif public_ips:
            LIVE_GEOS_CACHE.update(resolve_geos(set(public_ips), LIVE_GEO_OVERRIDES, False, throttle_api=False))
    still_missing = {ip for ip in ips if ip not in LIVE_GEOS_CACHE}
    if still_missing:
        LIVE_GEOS_CACHE.update(resolve_geos(still_missing, LIVE_GEO_OVERRIDES, resolve_online, throttle_api=False))
    return {ip: LIVE_GEOS_CACHE[ip] for ip in ips if ip in LIVE_GEOS_CACHE}


def update_live_data_cache(
    pci_rows: list[Any],
    ip_stats: dict[str, dict[str, int]],
    flows: dict[tuple[str, str, str], dict[str, int]],
    locations: list[dict[str, object]],
    map_flows: list[dict[str, object]],
    ip_geos: list[dict[str, object]],
) -> None:
    """
    功能说明：
        根据最新分析结果刷新全局 LIVE_DATA_CACHE，供 /api/live/status 快速返回而无需读盘。

    参数：
        pci_rows: IPv4 PCI 解析结果列表（PcapPacket 或等价结构）。
        ip_stats: IP 统计字典。
        flows: 五元组流字典。
        locations: 地图节点列表。
        map_flows: 地图连线流列表。
        ip_geos: IP 地理信息行（dict 列表）。

    返回值：
        无；原地更新 LIVE_DATA_CACHE。

    备注：
        PCI/表格字段按 LIVE_PCI_PREVIEW、LIVE_TABLE_PREVIEW 截断；
        summary 含 top_received_ips 与 top_flows 摘要。
    """
    global LIVE_DATA_CACHE
    flow_rows = flows_dict_to_rows(flows)
    stat_rows = stats_dict_to_rows(ip_stats)
    pci_preview = [asdict(row) for row in pci_rows[-LIVE_PCI_PREVIEW:]]
    LIVE_DATA_CACHE = {
        "pcaps": [],
        "pci": pci_preview,
        "ipStats": stat_rows[:LIVE_TABLE_PREVIEW],
        "flows": flow_rows[:LIVE_TABLE_PREVIEW],
        "ipGeo": ip_geos[:LIVE_TABLE_PREVIEW],
        "mapFlows": map_flows_for_table(map_flows),
        "summary": {
            "packet_count": len(pci_rows),
            "ip_count": len(ip_stats),
            "top_received_ips": sorted(stat_rows, key=lambda row: int(row["received_packets"]), reverse=True)[:10],
            "top_flows": flow_rows[:20],
        },
        "mapData": {"locations": locations, "flows": map_flows},
        "mapHtml": outputs_rel(LIVE_OUTPUTS_DIR / "traffic_map.html"),
    }


def persist_live_snapshot(
    pci_rows: list[Any],
    ip_stats: dict[str, dict[str, int]],
    flows: dict[tuple[str, str, str], dict[str, int]],
    locations: list[dict[str, object]],
    map_flows: list[dict[str, object]],
    ip_geos: list[dict[str, object]],
    *,
    force: bool = False,
) -> bool:
    """
    功能说明：
        每批实时分析后更新内存缓存，并按间隔将快照写入 LIVE_OUTPUTS_DIR（_live 目录）。

    参数：
        pci_rows、ip_stats、flows、locations、map_flows、ip_geos: 与 update_live_data_cache 相同。
        force: 为 True 时忽略 LIVE_PERSIST_INTERVAL，强制立即写盘（如停止抓包时）。

    返回值：
        True 表示本次已写入磁盘；False 表示仅更新了内存缓存。

    备注：
        使用 LIVE_LAST_PERSIST 与 time.monotonic() 节流，默认至少间隔 LIVE_PERSIST_INTERVAL 秒；
        写入 packet_pci、ip_stats、flows、traffic_summary.json、traffic_map_data.json、ip_geo.csv。
    """
    global LIVE_LAST_PERSIST
    update_live_data_cache(pci_rows, ip_stats, flows, locations, map_flows, ip_geos)
    now = time.monotonic()
    if not force and (now - LIVE_LAST_PERSIST) < LIVE_PERSIST_INTERVAL:
        return False

    LIVE_LAST_PERSIST = now
    outdir = LIVE_OUTPUTS_DIR
    outdir.mkdir(parents=True, exist_ok=True)
    flow_rows = flows_dict_to_rows(flows)
    stat_rows = stats_dict_to_rows(ip_stats)
    pci_preview = [asdict(row) for row in pci_rows[-LIVE_PCI_PREVIEW:]]
    if pci_preview:
        write_csv(outdir / "packet_pci.csv", pci_preview, list(pci_preview[0].keys()))
    write_csv(
        outdir / "ip_stats.csv",
        stat_rows,
        ["ip", "sent_packets", "received_packets", "sent_bytes", "received_bytes", "total_packets", "total_bytes"],
    )
    write_csv(outdir / "flows.csv", flow_rows, ["src_ip", "dst_ip", "protocol", "packets", "bytes"])
    summary = LIVE_DATA_CACHE["summary"]
    summary["pcap"] = str(outdir / "live_capture.pcap")
    (outdir / "traffic_summary.json").write_text(json.dumps(summary, ensure_ascii=False), encoding="utf-8")
    (outdir / "traffic_map_data.json").write_text(
        json.dumps({"locations": locations, "flows": map_flows}, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
    )
    write_csv(outdir / "ip_geo.csv", ip_geos, ["ip", "city", "lat", "lon", "source", "note"])
    return True


def process_live_analysis(resolve_online: bool, public_only: bool, *, force_persist: bool = False) -> dict[str, Any]:
    """
    功能说明：
        对当前 LIVE_PACKETS 滑动窗口执行 IPv4 分析、地理解析与地图聚合，并持久化快照。

    参数：
        resolve_online: 是否在线解析公网 IP 地理信息。
        public_only: 地图是否仅展示公网 IP 相关流。
        force_persist: 是否强制立即写盘（传给 persist_live_snapshot）。

    返回值：
        含 packet_count、ip_count、map（locations/flows 数量）的摘要 dict。

    备注：
        先复制包列表再分析，缩短持锁时间；会递增 LIVE_STATE["map_revision"]；
        应在 LIVE_ANALYSIS_LOCK 保护的工作线程或停止抓包时调用。
    """
    with LIVE_PACKETS_LOCK:
        packets_snapshot = list(LIVE_PACKETS)
    pci_rows, ip_stats, flows = analyze_packets(1, packets_snapshot)
    flow_rows = flows_dict_to_rows(flows)
    stat_rows = stats_dict_to_rows(ip_stats)
    ips = set(ip_stats.keys())
    for row in flow_rows:
        ips.add(row["src_ip"])
        ips.add(row["dst_ip"])
    geos = resolve_geos_cached(ips, resolve_online)
    locations, map_flows, ip_geos = aggregate_map_data(flow_rows, stat_rows, geos, public_only=public_only)
    ip_geo_rows = [asdict(geo) for geo in geos.values()]
    persist_live_snapshot(pci_rows, ip_stats, flows, locations, map_flows, ip_geo_rows, force=force_persist)
    LIVE_STATE["map_revision"] = int(LIVE_STATE.get("map_revision", 0)) + 1
    LIVE_STATE["analyzing"] = False
    return {
        "packet_count": len(pci_rows),
        "ip_count": len(ip_stats),
        "map": {"locations": len(locations), "flows": len(map_flows)},
    }


def schedule_live_analysis(resolve_online: bool, public_only: bool) -> None:
    """
    功能说明：
        异步调度一次实时窗口分析，避免阻塞 Scapy 抓包回调线程。

    参数：
        resolve_online: 传递给 process_live_analysis 的在线解析开关。
        public_only: 是否仅公网流量参与地图。

    返回值：
        无；若已有分析在进行，则设置 analysis_pending，当前任务结束后再链式调度。

    备注：
        使用 daemon 线程 "live-analysis" 与 LIVE_ANALYSIS_LOCK；
        抓包循环每批 accepted>0 时调用；内部嵌套 worker 函数执行实际分析。
    """
    if not LIVE_ANALYSIS_LOCK.acquire(blocking=False):
        LIVE_STATE["analysis_pending"] = True
        return

    def worker(online: bool = resolve_online, pub: bool = public_only) -> None:
        try:
            LIVE_STATE["analyzing"] = True
            LIVE_STATE["analysis_pending"] = False
            result = process_live_analysis(online, pub)
            LIVE_STATE["last_result"] = result
            LIVE_STATE["total_packets"] = len(LIVE_PACKETS)
            key = live_window_key()
            LIVE_STATE["window_first"] = key[1]
            LIVE_STATE["window_last"] = key[2]
        except Exception as exc:  # pragma: no cover - worker guard
            LIVE_STATE["last_error"] = str(exc)
        finally:
            LIVE_STATE["analyzing"] = False
            LIVE_ANALYSIS_LOCK.release()
            pending = LIVE_STATE.pop("analysis_pending", False)
            if pending and LIVE_STATE.get("running"):
                schedule_live_analysis(online, pub)

    threading.Thread(target=worker, daemon=True, name="live-analysis").start()


def reset_live_runtime() -> None:
    """
    功能说明：
        清空实时抓包相关的内存状态，在启动新一轮 live capture 前调用。

    参数：
        无。

    返回值：
        无。

    备注：
        重置 LIVE_PACKETS、LIVE_GEOS_CACHE、LIVE_DATA_CACHE、LIVE_GEO_OVERRIDES、
        LIVE_LAST_PERSIST；与 start_live_capture 配合，避免旧窗口数据污染新会话。
    """
    global LIVE_GEO_OVERRIDES, LIVE_LAST_PERSIST
    LIVE_PACKETS.clear()
    LIVE_GEOS_CACHE.clear()
    LIVE_GEO_OVERRIDES = None
    LIVE_DATA_CACHE.clear()
    LIVE_LAST_PERSIST = 0.0


def get_live_status_data() -> dict[str, Any]:
    """
    功能说明：
        为实时状态 API 提供数据：优先内存缓存，其次 _live 目录快照，最后回退到 read_outputs_data。

    参数：
        无。

    返回值：
        与 read_outputs_data 结构兼容的 dict，可能含 mapRevision 字段。

    备注：
        抓包进行中或 LIVE_DATA_CACHE 非空时走热路径；磁盘 JSON 损坏时静默回退；
        用于 /api/live/start 与 /api/live/status 的 data 字段。
    """
    if LIVE_DATA_CACHE:
        data = dict(LIVE_DATA_CACHE)
        data["mapRevision"] = LIVE_STATE.get("map_revision", 0)
        return data
    map_path = LIVE_OUTPUTS_DIR / "traffic_map_data.json"
    if map_path.exists():
        try:
            map_data = json.loads(map_path.read_text(encoding="utf-8"))
            if map_data.get("locations") or map_data.get("flows"):
                return {
                    "pcaps": [],
                    "pci": csv_rows(LIVE_OUTPUTS_DIR / "packet_pci.csv")[:LIVE_PCI_PREVIEW],
                    "ipStats": csv_rows(LIVE_OUTPUTS_DIR / "ip_stats.csv")[:LIVE_TABLE_PREVIEW],
                    "flows": csv_rows(LIVE_OUTPUTS_DIR / "flows.csv")[:LIVE_TABLE_PREVIEW],
                    "ipGeo": [],
                    "mapFlows": csv_rows(LIVE_OUTPUTS_DIR / "map_flows.csv")[:LIVE_TABLE_PREVIEW],
                    "summary": json.loads((LIVE_OUTPUTS_DIR / "traffic_summary.json").read_text(encoding="utf-8"))
                    if (LIVE_OUTPUTS_DIR / "traffic_summary.json").exists()
                    else {},
                    "mapData": map_data,
                    "mapHtml": outputs_rel(LIVE_OUTPUTS_DIR / "traffic_map.html"),
                    "mapRevision": LIVE_STATE.get("map_revision", 0),
                }
        except (json.JSONDecodeError, OSError):
            pass
    return read_outputs_data(LIVE_OUTPUTS_DIR)


def generate_map(resolve_online: bool = False, public_only: bool | None = None, outdir: Path = OUTPUTS_DIR) -> dict[str, Any]:
    """
    功能说明：
        基于已有 flows.csv 与 ip_stats.csv 重新解析地理信息并生成地图 JSON/HTML。

    参数：
        resolve_online: 是否对公网 IP 调用在线地理 API。
        public_only: 地图过滤公网；None 时使用 LIVE_STATE["public_only"]。
        outdir: 输出目录，默认实验三 outputs。

    返回值：
        {"locations": 节点数, "flows": 流数} 的摘要 dict。

    备注：
        写入 ip_geo.csv、map_flows.csv、traffic_map_data.json、traffic_map.html；
        analyze_pcap 完成分析后及 /api/map、保存 geo overrides 后可能调用。
    """
    flows = read_csv(outdir / "flows.csv")
    stats = read_csv(outdir / "ip_stats.csv")
    ips = {row["ip"] for row in stats}
    for row in flows:
        ips.add(row["src_ip"])
        ips.add(row["dst_ip"])

    geos = resolve_geos(ips, load_overrides(EXP3_DIR / "geo_overrides.csv"), resolve_online)
    if public_only is None:
        public_only = bool(LIVE_STATE.get("public_only"))
    locations, map_flows, ip_geos = aggregate_map_data(flows, stats, geos, public_only=public_only)
    outdir.mkdir(parents=True, exist_ok=True)

    write_csv(outdir / "ip_geo.csv", ip_geos, ["ip", "city", "lat", "lon", "source", "note"])
    map_flow_rows = []
    for flow in map_flows:
        row = dict(flow)
        row["src_ips"] = ";".join(row["src_ips"])
        row["dst_ips"] = ";".join(row["dst_ips"])
        map_flow_rows.append(row)
    write_csv(
        outdir / "map_flows.csv",
        map_flow_rows,
        ["src_city", "dst_city", "src_lat", "src_lon", "dst_lat", "dst_lon", "protocol", "packets", "bytes", "src_ips", "dst_ips"],
    )
    (outdir / "traffic_map_data.json").write_text(
        json.dumps({"locations": locations, "flows": map_flows, "ip_geos": ip_geos}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    write_map_html(outdir / "traffic_map.html", locations, map_flows, ip_geos)
    return {"locations": len(locations), "flows": len(map_flows)}


def analyze_pcap(pcap_path: Path, resolve_online: bool = False, public_only: bool | None = None, outdir: Path = OUTPUTS_DIR) -> dict[str, Any]:
    """
    功能说明：
        读取离线 pcap，执行 IPv4 PCI 分析与统计输出，并可选生成流量地图。

    参数：
        pcap_path: 已校验位于项目内的 pcap 文件路径。
        resolve_online: 是否在线解析 IP 地理信息。
        public_only: 传递给 generate_map 的公网过滤开关。
        outdir: 分析结果输出目录。

    返回值：
        含 pcap 相对路径、pcap_packets、ipv4_packets、ip_count、map 摘要的 dict。

    备注：
        调用 ip_traffic_analyzer 的 read_pcap、analyze_packets、write_outputs；
        对应 POST /api/analyze 核心业务。
    """
    datalink, packets = read_pcap(pcap_path)
    pci_rows, ip_stats, flows = analyze_packets(datalink, packets)
    write_outputs(outdir, pcap_path, pci_rows, ip_stats, flows)
    map_info = generate_map(resolve_online=resolve_online, public_only=public_only, outdir=outdir)
    return {
        "pcap": rel(pcap_path),
        "pcap_packets": len(packets),
        "ipv4_packets": len(pci_rows),
        "ip_count": len(ip_stats),
        "map": map_info,
    }


def capture_packets(payload: dict[str, Any]) -> dict[str, Any]:
    """
    功能说明：
        通过 Scapy 一次性抓取指定数量 IP 包，保存 pcap 与摘要 CSV 到实验二 outputs。

    参数：
        payload: 前端 JSON，可含 count、timeout、filter、iface 等字段。

    返回值：
        含 iface、count、pcap/csv 项目相对路径的 dict；无包时路径为空串。

    备注：
        依赖实验二 sniffer.packet_summary；count 限制 1–1000，timeout 1–300 秒；
        对应 POST /api/capture，与实时 live 抓包独立。
    """
    try:
        from scapy.all import conf, sniff, wrpcap
        from sniffer import packet_summary
    except ImportError as exc:
        raise RuntimeError("Scapy is not installed. Run setup_env.ps1 first.") from exc

    count = max(1, min(int(payload.get("count") or 20), 1000))
    timeout = max(1, min(int(payload.get("timeout") or 20), 300))
    bpf_filter = str(payload.get("filter") or "ip")
    iface = normalize_iface(str(payload.get("iface") or "").strip() or None)

    EXP2_OUTPUTS.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_path = EXP2_OUTPUTS / f"web_capture_{stamp}.pcap"
    csv_path = EXP2_OUTPUTS / f"web_packets_{stamp}.csv"

    packets = sniff(iface=iface, count=count, timeout=timeout, filter=bpf_filter, store=True)
    rows = [packet_summary(packet) for packet in packets]
    if packets:
        wrpcap(str(pcap_path), packets)
        with csv_path.open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
    return {
        "iface": iface or str(conf.iface),
        "count": len(packets),
        "pcap": rel(pcap_path) if packets else "",
        "csv": rel(csv_path) if packets else "",
    }


def live_capture_loop(iface: str | None, batch_count: int, interval: int, bpf_filter: str, resolve_online: bool, max_packets: int, public_only: bool) -> None:
    """
    功能说明：
        在后台线程中循环调用 Scapy sniff，将 IPv4 包写入滑动窗口并触发异步分析。

    参数：
        iface: 网卡名，None 表示默认；会经 normalize_iface 处理。
        batch_count: 每批最多捕获的原始包数量（prn 回调计数）。
        interval: sniff 超时秒数，超时后结束本批。
        bpf_filter: BPF 过滤表达式，默认 "ip"。
        resolve_online: 实时分析是否在线解析地理信息。
        max_packets: LIVE_PACKETS 滑动窗口最大长度。
        public_only: 地图是否仅展示公网流。

    返回值：
        无；线程结束时设置 LIVE_STATE["running"] = False。

    备注：
        由 LIVE_THREAD（daemon "live-capture"）执行；通过 LIVE_STOP 事件停止；
        每批 accepted IPv4 包数 > 0 时调用 schedule_live_analysis；停止时 force 持久化。
    """
    global LIVE_SEQUENCE
    try:
        from scapy.all import conf, sniff
    except ImportError as exc:
        LIVE_STATE["last_error"] = f"Scapy is not installed: {exc}"
        LIVE_STATE["running"] = False
        return

    iface = normalize_iface(iface)
    LIVE_OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    batch_state = {"captured": 0, "accepted": 0}

    # -------------------------------------------------------------------------
    # 嵌套回调 handle_packet（live_capture_loop 内，供 sniff prn= 使用）
    #
    # 功能说明：
    #     每收到一个原始帧即构造 PcapPacket，尝试 IPv4 解析；成功则追加到 LIVE_PACKETS
    #     滑动窗口，超出 max_packets 时丢弃最旧条目。
    # 参数：
    #     packet: Scapy 抓到的报文对象，通过 bytes(packet) 取链路层载荷。
    # 返回值：
    #     无；非 IPv4 包会回退 LIVE_SEQUENCE 且不加入窗口。
    # 备注：
    #     在 Scapy 抓包线程中同步执行，持 LIVE_PACKETS_LOCK 时间应尽量短；
    #     batch_state 统计本批 captured/accepted，供循环末尾判断是否调度分析。
    # -------------------------------------------------------------------------
    def handle_packet(packet: Any) -> None:
        global LIVE_SEQUENCE
        batch_state["captured"] += 1
        raw = bytes(packet)
        timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
        LIVE_SEQUENCE += 1
        pcap_packet = PcapPacket(
            index=LIVE_SEQUENCE,
            timestamp=timestamp,
            captured_length=len(raw),
            original_length=len(raw),
            data=raw,
        )
        if parse_ipv4_packet(pcap_packet, 1) is None:
            LIVE_SEQUENCE -= 1
            return
        batch_state["accepted"] += 1
        with LIVE_PACKETS_LOCK:
            LIVE_PACKETS.append(pcap_packet)
            if len(LIVE_PACKETS) > max_packets:
                del LIVE_PACKETS[: len(LIVE_PACKETS) - max_packets]

    LIVE_STATE.update(
        {
            "running": True,
            "started_at": datetime.now().isoformat(timespec="seconds"),
            "last_update": "",
            "last_error": "",
            "last_result": {},
            "iface": iface or str(conf.iface),
            "filter": bpf_filter,
            "batch_count": batch_count,
            "interval": interval,
            "total_packets": 0,
            "max_packets": max_packets,
            "public_only": public_only,
        }
    )

    while not LIVE_STOP.is_set():
        try:
            batch_state["captured"] = 0
            batch_state["accepted"] = 0
            sniff(
                iface=iface,
                count=batch_count,
                timeout=interval,
                filter=bpf_filter,
                store=False,
                prn=handle_packet,
            )
            if batch_state["accepted"] > 0:
                schedule_live_analysis(resolve_online, public_only)
            LIVE_STATE["last_batch_captured"] = batch_state["captured"]
            LIVE_STATE["last_batch_accepted"] = batch_state["accepted"]
            LIVE_STATE["last_update"] = datetime.now().isoformat(timespec="seconds")
            LIVE_STATE["last_error"] = ""
        except Exception as exc:  # pragma: no cover - long-running guard
            LIVE_STATE["last_error"] = str(exc)
            LIVE_STATE["last_update"] = datetime.now().isoformat(timespec="seconds")

    if LIVE_PACKETS:
        try:
            process_live_analysis(resolve_online, public_only, force_persist=True)
        except Exception as exc:  # pragma: no cover - shutdown guard
            LIVE_STATE["last_error"] = str(exc)
    LIVE_STATE["running"] = False


def start_live_capture(payload: dict[str, Any]) -> dict[str, Any]:
    """
    功能说明：
        停止已有实时抓包（若有），重置运行时状态并启动新的 live_capture_loop 后台线程。

    参数：
        payload: 含 iface、batchCount/count、interval/timeout、maxPackets、filter、
                 resolveOnline、publicOnly 等前端字段。

    返回值：
        当前 LIVE_STATE 的浅拷贝 dict（含 running、iface、filter 等状态）。

    备注：
        使用 LIVE_STOP、LIVE_THREAD；清空 _live 下 traffic_map_data.json 占位；
        对应 POST /api/live/start。
    """
    global LIVE_THREAD, LIVE_SEQUENCE
    if LIVE_THREAD and LIVE_THREAD.is_alive():
        LIVE_STOP.set()
        LIVE_THREAD.join(timeout=8)
        LIVE_STOP.clear()

    iface = normalize_iface(str(payload.get("iface") or "").strip() or None)
    batch_count = max(1, min(int(payload.get("batchCount") or payload.get("count") or 30), 100))
    interval = max(1, min(int(payload.get("interval") or payload.get("timeout") or 5), 60))
    max_packets = max(1, min(int(payload.get("maxPackets") or LIVE_WINDOW_LIMIT), 1000))
    bpf_filter = str(payload.get("filter") or "ip")
    resolve_online = bool(payload.get("resolveOnline"))
    public_only = bool(payload.get("publicOnly"))

    LIVE_SEQUENCE = 0
    LIVE_STOP.clear()
    reset_live_runtime()
    LIVE_STATE["map_revision"] = 0
    LIVE_OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    (LIVE_OUTPUTS_DIR / "traffic_map_data.json").write_text(
        json.dumps({"locations": [], "flows": []}, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
    )
    LIVE_THREAD = threading.Thread(
        target=live_capture_loop,
        args=(iface, batch_count, interval, bpf_filter, resolve_online, max_packets, public_only),
        daemon=True,
        name="live-capture",
    )
    LIVE_THREAD.start()
    return dict(LIVE_STATE)


def stop_live_capture() -> dict[str, Any]:
    """
    功能说明：
        设置停止事件并等待抓包线程结束，使 live_capture_loop 完成收尾分析。

    参数：
        无。

    返回值：
        停止后的 LIVE_STATE 字典副本。

    备注：
        join 超时 8 秒；对应 POST /api/live/stop；
        线程退出前可能对剩余 LIVE_PACKETS 执行 process_live_analysis(force_persist=True)。
    """
    global LIVE_THREAD
    LIVE_STOP.set()
    if LIVE_THREAD and LIVE_THREAD.is_alive():
        LIVE_THREAD.join(timeout=8)
    return dict(LIVE_STATE)


def list_interfaces() -> list[str]:
    """
    功能说明：
        枚举本机 Scapy 可见的网络接口列表，供前端下拉选择网卡。

    参数：
        无。

    返回值：
        接口名字符串列表；未安装 Scapy 时返回空列表 []。

    备注：
        对应 GET /api/interfaces；名称经 normalize_iface 可与 GUID 互转。
    """
    try:
        from scapy.all import get_if_list
    except ImportError:
        return []
    return list(get_if_list())


def get_data() -> dict[str, Any]:
    """
    功能说明：
        读取实验三默认 outputs 目录的完整分析数据，作为页面初始/分析后数据源。

    参数：
        无。

    返回值：
        read_outputs_data(OUTPUTS_DIR) 返回的聚合 dict。

    备注：
        用于 GET /api/data 及多次 POST 成功后的 data 字段刷新。
    """
    return read_outputs_data(OUTPUTS_DIR)


def save_geo_overrides(rows: list[dict[str, Any]]) -> None:
    """
    功能说明：
        校验并保存用户自定义 IP 地理覆盖表到 geo_overrides.csv。

    参数：
        rows: 每项含 ip、city、lat、lon、note 的字典列表；缺必填字段的行被跳过。

    返回值：
        无；调用 traffic_map.write_csv 写入 EXP3_DIR/geo_overrides.csv。

    备注：
        保存后 analyze/generate_map 会 load_overrides；实时分析中 LIVE_GEO_OVERRIDES 需重启抓包才重载；
        对应 POST /api/geo-overrides。
    """
    normalized = []
    for row in rows:
        ip = str(row.get("ip", "")).strip()
        city = str(row.get("city", "")).strip()
        lat = str(row.get("lat", "")).strip()
        lon = str(row.get("lon", "")).strip()
        note = str(row.get("note", "")).strip()
        if not ip or not city or not lat or not lon:
            continue
        normalized.append({"ip": ip, "city": city, "lat": float(lat), "lon": float(lon), "note": note})
    write_csv(EXP3_DIR / "geo_overrides.csv", normalized, ["ip", "city", "lat", "lon", "note"])


class AppHandler(BaseHTTPRequestHandler):
    """
    功能说明：
        实验三流量地图 Web 应用的 HTTP 请求处理器，路由静态资源与 REST API。

    参数：
        继承 BaseHTTPRequestHandler，由 ThreadingHTTPServer 为每个连接实例化。

    返回值：
        无（类本身）；各方法通过 send_response / json_response 写回客户端。

    备注：
        使用多线程 ThreadingHTTPServer，抓包与分析在独立线程，需注意 LIVE_* 全局状态并发；
        静态文件仅允许 STATIC_DIR 与 OUTPUTS_DIR 下的路径。
    """

    server_version = "TrafficMapHTTP/1.0"

    def do_GET(self) -> None:  # noqa: N802
        """
        功能说明：
            处理 GET：首页与 /static、/outputs 静态文件，以及 data、pcaps、interfaces、
            live/status、geo-overrides 等只读 API。

        参数：
            无（使用 self.path、self.headers）。

        返回值：
            无；成功时写入文件或 JSON，失败时 error_response。

        备注：
            /api/live/status 在抓包中或 LIVE_DATA_CACHE 存在时返回实时数据，否则为离线 outputs；
            异常统一捕获为 500 JSON 错误。
        """
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/" or parsed.path == "/index.html":
                self.serve_file(STATIC_DIR / "index.html")
            elif parsed.path.startswith("/static/"):
                self.serve_file(STATIC_DIR / parsed.path.removeprefix("/static/"))
            elif parsed.path.startswith("/outputs/"):
                self.serve_file(OUTPUTS_DIR / parsed.path.removeprefix("/outputs/"))
            elif parsed.path == "/api/data":
                json_response(self, {"ok": True, "data": get_data()})
            elif parsed.path == "/api/pcaps":
                json_response(self, {"ok": True, "pcaps": list_pcaps()})
            elif parsed.path == "/api/interfaces":
                json_response(self, {"ok": True, "interfaces": list_interfaces()})
            elif parsed.path == "/api/live/status":
                if LIVE_STATE.get("running"):
                    live_data = get_live_status_data()
                elif LIVE_DATA_CACHE:
                    live_data = get_live_status_data()
                else:
                    live_data = read_outputs_data(OUTPUTS_DIR)
                live_payload = dict(LIVE_STATE)
                json_response(self, {"ok": True, "live": live_payload, "data": live_data}, compact=True)
            elif parsed.path == "/api/geo-overrides":
                json_response(self, {"ok": True, "rows": csv_rows(EXP3_DIR / "geo_overrides.csv")})
            elif parsed.path == "/api/open-output":
                query = parse_qs(parsed.query)
                name = query.get("name", ["traffic_map.html"])[0]
                self.serve_file(OUTPUTS_DIR / name)
            else:
                error_response(self, "not found", HTTPStatus.NOT_FOUND)
        except Exception as exc:  # pragma: no cover - request guard
            error_response(self, str(exc), HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_POST(self) -> None:  # noqa: N802
        """
        功能说明：
            处理 POST：分析 pcap、生成地图、单次抓包、启停实时抓包、保存地理覆盖等写操作 API。

        参数：
            无；请求体经 read_body(self) 解析为 JSON dict。

        返回值：
            无；各路由返回 ok/result/data/live 等 JSON 字段。

        备注：
            /api/analyze 支持 pcap 路径或 pcapIndex；会更新 LIVE_STATE["public_only"]；
            live/start、live/stop 与全局 LIVE_THREAD、LIVE_STOP 交互。
        """
        parsed = urlparse(self.path)
        try:
            payload = read_body(self)
            if parsed.path == "/api/analyze":
                pcap_value = str(payload.get("pcap") or "")
                if not pcap_value and payload.get("pcapIndex") is not None:
                    pcaps = list_pcaps()
                    index = int(payload["pcapIndex"])
                    if index < 0 or index >= len(pcaps):
                        raise ValueError("pcapIndex is out of range")
                    pcap_value = pcaps[index]["path"]
                if not pcap_value:
                    raise ValueError("pcap or pcapIndex is required")
                LIVE_STATE["public_only"] = bool(payload.get("publicOnly"))
                result = analyze_pcap(safe_project_path(pcap_value), bool(payload.get("resolveOnline")), public_only=bool(payload.get("publicOnly")))
                json_response(self, {"ok": True, "result": result, "data": get_data()})
            elif parsed.path == "/api/map":
                LIVE_STATE["public_only"] = bool(payload.get("publicOnly"))
                result = generate_map(bool(payload.get("resolveOnline")), public_only=bool(payload.get("publicOnly")))
                json_response(self, {"ok": True, "result": result, "data": get_data()})
            elif parsed.path == "/api/capture":
                result = capture_packets(payload)
                json_response(self, {"ok": True, "result": result, "pcaps": list_pcaps()})
            elif parsed.path == "/api/live/start":
                result = start_live_capture(payload)
                json_response(self, {"ok": True, "live": result, "data": get_live_status_data()}, compact=True)
            elif parsed.path == "/api/live/stop":
                result = stop_live_capture()
                json_response(self, {"ok": True, "live": result})
            elif parsed.path == "/api/geo-overrides":
                rows = payload.get("rows")
                if not isinstance(rows, list):
                    raise ValueError("rows must be a list")
                save_geo_overrides(rows)
                result = generate_map(bool(payload.get("resolveOnline"))) if (OUTPUTS_DIR / "flows.csv").exists() else {}
                json_response(self, {"ok": True, "result": result, "rows": csv_rows(EXP3_DIR / "geo_overrides.csv"), "data": get_data()})
            else:
                error_response(self, "not found", HTTPStatus.NOT_FOUND)
        except Exception as exc:  # pragma: no cover - request guard
            error_response(self, str(exc), HTTPStatus.INTERNAL_SERVER_ERROR)

    def serve_file(self, path: Path) -> None:
        """
        功能说明：
            在路径白名单内读取文件并以合适 Content-Type 返回给浏览器。

        参数：
            path: 相对于 STATIC_DIR 或 OUTPUTS_DIR 拼接后的文件 Path。

        返回值：
            无；403/404 时调用 error_response，成功时写入二进制正文。

        备注：
            仅允许 resolved 路径前缀匹配 STATIC_DIR 或 OUTPUTS_DIR；
            html/css/js/json/csv 附加 charset=utf-8。
        """
        resolved = path.resolve()
        allowed = [STATIC_DIR.resolve(), OUTPUTS_DIR.resolve()]
        if not any(str(resolved).lower().startswith(str(root).lower()) for root in allowed):
            error_response(self, "file access denied", HTTPStatus.FORBIDDEN)
            return
        if not resolved.exists() or not resolved.is_file():
            error_response(self, "file not found", HTTPStatus.NOT_FOUND)
            return
        content = resolved.read_bytes()
        content_type = mimetypes.guess_type(str(resolved))[0] or "application/octet-stream"
        if resolved.suffix.lower() in {".html", ".css", ".js", ".json", ".csv"}:
            content_type += "; charset=utf-8"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, fmt: str, *args: Any) -> None:
        """
        功能说明：
            重写基类日志方法，在控制台打印带时间戳的访问记录，便于实验调试。

        参数：
            fmt: 日志格式字符串（基类传入）。
            *args: 格式化参数，通常含请求行与状态码。

        返回值：
            无；打印到标准输出。

        备注：
            不写入文件；多线程下各行日志可能交错。
        """
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {self.address_string()} {fmt % args}")


def build_parser() -> argparse.ArgumentParser:
    """
    功能说明：
        构建命令行参数解析器，配置 Web 服务监听地址与端口。

    参数：
        无。

    返回值：
        已添加 --host、--port 参数的 argparse.ArgumentParser 实例。

    备注：
        默认 127.0.0.1:8088，仅供本机实验访问；由 main() 调用 parse_args。
    """
    parser = argparse.ArgumentParser(description="Start local traffic map web app")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8088)
    return parser


def main() -> int:
    """
    功能说明：
        程序入口：创建 outputs 目录、启动 ThreadingHTTPServer 并阻塞直至 Ctrl+C。

    参数：
        无（从 sys.argv 读取 build_parser 定义的参数）。

    返回值：
        正常退出为 0。

    备注：
        使用 AppHandler 与多线程 HTTP 服务；KeyboardInterrupt 时关闭 server；
        脚本可直接 python server.py 或由 __main__ 调用。
    """
    args = build_parser().parse_args()
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer((args.host, args.port), AppHandler)
    print(f"Traffic map web app: http://{args.host}:{args.port}/")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
