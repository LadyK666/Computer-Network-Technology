#!/usr/bin/env python3
"""
实验三：根据 IP 流量统计结果生成自包含的流量地图。

功能说明:
    读取实验三输出的 flows.csv、ip_stats.csv，将 IP 解析为城市与经纬度，
    按地点聚合流量，并生成 HTML 地图、CSV 与 JSON 等可视化与中间数据文件。

输入数据:
    - flows.csv: 五元组/协议级流记录（源/目的 IP、协议、包数、字节数等）
    - ip_stats.csv: 各 IP 的发送/接收包与字节统计
    - geo_overrides.csv（可选）: 手工覆盖的 IP 地理位置

输出产物（默认 outputs/ 目录）:
    - traffic_map.html: 内嵌 SVG 的流量地理示意图
    - ip_geo.csv / map_flows.csv / traffic_map_data.json: 结构化数据

备注:
    公网 IP 可通过 --resolve-online 调用免费 API 查询地理信息；
    内网/组播等地址使用默认本地坐标（武汉），不发起外网请求。
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import math
import time
import urllib.error
import urllib.request
from collections import defaultdict
from dataclasses import asdict, dataclass
from html import escape
from pathlib import Path


DEFAULT_LOCAL_CITY = "武汉"
DEFAULT_LOCAL_LAT = 30.5928
DEFAULT_LOCAL_LON = 114.3055


@dataclass(frozen=True)
class GeoInfo:
    """
    单个 IP 地址的地理位置与解析来源信息。

    功能说明:
        不可变数据类，用于在解析、聚合与导出阶段统一表示 IP 对应的
        城市名、经纬度及数据从何而来（本地默认、手工覆盖、在线 API 等）。

    属性:
        ip: IP 地址字符串（IPv4/IPv6）。
        city: 城市或地区名称；无法定位时为「未知」。
        lat: 纬度（度，WGS84）。
        lon: 经度（度，WGS84）。
        source: 来源标识，如 local-default、override、ip-api、unknown。
        note: 补充说明（国家名、内网提示、失败原因等），默认为空。

    备注:
        frozen=True 保证实例不可变，便于作为字典键的组成部分或缓存结果。
    """

    ip: str
    city: str
    lat: float
    lon: float
    source: str
    note: str = ""


def read_csv(path: Path) -> list[dict[str, str]]:
    """
    从 CSV 文件读取全部行并转为字典列表。

    功能说明:
        使用 utf-8-sig 编码打开文件，自动处理 BOM，每行对应一个字段名到字符串值的字典。

    参数:
        path: CSV 文件路径。

    返回值:
        由 csv.DictReader 生成的字典列表；若文件无数据行则返回空列表。

    备注:
        文件不存在时抛出 FileNotFoundError，便于在流水线早期发现路径错误。
    """
    if not path.exists():
        raise FileNotFoundError(f"CSV file not found: {path}")
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, object]], fieldnames: list[str]) -> None:
    """
    将字典行列表写入 CSV 文件。

    功能说明:
        若父目录不存在则自动创建，写入表头后按 fieldnames 顺序写出各行。

    参数:
        path: 目标 CSV 路径。
        rows: 每行一个字典，键应与 fieldnames 对应。
        fieldnames: 列名顺序列表，决定输出表头与列顺序。

    返回值:
        无。

    备注:
        使用 utf-8-sig 编码，便于 Excel 正确识别中文；缺失键的列会留空。
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def load_overrides(path: Path) -> dict[str, GeoInfo]:
    """
    从手工地理位置覆盖表加载 IP 到 GeoInfo 的映射。

    功能说明:
        读取 geo_overrides.csv（或同类格式），每行包含 ip、city、lat、lon 及可选 note，
        用于在在线解析失败或实验环境无公网时固定某些 IP 的显示位置。

    参数:
        path: 覆盖表 CSV 路径。

    返回值:
        键为 IP 字符串、值为 GeoInfo 的字典；文件不存在时返回空字典。

    备注:
        source 字段统一设为 override，与在线 API 结果区分。
    """
    overrides: dict[str, GeoInfo] = {}
    if not path.exists():
        return overrides
    for row in read_csv(path):
        ip = row["ip"].strip()
        overrides[ip] = GeoInfo(
            ip=ip,
            city=row["city"].strip(),
            lat=float(row["lat"]),
            lon=float(row["lon"]),
            source="override",
            note=row.get("note", "").strip(),
        )
    return overrides


def is_private_or_special(ip: str) -> bool:
    """
    判断 IP 是否为内网、环回、链路本地、保留或组播等特殊地址。

    功能说明:
        利用标准库 ipaddress 解析地址并检查 RFC 定义的私有与特殊用途范围，
        用于决定是否应使用本地默认坐标而非调用公网地理 API。

    参数:
        ip: 待检查的 IP 字符串。

    返回值:
        若为私有或特殊地址返回 True，否则为公网可查询地址返回 False。

    备注:
        与 is_local_or_multicast 判断集合相同，语义上强调「不宜在线定位」。
    """
    address = ipaddress.ip_address(ip)
    return address.is_private or address.is_loopback or address.is_link_local or address.is_reserved or address.is_multicast


def is_local_or_multicast(ip: str) -> bool:
    """
    判断 IP 是否应视为「本地侧」端点（内网/环回/链路本地/保留/组播）。

    功能说明:
        在 --public-only 模式下过滤流：仅当源与目的均为本地或组播地址时才隐藏该流，
        从而地图侧重展示涉及公网或跨地域的通信。

    参数:
        ip: 待检查的 IP 字符串。

    返回值:
        属于本地或组播等特殊范围时返回 True。

    备注:
        实现与 is_private_or_special 一致，函数名表达在流量过滤场景中的用途。
    """
    address = ipaddress.ip_address(ip)
    return address.is_private or address.is_loopback or address.is_link_local or address.is_reserved or address.is_multicast


def geo_needs_online_retry(geo: GeoInfo | None) -> bool:
    """
    判断某 IP 的地理信息是否仍需或适合再次尝试在线解析。

    功能说明:
        当尚未有记录，或来源为 unknown、城市为「未知」时，认为需要重试在线查询。

    参数:
        geo: 已有的 GeoInfo，或 None 表示尚未解析。

    返回值:
        需要（或值得）在线重试时返回 True，否则 False。

    备注:
        本模块主流程在 resolve_geos 中一次性解析；此函数便于扩展增量更新逻辑。
    """
    if geo is None:
        return True
    return geo.source == "unknown" or geo.city == "未知"


def resolve_ip_api(ip: str, timeout: int = 5) -> GeoInfo | None:
    """
    通过 ip-api.com 免费接口查询公网 IP 的地理位置。

    功能说明:
        发起 HTTP GET 请求，解析 JSON 中的城市、经纬度与国家信息，
        组装为 GeoInfo，source 标记为 ip-api。

    参数:
        ip: 公网 IP 地址字符串。
        timeout: 套接字读取超时秒数，默认 5。

    返回值:
        查询成功时返回 GeoInfo；网络错误、超时、JSON 无效或 status 非 success 时返回 None。

    备注:
        免费接口有频率限制，批量调用时应配合 resolve_geos 中的节流 sleep。
    """
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,query&lang=zh-CN"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None
    if payload.get("status") != "success":
        return None
    city = payload.get("city") or payload.get("regionName") or payload.get("country") or "未知"
    return GeoInfo(
        ip=ip,
        city=city,
        lat=float(payload["lat"]),
        lon=float(payload["lon"]),
        source="ip-api",
        note=payload.get("country", ""),
    )


def resolve_ip_whois(ip: str, timeout: int = 5) -> GeoInfo | None:
    """
    通过 ipwho.is 接口作为备用方案查询 IP 地理位置。

    功能说明:
        当 ip-api 失败时，resolve_ip_online 会调用本函数；解析 latitude/longitude
        与城市、国家字段并构造 GeoInfo。

    参数:
        ip: 公网 IP 地址字符串。
        timeout: 请求超时秒数，默认 5。

    返回值:
        success 为真时返回 GeoInfo（source=ipwhois），否则返回 None。

    备注:
        与 resolve_ip_api 互为备份，提高实验环境下至少一种服务可用的概率。
    """
    url = f"https://ipwho.is/{ip}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None
    if not payload.get("success"):
        return None
    city = payload.get("city") or payload.get("region") or payload.get("country") or "未知"
    return GeoInfo(
        ip=ip,
        city=city,
        lat=float(payload["latitude"]),
        lon=float(payload["longitude"]),
        source="ipwhois",
        note=payload.get("country", ""),
    )


def resolve_ip_online(ip: str, timeout: int = 5) -> GeoInfo | None:
    """
    在线解析单个公网 IP：优先 ip-api，失败则尝试 ipwho.is。

    功能说明:
        封装双 API 回退策略，对调用方提供统一的「一次调用、尽量成功」接口。

    参数:
        ip: 公网 IP 地址。
        timeout: 各次 HTTP 请求的超时秒数。

    返回值:
        任一服务成功则返回对应 GeoInfo，全部失败返回 None。
    """
    geo = resolve_ip_api(ip, timeout)
    if geo:
        return geo
    return resolve_ip_whois(ip, timeout)


def resolve_geos(ips: set[str], overrides: dict[str, GeoInfo], resolve_online: bool, *, throttle_api: bool = True) -> dict[str, GeoInfo]:
    """
    批量将 IP 集合解析为 GeoInfo 字典。

    功能说明:
        按 IP 排序后依次处理：手工覆盖优先；内网/特殊地址使用武汉默认坐标；
        公网地址在 resolve_online 为真时调用在线 API，失败则标记 unknown 并落在默认经纬度。

    参数:
        ips: 需要定位的 IP 集合（通常来自 flows 与 ip_stats）。
        overrides: load_overrides 返回的覆盖表。
        resolve_online: 是否对公网 IP 发起在线查询。
        throttle_api: 为 True 时，对 ip-api 连续调用间隔约 1.35 秒，避免触发限流。

    返回值:
        键为 IP、值为 GeoInfo 的完整映射，覆盖输入集合中的每个 IP。

    备注:
        仅对 source 为 ip-api 的成功结果计数节流；ipwhois 备份不增加 sleep 计数。
    """
    geos: dict[str, GeoInfo] = {}
    api_calls = 0
    for ip in sorted(ips):
        if ip in overrides:
            geos[ip] = overrides[ip]
            continue
        if is_private_or_special(ip):
            geos[ip] = GeoInfo(ip, DEFAULT_LOCAL_CITY, DEFAULT_LOCAL_LAT, DEFAULT_LOCAL_LON, "local-default", "内网或特殊地址无法通过公网接口定位")
            continue
        online_geo = None
        if resolve_online:
            if throttle_api and api_calls > 0:
                time.sleep(1.35)
            online_geo = resolve_ip_online(ip)
            if online_geo and online_geo.source == "ip-api":
                api_calls += 1
        if online_geo:
            geos[ip] = online_geo
        else:
            note = "在线接口未返回结果（可稍后重试或写入地理位置配置）" if resolve_online else "未启用在线解析"
            geos[ip] = GeoInfo(ip, "未知", DEFAULT_LOCAL_LAT, DEFAULT_LOCAL_LON, "unknown", note)
    return geos


def aggregate_map_data(flows: list[dict[str, str]], stats: list[dict[str, str]], geos: dict[str, GeoInfo], public_only: bool = False) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    """
    将流表、IP 统计与地理信息聚合为地图所需的三个数据集。

    功能说明:
        1) 按可选 public_only 过滤流并收集可见 IP；
        2) 按城市聚合 ip_stats 中的收发包与字节，得到 locations；
        3) 按（源城市、目的城市、协议）聚合可见流，得到 map_flows；
        4) 导出全部 IP 的 GeoInfo 序列化行 ip_geo_rows。

    参数:
        flows: read_csv 读取的流记录列表。
        stats: read_csv 读取的 per-IP 统计列表。
        geos: resolve_geos 产生的 IP→GeoInfo 映射。
        public_only: 为 True 时忽略「源与目的均为本地/组播」的流，且统计仅含可见流涉及的 IP。

    返回值:
        三元组 (locations, map_flows, ip_geo_rows):
        - locations: 按城市汇总的流量与 IP 列表、总包/字节等；
        - map_flows: 城市间流向，含经纬度、协议、包字节及涉及的 IP 集合；
        - ip_geo_rows: 各 GeoInfo 的 dict 形式，用于写 ip_geo.csv。

    备注:
        map_flows 按 bytes 降序排序；locations 内 ips 字段由 set 转为排序列表便于 JSON/CSV。
    """
    visible_flows = []
    visible_ips: set[str] = set()
    for row in flows:
        if public_only and is_local_or_multicast(row["src_ip"]) and is_local_or_multicast(row["dst_ip"]):
            continue
        visible_flows.append(row)
        visible_ips.add(row["src_ip"])
        visible_ips.add(row["dst_ip"])

    location_stats: dict[str, dict[str, object]] = {}
    for row in stats:
        ip = row["ip"]
        if public_only and ip not in visible_ips:
            continue
        geo = geos[ip]
        key = geo.city
        entry = location_stats.setdefault(
            key,
            {
                "city": geo.city,
                "lat": geo.lat,
                "lon": geo.lon,
                "ips": set(),
                "sent_packets": 0,
                "received_packets": 0,
                "sent_bytes": 0,
                "received_bytes": 0,
            },
        )
        entry["ips"].add(ip)
        entry["sent_packets"] += int(row.get("sent_packets") or 0)
        entry["received_packets"] += int(row.get("received_packets") or 0)
        entry["sent_bytes"] += int(row.get("sent_bytes") or 0)
        entry["received_bytes"] += int(row.get("received_bytes") or 0)

    locations = []
    for entry in location_stats.values():
        copied = dict(entry)
        copied["ips"] = sorted(copied["ips"])
        copied["total_packets"] = copied["sent_packets"] + copied["received_packets"]
        copied["total_bytes"] = copied["sent_bytes"] + copied["received_bytes"]
        locations.append(copied)

    flow_groups: dict[tuple[str, str, str], dict[str, object]] = defaultdict(lambda: {"packets": 0, "bytes": 0, "src_ips": set(), "dst_ips": set()})
    for row in visible_flows:
        src_geo = geos[row["src_ip"]]
        dst_geo = geos[row["dst_ip"]]
        key = (src_geo.city, dst_geo.city, row["protocol"])
        group = flow_groups[key]
        group["src_city"] = src_geo.city
        group["dst_city"] = dst_geo.city
        group["src_lat"] = src_geo.lat
        group["src_lon"] = src_geo.lon
        group["dst_lat"] = dst_geo.lat
        group["dst_lon"] = dst_geo.lon
        group["protocol"] = row["protocol"]
        group["packets"] += int(row.get("packets") or 0)
        group["bytes"] += int(row.get("bytes") or 0)
        group["src_ips"].add(row["src_ip"])
        group["dst_ips"].add(row["dst_ip"])

    map_flows = []
    for group in flow_groups.values():
        copied = dict(group)
        copied["src_ips"] = sorted(copied["src_ips"])
        copied["dst_ips"] = sorted(copied["dst_ips"])
        map_flows.append(copied)

    ip_geo_rows = [asdict(geo) for geo in geos.values()]
    return locations, sorted(map_flows, key=lambda item: item["bytes"], reverse=True), ip_geo_rows


def project(lon: float, lat: float, width: int, height: int, bounds: tuple[float, float, float, float]) -> tuple[float, float]:
    """
    将经纬度线性映射到 SVG 画布像素坐标。

    功能说明:
        在给定经纬度边界框内做等比例线性变换：经度映射到 x，纬度映射到 y
        （北纬向上，故 y 轴对纬度做翻转，使地图上方向与习惯一致）。

    参数:
        lon: 经度。
        lat: 纬度。
        width: 画布宽度（像素）。
        height: 画布高度（像素）。
        bounds: (min_lon, max_lon, min_lat, max_lat) 显示范围。

    返回值:
        (x, y) 像素坐标，原点在画布左上角。

    备注:
        假定 max_lon > min_lon 且 max_lat > min_lat；边界由 build_bounds 保证有效跨度。
    """
    min_lon, max_lon, min_lat, max_lat = bounds
    x = (lon - min_lon) / (max_lon - min_lon) * width
    y = height - (lat - min_lat) / (max_lat - min_lat) * height
    return x, y


def build_bounds(locations: list[dict[str, object]]) -> tuple[float, float, float, float]:
    """
    根据各地点经纬度计算地图显示用的经纬度边界（含留白）。

    功能说明:
        取所有 location 的 min/max 经纬度；若某方向跨度为 0 则人工扩展 ±3 度；
        再按跨度的 20% 或至少 2 度添加 padding，避免点贴边。

    参数:
        locations: aggregate_map_data 返回的地点列表，每项含 lat、lon。

    返回值:
        (min_lon, max_lon, min_lat, max_lat) 供 project 使用的显示范围。

    备注:
        无地点时由 write_map_html 使用中国范围的默认 bounds。
    """
    lons = [float(item["lon"]) for item in locations]
    lats = [float(item["lat"]) for item in locations]
    min_lon, max_lon = min(lons), max(lons)
    min_lat, max_lat = min(lats), max(lats)
    if math.isclose(min_lon, max_lon):
        min_lon -= 3
        max_lon += 3
    if math.isclose(min_lat, max_lat):
        min_lat -= 3
        max_lat += 3
    lon_pad = max((max_lon - min_lon) * 0.2, 2)
    lat_pad = max((max_lat - min_lat) * 0.2, 2)
    return min_lon - lon_pad, max_lon + lon_pad, min_lat - lat_pad, max_lat + lat_pad


def write_map_html(path: Path, locations: list[dict[str, object]], flows: list[dict[str, object]], ip_geos: list[dict[str, object]]) -> None:
    """
    生成自包含的 traffic_map.html，内嵌 SVG 地图与数据表格。

    功能说明:
        将城市间流画为带箭头的线段（线宽与字节数成正比），城市画为圆点（半径与包量相关），
        并附带「地点间流量」与「IP 地理位置来源」两个 HTML 表格；样式与脚本均内联，可离线打开。

    参数:
        path: 输出 HTML 文件路径。
        locations: 按城市聚合后的地点统计列表。
        flows: 城市间聚合流列表（含经纬度与协议等）。
        ip_geos: 各 IP 地理信息的字典列表。

    返回值:
        无；结果写入 path，编码 utf-8。

    备注:
        使用 html.escape 防止城市名等注入；悬停 title 展示详细包/字节信息。
    """
    width = 960
    height = 560
    bounds = build_bounds(locations) if locations else (70, 140, 15, 55)
    max_flow_bytes = max([int(flow["bytes"]) for flow in flows] or [1])
    max_packets = max([int(location["total_packets"]) for location in locations] or [1])

    flow_svg = []
    for flow in flows:
        x1, y1 = project(float(flow["src_lon"]), float(flow["src_lat"]), width, height, bounds)
        x2, y2 = project(float(flow["dst_lon"]), float(flow["dst_lat"]), width, height, bounds)
        stroke_width = 1.5 + 5 * int(flow["bytes"]) / max_flow_bytes
        flow_svg.append(
            f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
            f'stroke="#d35400" stroke-width="{stroke_width:.2f}" stroke-opacity="0.72" marker-end="url(#arrow)">'
            f'<title>{escape(flow["src_city"])} -> {escape(flow["dst_city"])} | {escape(flow["protocol"])} | '
            f'{flow["packets"]} packets | {flow["bytes"]} bytes</title></line>'
        )

    location_svg = []
    for location in locations:
        x, y = project(float(location["lon"]), float(location["lat"]), width, height, bounds)
        radius = 7 + 18 * math.sqrt(int(location["total_packets"]) / max_packets)
        title = f'{location["city"]} | IP: {", ".join(location["ips"])} | received: {location["received_packets"]} packets'
        location_svg.append(
            f'<g><circle cx="{x:.1f}" cy="{y:.1f}" r="{radius:.1f}" fill="#1f77b4" fill-opacity="0.78">'
            f'<title>{escape(title)}</title></circle>'
            f'<text x="{x + radius + 4:.1f}" y="{y + 4:.1f}">{escape(str(location["city"]))}</text></g>'
        )

    flow_rows = "\n".join(
        "<tr>"
        f"<td>{escape(str(flow['src_city']))}</td>"
        f"<td>{escape(str(flow['dst_city']))}</td>"
        f"<td>{escape(str(flow['protocol']))}</td>"
        f"<td>{flow['packets']}</td>"
        f"<td>{flow['bytes']}</td>"
        "</tr>"
        for flow in flows
    )
    ip_rows = "\n".join(
        "<tr>"
        f"<td>{escape(str(row['ip']))}</td>"
        f"<td>{escape(str(row['city']))}</td>"
        f"<td>{row['lat']}</td>"
        f"<td>{row['lon']}</td>"
        f"<td>{escape(str(row['source']))}</td>"
        f"<td>{escape(str(row.get('note', '')))}</td>"
        "</tr>"
        for row in ip_geos
    )

    html = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>流量地图</title>
  <style>
    body {{ margin: 0; font-family: Arial, "Microsoft YaHei", sans-serif; color: #202124; background: #f8fafc; }}
    header {{ padding: 18px 24px; background: #ffffff; border-bottom: 1px solid #d8dee8; }}
    h1 {{ margin: 0 0 6px; font-size: 24px; }}
    main {{ padding: 18px 24px 28px; }}
    .map {{ background: #ffffff; border: 1px solid #d8dee8; border-radius: 8px; overflow: hidden; }}
    svg {{ width: 100%; height: auto; display: block; background: linear-gradient(180deg, #eef6ff, #ffffff); }}
    text {{ font-size: 13px; fill: #1f2937; paint-order: stroke; stroke: #fff; stroke-width: 3px; }}
    table {{ width: 100%; border-collapse: collapse; background: #ffffff; margin-top: 16px; font-size: 13px; }}
    th, td {{ padding: 8px 10px; border-bottom: 1px solid #e5e7eb; text-align: left; }}
    th {{ background: #f1f5f9; }}
    .note {{ color: #5f6b7a; margin: 0; }}
  </style>
</head>
<body>
  <header>
    <h1>流量地图</h1>
    <p class="note">圆点大小表示地点相关包数量，连线粗细表示源地点到目的地点的字节数；鼠标悬停可查看具体流量。</p>
  </header>
  <main>
    <section class="map">
      <svg viewBox="0 0 {width} {height}" role="img" aria-label="traffic map">
        <defs>
          <marker id="arrow" markerWidth="12" markerHeight="12" refX="10" refY="3" orient="auto" markerUnits="strokeWidth">
            <path d="M0,0 L0,6 L10,3 z" fill="#d35400"></path>
          </marker>
        </defs>
        <rect x="0" y="0" width="{width}" height="{height}" fill="transparent"></rect>
        {"".join(flow_svg)}
        {"".join(location_svg)}
      </svg>
    </section>
    <h2>地点间流量</h2>
    <table>
      <thead><tr><th>源地点</th><th>目的地点</th><th>协议</th><th>包数量</th><th>字节数</th></tr></thead>
      <tbody>{flow_rows}</tbody>
    </table>
    <h2>IP 地理位置来源</h2>
    <table>
      <thead><tr><th>IP</th><th>地点</th><th>纬度</th><th>经度</th><th>来源</th><th>说明</th></tr></thead>
      <tbody>{ip_rows}</tbody>
    </table>
  </main>
</body>
</html>
"""
    path.write_text(html, encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    """
    构建命令行参数解析器。

    功能说明:
        定义实验三流量地图脚本的输入输出路径及行为开关（在线解析、仅公网流等），
        默认路径相对于本脚本所在目录的 outputs/ 与 geo_overrides.csv。

    参数:
        无。

    返回值:
        配置完成的 argparse.ArgumentParser 实例，供 main 中 parse_args 使用。

    备注:
        --resolve-online 需显式指定才会访问外网 API；适合实验报告 reproducibility 说明。
    """
    default_dir = Path(__file__).with_name("outputs")
    parser = argparse.ArgumentParser(description="Build traffic map from flows.csv and ip_stats.csv")
    parser.add_argument("--flows", type=Path, default=default_dir / "flows.csv", help="flows.csv path")
    parser.add_argument("--stats", type=Path, default=default_dir / "ip_stats.csv", help="ip_stats.csv path")
    parser.add_argument("--overrides", type=Path, default=Path(__file__).with_name("geo_overrides.csv"), help="IP geolocation override CSV")
    parser.add_argument("--outdir", type=Path, default=default_dir, help="output directory")
    parser.add_argument("--resolve-online", action="store_true", help="resolve public IP locations with ip-api.com")
    parser.add_argument("--public-only", action="store_true", help="hide flows where both endpoints are local or multicast addresses")
    return parser


def main() -> int:
    """
    程序入口：读取 CSV、解析地理信息、聚合并写出全部输出文件。

    功能说明:
        1) 解析命令行并读取 flows、ip_stats；
        2) 收集全部相关 IP，结合覆盖表与可选在线 API 调用 resolve_geos；
        3) aggregate_map_data 生成 locations、map_flows、ip_geos；
        4) 写入 ip_geo.csv、map_flows.csv、traffic_map_data.json、traffic_map.html；
        5) 打印地点数、流条数与输出目录。

    参数:
        无（通过 sys.argv 与 build_parser 获取）。

    返回值:
        成功时返回 0，供 SystemExit 使用。

    备注:
        map_flows 写入 CSV 前将 src_ips/dst_ips 列表用分号连接为字符串。
    """
    args = build_parser().parse_args()
    flows = read_csv(args.flows)
    stats = read_csv(args.stats)
    ips = {row["ip"] for row in stats}
    for row in flows:
        ips.add(row["src_ip"])
        ips.add(row["dst_ip"])

    geos = resolve_geos(ips, load_overrides(args.overrides), args.resolve_online)
    locations, map_flows, ip_geos = aggregate_map_data(flows, stats, geos, public_only=args.public_only)
    args.outdir.mkdir(parents=True, exist_ok=True)

    write_csv(args.outdir / "ip_geo.csv", ip_geos, ["ip", "city", "lat", "lon", "source", "note"])
    map_flow_rows = []
    for flow in map_flows:
        row = dict(flow)
        row["src_ips"] = ";".join(row["src_ips"])
        row["dst_ips"] = ";".join(row["dst_ips"])
        map_flow_rows.append(row)
    write_csv(
        args.outdir / "map_flows.csv",
        map_flow_rows,
        ["src_city", "dst_city", "src_lat", "src_lon", "dst_lat", "dst_lon", "protocol", "packets", "bytes", "src_ips", "dst_ips"],
    )
    (args.outdir / "traffic_map_data.json").write_text(
        json.dumps({"locations": locations, "flows": map_flows, "ip_geos": ip_geos}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    write_map_html(args.outdir / "traffic_map.html", locations, map_flows, ip_geos)

    print(f"locations: {len(locations)}")
    print(f"flows    : {len(map_flows)}")
    print(f"output   : {args.outdir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
