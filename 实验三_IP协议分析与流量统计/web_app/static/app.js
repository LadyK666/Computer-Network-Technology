/**
 * @file app.js
 * @description 实验三 IP 流量分析 Web 前端模块。负责调用后端 REST API、渲染 PCAP/网卡/地理覆盖编辑、
 *   表格与 ECharts 中国地图流量可视化，以及实时抓包状态的轮询与界面联动。
 */

const LIVE_POLL_MS = 3000;

const state = {
  data: null,
  geoRows: [],
  chart: null,
  chinaMapReady: false,
  liveTimer: null,
  lastMapRevision: -1,
};

/**
 * 根据元素 id 获取 DOM 节点。
 * @param {string} id - HTML 元素的 id 属性值
 * @returns {HTMLElement|null} 对应的 DOM 元素，不存在时为 null
 * @description 封装 document.getElementById，供全文件统一引用页面控件。
 */
const $ = (id) => document.getElementById(id);

/**
 * 更新页面顶部状态栏文案。
 * @param {string} message - 要显示的状态提示文字
 * @returns {void}
 * @description 将状态信息写入 id 为 status 的元素，用于反馈加载、错误或完成等状态。
 */
function setStatus(message) {
  $("status").textContent = message;
}

/**
 * 切换全局按钮的可用/禁用状态。
 * @param {boolean} isBusy - 为 true 时禁用所有按钮，为 false 时恢复可点击
 * @returns {void}
 * @description 在异步任务执行期间防止用户重复提交抓包、分析等操作。
 */
function setBusy(isBusy) {
  for (const button of document.querySelectorAll("button")) {
    button.disabled = isBusy;
  }
}

/**
 * 向后端发起 JSON API 请求并解析统一响应格式。
 * @param {string} path - API 路径（如 /api/data）
 * @param {RequestInit} [options={}] - 传给 fetch 的额外选项（method、body 等）
 * @returns {Promise<object>} 解析后的 payload；当 payload.ok 为 false 时抛出错误
 * @description 自动设置 Content-Type，校验服务端返回的 ok 字段，失败时抛出带 error 信息的异常。
 */
async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const payload = await response.json();
  if (!payload.ok) {
    throw new Error(payload.error || "请求失败");
  }
  return payload;
}

/**
 * 将对象数组渲染为 HTML 表格字符串。
 * @param {Array<object>|null|undefined} rows - 表格数据行
 * @param {Array<{key: string, title: string}>} columns - 列定义：key 为字段名，title 为表头
 * @returns {string} 完整 table HTML，或无数据时的占位 div
 * @description 用于 PCI、IP 统计、流量流等列表的通用表格生成。
 */
function table(rows, columns) {
  if (!rows || rows.length === 0) {
    return "<div class=\"empty\">暂无数据</div>";
  }
  const head = columns.map((col) => `<th>${col.title}</th>`).join("");
  const body = rows.map((row) => {
    return `<tr>${columns.map((col) => `<td>${row[col.key] ?? ""}</td>`).join("")}</tr>`;
  }).join("");
  return `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
}

/**
 * 用 PCAP 文件列表填充下拉选择框。
 * @param {Array<{path: string, name: string, size: number}>} pcaps - 服务端返回的 PCAP 元数据列表
 * @returns {void}
 * @description 为每个文件创建 option，显示文件名与约略大小（KB）。
 */
function renderPcaps(pcaps) {
  const select = $("pcapSelect");
  select.innerHTML = "";
  for (const pcap of pcaps) {
    const option = document.createElement("option");
    option.value = pcap.path;
    option.dataset.index = String(select.options.length);
    option.textContent = `${pcap.name} (${Math.max(1, Math.round(pcap.size / 1024))} KB)`;
    select.appendChild(option);
  }
}

/**
 * 从 Npcap/WinPcap 风格网卡描述中提取简短显示名。
 * @param {string} iface - 完整网卡描述字符串（可能含 {GUID} 等形式）
 * @returns {string} 花括号内名称；无匹配时返回原字符串
 * @description 便于在下拉框中显示可读网卡名而非冗长系统字符串。
 */
function ifaceLabel(iface) {
  const match = iface.match(/\{([^}]+)\}/i);
  return match ? match[1] : iface;
}

/**
 * 渲染网卡选择下拉框并尽量保持先前选中项。
 * @param {string[]} interfaces - 可用网卡描述列表
 * @returns {void}
 * @description 首项为「默认网卡」空值；刷新后按精确或模糊匹配恢复用户上次选择。
 */
function renderInterfaces(interfaces) {
  const select = $("ifaceSelect");
  const previous = select.value;
  select.innerHTML = "";
  const auto = document.createElement("option");
  auto.value = "";
  auto.textContent = "默认网卡";
  select.appendChild(auto);
  for (const iface of interfaces) {
    const option = document.createElement("option");
    option.value = iface;
    option.textContent = ifaceLabel(iface);
    select.appendChild(option);
  }
  if (previous) {
    const exact = [...select.options].find((option) => option.value === previous);
    const fuzzy = [...select.options].find((option) => option.value.toUpperCase().includes(previous.toUpperCase().replace(/[{}]/g, "")));
    if (exact) {
      select.value = exact.value;
    } else if (fuzzy) {
      select.value = fuzzy.value;
    }
  }
}

/**
 * 渲染 IP 地理位置手动覆盖编辑区。
 * @param {Array<{ip?: string, city?: string, lat?: string, lon?: string, note?: string}>} rows - 已有覆盖行
 * @returns {void}
 * @description 同步到 state.geoRows，并为每行生成 IP/地点/纬/经度输入框，末尾追加一空行便于新增。
 */
function renderGeoEditor(rows) {
  state.geoRows = rows.length ? rows : [];
  const editor = $("geoEditor");
  editor.innerHTML = "";
  const allRows = [...state.geoRows, { ip: "", city: "", lat: "", lon: "", note: "" }];
  allRows.forEach((row, index) => {
    const wrap = document.createElement("div");
    wrap.className = "geo-row";
    wrap.innerHTML = `
      <input data-geo="${index}" data-key="ip" value="${row.ip || ""}" placeholder="IP">
      <input data-geo="${index}" data-key="city" value="${row.city || ""}" placeholder="地点">
      <input data-geo="${index}" data-key="lat" value="${row.lat || ""}" placeholder="纬度">
      <input data-geo="${index}" data-key="lon" value="${row.lon || ""}" placeholder="经度">
    `;
    editor.appendChild(wrap);
  });
}

/**
 * 从地理覆盖编辑器 DOM 中收集有效行。
 * @returns {Array<{ip: string, city: string, lat: string, lon: string, note: string}>} 非空字段组成的行数组
 * @description 跳过完全空白的行；note 固定为空字符串供后端使用。
 */
function collectGeoRows() {
  const rows = [];
  for (const wrap of $("geoEditor").querySelectorAll(".geo-row")) {
    const row = {};
    for (const input of wrap.querySelectorAll("input")) {
      row[input.dataset.key] = input.value.trim();
    }
    if (row.ip || row.city || row.lat || row.lon) {
      row.note = "";
      rows.push(row);
    }
  }
  return rows;
}

/**
 * 用一次完整分析结果刷新整页数据展示。
 * @param {object} data - 后端返回的分析数据（pci、ipStats、mapData、flows 等）
 * @returns {void}
 * @description 更新指标卡片、各表格、备用 SVG 地图 iframe 与 ECharts 地图，并写入 state.data。
 */
function renderData(data) {
  state.data = data;
  renderPcaps(data.pcaps || []);
  $("packetMetric").textContent = data.summary?.packet_count ?? data.pci?.length ?? 0;
  $("ipMetric").textContent = data.ipStats?.length ?? 0;
  $("locationMetric").textContent = data.mapData?.locations?.length ?? 0;
  $("flowMetric").textContent = data.mapData?.flows?.length ?? data.flows?.length ?? 0;

  $("pciTable").innerHTML = table(data.pci || [], [
    { key: "packet_index", title: "序号" },
    { key: "timestamp", title: "时间" },
    { key: "src_ip", title: "源 IP" },
    { key: "dst_ip", title: "目的 IP" },
    { key: "protocol", title: "协议" },
    { key: "ttl", title: "TTL" },
    { key: "total_length", title: "总长度" },
    { key: "identification", title: "标识" },
    { key: "flags", title: "标志" },
    { key: "fragment_offset", title: "片偏移" },
    { key: "header_checksum", title: "校验和" },
    { key: "src_port", title: "源端口" },
    { key: "dst_port", title: "目的端口" },
  ]);
  $("ipTable").innerHTML = table(data.ipStats || [], [
    { key: "ip", title: "IP" },
    { key: "sent_packets", title: "发送包" },
    { key: "received_packets", title: "接收包" },
    { key: "sent_bytes", title: "发送字节" },
    { key: "received_bytes", title: "接收字节" },
    { key: "total_packets", title: "总包数" },
  ]);
  $("flowTable").innerHTML = table(data.mapFlows?.length ? data.mapFlows : data.flows || [], [
    { key: "src_city", title: "源地点" },
    { key: "dst_city", title: "目的地点" },
    { key: "src_ip", title: "源 IP" },
    { key: "dst_ip", title: "目的 IP" },
    { key: "protocol", title: "协议" },
    { key: "packets", title: "包数量" },
    { key: "bytes", title: "字节数" },
  ]);
  const mapHtml = data.mapHtml || "traffic_map.html";
  $("mapFrame").src = `/outputs/${mapHtml}?ts=${Date.now()}`;
  renderEchartsMap(data);
  updateMapHint(data);
}

/**
 * 确保 ECharts 已注册中国地图 GeoJSON（仅加载一次）。
 * @returns {Promise<boolean>} 注册成功为 true；无 echarts 时为 false
 * @description 从 /static/china-outline.json 拉取底图并 registerMap("china-demo")。
 */
async function ensureChinaMap() {
  if (state.chinaMapReady) return true;
  if (!window.echarts) return false;
  const response = await fetch("/static/china-outline.json");
  const geoJson = await response.json();
  echarts.registerMap("china-demo", geoJson);
  state.chinaMapReady = true;
  return true;
}

/**
 * 将任意值安全转换为有限数字。
 * @param {*} value - 待转换的值
 * @param {number} [fallback=0] - 非有限数字时使用的默认值
 * @returns {number} 有限数字或 fallback
 * @description 用于地图经纬度、包数、字节数等字段的数值化处理。
 */
function asNumber(value, fallback = 0) {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}

/**
 * 使用 ECharts 在中国地图上绘制地点散点与地点间流量连线。
 * @param {object} data - 含 mapData.locations、mapData.flows 的分析数据
 * @param {number} [mapRevision=0] - 实时窗口版本号，显示在图表标题
 * @returns {Promise<void>}
 * @description 初始化或更新 state.chart，配置 geo、effectScatter、lines 及 visualMap。
 */
async function renderEchartsMap(data, mapRevision = 0) {
  const hint = $("mapHint");
  const target = $("echartsMap");
  if (!target) return;
  if (!window.echarts) {
    hint.textContent = "ECharts 未加载，正在显示备用 SVG 地图";
    target.innerHTML = "<div class=\"empty\">ECharts CDN 未加载，可展开下方备用 SVG 地图。</div>";
    return;
  }
  try {
    await ensureChinaMap();
  } catch (error) {
    hint.textContent = "地图底图加载失败，正在显示备用 SVG 地图";
    target.innerHTML = "<div class=\"empty\">地图底图加载失败，可展开下方备用 SVG 地图。</div>";
    return;
  }

  const mapData = data.mapData || {};
  const locations = mapData.locations || [];
  const flows = mapData.flows || [];
  const coords = new Map();
  for (const location of locations) {
    coords.set(location.city, [asNumber(location.lon), asNumber(location.lat)]);
  }

  const scatterData = locations.map((location) => ({
    name: location.city,
    value: [
      asNumber(location.lon),
      asNumber(location.lat),
      asNumber(location.total_packets),
      asNumber(location.received_packets),
      asNumber(location.total_bytes),
    ],
    ips: location.ips || [],
  }));
  const rawLineData = flows
    .filter((flow) => coords.has(flow.src_city) && coords.has(flow.dst_city))
    .map((flow) => ({
      fromName: flow.src_city,
      toName: flow.dst_city,
      coords: [coords.get(flow.src_city), coords.get(flow.dst_city)],
      value: asNumber(flow.bytes),
      packets: asNumber(flow.packets),
      protocol: flow.protocol,
      srcIps: flow.src_ips || [],
      dstIps: flow.dst_ips || [],
    }));
  const maxBytes = Math.max(1, ...rawLineData.map((item) => item.value));
  const lineData = rawLineData.map((item) => ({
    ...item,
    lineStyle: { width: 1.5 + 6 * (item.value / maxBytes) },
  }));

  if (!state.chart) {
    state.chart = echarts.init(target);
    window.addEventListener("resize", () => state.chart?.resize());
  }

  state.chart.setOption({
    backgroundColor: "#f8fbff",
    title: {
      text: mapRevision ? `实时窗口 #${mapRevision}` : "",
      left: 12,
      top: 8,
      textStyle: { fontSize: 12, color: "#64748b", fontWeight: "normal" },
    },
    tooltip: {
      trigger: "item",
      /**
       * ECharts 提示框自定义格式化。
       * @param {object} params - ECharts tooltip 参数（含 seriesType、data、name 等）
       * @returns {string} HTML 片段，用于散点或连线的详情展示
       * @description 按 series 类型分别展示地点统计或流向协议、包数、字节数。
       */
      formatter(params) {
        if (params.seriesType === "effectScatter") {
          const ips = params.data.ips?.join("<br>") || "";
          return `${params.name}<br>总包数：${params.value[2]}<br>接收包：${params.value[3]}<br>总字节：${params.value[4]}<br>${ips}`;
        }
        if (params.seriesType === "lines") {
          const dataItem = params.data;
          return `${dataItem.fromName} → ${dataItem.toName}<br>协议：${dataItem.protocol}<br>包数量：${dataItem.packets}<br>字节数：${dataItem.value}`;
        }
        return params.name;
      },
    },
    visualMap: {
      min: 0,
      max: maxBytes,
      calculable: true,
      orient: "horizontal",
      left: 18,
      bottom: 14,
      text: ["高字节", "低字节"],
      inRange: { color: ["#f6c76f", "#c75c14"] },
    },
    geo: {
      map: "china-demo",
      roam: true,
      zoom: 1.1,
      label: { show: true, color: "#4b5563", fontSize: 11 },
      itemStyle: {
        areaColor: "#e7eef8",
        borderColor: "#8aa1bd",
        borderWidth: 1,
      },
      emphasis: {
        label: { show: true },
        itemStyle: { areaColor: "#d6e5f7" },
      },
    },
    series: [
      {
        name: "地点",
        type: "effectScatter",
        coordinateSystem: "geo",
        data: scatterData,
        /**
         * 根据该点包数量计算散点符号大小。
         * @param {number[]} value - 数据项 value 数组，索引 2 为总包数
         * @returns {number} 像素级 symbolSize，范围约 10～34
         * @description 使用 sqrt 缩放避免大流量地点过度遮挡地图。
         */
        symbolSize(value) {
          return Math.max(10, Math.min(34, 8 + Math.sqrt(asNumber(value[2])) * 6));
        },
        rippleEffect: { brushType: "stroke" },
        itemStyle: { color: "#2358a6" },
        zlevel: 2,
      },
      {
        name: "地点间流量",
        type: "lines",
        coordinateSystem: "geo",
        data: lineData,
        lineStyle: {
          color: "#c75c14",
          width: 2,
          opacity: 0.72,
          curveness: 0.22,
        },
        effect: {
          show: true,
          constantSpeed: 36,
          symbol: "arrow",
          symbolSize: 8,
          color: "#c75c14",
        },
        zlevel: 1,
      },
    ],
  }, true);
  hint.textContent = locations.length ? `已加载 ${locations.length} 个地点、${flows.length} 条地点间流量` : "暂无地图数据，请先分析 PCAP";
}

/**
 * 实时抓包轮询时增量更新界面（仅刷新当前可见 Tab 的表格）。
 * @param {object} data - 最新滑动窗口内的分析数据
 * @param {object} [live={}] - 实时状态对象（含 map_revision 等）
 * @returns {void}
 * @description 避免全量重绘所有表格，按激活 Tab 更新 PCI/IP/流量表并刷新 ECharts。
 */
function renderLiveUpdate(data, live = {}) {
  state.data = data;
  $("packetMetric").textContent = data.summary?.packet_count ?? data.pci?.length ?? 0;
  $("ipMetric").textContent = data.ipStats?.length ?? 0;
  $("locationMetric").textContent = data.mapData?.locations?.length ?? 0;
  $("flowMetric").textContent = data.mapData?.flows?.length ?? data.flows?.length ?? 0;

  const activeTab = document.querySelector(".tabs button.active")?.dataset.tab;
  if (activeTab === "pci") {
    $("pciTable").innerHTML = table(data.pci || [], [
      { key: "packet_index", title: "序号" },
      { key: "timestamp", title: "时间" },
      { key: "src_ip", title: "源 IP" },
      { key: "dst_ip", title: "目的 IP" },
      { key: "protocol", title: "协议" },
      { key: "ttl", title: "TTL" },
      { key: "total_length", title: "总长度" },
    ]);
  } else if (activeTab === "ips") {
    $("ipTable").innerHTML = table(data.ipStats || [], [
      { key: "ip", title: "IP" },
      { key: "sent_packets", title: "发送包" },
      { key: "received_packets", title: "接收包" },
      { key: "sent_bytes", title: "发送字节" },
      { key: "received_bytes", title: "接收字节" },
      { key: "total_packets", title: "总包数" },
    ]);
  } else if (activeTab === "flows") {
    $("flowTable").innerHTML = table(data.mapFlows?.length ? data.mapFlows : data.flows || [], [
      { key: "src_city", title: "源地点" },
      { key: "dst_city", title: "目的地点" },
      { key: "protocol", title: "协议" },
      { key: "packets", title: "包数量" },
      { key: "bytes", title: "字节数" },
    ]);
  }

  renderEchartsMap(data, Number(live.map_revision ?? data.mapRevision ?? 0));
  updateMapHint(data);
}

/**
 * 根据 IP 地理解析结果更新地图区域提示文案。
 * @param {object} data - 含 ipGeo 数组的分析数据
 * @returns {void}
 * @description 当存在未定位公网 IP 时提示用户开启在线解析或重新分析。
 */
function updateMapHint(data) {
  const unknownCount = (data.ipGeo || []).filter((row) => row.source === "unknown" || row.city === "未知").length;
  if (unknownCount > 0) {
    $("mapHint").textContent = `有 ${unknownCount} 个公网 IP 尚未定位，请勾选「在线解析」后重新分析或重启实时抓包`;
  }
}

/**
 * 并行拉取数据、网卡、地理覆盖与实时状态并刷新整页。
 * @returns {Promise<void>}
 * @description 页面加载与手动刷新时调用；若实时抓包已在运行则启动轮询。
 */
async function refreshAll() {
  setStatus("正在刷新");
  const [dataPayload, interfacesPayload, geoPayload, livePayload] = await Promise.all([
    api("/api/data"),
    api("/api/interfaces"),
    api("/api/geo-overrides"),
    api("/api/live/status"),
  ]);
  renderInterfaces(interfacesPayload.interfaces || []);
  renderGeoEditor(geoPayload.rows || []);
  renderData(dataPayload.data);
  renderLiveStatus(livePayload.live || {});
  if (livePayload.live?.running) startLivePolling();
  setStatus("就绪");
}

/**
 * 将实时抓包后端状态渲染到 liveStatus 文本区域。
 * @param {object} live - 实时会话状态（running、last_update、map_revision 等）
 * @returns {void}
 * @description 拼接运行状态、滑动窗口包数、地图版本、批处理与错误信息。
 */
function renderLiveStatus(live) {
  const status = live.running ? "运行中" : "未启动";
  const update = live.last_update ? `，最近更新：${live.last_update}` : "";
  const windowLimit = live.max_packets || 100;
  const total = live.total_packets !== undefined
    ? `，滑动窗口：${live.total_packets}/${windowLimit} 个 IPv4 包（满窗后新包替换旧包）`
    : "";
  const rev = live.map_revision !== undefined ? `，地图版本：${live.map_revision}` : "";
  const batch = live.last_batch_accepted !== undefined ? `，本批入窗：${live.last_batch_accepted} 包` : "";
  const analyzing = live.analyzing ? "，正在更新地图…" : live.analysis_pending ? "，统计排队中…" : "";
  const error = live.last_error ? `，错误：${live.last_error}` : "";
  $("liveStatus").textContent = `实时状态：${status}${update}${total}${rev}${batch}${analyzing}${error}`;
}

/**
 * 启动实时抓包状态的定时轮询（若尚未启动）。
 * @returns {void}
 * @description 每 LIVE_POLL_MS 毫秒请求 /api/live/status，停止时自动 refreshAll。
 */
function startLivePolling() {
  if (state.liveTimer) return;
  state.lastMapRevision = -1;
  state.liveTimer = window.setInterval(async () => {
    try {
      const payload = await api("/api/live/status");
      renderLiveStatus(payload.live || {});
      renderLiveUpdate(payload.data, payload.live || {});
      if (!payload.live?.running) {
        stopLivePolling();
        await refreshAll();
      }
    } catch (error) {
      setStatus(error.message);
    }
  }, LIVE_POLL_MS);
}

/**
 * 停止实时抓包轮询定时器。
 * @returns {void}
 * @description 清除 setInterval 并将 state.liveTimer 置空。
 */
function stopLivePolling() {
  if (state.liveTimer) {
    window.clearInterval(state.liveTimer);
    state.liveTimer = null;
  }
}

/**
 * 在忙碌状态下执行异步任务并统一处理状态与错误。
 * @param {string} label - 执行过程中显示在状态栏的文案
 * @param {() => Promise<void>} task - 要执行的异步函数
 * @returns {Promise<void>}
 * @description 自动 setBusy、setStatus，成功显示「完成」，失败显示 error.message。
 */
async function runTask(label, task) {
  try {
    setBusy(true);
    setStatus(label);
    await task();
    setStatus("完成");
  } catch (error) {
    console.error(error);
    setStatus(error.message);
  } finally {
    setBusy(false);
  }
}

/**
 * 为页面各按钮与 Tab 切换绑定事件处理。
 * @returns {void}
 * @description 关联刷新、抓包、实时启停、分析、生成地图、保存地理覆盖及标签页切换逻辑。
 */
function bindEvents() {
  $("refreshBtn").addEventListener("click", () => runTask("正在刷新", refreshAll));
  $("captureBtn").addEventListener("click", () => runTask("正在抓包", async () => {
    const payload = await api("/api/capture", {
      method: "POST",
      body: JSON.stringify({
        iface: $("ifaceSelect").value,
        count: $("captureCount").value,
        timeout: $("captureTimeout").value,
        filter: $("captureFilter").value,
      }),
    });
    renderPcaps(payload.pcaps || []);
  }));
  $("liveStartBtn").addEventListener("click", () => runTask("正在启动实时抓包", async () => {
    const payload = await api("/api/live/start", {
      method: "POST",
      body: JSON.stringify({
        iface: $("ifaceSelect").value,
        batchCount: $("captureCount").value,
        interval: $("captureTimeout").value,
        maxPackets: $("liveMaxPackets").value,
        filter: $("captureFilter").value,
        resolveOnline: $("resolveOnline").checked,
        publicOnly: $("publicOnly").checked,
      }),
    });
    renderLiveStatus(payload.live || {});
    if (payload.data) {
      state.lastMapRevision = -1;
      renderLiveUpdate(payload.data, payload.live || {});
    }
    startLivePolling();
  }));
  $("liveStopBtn").addEventListener("click", () => runTask("正在停止实时抓包", async () => {
    const payload = await api("/api/live/stop", { method: "POST", body: JSON.stringify({}) });
    renderLiveStatus(payload.live || {});
    stopLivePolling();
    state.lastMapRevision = -1;
    await refreshAll();
  }));
  $("analyzeBtn").addEventListener("click", () => runTask("正在分析", async () => {
    const pcap = $("pcapSelect").value;
    const pcapIndex = Number($("pcapSelect").selectedOptions[0]?.dataset.index ?? 0);
    const payload = await api("/api/analyze", {
      method: "POST",
      body: JSON.stringify({ pcap, pcapIndex, resolveOnline: $("resolveOnline").checked, publicOnly: $("publicOnly").checked }),
    });
    renderData(payload.data);
  }));
  $("mapBtn").addEventListener("click", () => runTask("正在生成地图", async () => {
    const payload = await api("/api/map", {
      method: "POST",
      body: JSON.stringify({ resolveOnline: $("resolveOnline").checked, publicOnly: $("publicOnly").checked }),
    });
    renderData(payload.data);
  }));
  $("saveGeoBtn").addEventListener("click", () => runTask("正在保存位置", async () => {
    const payload = await api("/api/geo-overrides", {
      method: "POST",
      body: JSON.stringify({ rows: collectGeoRows(), resolveOnline: $("resolveOnline").checked }),
    });
    renderGeoEditor(payload.rows || []);
    renderData(payload.data);
  }));
  for (const button of document.querySelectorAll(".tabs button")) {
    button.addEventListener("click", () => {
      for (const item of document.querySelectorAll(".tabs button")) item.classList.remove("active");
      for (const panel of document.querySelectorAll(".tab-panel")) panel.classList.remove("active");
      button.classList.add("active");
      $(`tab-${button.dataset.tab}`).classList.add("active");
    });
  }
}

bindEvents();
runTask("正在加载", refreshAll);
