const form = document.querySelector("#analytics-filter");
const message = document.querySelector("#analytics-message");
const content = document.querySelector("#analytics-content");
let currentPage = 1;
let revealIp = false;
let lastTotal = 0;

const labels = {accounts:"Accounts",wiki:"Campus Wiki",todo:"Todo",cas:"Codex CAS",techx:"TechX"};
const number = (value) => new Intl.NumberFormat("zh-CN").format(Number(value || 0));
const dateText = (value) => value ? new Date(value).toLocaleString("zh-CN") : "—";
function node(tag, className, value) {
  const item = document.createElement(tag);
  if (className) item.className = className;
  if (value !== undefined) item.textContent = String(value);
  return item;
}
function range() {
  const data = new FormData(form);
  const params = new URLSearchParams();
  for (const [key, value] of data.entries()) if (value && key !== "range") params.set(key, value);
  const now = new Date();
  const selected = data.get("range");
  if (selected !== "custom") {
    const start = new Date(now);
    if (selected === "today") start.setHours(0, 0, 0, 0);
    else start.setDate(start.getDate() - (selected === "30d" ? 30 : 7));
    params.set("from", start.toISOString());
    params.set("to", now.toISOString());
  } else {
    if (params.has("from")) params.set("from", new Date(params.get("from")).toISOString());
    if (params.has("to")) params.set("to", new Date(params.get("to")).toISOString());
  }
  if (revealIp) params.set("revealIp", "1");
  return params;
}
async function fetchJson(path, params) {
  const response = await fetch(`${path}?${params}`, {credentials:"same-origin"});
  if (!response.ok) throw new Error(`查询失败：HTTP ${response.status}`);
  return response.json();
}
function renderMetrics(data) {
  const values = [
    ["请求数", number(data.requests)], ["页面访问", number(data.pageViews)],
    ["独立 IP", data.uniqueIps === null ? "—" : number(data.uniqueIps)],
    ["独立用户", data.uniqueUsers === null ? "—" : number(data.uniqueUsers)],
    ["5xx 错误率", `${(100 * data.errorRate).toFixed(2)}%`],
    ["P95 耗时", data.p95Ms === null ? "—" : `${number(Math.round(data.p95Ms))} ms`],
  ];
  const container = document.querySelector("#metrics");
  container.replaceChildren(...values.map(([title, value]) => {
    const card = node("div", "metric");
    card.append(node("span", "", title), node("strong", "", value));
    return card;
  }));
}
function renderRanks(selector, items, formatter, onSelect) {
  const target = document.querySelector(selector);
  target.replaceChildren();
  if (!items.length) {target.append(node("p", "empty-note", "暂无数据")); return;}
  const max = Math.max(...items.map((item) => item.count));
  for (const item of items) {
    const row = node("div", "rank-row");
    const name = onSelect ? node("button", "rank-name rank-button", formatter(item)) : node("span", "rank-name", formatter(item));
    if (onSelect) {name.type = "button"; name.addEventListener("click", () => onSelect(item));}
    name.title = formatter(item);
    const bar = node("span", "rank-bar");
    const fill = node("span"); fill.style.width = `${Math.max(3, 100 * item.count / max)}%`; bar.append(fill);
    row.append(name, bar, node("span", "rank-count", number(item.count)));
    target.append(row);
  }
}
function renderTrend(series) {
  const chart = document.querySelector("#trend-chart");
  const byBucket = new Map();
  for (const row of series) byBucket.set(row.bucket, (byBucket.get(row.bucket) || 0) + row.requests);
  const buckets = [...byBucket.entries()].sort(([a], [b]) => a.localeCompare(b));
  chart.replaceChildren();
  const max = Math.max(1, ...buckets.map(([, count]) => count));
  for (const [bucket, count] of buckets) {
    const bar = node("div", "trend-bar");
    bar.style.height = `${Math.max(3, 100 * count / max)}%`;
    bar.title = `${bucket}: ${number(count)} 次`;
    chart.append(bar);
  }
  const unit = buckets[0] && buckets[0][0].length === 10 ? "天" : "小时";
  document.querySelector("#chart-caption").textContent = `${buckets.length} ${unit} · 当前筛选范围`;
}
function renderSlow(items) {
  const body = document.querySelector("#slow-table"); body.replaceChildren();
  for (const item of items) {
    const tr = node("tr");
    [labels[item.site] || item.site, item.path, item.status, `${Math.round(item.occurredMs)} ms`].forEach((value) => tr.append(node("td", "", value)));
    body.append(tr);
  }
}
function renderEvents(data) {
  const body = document.querySelector("#event-table"); body.replaceChildren();
  lastTotal = data.total;
  for (const event of data.events) {
    const tr = node("tr");
    const name = data.userNames[event.user_sub];
    const values = [dateText(event.occurred_at), labels[event.site] || event.site,
      name ? `${name.displayName} (@${name.username})` : event.user_sub || "匿名",
      event.ip || event.ipMasked, `${event.method} ${event.path}`, event.status,
      `${Math.round(event.duration_ms)} ms`, event.ray_id || "—"];
    values.forEach((value, index) => tr.append(node("td", index === 5 && event.status >= 500 ? "status-error" : "", value)));
    body.append(tr);
  }
  if (!data.events.length) {const tr = node("tr"); const td = node("td", "empty-note", "此筛选条件下没有请求"); td.colSpan = 8; tr.append(td); body.append(tr);}
  document.querySelector("#event-count").textContent = `共 ${number(data.total)} 条`;
  document.querySelector("#page-label").textContent = `${currentPage} / ${Math.max(1, Math.ceil(data.total / data.pageSize))}`;
  document.querySelector("#prev-page").disabled = currentPage <= 1;
  document.querySelector("#next-page").disabled = currentPage * data.pageSize >= data.total;
}
async function load() {
  message.textContent = "正在查询…";
  try {
    const params = range();
    const eventsParams = new URLSearchParams(params); eventsParams.set("page", String(currentPage));
    const [summary, trend, events] = await Promise.all([
      fetchJson("/admin/analytics/summary", params),
      fetchJson("/admin/analytics/timeseries", params),
      fetchJson("/admin/analytics/events", eventsParams),
    ]);
    renderMetrics(summary); renderTrend(trend); renderSlow(summary.slow); renderEvents(events);
    renderRanks("#site-list", summary.sites, (v) => labels[v.value] || v.value);
    renderRanks("#status-list", summary.statuses, (v) => v.value);
    renderRanks("#path-list", summary.paths, (v) => v.value, (v) => {form.elements.path.value = v.value; currentPage = 1; load();});
    renderRanks("#user-list", summary.users, (v) => {
      const u = summary.userNames[v.value]; return u ? `${u.displayName} (@${u.username})` : v.value || "匿名";
    }, (v) => {form.elements.userSub.value = v.value; currentPage = 1; load();});
    renderRanks("#ip-list", summary.ips, (v) => v.value || v.masked, (v) => {
      if (v.value) {form.elements.ip.value = v.value; currentPage = 1; load();}
      else message.textContent = "先点击「显示完整 IP」，再选择 IP。";
    });
    renderRanks("#country-list", summary.countries, (v) => v.value || "未知");
    renderRanks("#referer-list", summary.referrers, (v) => v.value || "直接访问");
    renderRanks("#agent-list", summary.agents, (v) => v.value || "未知");
    const exportParams = new URLSearchParams(params); exportParams.delete("revealIp");
    document.querySelector("#export-link").href = `/admin/analytics/export.csv?${exportParams}`;
    message.textContent = summary.historical
      ? `日聚合共 ${number(summary.requests)} 条请求；30 天以外的用户、IP 和 P95 明细已按保留期清理。`
      : `已读取 ${number(summary.requests)} 条请求；IP 默认掩码，导出也使用掩码。`;
    content.hidden = false;
  } catch (error) {message.textContent = error.message; content.hidden = true;}
}
form.addEventListener("submit", (event) => {event.preventDefault(); currentPage = 1; load();});
form.elements.range.addEventListener("change", () => {
  const custom = form.elements.range.value === "custom";
  form.elements.from.disabled = !custom; form.elements.to.disabled = !custom;
});
form.elements.range.dispatchEvent(new Event("change"));
document.querySelector("#reveal-ip").addEventListener("click", () => {
  revealIp = !revealIp; document.querySelector("#reveal-ip").textContent = revealIp ? "隐藏完整 IP" : "显示完整 IP"; load();
});
document.querySelector("#prev-page").addEventListener("click", () => {if (currentPage > 1) {currentPage--; load();}});
document.querySelector("#next-page").addEventListener("click", () => {if (currentPage * 50 < lastTotal) {currentPage++; load();}});
load();
