// Small helpers for the server-rendered UI (no build step).

// Counters above the results toggle the status filter of the filter form.
function ktFilterStatus(status) {
  const select = document.querySelector(".filters select[name=status]");
  if (!select) return;
  select.value = select.value === status ? "" : status;
  select.dispatchEvent(new Event("change", { bubbles: true }));
}

// Filters set by a link (Synthesis): their chip removes them and reloads the results.
function ktRemoveFilter(button) {
  const form = button.closest("form");
  const chips = button.closest(".filter-chips");
  button.closest(".filter-chip").remove();
  if (chips && !chips.children.length) chips.remove();
  form.dispatchEvent(new Event("change", { bubbles: true }));
}

// Detail panel (images, charts): loaded by htmx into #detail, closed by emptying it.
// Each panel opens at the default size: closing it forgets its width and full screen mode.
function ktCloseDetail() {
  const detail = document.getElementById("detail");
  detail.innerHTML = "";
  detail.classList.remove("drawer-full", "drawer-resizing");
  detail.style.removeProperty("--kt-drawer-width");
}
// Open the panel at once, empty and busy, while its content loads: rendering a large panel (thousands of
// CVEs or pods) can take a moment. A panel closed before its content arrives stays closed.
document.addEventListener("htmx:beforeRequest", (e) => {
  const detail = document.getElementById("detail");
  if (!detail || e.detail.target !== detail || e.detail.pathInfo.requestPath.includes("polling=1")) return;
  const panel = detail.querySelector(".drawer-panel");
  if (panel) {
    panel.setAttribute("aria-busy", "true");
  } else {
    detail.innerHTML = '<div class="drawer-backdrop" onclick="ktCloseDetail()"></div>'
      + '<article class="drawer-panel drawer-loading" aria-busy="true">Loading…</article>';
  }
});
document.addEventListener("htmx:beforeSwap", (e) => {
  const detail = document.getElementById("detail");
  if (detail && e.detail.target === detail && !detail.firstElementChild) e.detail.shouldSwap = false;
});
document.addEventListener("htmx:afterRequest", (e) => {
  const detail = document.getElementById("detail");
  if (!detail || e.detail.target !== detail || e.detail.successful) return;
  const panel = detail.querySelector(".drawer-panel");
  if (panel && panel.classList.contains("drawer-loading")) {
    panel.removeAttribute("aria-busy");
    panel.textContent = "The details could not be loaded. Close this panel and try again.";
  } else if (panel) {
    panel.removeAttribute("aria-busy");
  }
});
// A click beside the panel lands on its backdrop, which closes the panel: pass the click on to what is
// below, so another row opens its details at once instead of needing a second click.
document.addEventListener("click", (e) => {
  if (!e.target.classList || !e.target.classList.contains("drawer-backdrop")) return;
  ktCloseDetail();
  const below = document.elementFromPoint(e.clientX, e.clientY);
  if (below) below.click();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") ktCloseDetail();
});

// Detail panel size: dragged from its left edge, or full screen. Kept on #detail (it outlives the panels
// htmx loads into it, e.g. the refreshes during a rescan) until the panel is closed.
const KT_DRAWER_MIN = 320;
function ktSetDrawerWidth(px) {
  const detail = document.getElementById("detail");
  if (!detail) return;
  if (px === null) {
    detail.style.removeProperty("--kt-drawer-width");
  } else {
    px = Math.round(Math.min(Math.max(px, KT_DRAWER_MIN), window.innerWidth));
    detail.style.setProperty("--kt-drawer-width", px + "px");
  }
}
function ktDrawerWidth() {
  const panel = document.querySelector("#detail .drawer-panel");
  return panel ? panel.getBoundingClientRect().width : 0;
}
function ktResizeStart(e) {
  e.preventDefault();
  const detail = document.getElementById("detail");
  detail.classList.add("drawer-resizing");
  const move = (ev) => ktSetDrawerWidth(window.innerWidth - ev.clientX);
  const stop = () => {
    detail.classList.remove("drawer-resizing");
    document.removeEventListener("pointermove", move);
    document.removeEventListener("pointerup", stop);
  };
  document.addEventListener("pointermove", move);
  document.addEventListener("pointerup", stop);
}
function ktResizeKey(e) {
  const step = e.shiftKey ? 160 : 40;
  if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
  e.preventDefault();
  ktSetDrawerWidth(ktDrawerWidth() + (e.key === "ArrowLeft" ? step : -step));
}
function ktResizeReset() {
  ktSetDrawerWidth(null);
}
function ktToggleFull() {
  document.getElementById("detail").classList.toggle("drawer-full");
  ktSyncFullButton();
}
function ktSyncFullButton() {
  const full = document.getElementById("detail").classList.contains("drawer-full");
  document.querySelectorAll(".drawer-full-toggle").forEach((b) => {
    b.setAttribute("aria-pressed", full ? "true" : "false");
    b.setAttribute("aria-label", full ? "Exit full screen" : "Full screen");
    b.title = full ? "Exit full screen" : "Full screen";
  });
}
document.addEventListener("htmx:afterSettle", (e) => {
  if (e.target.id === "detail") ktSyncFullButton();
});

// A rescan from a detail panel is over: reload the results of the page (same filters) to update its row.
document.addEventListener("kt-rescanned", () => {
  const form = document.querySelector("form.filters");
  if (form) htmx.trigger(form, "change");
});

// Sortable columns: click a header with data-sort (data-sort="desc" sorts descending first). A cell
// sorts on its data-sort value when it has one, else on its text. Tables with one tbody per item
// (Helm charts and their subcharts) sort their tbodies. The sort survives the htmx reloads of #results.
// Headers with data-server-sort belong to lists loaded page by page: the server sorts them.
const ktSort = {};
function ktCellValue(row, index) {
  const cell = row.cells[index];
  if (!cell) return "";
  return cell.dataset.sort !== undefined ? cell.dataset.sort : cell.textContent.trim();
}
function ktCompare(a, b) {
  if (a === "" || b === "") return a === b ? 0 : a === "" ? 1 : -1;  // empty cells last
  const x = Number(a), y = Number(b);
  if (!Number.isNaN(x) && !Number.isNaN(y)) return x - y;
  return a.localeCompare(b, undefined, { numeric: true, sensitivity: "base" });
}
function ktApplySort(table, index, dir) {
  const bodies = [...table.tBodies];
  const items = bodies.length > 1
    ? bodies.map((b) => ({ node: b, row: b.rows[0], parent: table }))
    : [...(bodies[0] ? bodies[0].rows : [])].map((r) => ({ node: r, row: r, parent: bodies[0] }));
  if (items.length < 2 || items.some((i) => i.row && i.row.cells.length === 1 && i.row.cells[0].colSpan > 1)) return;
  const sign = dir === "descending" ? -1 : 1;
  items.sort((p, q) => sign * ktCompare(ktCellValue(p.row, index), ktCellValue(q.row, index)));
  items.forEach((i) => i.parent.appendChild(i.node));
  table.querySelectorAll("th[data-sort]").forEach((th) => th.removeAttribute("aria-sort"));
  table.tHead.rows[0].cells[index].setAttribute("aria-sort", dir);
}
function ktSortBy(th) {
  const current = th.getAttribute("aria-sort");
  const first = th.dataset.sort === "desc" ? "descending" : "ascending";
  const dir = current ? (current === "ascending" ? "descending" : "ascending") : first;
  const form = document.querySelector("form.filters");
  if (th.dataset.serverSort !== undefined && form && form.elements.sort) {
    // Lists loaded page by page (infinite scroll) are sorted by the server: reload them sorted.
    form.elements.sort.value = th.dataset.serverSort;
    form.elements.dir.value = dir;
    form.dispatchEvent(new Event("change", { bubbles: true }));
    return;
  }
  ktApplySort(th.closest("table"), th.cellIndex, dir);
  ktSort[location.pathname] = { index: th.cellIndex, dir };
}
document.addEventListener("click", (e) => {
  const th = e.target.closest("th[data-sort]");
  if (th) ktSortBy(th);
});
// Keyboard: sortable headers are focusable and sort with Enter or Space.
document.addEventListener("keydown", (e) => {
  const th = e.target.closest && e.target.closest("th[data-sort]");
  if (th && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); ktSortBy(th); }
});
function ktFocusableHeaders(root) {
  (root || document).querySelectorAll("th[data-sort]").forEach((th) => { th.tabIndex = 0; });
}
document.addEventListener("DOMContentLoaded", () => ktFocusableHeaders());
document.addEventListener("htmx:afterSwap", (e) => ktFocusableHeaders(e.target));
document.addEventListener("htmx:afterSwap", (e) => {
  const state = ktSort[location.pathname];
  const table = e.target.querySelector && e.target.querySelector("table");
  if (state && table && e.target.id === "results") ktApplySort(table, state.index, state.dir);
});

// "Last scan" shows its age (5 min ago), kept up to date.
function ktShowAges() {
  document.querySelectorAll("time.ago").forEach((t) => {
    const minutes = Math.round((Date.now() - new Date(t.getAttribute("datetime"))) / 60000);
    t.textContent = minutes < 1 ? "just now" : minutes < 60 ? `${minutes} min ago`
      : minutes < 2880 ? `${Math.round(minutes / 60)} h ago` : `${Math.round(minutes / 1440)} days ago`;
  });
}
document.addEventListener("DOMContentLoaded", ktShowAges);
document.addEventListener("htmx:afterSettle", ktShowAges);
setInterval(ktShowAges, 30000);

// Theme: auto (follow the system) -> light -> dark.
const KT_THEMES = ["auto", "light", "dark"];
function ktCurrentTheme() {
  return document.documentElement.dataset.theme || "auto";
}
function ktShowTheme() {
  const theme = ktCurrentTheme();
  const label = document.querySelector(".theme-label");
  if (label) label.textContent = theme === "auto" ? "Auto theme" : theme === "light" ? "Light theme" : "Dark theme";
}
function ktCycleTheme() {
  const next = KT_THEMES[(KT_THEMES.indexOf(ktCurrentTheme()) + 1) % KT_THEMES.length];
  if (next === "auto") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = next;
  try { localStorage.setItem("kt-theme", next === "auto" ? "" : next); } catch (e) {}
  ktShowTheme();
}
document.addEventListener("DOMContentLoaded", ktShowTheme);
