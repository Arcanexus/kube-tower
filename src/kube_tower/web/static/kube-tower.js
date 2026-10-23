// Small helpers for the server-rendered UI (no build step).

// Counters above the results toggle the status filter of the filter form.
function ktFilterStatus(status) {
  const select = document.querySelector(".filters select[name=status]");
  if (!select) return;
  select.value = select.value === status ? "" : status;
  select.dispatchEvent(new Event("change", { bubbles: true }));
}

// Detail panel (images, charts): loaded by htmx into #detail, closed by emptying it.
function ktCloseDetail() {
  document.getElementById("detail").innerHTML = "";
}
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") ktCloseDetail();
});

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
