(function () {
  const root = document.documentElement;
  const button = document.getElementById("theme-toggle");
  const label = button && button.querySelector(".theme-label");
  let saved = "dark";
  try { saved = localStorage.getItem("phishguard-theme") || "dark"; } catch (_) {}
  root.dataset.theme = saved === "light" ? "light" : "dark";
  function sync() {
    if (!button) return;
    const light = root.dataset.theme === "light";
    if (label) label.textContent = light ? "Dark mode" : "Light mode";
    button.setAttribute("aria-label", light ? "Switch to dark theme" : "Switch to light theme");
    button.title = light ? "Switch to dark theme" : "Switch to light theme";
  }
  sync();
  if (button) button.addEventListener("click", function () {
    root.dataset.theme = root.dataset.theme === "dark" ? "light" : "dark";
    try { localStorage.setItem("phishguard-theme", root.dataset.theme); } catch (_) {}
    sync();
  });
})();