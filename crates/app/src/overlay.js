// Injected into every page of the main window. On the InvenTree pages it adds a small
// button that leads back to the app's status page. The link target is intercepted by the
// app (see on_navigation in main.rs) and never reaches the server.
(function () {
  if (location.origin !== "http://localhost:8080") return;
  function add() {
    if (!document.body || document.getElementById("__connect_for_inventree")) return;
    const a = document.createElement("a");
    a.id = "__connect_for_inventree";
    a.href = "/__connect/home";
    a.textContent = "⇄ Verbindung";
    a.title = "Connect for InvenTree: Verbindung und Geräte";
    a.style.cssText =
      "position:fixed;left:12px;bottom:12px;z-index:2147483647;padding:4px 10px;border-radius:99px;" +
      "background:#2b6cb0;color:#fff;font:600 12px system-ui,sans-serif;text-decoration:none;" +
      "opacity:.7;box-shadow:0 1px 4px rgba(0,0,0,.3)";
    a.onmouseenter = () => (a.style.opacity = "1");
    a.onmouseleave = () => (a.style.opacity = ".7");
    document.body.appendChild(a);
  }
  document.addEventListener("DOMContentLoaded", add);
  new MutationObserver(add).observe(document.documentElement, { childList: true, subtree: true });
})();
