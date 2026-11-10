/* ==========================================================================
   CyberCRM Guardian — core front-end behaviour
   Theme toggle, collapsible sidebar, toasts, dropdowns, modals, AJAX helper
   ========================================================================== */

(function () {
  "use strict";

  /* ---------------- Theme ---------------- */
  const THEME_KEY = "cybercrm-theme";

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    document.querySelectorAll("[data-theme-icon]").forEach((el) => {
      el.className = theme === "light" ? "fa-solid fa-moon" : "fa-solid fa-sun";
    });
    document.querySelectorAll("[data-theme-label]").forEach((el) => {
      el.textContent = theme === "light" ? "Dark Mode" : "Light Mode";
    });
  }

  function toggleTheme() {
    const current = localStorage.getItem(THEME_KEY) || "dark";
    const next = current === "dark" ? "light" : "dark";
    localStorage.setItem(THEME_KEY, next);
    applyTheme(next);
  }

  window.CyberCRM = window.CyberCRM || {};
  window.CyberCRM.toggleTheme = toggleTheme;

  document.addEventListener("DOMContentLoaded", () => {
    const saved = localStorage.getItem(THEME_KEY) || "dark";
    applyTheme(saved);

    document.querySelectorAll("[data-action='toggle-theme']").forEach((btn) => {
      btn.addEventListener("click", toggleTheme);
    });

    initSidebar();
    initDropdowns();
    initModals();
    initFlashToTeasts();
    initSortableTables();
  });

  /* ---------------- Sidebar ---------------- */
  function initSidebar() {
    const sidebar = document.getElementById("sidebar");
    const overlay = document.getElementById("sidebarOverlay");
    if (!sidebar) return;

    const COLLAPSE_KEY = "cybercrm-sidebar-collapsed";

    const desktopToggle = document.getElementById("sidebarCollapseToggle");
    const mobileToggle = document.getElementById("sidebarMobileToggle");

    if (localStorage.getItem(COLLAPSE_KEY) === "1" && window.innerWidth > 900) {
      sidebar.classList.add("collapsed");
    }

    if (desktopToggle) {
      desktopToggle.addEventListener("click", () => {
        sidebar.classList.toggle("collapsed");
        localStorage.setItem(COLLAPSE_KEY, sidebar.classList.contains("collapsed") ? "1" : "0");
      });
    }

    if (mobileToggle) {
      mobileToggle.addEventListener("click", () => {
        sidebar.classList.toggle("mobile-open");
        if (overlay) overlay.classList.toggle("show");
      });
    }

    if (overlay) {
      overlay.addEventListener("click", () => {
        sidebar.classList.remove("mobile-open");
        overlay.classList.remove("show");
      });
    }
  }

  /* ---------------- Dropdowns (notifications, user menu) ---------------- */
  function initDropdowns() {
    document.querySelectorAll("[data-dropdown-trigger]").forEach((trigger) => {
      const targetId = trigger.getAttribute("data-dropdown-trigger");
      const panel = document.getElementById(targetId);
      if (!panel) return;

      trigger.addEventListener("click", (e) => {
        e.stopPropagation();
        const isOpen = panel.classList.contains("show");
        document.querySelectorAll(".dropdown-panel.show").forEach((p) => p.classList.remove("show"));
        if (!isOpen) panel.classList.add("show");
      });
    });

    document.addEventListener("click", (e) => {
      document.querySelectorAll(".dropdown-panel.show").forEach((panel) => {
        if (!panel.contains(e.target)) panel.classList.remove("show");
      });
    });
  }

  /* ---------------- Toasts ---------------- */
  function ensureToastContainer() {
    let c = document.querySelector(".toast-container-c");
    if (!c) {
      c = document.createElement("div");
      c.className = "toast-container-c";
      document.body.appendChild(c);
    }
    return c;
  }

  const ICONS = {
    success: "fa-solid fa-circle-check",
    danger: "fa-solid fa-circle-exclamation",
    warning: "fa-solid fa-triangle-exclamation",
    info: "fa-solid fa-circle-info",
  };

  function showToast(message, type) {
    type = type || "info";
    const container = ensureToastContainer();
    const toast = document.createElement("div");
    toast.className = "toast-c toast-" + type;
    toast.innerHTML =
      '<i class="' + (ICONS[type] || ICONS.info) + '"></i>' +
      '<div class="toast-msg"></div>' +
      '<i class="fa-solid fa-xmark toast-close"></i>';
    toast.querySelector(".toast-msg").textContent = message;
    container.appendChild(toast);

    const remove = () => {
      toast.classList.add("leaving");
      setTimeout(() => toast.remove(), 200);
    };
    toast.querySelector(".toast-close").addEventListener("click", remove);
    setTimeout(remove, 4500);
  }
  window.CyberCRM.showToast = showToast;

  function initFlashToTeasts() {
    document.querySelectorAll("[data-flash]").forEach((el) => {
      showToast(el.getAttribute("data-flash-message"), el.getAttribute("data-flash-category"));
      el.remove();
    });
  }

  /* ---------------- Modals ---------------- */
  function initModals() {
    document.querySelectorAll("[data-modal-open]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const id = btn.getAttribute("data-modal-open");
        openModal(id);
      });
    });
    document.querySelectorAll("[data-modal-close]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const backdrop = btn.closest(".modal-backdrop-c");
        if (backdrop) closeModal(backdrop.id);
      });
    });
    document.querySelectorAll(".modal-backdrop-c").forEach((backdrop) => {
      backdrop.addEventListener("click", (e) => {
        if (e.target === backdrop) closeModal(backdrop.id);
      });
    });
  }

  function openModal(id) {
    const el = document.getElementById(id);
    if (el) el.classList.add("show");
  }
  function closeModal(id) {
    const el = document.getElementById(id);
    if (el) el.classList.remove("show");
  }
  window.CyberCRM.openModal = openModal;
  window.CyberCRM.closeModal = closeModal;

  /* ---------------- AJAX helper ---------------- */
  async function ajaxForm(url, formData, method) {
    method = method || "POST";
    const res = await fetch(url, {
      method: method,
      body: formData,
      headers: { "X-Requested-With": "XMLHttpRequest" },
    });
    let data;
    try {
      data = await res.json();
    } catch (err) {
      data = { success: res.ok, message: res.ok ? "Done." : "Something went wrong." };
    }
    return { ok: res.ok, data: data };
  }
  window.CyberCRM.ajaxForm = ajaxForm;

  /* ---------------- Simple client-side table sort (real, already-loaded data) ---------------- */
  function initSortableTables() {
    document.querySelectorAll("table[data-sortable]").forEach((table) => {
      table.querySelectorAll("thead th[data-sort-key]").forEach((th, index) => {
        th.classList.add("sortable");
        th.addEventListener("click", () => {
          const tbody = table.querySelector("tbody");
          const rows = Array.from(tbody.querySelectorAll("tr"));
          const dir = th.getAttribute("data-dir") === "asc" ? "desc" : "asc";
          table.querySelectorAll("thead th").forEach((h) => h.removeAttribute("data-dir"));
          th.setAttribute("data-dir", dir);

          const colIndex = Array.from(th.parentNode.children).indexOf(th);
          rows.sort((a, b) => {
            const av = (a.children[colIndex] && a.children[colIndex].getAttribute("data-value")) ||
              (a.children[colIndex] ? a.children[colIndex].textContent.trim() : "");
            const bv = (b.children[colIndex] && b.children[colIndex].getAttribute("data-value")) ||
              (b.children[colIndex] ? b.children[colIndex].textContent.trim() : "");
            const an = parseFloat(av), bn = parseFloat(bv);
            let cmp;
            if (!isNaN(an) && !isNaN(bn)) cmp = an - bn;
            else cmp = av.localeCompare(bv);
            return dir === "asc" ? cmp : -cmp;
          });
          rows.forEach((r) => tbody.appendChild(r));
        });
      });
    });
  }
})();
