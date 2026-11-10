/* ==========================================================================
   Admin pages — Alert resolve, user reset/toggle actions via AJAX
   ========================================================================== */

document.addEventListener("DOMContentLoaded", () => {
  // Resolve alert
  document.querySelectorAll("[data-resolve-alert]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.getAttribute("data-resolve-alert");
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner-c"></span>';
      const { ok, data } = await window.CyberCRM.ajaxForm("/admin/alerts/" + id + "/resolve", new FormData(), "POST");
      if (ok && data.success !== false) {
        window.CyberCRM.showToast(data.message || "Alert marked as resolved.", "success");
        const row = document.getElementById("alert-row-" + id);
        if (row) {
          const statusCell = row.querySelector("[data-alert-status]");
          if (statusCell) statusCell.innerHTML = '<span class="badge-pill badge-success">Resolved</span>';
          btn.remove();
        }
      } else {
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-check"></i> Resolve';
        window.CyberCRM.showToast(data.message || "Unable to update the alert.", "danger");
      }
    });
  });

  // Reset risk score
  document.querySelectorAll("[data-reset-score]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.getAttribute("data-reset-score");
      const { ok, data } = await window.CyberCRM.ajaxForm("/admin/users/" + id + "/reset-score", new FormData(), "POST");
      if (ok && data.success !== false) {
        window.CyberCRM.showToast(data.message || "Risk score reset.", "success");
        setTimeout(() => window.location.reload(), 500);
      } else {
        window.CyberCRM.showToast(data.message || "Unable to reset score.", "danger");
      }
    });
  });

  // Toggle active / suspended (confirm before suspending an active account)
  document.querySelectorAll("[data-toggle-active]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.getAttribute("data-toggle-active");
      const isSuspendAction = btn.classList.contains("btn-danger-c") || btn.textContent.trim().toLowerCase().includes("suspend");
      if (isSuspendAction && !confirm("Suspend this user's account? They will be immediately blocked from logging in.")) {
        return;
      }
      const formData = new FormData();
      const next = btn.getAttribute("data-next");
      if (next) formData.append("next", next);
      const { ok, data } = await window.CyberCRM.ajaxForm("/admin/users/" + id + "/toggle-active", formData, "POST");
      if (ok && data.success !== false) {
        window.CyberCRM.showToast(data.message || "User status updated.", "success");
        setTimeout(() => window.location.reload(), 500);
      } else {
        window.CyberCRM.showToast(data.message || "Unable to update user.", "danger");
      }
    });
  });

  // Revoke active session (does not suspend the account)
  document.querySelectorAll("[data-revoke-session]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.getAttribute("data-revoke-session");
      if (!confirm("Revoke this user's active session? They will be logged out immediately on their next request.")) return;
      const formData = new FormData();
      const next = btn.getAttribute("data-next");
      if (next) formData.append("next", next);
      const { ok, data } = await window.CyberCRM.ajaxForm("/admin/users/" + id + "/revoke-session", formData, "POST");
      if (ok && data.success !== false) {
        window.CyberCRM.showToast(data.message || "Session revoked.", "success");
      } else {
        window.CyberCRM.showToast(data.message || "Unable to revoke session.", "danger");
      }
    });
  });

  // Disable privileged access (demote admin -> employee immediately)
  document.querySelectorAll("[data-disable-privileged]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.getAttribute("data-disable-privileged");
      if (!confirm("Disable privileged access for this account? It will immediately be demoted to a normal employee role.")) return;
      const formData = new FormData();
      const next = btn.getAttribute("data-next");
      if (next) formData.append("next", next);
      const { ok, data } = await window.CyberCRM.ajaxForm("/admin/users/" + id + "/disable-privileged", formData, "POST");
      if (ok && data.success !== false) {
        window.CyberCRM.showToast(data.message || "Privileged access disabled.", "success");
        setTimeout(() => window.location.reload(), 500);
      } else {
        window.CyberCRM.showToast(data.message || "Unable to disable privileged access.", "danger");
      }
    });
  });

  // Generic AJAX submit for any form with data-ajax-submit (Add User, etc.)
  document.querySelectorAll("form[data-ajax-submit]").forEach((form) => {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const submitBtn = form.querySelector("button[type='submit']");
      const original = submitBtn ? submitBtn.innerHTML : "";
      if (submitBtn) { submitBtn.disabled = true; submitBtn.innerHTML = '<span class="spinner-c"></span> Working...'; }
      const { ok, data } = await window.CyberCRM.ajaxForm(form.action, new FormData(form), "POST");
      if (submitBtn) { submitBtn.disabled = false; submitBtn.innerHTML = original; }
      if (ok && data.success !== false) {
        window.CyberCRM.showToast(data.message || "Done.", "success");
        setTimeout(() => window.location.reload(), 500);
      } else {
        window.CyberCRM.showToast(data.message || "Something went wrong.", "danger");
      }
    });
  });

  // View user modal (uses real data embedded in the row)
  document.querySelectorAll("[data-view-user]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const u = JSON.parse(btn.getAttribute("data-view-user"));
      const body = document.getElementById("viewUserBody");
      if (!body) return;
      body.innerHTML =
        '<div class="stack-gap">' +
        row("Username", u.username) +
        row("Email", u.email) +
        row("Role", u.role) +
        row("Live Risk Score", u.live_risk_score) +
        row("Risk Level", u.risk_level) +
        row("Suspicious", u.is_suspicious ? "Yes" : "No") +
        row("Status", u.is_active ? "Active" : "Disabled") +
        row("Last Login", u.last_login || "Never") +
        "</div>";
      window.CyberCRM.openModal("viewUserModal");
    });
  });

  function row(label, value) {
    return (
      '<div class="flex-between" style="border-bottom:1px solid var(--border); padding-bottom:8px;">' +
      '<span style="color:var(--text-muted); font-size:12px;">' + label + "</span>" +
      '<span style="font-weight:600; font-size:12.5px;">' + value + "</span>" +
      "</div>"
    );
  }
});
