/* ==========================================================================
   Customers page — Add / Edit / Delete modal logic
   All operations hit the real Flask backend and refresh from the database.
   ========================================================================== */

document.addEventListener("DOMContentLoaded", () => {
  const addBtn = document.getElementById("btnAddCustomer");
  const addForm = document.getElementById("addCustomerForm");
  const editForm = document.getElementById("editCustomerForm");
  const deleteForm = document.getElementById("deleteCustomerForm");

  if (addBtn && addForm) {
    addBtn.addEventListener("click", () => {
      addForm.reset();
      window.CyberCRM.openModal("addCustomerModal");
    });
  }

  // Edit — data already rendered server-side on each row (real DB data)
  document.querySelectorAll("[data-edit-customer]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const c = JSON.parse(btn.getAttribute("data-edit-customer"));
      editForm.action = "/customers/" + c.id + "/edit";
      editForm.querySelector("[name='name']").value = c.name || "";
      editForm.querySelector("[name='company']").value = c.company || "";
      editForm.querySelector("[name='email']").value = c.email || "";
      editForm.querySelector("[name='phone']").value = c.phone || "";
      editForm.querySelector("[name='address']").value = c.address || "";
      editForm.querySelector("[name='notes']").value = c.notes || "";
      window.CyberCRM.openModal("editCustomerModal");
    });
  });

  // Delete confirmation
  document.querySelectorAll("[data-delete-customer]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.getAttribute("data-delete-customer");
      const name = btn.getAttribute("data-customer-name");
      deleteForm.action = "/customers/" + id + "/delete";
      document.getElementById("deleteCustomerName").textContent = name;
      window.CyberCRM.openModal("deleteCustomerModal");
    });
  });

  [addForm, editForm, deleteForm].forEach((form) => {
    if (!form) return;
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const submitBtn = form.querySelector("button[type='submit']");
      const originalHtml = submitBtn ? submitBtn.innerHTML : "";
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span class="spinner-c"></span> Working...';
      }

      const formData = new FormData(form);
      const { ok, data } = await window.CyberCRM.ajaxForm(form.action, formData, "POST");

      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalHtml;
      }

      if (ok && data.success !== false) {
        window.CyberCRM.showToast(data.message || "Done.", "success");
        setTimeout(() => window.location.reload(), 500);
      } else {
        window.CyberCRM.showToast(data.message || "Something went wrong.", "danger");
      }
    });
  });
});
