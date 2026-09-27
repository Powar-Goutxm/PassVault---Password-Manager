// vault.js — PassVault Vault Management & Interactive Modals
(() => {
  // Modal elements
  const confirmBackdrop = document.getElementById("confirmModalBackdrop");
  const confirmTitle = document.getElementById("confirmTitle");
  const confirmDesc = document.getElementById("confirmDesc");
  const btnModalConfirm = document.getElementById("modalConfirm");

  const addBackdrop = document.getElementById("addModalBackdrop");
  const editBackdrop = document.getElementById("editModalBackdrop");

  // State for confirm modal action
  let pendingConfirmAction = null;

  // Accessible Modal helpers
  function openModal(modalEl) {
    if (!modalEl) return;
    modalEl.classList.add("show");
    modalEl.setAttribute("aria-hidden", "false");

    // Focus first interactive element for accessibility
    const firstInput = modalEl.querySelector("input:not([type='hidden']), button:not(.modal-close-x)");
    if (firstInput && typeof firstInput.focus === "function") {
      setTimeout(() => firstInput.focus(), 50);
    }
  }

  function closeModal(modalEl) {
    if (!modalEl) return;
    modalEl.classList.remove("show");
    modalEl.setAttribute("aria-hidden", "true");
    if (modalEl === confirmBackdrop) {
      pendingConfirmAction = null;
    }
  }

  function closeAllModals() {
    document.querySelectorAll(".modal-backdrop.show").forEach((m) => closeModal(m));
  }

  // Global Escape key listener for accessible modal closing
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" || e.keyCode === 27) {
      closeAllModals();
    }
  });

  // Modal backdrop click (outside click) & cancel button listeners
  document.addEventListener("click", (e) => {
    const target = e.target;
    if (!(target instanceof HTMLElement)) return;

    // Click on backdrop directly closes modal
    if (target.classList.contains("modal-backdrop")) {
      closeModal(target);
      return;
    }

    // Cancel buttons inside modals
    if (target.matches(".modal-cancel-btn") || target.closest(".modal-cancel-btn")) {
      const parentModal = target.closest(".modal-backdrop");
      if (parentModal) {
        closeModal(parentModal);
      }
      return;
    }
  });

  // Confirm Modal Confirm button handler
  if (btnModalConfirm) {
    btnModalConfirm.addEventListener("click", () => {
      if (typeof pendingConfirmAction === "function") {
        pendingConfirmAction();
      }
      closeModal(confirmBackdrop);
    });
  }

  // Helper to show confirm modal
  function showConfirmModal({ title, desc, confirmText = "Confirm", danger = false, onConfirm }) {
    if (!confirmBackdrop) return;
    if (confirmTitle) confirmTitle.textContent = title;
    if (confirmDesc) confirmDesc.textContent = desc;
    if (btnModalConfirm) {
      btnModalConfirm.textContent = confirmText;
      btnModalConfirm.classList.toggle("danger", !!danger);
    }
    pendingConfirmAction = onConfirm;
    openModal(confirmBackdrop);
  }

  // Add Modal Trigger
  const openAddModalBtn = document.getElementById("openAddModalBtn");
  if (openAddModalBtn) {
    openAddModalBtn.addEventListener("click", () => {
      const addForm = document.getElementById("addForm");
      if (addForm) addForm.reset();
      const addPw = document.getElementById("addPassword");
      if (addPw) {
        addPw.value = "";
        addPw.dispatchEvent(new Event("input", { bubbles: true }));
      }
      openModal(addBackdrop);
    });
  }

  // Auto-open Add Modal if URL hash is #add
  if (window.location.hash === "#add" && addBackdrop) {
    openModal(addBackdrop);
  }

  // Helper to retrieve decrypted password on-demand (SEC-04 Remediation)
  function getPasswordOnDemand(tr, callback) {
    if (tr.dataset.plainPassword !== undefined) {
      callback(tr.dataset.plainPassword);
      return;
    }

    const itemId = tr.dataset.id;
    const csrfInput = document.querySelector('input[name="csrf_token"]');
    const csrfToken = csrfInput ? csrfInput.value : "";

    const formData = new FormData();
    formData.append("action", "reveal");
    formData.append("id", itemId);
    formData.append("csrf_token", csrfToken);

    fetch("vault.php", {
      method: "POST",
      body: formData,
      headers: { "X-Requested-With": "XMLHttpRequest" }
    })
      .then((res) => res.json())
      .then((data) => {
        if (data.success && typeof data.password === "string") {
          tr.dataset.plainPassword = data.password;
          callback(data.password);
        } else {
          alert(data.error || "Failed to load password.");
        }
      })
      .catch(() => {
        alert("Network or security error retrieving password.");
      });
  }

  // CSPRNG Strong Password Generator (SEC-05 Remediation)
  function generateSecurePassword(len = 16) {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=";
    const randomValues = new Uint32Array(len);
    window.crypto.getRandomValues(randomValues);
    let out = "";
    for (let i = 0; i < len; i++) {
      out += chars.charAt(randomValues[i] % chars.length);
    }
    return out;
  }

  // Click delegation for page actions
  document.addEventListener("click", (e) => {
    const el = e.target;
    if (!(el instanceof HTMLElement)) return;

    // DELETE BUTTON -> Open accessible confirm modal
    const deleteBtn = el.matches(".delete-btn") ? el : el.closest(".delete-btn");
    if (deleteBtn) {
      const form = deleteBtn.closest("form.delete-form");
      if (!form) return;
      const website = deleteBtn.dataset.website || "";
      const desc = website
        ? `Are you sure you want to permanently delete the password for "${website}"? This action cannot be undone.`
        : "Are you sure you want to permanently delete this saved password? This action cannot be undone.";

      showConfirmModal({
        title: "Delete Password",
        desc: desc,
        confirmText: "Delete",
        danger: true,
        onConfirm: () => {
          form.submit();
        },
      });
      return;
    }

    // EDIT BUTTON -> Open accessible Edit Modal
    const editBtn = el.matches(".edit-btn") ? el : el.closest(".edit-btn");
    if (editBtn) {
      const tr = editBtn.closest("tr");
      const id = editBtn.dataset.id || (tr ? tr.dataset.id : "");
      const website = editBtn.dataset.website || (tr ? tr.dataset.website : "") || "";
      const username = editBtn.dataset.username || (tr ? tr.dataset.username : "") || "";

      const editIdInput = document.getElementById("editEntryId");
      const editWebInput = document.getElementById("editWebsite");
      const editUserInput = document.getElementById("editUsername");
      const editPwInput = document.getElementById("editPassword");

      if (editIdInput) editIdInput.value = id;
      if (editWebInput) editWebInput.value = website;
      if (editUserInput) editUserInput.value = username;
      if (editPwInput) {
        editPwInput.value = "";
        editPwInput.dispatchEvent(new Event("input", { bubbles: true }));
      }

      openModal(editBackdrop);
      return;
    }

    // ON-DEMAND SECURE SHOW / HIDE TOGGLE
    const showBtn = el.matches(".show-btn") ? el : el.closest(".show-btn");
    if (showBtn) {
      const tr = showBtn.closest("tr");
      if (!tr) return;

      const masked = tr.querySelector(".masked");
      const plain = tr.querySelector(".plain");
      if (!masked || !plain) return;

      const plainShown = window.getComputedStyle(plain).display !== "none";

      if (plainShown) {
        plain.style.display = "none";
        masked.style.display = "";
        showBtn.textContent = "Show";
      } else {
        showBtn.textContent = "...";
        getPasswordOnDemand(tr, (password) => {
          plain.textContent = password;
          plain.style.display = "inline";
          masked.style.display = "none";
          showBtn.textContent = "Hide";
        });
      }
      return;
    }

    // ON-DEMAND SECURE COPY (1400ms feedback)
    const copyBtn = el.matches(".copy-btn") ? el : el.closest(".copy-btn");
    if (copyBtn) {
      const tr = copyBtn.closest("tr");
      if (!tr) return;

      const prev = copyBtn.textContent;
      copyBtn.textContent = "...";
      getPasswordOnDemand(tr, (password) => {
        navigator.clipboard
          .writeText(password)
          .then(() => {
            copyBtn.textContent = "Copied";
            setTimeout(() => {
              copyBtn.textContent = prev || "Copy";
            }, 1400);
          })
          .catch(() => {
            copyBtn.textContent = prev || "Copy";
            alert("Copy failed. Please try manually.");
          });
      });
      return;
    }

    // CSPRNG GENERATOR BUTTONS (Add modal & Edit modal)
    const genAddBtn = el.matches("#genAddBtn") || el.closest("#genAddBtn") || el.matches("#genBtn") || el.closest("#genBtn");
    if (genAddBtn) {
      const input = document.getElementById("addPassword") || document.getElementById("new-password");
      if (input instanceof HTMLInputElement) {
        input.value = generateSecurePassword(16);
        input.dispatchEvent(new Event("input", { bubbles: true }));
        input.focus();
      }
      return;
    }

    const genEditBtn = el.matches("#genEditBtn") || el.closest("#genEditBtn");
    if (genEditBtn) {
      const input = document.getElementById("editPassword");
      if (input instanceof HTMLInputElement) {
        input.value = generateSecurePassword(16);
        input.dispatchEvent(new Event("input", { bubbles: true }));
        input.focus();
      }
      return;
    }
  });

  // Client-Side Live Search on #vaultSearch
  const searchInput = document.getElementById("vaultSearch");
  if (searchInput) {
    searchInput.addEventListener("input", () => {
      const term = searchInput.value.trim().toLowerCase();
      const rows = document.querySelectorAll("#credentialsTable tbody tr[data-id]");
      let matchCount = 0;

      rows.forEach((row) => {
        const site = (row.dataset.website || row.querySelector(".site-col")?.textContent || "").toLowerCase();
        const user = (row.dataset.username || row.querySelector(".user-col")?.textContent || "").toLowerCase();
        const matches = term === "" || site.includes(term) || user.includes(term);

        row.style.display = matches ? "" : "none";
        if (matches) matchCount++;
      });

      const noMatchRow = document.getElementById("noSearchMatchRow");
      if (noMatchRow) {
        noMatchRow.style.display = (matchCount === 0 && rows.length > 0) ? "" : "none";
      }
    });
  }

  // Expose modal helpers globally if needed
  window.pv_openModal = openModal;
  window.pv_closeModal = closeModal;
})();

/* ---------- Dark Theme Password Strength Meter ---------- */
(function () {
  const common = [
    "123456",
    "password",
    "123456789",
    "qwerty",
    "111111",
    "12345678",
    "abc123",
    "password1",
    "letmein",
  ];

  function scorePassword(pw) {
    if (!pw) return 0;
    let score = 0;

    // length
    score += Math.min(40, pw.length * 3);

    // variety: uppercase, lowercase, digits, symbols
    if (/[a-z]/.test(pw)) score += 10;
    if (/[A-Z]/.test(pw)) score += 10;
    if (/\d/.test(pw)) score += 12;
    if (/[\W_]/.test(pw)) score += 18;

    // bonus for long passphrases
    if (pw.length >= 16) score += 10;

    // penalty for common passwords
    const low = pw.toLowerCase();
    for (const c of common) {
      if (low.includes(c)) {
        score = Math.max(0, score - 40);
        break;
      }
    }

    return Math.max(0, Math.min(100, Math.round(score)));
  }

  function labelForScore(s) {
    if (s < 40) return { text: "Weak", cls: "weak", level: 1 };
    if (s < 70) return { text: "Medium", cls: "medium", level: 2 };
    if (s < 90) return { text: "Strong", cls: "strong", level: 3 };
    return { text: "Very Strong", cls: "vstrong", level: 4 };
  }

  function updateMeterForInput(inputEl) {
    if (!(inputEl instanceof HTMLInputElement)) return;
    let meter = inputEl.nextElementSibling;
    if (!meter || !meter.classList.contains("pw-strength")) {
      meter = inputEl.parentElement
        ? inputEl.parentElement.querySelector(".pw-strength")
        : null;
    }
    if (!meter) return;

    const barSpans = Array.from(meter.querySelectorAll(".pw-bar span"));
    const label = meter.querySelector(".pw-label");
    const val = inputEl.value || "";

    if (!val) {
      barSpans.forEach((sp) => {
        sp.className = "";
      });
      if (label) {
        label.textContent = "Strength";
        label.className = "pw-label";
      }
      return;
    }

    const score = scorePassword(val);
    const info = labelForScore(score);

    barSpans.forEach((sp, idx) => {
      sp.className = "";
      if (idx < info.level) {
        const clsMap = ["active-1", "active-2", "active-3", "active-4"];
        sp.classList.add(clsMap[Math.max(0, Math.min(clsMap.length - 1, info.level - 1))]);
      }
    });

    if (label) {
      label.textContent = info.text + ` · ${score}%`;
      label.className = "pw-label " + info.cls;
    }
  }

  function attachListeners() {
    const inputs = document.querySelectorAll("input.password-input");
    inputs.forEach((inp) => {
      if (inp._pwBound) return;
      inp._pwBound = true;
      inp.addEventListener("input", () => updateMeterForInput(inp));
      updateMeterForInput(inp);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", attachListeners);
  } else {
    attachListeners();
  }
  window.pv_attach_pw_strength = attachListeners;
})();
