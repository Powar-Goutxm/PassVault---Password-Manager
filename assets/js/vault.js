//  modal confirmations + copy + edit toggle + generator
(() => {
  // modal elements
  const backdrop = document.getElementById("confirmModalBackdrop");
  const modalTitle = document.getElementById("confirmTitle");
  const modalDesc = document.getElementById("confirmDesc");
  const btnCancel = document.getElementById("modalCancel");
  const btnConfirm = document.getElementById("modalConfirm");

  // state for what the modal will do
  let pendingAction = null;
  let pendingData = null;

  // helper to show modal
  function showModal({
    title,
    desc,
    confirmText = "Confirm",
    danger = false,
    onConfirm,
  }) {
    modalTitle.textContent = title;
    modalDesc.textContent = desc;
    btnConfirm.textContent = confirmText;
    btnConfirm.classList.toggle("danger", !!danger);
    pendingAction = onConfirm;
    pendingData = null;
    backdrop.classList.add("show");
    backdrop.setAttribute("aria-hidden", "false");
  }

  function hideModal() {
    backdrop.classList.remove("show");
    backdrop.setAttribute("aria-hidden", "true");
    pendingAction = null;
    pendingData = null;
  }

  // cancel handler
  btnCancel.addEventListener("click", hideModal);
  backdrop.addEventListener("click", (e) => {
    if (e.target === backdrop) hideModal(); // click outside closes
  });

  // confirm handler
  btnConfirm.addEventListener("click", () => {
    if (typeof pendingAction === "function") pendingAction(pendingData);
    hideModal();
  });

  // Click delegation for page actions
  document.addEventListener("click", (e) => {
    const el = e.target;
    if (!(el instanceof HTMLElement)) return;

    // DELETE button: open confirm modal for delete
    if (el.matches(".delete-btn")) {
      const form = el.closest("form.delete-form");
      if (!form) return;
      // modal text
      showModal({
        title: "Delete password",
        desc: "This will permanently delete the saved password. This action cannot be undone.",
        confirmText: "Delete",
        danger: true,
        onConfirm: () => {
          // submit the form after confirm
          form.submit();
        },
      });
      return;
    }

    // SIMPLE SHOW / HIDE TOGGLE
    // SHOW / HIDE toggle — robust and simple
    if (el.matches(".show-btn")) {
      const tr = el.closest("tr");
      if (!tr) return;

      const masked = tr.querySelector(".masked");
      const plain = tr.querySelector(".plain");
      if (!masked || !plain) return;

      // If plain is currently visible (computed)
      const plainShown = window.getComputedStyle(plain).display !== "none";

      if (plainShown) {
        // hide plain, show masked
        plain.style.display = "none";
        masked.style.display = ""; // revert to default (inline)
        el.textContent = "Show";
      } else {
        // show plain, hide masked
        plain.style.display = "inline";
        masked.style.display = "none";
        el.textContent = "Hide";
      }
      return;
    }

    // COPY
    if (el.matches(".copy-btn")) {
      const tr = el.closest("tr");
      if (!tr) return;
      const plain = tr.querySelector(".plain");
      if (!plain) return;
      const text = plain.textContent || "";
      navigator.clipboard
        .writeText(text)
        .then(() => {
          const prev = el.textContent;
          el.textContent = "Copied";
          setTimeout(() => {
            el.textContent = prev || "Copy";
          }, 1400);
        })
        .catch(() => alert("Copy failed. Try manually."));
      return;
    }

    // EDIT toggle
    if (el.matches(".edit-toggle")) {
      const id = el.dataset.id;
      const row = document.getElementById("edit-" + id);
      if (row) row.style.display = "";
      return;
    }
    if (el.matches(".edit-cancel")) {
      const id = el.dataset.id;
      const row = document.getElementById("edit-" + id);
      if (row) row.style.display = "none";
      return;
    }

    // PASSWORD GENERATOR
    if (el.matches("#genBtn")) {
      showModal({
        title: "Generate strong password?",
        desc: "A secure, random password will be generated and placed into the password field.",
        confirmText: "Generate",
        danger: false,
        onConfirm: () => {
          const len = 16;
          const chars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=";
          let out = "";
          for (let i = 0; i < len; i++) {
            out += chars.charAt(Math.floor(Math.random() * chars.length));
          }
          const input = document.getElementById("new-password");
          if (input instanceof HTMLInputElement) {
            input.value = out;
            // notify listeners (so strength meter updates)
            input.dispatchEvent(new Event("input", { bubbles: true }));
            input.focus();
          }
        },
      });
      return;
    }
  });
})();

// mobile toggle for clean nav
(function () {
  const hamburger = document.getElementById("clean-hamburger");
  const navWrap = document.querySelector(".modern-clean .nav-wrap");
  const cleanNav = document.querySelector(".modern-clean .nav-center");

  if (!hamburger || !navWrap) return;
  hamburger.addEventListener("click", () => {
    const open = navWrap.classList.toggle("open");
    hamburger.setAttribute("aria-expanded", open ? "true" : "false");
    cleanNav.style.display = open ? "block" : "";
  });
})();

/* ---------- Password strength checker ---------- */
(function () {
  // common weak passwords to penalize
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
    score += Math.min(40, pw.length * 3); // up to 40

    // variety: uppercase, lowercase, digits, symbols
    if (/[a-z]/.test(pw)) score += 10;
    if (/[A-Z]/.test(pw)) score += 10;
    if (/\d/.test(pw)) score += 12;
    if (/[\W_]/.test(pw)) score += 18;

    // bonus for long passphrases
    if (pw.length >= 16) score += 10;

    // penalty for common passwords or repetitive sequences
    const low = pw.toLowerCase();
    for (const c of common)
      if (low.includes(c)) score = Math.max(0, score - 40);

    // cap
    score = Math.max(0, Math.min(100, Math.round(score)));
    return score;
  }

  function labelForScore(s) {
    if (s < 40) return { text: "Weak", cls: "weak", level: 1 };
    if (s < 70) return { text: "Medium", cls: "medium", level: 2 };
    if (s < 90) return { text: "Strong", cls: "strong", level: 3 };
    return { text: "Very Strong", cls: "vstrong", level: 4 };
  }

  function updateMeterForInput(inputEl) {
    if (!(inputEl instanceof HTMLInputElement)) return;
    // find nearest .pw-strength (either nextSibling or parent)
    let meter = inputEl.nextElementSibling;
    if (!meter || !meter.classList.contains("pw-strength")) {
      // try parent search
      meter = inputEl.parentElement
        ? inputEl.parentElement.querySelector(".pw-strength")
        : null;
    }
    if (!meter) return;

    const barSpans = Array.from(meter.querySelectorAll(".pw-bar span"));
    const label = meter.querySelector(".pw-label");
    const score = scorePassword(inputEl.value || "");

    const info = labelForScore(score);

    // clear all active classes then set based on level
    barSpans.forEach((sp, idx) => {
      sp.className = ""; // reset classes
      if (idx < info.level) {
        // set color class depending on level
        const clsMap = ["active-1", "active-2", "active-3", "active-4"];
        sp.classList.add(
          clsMap[Math.max(0, Math.min(clsMap.length - 1, info.level - 1))]
        );
      }
    });

    // set label text & class
    label.textContent = info.text + (inputEl.value ? ` · ${score}%` : "");
    label.className = "pw-label " + info.cls;
  }

  // wire up all existing and future password inputs
  function attachListeners() {
    // initial: all current inputs with class 'password-input'
    const inputs = document.querySelectorAll("input.password-input");
    inputs.forEach((inp) => {
      // avoid double-binding
      if (inp._pwBound) return;
      inp._pwBound = true;

      // on input update meter
      inp.addEventListener("input", () => updateMeterForInput(inp));
      // update initial state (in case prefilled)
      updateMeterForInput(inp);
    });
  }

  // run on DOM ready and expose a re-run utility for dynamically added rows
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", attachListeners);
  } else {
    attachListeners();
  }
  // expose fn for manual reattach (if you add rows dynamically)
  window.pv_attach_pw_strength = attachListeners;
})();
