// header.js - Mobile navigation controller and active state sync
(function () {
  function initHeader() {
    const btn = document.getElementById("clean-hamburger");
    const wrap = document.querySelector(".nav-wrap");
    if (!btn || !wrap) return;

    // Idempotent binding guard
    if (btn.dataset.headerBound === "true") {
      return;
    }
    btn.dataset.headerBound = "true";

    const toggleMenu = (shouldOpen) => {
      const open = typeof shouldOpen === "boolean" ? shouldOpen : !wrap.classList.contains("open");
      wrap.classList.toggle("open", open);
      btn.setAttribute("aria-expanded", open ? "true" : "false");
    };

    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      toggleMenu();
    });

    // Close menu when a navigation link is clicked
    const navLinks = wrap.querySelectorAll(".nav-link");
    navLinks.forEach((link) => {
      link.addEventListener("click", () => {
        toggleMenu(false);
      });
    });

    // Close menu on outside click
    document.addEventListener("click", (e) => {
      if (wrap.classList.contains("open") && !wrap.contains(e.target) && !btn.contains(e.target)) {
        toggleMenu(false);
      }
    });

    // Close menu on Escape key press
    document.addEventListener("keydown", (e) => {
      if ((e.key === "Escape" || e.key === "Esc") && wrap.classList.contains("open")) {
        toggleMenu(false);
        btn.focus();
      }
    });

    // Client-side active path matching fallback
    try {
      const currentPath = window.location.pathname;
      const currentPage = currentPath.split("/").pop() || "dashboard.php";
      navLinks.forEach((link) => {
        const rawHref = link.getAttribute("href") || "";
        const cleanHref = rawHref.replace(/^\.\//, "").split("#")[0].split("?")[0];
        if (
          cleanHref === currentPage ||
          (currentPage === "" && cleanHref === "dashboard.php")
        ) {
          link.classList.add("active");
          link.setAttribute("aria-current", "page");
        }
      });
    } catch (err) {
      // Gracefully continue if URL parsing fails
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initHeader);
  } else {
    initHeader();
  }
})();
