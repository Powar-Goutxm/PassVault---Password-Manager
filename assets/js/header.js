// Mobile hamburger menu toggle
(function () {
  const btn = document.getElementById("clean-hamburger");
  const wrap = document.querySelector(".nav-wrap");
  if (btn && wrap) {
    btn.addEventListener("click", () => {
      wrap.classList.toggle("open");
      btn.setAttribute("aria-expanded", wrap.classList.contains("open"));
    });

    // Close menu when a link is clicked
    const navLinks = wrap.querySelectorAll(".nav-link");
    navLinks.forEach((link) => {
      link.addEventListener("click", () => {
        wrap.classList.remove("open");
        btn.setAttribute("aria-expanded", "false");
      });
    });

    // Highlight active nav link
    const currentPage =
      window.location.pathname.split("/").pop() || "dashboard.php";
    navLinks.forEach((link) => {
      if (
        link.getAttribute("href") === currentPage ||
        (currentPage === "" && link.getAttribute("href") === "dashboard.php")
      ) {
        link.classList.add("active");
      }
    });
  }
})();
