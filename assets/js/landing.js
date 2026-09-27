(function () {
  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var year = document.getElementById("site-year");
  if (year) year.textContent = String(new Date().getFullYear());

  var toggle = document.getElementById("landing-menu");
  var nav = document.getElementById("landing-nav");
  if (toggle && nav) {
    toggle.addEventListener("click", function () {
      var open = nav.classList.toggle("is-open");
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
  }

  if (reduce) {
    document.documentElement.classList.add("reduce-motion");
    document.querySelectorAll(".reveal").forEach(function (el) {
      el.classList.add("is-in");
    });
    var mock = document.querySelector(".vault-mock");
    if (mock) mock.classList.add("is-complete");
    return;
  }

  document.documentElement.classList.add("motion-ok");

  var mock = document.querySelector(".vault-mock");
  if (mock) {
    requestAnimationFrame(function () {
      mock.classList.add("is-playing");
    });
  }

  if (!("IntersectionObserver" in window)) {
    document.querySelectorAll(".reveal").forEach(function (el) {
      el.classList.add("is-in");
    });
    return;
  }

  var io = new IntersectionObserver(
    function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-in");
          io.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.14, rootMargin: "0px 0px -48px 0px" }
  );

  document.querySelectorAll(".reveal").forEach(function (el) {
    io.observe(el);
  });
})();
