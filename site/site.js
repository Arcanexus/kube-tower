// kube-tower product site: menu, screenshot tour, copy button, latest release
(function () {
  "use strict";

  // Phone menu
  var menu = document.querySelector(".menu");
  var links = document.getElementById("nav-links");
  menu.addEventListener("click", function () {
    var open = links.classList.toggle("open");
    menu.setAttribute("aria-expanded", String(open));
  });
  links.addEventListener("click", function (e) {
    if (e.target.closest("a")) { links.classList.remove("open"); menu.setAttribute("aria-expanded", "false"); }
  });

  // Screenshot tour
  var captions = {
    "images": "Every image with its current and latest version and its vulnerabilities, one search for names, tags and CVE IDs.",
    "image-detail": "Image details: digests, size, registry links, the tree of where the image runs and its CVE list.",
    "charts": "Helm charts deployed by ArgoCD, with the tree of their subcharts and the latest version of each.",
    "security": "Trivy Operator reports of every cluster: misconfigurations, exposed secrets, RBAC, infrastructure and compliance.",
    "administration": "Administration: the state of every role and pod, rescans, Trivy database, connectivity and credential tests, logs.",
    "dark": "A dark theme, chosen by your system or by you.",
    "grafana": "Prometheus metrics and a ready-made Grafana dashboard for alerts and trends."
  };
  var img = document.getElementById("tour-img");
  var caption = document.getElementById("tour-caption");
  var tabs = document.querySelectorAll(".tabs [data-shot]");
  function show(tab) {
    var name = tab.getAttribute("data-shot");
    tabs.forEach(function (t) { t.setAttribute("aria-selected", String(t === tab)); });
    img.classList.add("fading");
    var next = new Image();
    next.onload = next.onerror = function () {
      img.src = next.src;
      img.width = next.naturalWidth || 1360;
      img.height = next.naturalHeight || 900;
      img.classList.remove("fading");
    };
    next.src = "images/" + name + ".png";
    img.alt = captions[name];
    caption.textContent = captions[name];
  }
  tabs.forEach(function (t) { t.addEventListener("click", function () { show(t); }); });
  caption.textContent = captions.images;
  img.alt = captions.images;

  // Copy the quick start commands
  var copy = document.querySelector(".copy");
  copy.addEventListener("click", function () {
    var text = document.querySelector(".code pre").innerText;
    var label = copy.querySelector("span");
    navigator.clipboard.writeText(text).then(function () {
      label.textContent = "Copied";
      setTimeout(function () { label.textContent = "Copy"; }, 1800);
    });
  });

  // Latest release in the hero pill (all releases may be pre-releases: take the newest one)
  fetch("https://api.github.com/repos/Arcanexus/kube-tower/releases?per_page=1")
    .then(function (r) { return r.ok ? r.json() : []; })
    .then(function (list) {
      if (!list.length) { return; }
      document.querySelector("[data-release-text]").textContent = list[0].tag_name + " is out · Apache-2.0";
      document.querySelector("[data-release]").href = list[0].html_url;
    })
    .catch(function () { /* keep the static text */ });
})();
