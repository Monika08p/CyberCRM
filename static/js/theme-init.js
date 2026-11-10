(function () {
  try {
    var t = localStorage.getItem("cybercrm-theme") || "dark";
    document.documentElement.setAttribute("data-theme", t);
  } catch (e) {
    document.documentElement.setAttribute("data-theme", "dark");
  }
})();
