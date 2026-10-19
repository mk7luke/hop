(function () {
  var input = document.getElementById("url");
  document.addEventListener("keydown", function (ev) {
    var tag = (ev.target && ev.target.tagName) || "";
    if (ev.key === "/" && tag !== "INPUT" && tag !== "SELECT" && tag !== "TEXTAREA") {
      ev.preventDefault();
      if (input) input.focus();
    }
  });

  function copy(btn, text) {
    if (!btn || !text || !navigator.clipboard) return;
    btn.addEventListener("click", function () {
      navigator.clipboard.writeText(text).then(function () {
        var prev = btn.textContent;
        btn.textContent = "Copied";
        setTimeout(function () { btn.textContent = prev; }, 1200);
      }).catch(function () {});
    });
  }

  var clean = document.getElementById("clean");
  copy(document.getElementById("copy-clean"), clean ? clean.textContent : "");
  copy(document.getElementById("copy-page"), window.location.href);
})();
