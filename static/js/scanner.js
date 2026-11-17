// Scanner interaction: input examples, validation and a clear loading state.
(function () {
  var form = document.getElementById("scan-form");
  if (!form) return;
  var input = document.getElementById("url-input");
  var button = document.getElementById("scan-btn");
  var label = document.getElementById("scan-label");
  function reset() {
    form.classList.remove("loading");
    button.disabled = false;
    if (label) label.innerHTML = 'Analyze URL <b>↗</b>';
  }
  form.addEventListener("submit", function (event) {
    if (!input.value.trim()) {
      event.preventDefault();
      input.setAttribute("aria-invalid", "true");
      input.focus();
      return;
    }
    input.removeAttribute("aria-invalid");
    form.classList.add("loading");
    button.disabled = true;
    if (label) label.textContent = "Analyzing…";
  });
  input.addEventListener("input", function () { input.removeAttribute("aria-invalid"); });
  document.querySelectorAll(".example").forEach(function (chip) {
    chip.addEventListener("click", function () {
      input.value = chip.getAttribute("data-url");
      input.focus();
    });
  });
  window.addEventListener("pageshow", reset);
  var result = document.getElementById("result");
  if (result) result.scrollIntoView({ behavior: "smooth", block: "start" });
})();