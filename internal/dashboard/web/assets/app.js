(() => {
  const forms = document.querySelectorAll("form[data-confirm], form[action^='/demo/']");
  let submitting = false;

  forms.forEach((form) => {
    form.addEventListener("submit", (event) => {
      const message = form.dataset.confirm;
      if (message && !window.confirm(message)) {
        event.preventDefault();
        return;
      }

      submitting = true;
      const button = form.querySelector("button[type='submit']");
      if (button) {
        button.disabled = true;
        button.dataset.originalText = button.textContent;
        button.textContent = "Working…";
      }
    });
  });

  document.querySelectorAll("[data-copy]").forEach((button) => {
    button.addEventListener("click", async () => {
      const selector = button.dataset.copy;
      const target = selector ? document.querySelector(selector) : null;
      if (!target) return;
      await navigator.clipboard.writeText(target.textContent || "");
      const previous = button.textContent;
      button.textContent = "Copied";
      window.setTimeout(() => { button.textContent = previous; }, 1200);
    });
  });

  if (document.body.dataset.autoRefresh !== "true") return;

  const label = document.getElementById("refresh-label");
  const configured = Number.parseInt(document.body.dataset.refreshSeconds || "15", 10);
  let remaining = Number.isFinite(configured) && configured > 0 ? configured : 15;

  window.setInterval(() => {
    if (submitting || document.visibilityState !== "visible") return;

    remaining -= 1;
    if (label) label.textContent = `Refresh in ${remaining}s`;

    if (remaining <= 0) window.location.reload();
  }, 1000);
})();
