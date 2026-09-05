document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".avatar img").forEach((image) => {
    image.addEventListener("error", () => image.remove(), { once: true });
  });
});
