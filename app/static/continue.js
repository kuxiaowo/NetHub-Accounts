(() => {
  const continuation = document.querySelector("[data-auth-continue]");
  if (!continuation || continuation.dataset.continueInitialized === "true") {
    return;
  }
  continuation.dataset.continueInitialized = "true";
  const destination = continuation.dataset.destination;
  let navigating = false;

  function continueOnce() {
    if (navigating) {
      return;
    }
    // Lock before navigating: a pending navigation must not issue another code.
    navigating = true;
    continuation.disabled = true;
    continuation.textContent = "正在返回…";
    window.location.replace(destination);
  }

  continuation.addEventListener("click", continueOnce);
  continuation.disabled = false;
  window.setTimeout(continueOnce, 0);
})();
