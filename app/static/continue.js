const continuation = document.querySelector("[data-auth-continue]");

if (continuation) {
  window.location.replace(continuation.href);
}
