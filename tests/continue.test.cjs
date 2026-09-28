const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const script = fs.readFileSync(path.join(__dirname, "../app/static/continue.js"), "utf8");
const destination = "/oauth/authorize?state=original-state&nonce=original-nonce";

function page() {
  const button = new EventTarget();
  Object.assign(button, {
    dataset: { destination },
    disabled: true,
    textContent: "继续",
  });
  const requests = [];
  const timers = [];
  const context = {
    document: { querySelector: () => button },
    window: {
      location: { replace: (url) => requests.push(url) },
      setTimeout: (callback) => timers.push(callback),
    },
  };
  const load = () => vm.runInNewContext(script, context);
  load();
  return { button, requests, timers, load };
}

test("automatic navigation followed by repeated clicks sends one request", () => {
  const { button, requests, timers } = page();
  timers[0]();
  // Even queued events delivered after disabling must not navigate again.
  button.dispatchEvent(new Event("click"));
  button.dispatchEvent(new Event("click"));
  assert.deepEqual(requests, [destination]);
  assert.equal(button.disabled, true);
});

test("manual click wins a race with automatic navigation and preserves state", () => {
  const { button, requests, timers } = page();
  assert.equal(button.disabled, false);
  button.dispatchEvent(new Event("click"));
  timers[0]();
  assert.deepEqual(requests, [destination]);
  assert.equal(new URL(requests[0], "https://accounts.test").searchParams.get("state"),
    "original-state");
  assert.equal(button.disabled, true);
});

test("double clicking before the automatic timer sends one request", () => {
  const { button, requests, timers } = page();
  button.dispatchEvent(new Event("click"));
  button.dispatchEvent(new Event("click"));
  timers[0]();
  assert.deepEqual(requests, [destination]);
});

test("loading the script twice cannot schedule a second navigation", () => {
  const { requests, timers, load } = page();
  load();
  assert.equal(timers.length, 1);
  timers[0]();
  load();
  assert.deepEqual(requests, [destination]);
});
