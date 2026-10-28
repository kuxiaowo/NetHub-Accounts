document.querySelectorAll(".delete-user-form").forEach((form) => {
  form.addEventListener("submit", (event) => {
    if (!window.confirm(form.dataset.confirm)) {
      event.preventDefault();
    }
  });
});

(() => {
  const t = window.nethubT || ((text) => text);
  const dialog = document.getElementById("restriction-dialog");
  if (!dialog) return;
  const form = document.getElementById("restriction-form");
  const action = document.getElementById("restriction-action");
  const duration = document.getElementById("restriction-duration");
  const days = document.getElementById("restriction-days");
  const reason = document.getElementById("restriction-reason");
  const effect = document.getElementById("restriction-effect");
  const submit = document.getElementById("restriction-submit");
  const actions = {
    suspend_invitation: {
      label: t("暂停邀请"),
      effect: t("暂停期间不能生成邀请；该账号尚未使用的邀请将被撤销，恢复权限后也不会重新生效。"),
      example: t("例如：多次邀请广告账号，暂停邀请权限"),
      limited: true,
    },
    restore_invitation: {
      label: t("恢复邀请"),
      effect: t("解除邀请权限暂停；生成邀请仍须满足邮箱验证、72 小时等待及每日额度要求。"),
      example: t("例如：申诉核实通过，恢复邀请权限"),
      limited: false,
    },
    ban: {
      label: t("全站封禁"),
      effect: t("撤销该账号的登录会话与令牌，通知各站退出，并撤销尚未使用的邀请。"),
      example: t("例如：多次骚扰其他成员，经核实后封禁"),
      limited: true,
    },
    unban: {
      label: t("解除全站封禁"),
      effect: t("恢复账号使用资格；用户需要重新登录，已撤销的邀请不会恢复。"),
      example: t("例如：申诉核实通过，解除全站封禁"),
      limited: false,
    },
  };

  function updateAction() {
    const selected = actions[action.value];
    duration.hidden = !selected.limited;
    days.disabled = !selected.limited;
    if (!selected.limited) days.value = "0";
    effect.textContent = selected.effect;
    effect.classList.toggle("is-danger", action.value === "ban");
    reason.placeholder = selected.example;
    submit.textContent = selected.label;
    submit.classList.toggle("danger", action.value === "ban");
  }

  document.querySelectorAll("[data-restriction-url]").forEach((button) => {
    button.addEventListener("click", () => {
      form.reset();
      reason.setCustomValidity("");
      submit.disabled = false;
      form.action = button.dataset.restrictionUrl;
      document.getElementById("restriction-user").textContent =
        `${button.dataset.displayName} · ${button.dataset.username} (ID ${button.dataset.userId})`;
      updateAction();
      dialog.showModal();
      document.body.classList.add("restriction-dialog-open");
    });
  });
  action.addEventListener("change", updateAction);
  reason.addEventListener("input", () => reason.setCustomValidity(""));
  document.querySelectorAll("[data-close-restriction]").forEach((button) => {
    button.addEventListener("click", () => dialog.close());
  });
  dialog.addEventListener("close", () => document.body.classList.remove("restriction-dialog-open"));
  form.addEventListener("submit", (event) => {
    reason.value = reason.value.trim();
    if (!reason.value) {
      event.preventDefault();
      reason.setCustomValidity(t("请填写处理原因，不能只输入空格。"));
      reason.reportValidity();
      return;
    }
    submit.disabled = true;
  });
})();
