(() => {
  'use strict';
  const root = document.documentElement;
  const media = window.matchMedia('(prefers-color-scheme: dark)');
  let theme = 'system';
  try {
    theme = localStorage.getItem('nethub-theme') || 'system';
  } catch (_) { /* Use defaults when storage is unavailable. */ }

  function remember(key, value) {
    try { localStorage.setItem(key, value); } catch (_) { /* Apply on this page. */ }
  }

  function applyColor() {
    const dark = theme === 'dark' || (theme !== 'light' && media.matches);
    root.dataset.theme = dark ? 'dark' : 'light';
    const button = document.querySelector('[data-theme-toggle]');
    if (button) {
      button.setAttribute('aria-checked', String(dark));
      button.setAttribute('aria-label', window.nethubT('深色模式'));
      button.title = window.nethubT(dark ? '切换浅色主题' : '切换深色主题');
      button.querySelector('.theme-switch-label').textContent = window.nethubT(dark ? '深色' : '浅色');
    }
  }

  applyColor();
  media.addEventListener('change', applyColor);
  document.addEventListener('DOMContentLoaded', () => {
    remember('nethub-language', root.lang === 'en' ? 'en' : 'zh');
    applyColor();
    const themeSwitch = document.querySelector('[data-theme-toggle]');
    themeSwitch.hidden = false;
    themeSwitch.addEventListener('click', () => {
      theme = root.dataset.theme === 'dark' ? 'light' : 'dark';
      remember('nethub-theme', theme);
      applyColor();
    });
    const menu = document.querySelector('details.nav-account');
    if (menu) {
      document.addEventListener('click', (event) => {
        if (menu.open && !menu.contains(event.target)) menu.open = false;
      });
      menu.addEventListener('focusout', (event) => {
        if (event.relatedTarget && !menu.contains(event.relatedTarget)) menu.open = false;
      });
      menu.addEventListener('keydown', (event) => {
        if (event.key === 'Escape' && menu.open) {
          menu.open = false;
          menu.querySelector('summary').focus();
        }
      });
    }
  });
})();
