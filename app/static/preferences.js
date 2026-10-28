(() => {
  'use strict';
  const root = document.documentElement;
  const media = window.matchMedia('(prefers-color-scheme: dark)');
  let theme = 'system';
  try { theme = localStorage.getItem('nethub-theme') || 'system'; } catch (_) { /* Storage may be disabled. */ }
  function applyTheme() {
    const dark = theme === 'dark' || (theme === 'system' && media.matches);
    root.dataset.theme = dark ? 'dark' : 'light';
    const button = document.querySelector('[data-theme-toggle]');
    if (button) {
      button.setAttribute('aria-pressed', String(dark));
      button.setAttribute('aria-label', root.lang === 'en' ? (dark ? 'Switch to light theme' : 'Switch to dark theme') : (dark ? '切换浅色主题' : '切换深色主题'));
    }
  }
  applyTheme();
  media.addEventListener('change', applyTheme);
  document.addEventListener('DOMContentLoaded', () => {
    try { localStorage.setItem('nethub-language', root.lang === 'en' ? 'en' : 'zh'); } catch (_) { /* Preference remains in the cookie. */ }
    applyTheme();
    document.querySelector('[data-theme-toggle]')?.addEventListener('click', () => {
      theme = root.dataset.theme === 'dark' ? 'light' : 'dark';
      try { localStorage.setItem('nethub-theme', theme); } catch (_) { /* Still apply for this page. */ }
      applyTheme();
    });
  });
})();
