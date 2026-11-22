(() => {
  'use strict';
  const root = document.documentElement;
  const media = window.matchMedia('(prefers-color-scheme: dark)');
  let layout = 'classic';
  let theme = 'system';
  try {
    if (localStorage.getItem('nethub-layout') === 'modern') layout = 'modern';
    theme = localStorage.getItem('nethub-theme') || 'system';
  } catch (_) { /* Use defaults when storage is unavailable. */ }

  function remember(key, value) {
    try { localStorage.setItem(key, value); } catch (_) { /* Apply on this page. */ }
  }

  function applyColor() {
    const dark = layout === 'modern' && (theme === 'dark' || (theme === 'system' && media.matches));
    root.dataset.theme = dark ? 'dark' : 'light';
    const button = document.querySelector('[data-theme-toggle]');
    if (button) {
      button.setAttribute('aria-pressed', String(dark));
      button.setAttribute('aria-label', root.lang === 'en'
        ? (dark ? 'Switch to light theme' : 'Switch to dark theme')
        : (dark ? '切换浅色主题' : '切换深色主题'));
    }
  }

  function applyLayout() {
    root.dataset.ui = layout;
    for (const sheet of document.querySelectorAll('[data-layout-sheet]')) {
      sheet.media = sheet.dataset.layoutSheet === layout ? 'all' : 'not all';
    }
    const icon = document.querySelector('[data-layout-icon]');
    icon.href = icon.dataset[layout];
    applyColor();
  }

  applyLayout();
  media.addEventListener('change', applyColor);
  document.addEventListener('DOMContentLoaded', () => {
    remember('nethub-language', root.lang === 'en' ? 'en' : 'zh');
    applyColor();
    const switcher = document.querySelector('[data-layout-toggle]');
    switcher.hidden = false;
    switcher.addEventListener('click', () => {
      layout = layout === 'modern' ? 'classic' : 'modern';
      remember('nethub-layout', layout);
      applyLayout();
    });
    document.querySelector('[data-theme-toggle]').addEventListener('click', () => {
      theme = root.dataset.theme === 'dark' ? 'light' : 'dark';
      remember('nethub-theme', theme);
      applyColor();
    });
  });
})();
