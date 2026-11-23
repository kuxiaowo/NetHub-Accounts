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

  function setupScrollingHeader(header) {
    let height = 0;
    let hidden = 0;
    function setHidden(pixels) {
      const next = Math.max(0, Math.min(height, pixels));
      if (next === hidden) return;
      hidden = next;
      root.style.setProperty('--header-scroll-offset', -hidden + 'px');
    }
    const setHeaderHeight = () => {
      const fractionHidden = height ? hidden / height : 0;
      height = Math.ceil(header.getBoundingClientRect().height);
      root.style.setProperty('--site-header-height', height + 'px');
      setHidden(Math.min(window.scrollY, fractionHidden * height));
    };
    setHeaderHeight();
    new ResizeObserver(setHeaderHeight).observe(header);
    let previousScrollY = window.scrollY;
    window.addEventListener('scroll', () => {
      const y = Math.max(0, Math.min(window.scrollY, root.scrollHeight - window.innerHeight));
      setHidden(Math.min(y, hidden + (y - previousScrollY)));
      previousScrollY = y;
    }, { passive: true });
    return pixels => {
      previousScrollY = window.scrollY;
      setHidden(Math.min(previousScrollY, pixels));
    };
  }

  function setupLanguageSwitch(header, restoreHeaderOffset) {
    const control = document.querySelector('.language-toggle');
    const key = 'nethub-language-position';
    const sections = Array.from(document.querySelectorAll('main section'));
    const disclosures = Array.from(document.querySelectorAll('main details'));
    function savePosition(destination) {
      const url = new URL(destination);
      const headerBounds = header.getBoundingClientRect();
      const readingLine = headerBounds.bottom + 24;
      const section = sections.find(el => {
        const rect = el.getBoundingClientRect();
        return rect.top <= readingLine && rect.bottom > readingLine;
      });
      const position = {
        path: url.pathname, language: url.searchParams.get('lang'),
        x: window.scrollX, y: window.scrollY,
        hiddenHeader: Math.max(0, -headerBounds.top),
        atBottom: window.scrollY > 0 && window.scrollY + window.innerHeight >= root.scrollHeight - 1,
        section: sections.indexOf(section), top: section?.getBoundingClientRect().top,
        open: disclosures.map(el => el.open),
      };
      try { sessionStorage.setItem(key, JSON.stringify(position)); } catch (_) { /* Follow the regular link. */ }
    }

    let position;
    try {
      position = JSON.parse(sessionStorage.getItem(key));
      sessionStorage.removeItem(key);
    } catch (_) { /* Storage is optional. */ }
    if (position && position.path === location.pathname && position.language === root.lang.split('-')[0]) {
      disclosures.forEach((el, index) => { if (position.open[index]) el.open = true; });
      const restore = () => {
        const section = sections[position.section];
        let y = position.y;
        if (position.atBottom) y = root.scrollHeight;
        else if (y > 0 && section) y = window.scrollY + section.getBoundingClientRect().top - position.top;
        window.scrollTo({ left: position.x, top: y, behavior: 'instant' });
        restoreHeaderOffset(position.hiddenHeader ?? 0);
      };
      restore();
      // Native fragment navigation can run after DOMContentLoaded.
      window.addEventListener('pageshow', restore, { once: true });
    }

    if (control.form) {
      control.form.addEventListener('submit', () => savePosition(control.form.action));
    } else {
      const syncHash = () => { control.hash = location.hash; };
      syncHash();
      window.addEventListener('hashchange', syncHash);
      control.addEventListener('click', event => {
        if (!event.defaultPrevented && !event.ctrlKey && !event.metaKey && !event.shiftKey && !event.altKey) {
          savePosition(control.href);
        }
      });
    }
  }

  applyColor();
  media.addEventListener('change', applyColor);
  document.addEventListener('DOMContentLoaded', () => {
    remember('nethub-language', root.lang === 'en' ? 'en' : 'zh');
    applyColor();
    const header = document.querySelector('.site-header');
    const restoreHeaderOffset = setupScrollingHeader(header);
    setupLanguageSwitch(header, restoreHeaderOffset);
    const themeSwitch = document.querySelector('[data-theme-toggle]');
    themeSwitch.hidden = false;
    themeSwitch.addEventListener('click', () => {
      theme = root.dataset.theme === 'dark' ? 'light' : 'dark';
      remember('nethub-theme', theme);
      applyColor();
    });
    const sectionLinks = Array.from(document.querySelectorAll('.account-nav a[href^="#"]'));
    if (sectionLinks.length) {
      const updateSection = () => {
        const active = sectionLinks.find(link => link.hash === location.hash) || sectionLinks[0];
        for (const link of sectionLinks) {
          if (link === active) link.setAttribute('aria-current', 'location');
          else link.removeAttribute('aria-current');
        }
      };
      window.addEventListener('hashchange', updateSection);
      updateSection();
    }
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
