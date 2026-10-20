// content.js - Blocker Instagram Shield for Single Page Application navigation
(function() {
  'use strict';

  function enforceBlock() {
    const p = window.location.pathname || '';
    if (p.startsWith('/explore')) {
      // Force navigation so the browser's URLBlocklist policy triggers ERR_BLOCKED_BY_ADMINISTRATOR
      // or redirect back to main feed if blocked
      window.location.replace('https://www.instagram.com/');
    }
  }

  // 1. Intercept client-side routing (pushState & replaceState)
  const origPush = history.pushState;
  history.pushState = function(...args) {
    origPush.apply(this, args);
    enforceBlock();
  };

  const origReplace = history.replaceState;
  history.replaceState = function(...args) {
    origReplace.apply(this, args);
    enforceBlock();
  };

  window.addEventListener('popstate', enforceBlock);
  enforceBlock();
  setInterval(enforceBlock, 400);

  // 2. Hide Explore and Search UI elements from the DOM
  const css = `
    /* Hide explore icon/link in sidebar and navigation */
    a[href^="/explore"],
    a[href*="/explore"],
    div:has(> a[href^="/explore"]),
    div:has(> a[href*="/explore"]),

    /* Hide search button and its container in Instagram sidebar */
    div:has(> svg[aria-label="Search"]),
    div:has(> svg[aria-label="Explore"]),
    svg[aria-label="Search"],
    svg[aria-label="Explore"],

    /* Hide search drawer and inputs */
    input[aria-label="Search input"],
    input[placeholder="Search"],
    div[aria-label="Search"] {
      display: none !important;
      visibility: hidden !important;
      pointer-events: none !important;
    }
  `;

  function injectCSS() {
    if (document.getElementById('blocker-ig-shield-style')) return;
    const style = document.createElement('style');
    style.id = 'blocker-ig-shield-style';
    style.textContent = css;
    const target = document.head || document.documentElement;
    if (target) target.appendChild(style);
  }

  injectCSS();
  document.addEventListener('DOMContentLoaded', injectCSS);
  const observer = new MutationObserver(injectCSS);
  observer.observe(document.documentElement, { childList: true, subtree: true });
})();
