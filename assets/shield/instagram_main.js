// instagram_main.js - Runs in Instagram's MAIN execution world at document_start
// Multi-layer client-side SPA navigation guard
(function() {
  'use strict';

  function isExplorePath(pathname) {
    if (!pathname || typeof pathname !== 'string') return false;
    const p = pathname.trim().toLowerCase();
    return p === '/explore' || p === '/explore/' || p.startsWith('/explore/') || p.startsWith('/explore?');
  }

  function checkAndRedirect(targetUrl) {
    let path = '';
    try {
      const u = new URL(targetUrl, window.location.origin);
      path = u.pathname;
    } catch (_) {
      path = String(targetUrl || '');
    }
    if (isExplorePath(path)) {
      window.location.replace('https://www.instagram.com/');
      return true;
    }
    return false;
  }

  // Intercept history.pushState
  const origPush = history.pushState;
  history.pushState = function(state, title, url) {
    if (url && checkAndRedirect(url)) {
      return;
    }
    origPush.apply(this, arguments);
    checkCurrentRoute();
  };

  // Intercept history.replaceState
  const origReplace = history.replaceState;
  history.replaceState = function(state, title, url) {
    if (url && checkAndRedirect(url)) {
      return;
    }
    origReplace.apply(this, arguments);
    checkCurrentRoute();
  };

  function checkCurrentRoute() {
    if (isExplorePath(window.location.pathname)) {
      window.location.replace('https://www.instagram.com/');
    }
  }

  window.addEventListener('popstate', checkCurrentRoute);

  // Check immediately at document_start
  checkCurrentRoute();
})();
