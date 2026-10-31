// reddit_main.js - Injected directly into Reddit's MAIN execution world
// Runs in the exact same JS context as Reddit's React / Faceplate application
(function() {
  'use strict';

  function cleanUrl(url) {
    if (!url || typeof url !== 'string') return url;
    return url
      .replace(/[?&]type=media(&|$)/, '$1')
      .replace(/[?&]type=video(&|$)/, '$1')
      .replace(/[?&]include_over_18=[^&]*(&|$)/, '$1')
      .replace(/[?&]$/, '');
  }

  // -------------------------------------------------------------------------
  // 1. Monkey-Patch window.fetch in Page Execution Context
  // -------------------------------------------------------------------------
  if (typeof window.fetch === 'function') {
    const origFetch = window.fetch;
    window.fetch = function(resource, init) {
      if (init && init.body) {
        if (typeof init.body === 'string') {
          try {
            if (init.body.includes('"over_18":true') || init.body.includes('"over_18": true')) {
              init.body = init.body.replace(/"over_18":\s*true/g, '"over_18": false');
            }
            if (init.body.includes('"over18":true') || init.body.includes('"over18": true')) {
              init.body = init.body.replace(/"over18":\s*true/g, '"over18": false');
            }
            if (init.body.includes('"search_include_over_18":true') || init.body.includes('"search_include_over_18": true')) {
              init.body = init.body.replace(/"search_include_over_18":\s*true/g, '"search_include_over_18": false');
            }
            if (init.body.includes('"include_over_18":true') || init.body.includes('"include_over_18": true')) {
              init.body = init.body.replace(/"include_over_18":\s*true/g, '"include_over_18": false');
            }
          } catch (_) {}
        }
      }

      // Sanitize URL if it contains include_over_18 or type=media
      if (typeof resource === 'string') {
        if (resource.includes('include_over_18') || resource.includes('type=media') || resource.includes('type=video')) {
          resource = cleanUrl(resource);
        }
      } else if (resource && resource.url && typeof resource.url === 'string') {
        if (resource.url.includes('include_over_18') || resource.url.includes('type=media')) {
          try {
            resource = new Request(cleanUrl(resource.url), resource);
          } catch (_) {}
        }
      }

      return origFetch.apply(this, arguments);
    };
  }

  // -------------------------------------------------------------------------
  // 2. Monkey-Patch XMLHttpRequest in Page Execution Context
  // -------------------------------------------------------------------------
  if (typeof XMLHttpRequest !== 'undefined' && XMLHttpRequest.prototype) {
    const origOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url, ...rest) {
      if (typeof url === 'string' && (url.includes('include_over_18') || url.includes('type=media'))) {
        url = cleanUrl(url);
      }
      return origOpen.call(this, method, url, ...rest);
    };

    const origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function(body) {
      if (body && typeof body === 'string') {
        try {
          if (body.includes('"over_18":true') || body.includes('"over_18": true')) {
            body = body.replace(/"over_18":\s*true/g, '"over_18": false');
          }
          if (body.includes('"over18":true') || body.includes('"over18": true')) {
            body = body.replace(/"over18":\s*true/g, '"over18": false');
          }
          if (body.includes('"search_include_over_18":true') || body.includes('"search_include_over_18": true')) {
            body = body.replace(/"search_include_over_18":\s*true/g, '"search_include_over_18": false');
          }
          if (body.includes('"include_over_18":true') || body.includes('"include_over_18": true')) {
            body = body.replace(/"include_over_18":\s*true/g, '"include_over_18": false');
          }
        } catch (_) {}
      }
      return origSend.call(this, body);
    };
  }

  // -------------------------------------------------------------------------
  // 3. Proactive Account Preferences Sync
  // -------------------------------------------------------------------------
  let lastSync = 0;
  function syncServerPrefs(force) {
    const now = Date.now();
    if (!force && (now - lastSync < 5000)) return;
    lastSync = now;

    const payload = JSON.stringify({
      over_18: false,
      search_include_over_18: false,
      label_nsfw: true,
      no_profanity: true
    });

    const endpoints = [
      'https://www.reddit.com/api/v1/me/prefs',
      'https://oauth.reddit.com/api/v1/me/prefs'
    ];

    for (let i = 0; i < endpoints.length; i++) {
      try {
        fetch(endpoints[i], {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: payload
        }).catch(function() {});
      } catch (_) {}
    }
  }

  syncServerPrefs(true);
  window.addEventListener('load', function() { syncServerPrefs(true); });

  // -------------------------------------------------------------------------
  // 4. Client-side Navigation Guard (pushState / replaceState)
  // -------------------------------------------------------------------------
  const origPush = history.pushState;
  history.pushState = function(...args) {
    let url = args[2] ? String(args[2]) : '';
    if (url.includes('include_over_18') || url.includes('type=media')) {
      url = cleanUrl(url);
      args[2] = url;
    }
    return origPush.apply(this, args);
  };

  const origReplace = history.replaceState;
  history.replaceState = function(...args) {
    let url = args[2] ? String(args[2]) : '';
    if (url.includes('include_over_18') || url.includes('type=media')) {
      url = cleanUrl(url);
      args[2] = url;
    }
    return origReplace.apply(this, args);
  };
})();
