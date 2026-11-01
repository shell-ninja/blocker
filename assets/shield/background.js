// background.js - Blocker Extension Service Worker
// Enforces default-OFF safe cookies and monitors security rules

(function() {
  'use strict';

  function enforceRedditCookie(cookie) {
    if (!chrome.cookies) return;
    if (!cookie) return;
    const name = cookie.name || '';
    if (name === 'over18' || name === 'over_18') {
      if (cookie.value !== '0') {
        const domain = cookie.domain || '.reddit.com';
        const targetDomain = domain.startsWith('.') ? domain : '.' + domain;
        chrome.cookies.set({
          url: 'https://www.reddit.com/',
          domain: targetDomain,
          name: name,
          value: '0',
          path: '/',
          secure: cookie.secure !== undefined ? cookie.secure : true,
          sameSite: cookie.sameSite || 'lax'
        }, function() {
          if (chrome.runtime.lastError) {
            // Retry without explicit domain
            chrome.cookies.set({
              url: 'https://www.reddit.com/',
              name: name,
              value: '0',
              path: '/'
            }, function() {});
          }
        });
      }
    }
  }

  function scanRedditCookies() {
    if (!chrome.cookies) return;
    const targets = ['.reddit.com', 'reddit.com', 'www.reddit.com', 'old.reddit.com'];
    for (const d of targets) {
      chrome.cookies.getAll({ domain: d }, function(cookies) {
        if (chrome.runtime.lastError || !cookies) return;
        for (let i = 0; i < cookies.length; i++) {
          enforceRedditCookie(cookies[i]);
        }
      });
    }
  }

  // Monitor cookie changes in real-time
  if (chrome.cookies && chrome.cookies.onChanged) {
    chrome.cookies.onChanged.addListener(function(changeInfo) {
      if (!changeInfo.removed && changeInfo.cookie) {
        const d = changeInfo.cookie.domain || '';
        if (d.includes('reddit.com')) {
          enforceRedditCookie(changeInfo.cookie);
        }
      }
    });
  }

  // Initial enforcement on extension startup and install
  chrome.runtime.onInstalled.addListener(function() {
    scanRedditCookies();
  });

  chrome.runtime.onStartup.addListener(function() {
    scanRedditCookies();
  });

  // Periodic safety sweep
  setInterval(scanRedditCookies, 30000);
  scanRedditCookies();
})();
