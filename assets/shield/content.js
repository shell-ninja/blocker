// content.js - Blocker In-Page UI and Keyword Shield for Instagram & Reddit
(function() {
  'use strict';

  const host = (typeof window !== 'undefined' && window.location && window.location.hostname) ? window.location.hostname : '';

  // =========================================================================
  // 1. INSTAGRAM PROTECTION
  // =========================================================================
  if (host.includes('instagram.com')) {
    const BLOCKED_KEYWORDS = [
      'bikini', 'nsfw', 'porn', 'xxx', 'nude', 'nudes', 'sexy',
      'onlyfans', 'erotic', 'hentai', 'boobs', 'tits', 'ass',
      'pussy', 'dick', 'cock', 'lingerie', 'thong', 'milf',
      'bdsm', 'fetish', 'leaks', 'cuckold', 'grool', 'jacking',
      'camgirl', 'playboy', 'futanari', 'ecchi'
    ];

    function checkInstagramRoute() {
      const p = window.location.pathname || '';
      if (p.startsWith('/explore') || p.startsWith('/tags/')) {
        window.location.replace('https://www.instagram.com/');
      }
    }

    // Intercept client-side pushState / replaceState (SPA navigation)
    const origPush = history.pushState;
    history.pushState = function(...args) {
      const url = args[2] ? String(args[2]) : '';
      if (url.includes('/explore') || url.includes('/tags/')) {
        window.location.replace('https://www.instagram.com/');
        return;
      }
      origPush.apply(this, args);
      checkInstagramRoute();
    };

    const origReplace = history.replaceState;
    history.replaceState = function(...args) {
      const url = args[2] ? String(args[2]) : '';
      if (url.includes('/explore') || url.includes('/tags/')) {
        window.location.replace('https://www.instagram.com/');
        return;
      }
      origReplace.apply(this, args);
      checkInstagramRoute();
    };

    window.addEventListener('popstate', checkInstagramRoute);
    checkInstagramRoute();
    setInterval(checkInstagramRoute, 400);

    // Intercept click on any link to explore/tags
    document.addEventListener('click', function(e) {
      const a = e.target && e.target.closest ? e.target.closest('a') : null;
      if (a && a.href) {
        if (a.href.includes('/explore') || a.href.includes('/tags/')) {
          e.preventDefault();
          e.stopPropagation();
          window.location.replace('https://www.instagram.com/');
        }
      }
    }, true);

    // Intercept search inputs for blocked keywords (e.g. 'bikini')
    document.addEventListener('input', function(e) {
      const target = e.target;
      if (!target || typeof target.value !== 'string') return;
      const lower = target.value.toLowerCase();
      for (const kw of BLOCKED_KEYWORDS) {
        if (lower.includes(kw)) {
          target.value = '';
          target.blur();
          const flyout = document.querySelector('div[role="dialog"], div[aria-label="Search"]');
          if (flyout) flyout.remove();
          break;
        }
      }
    }, true);

    // Hide Explore and Search UI elements permanently
    const igCSS = `
      /* Hide explore icon & link in sidebar */
      a[href^="/explore"],
      a[href*="/explore"],
      div:has(> a[href^="/explore"]),
      div:has(> a[href*="/explore"]),
      svg[aria-label="Explore"],
      div:has(> svg[aria-label="Explore"]),

      /* Hide search button and search flyout in Instagram sidebar */
      svg[aria-label="Search"],
      div:has(> svg[aria-label="Search"]),
      input[aria-label="Search input"],
      input[placeholder="Search"] {
        display: none !important;
        visibility: hidden !important;
        pointer-events: none !important;
      }
    `;

    function injectIGStyle() {
      if (document.getElementById('blocker-ig-style')) return;
      const st = document.createElement('style');
      st.id = 'blocker-ig-style';
      st.textContent = igCSS;
      const root = document.head || document.documentElement;
      if (root) root.appendChild(st);
    }
    injectIGStyle();
    document.addEventListener('DOMContentLoaded', injectIGStyle);
    const igObs = new MutationObserver(injectIGStyle);
    igObs.observe(document.documentElement, { childList: true, subtree: true });
  }

  // =========================================================================
  // 2. REDDIT PROTECTION
  // =========================================================================
  if (host.includes('reddit.com')) {
    function checkRedditRoute() {
      const p = window.location.pathname || '';
      if (p.startsWith('/r/nsfw') || p.startsWith('/over18') || p.startsWith('/r/over18')) {
        window.location.replace('https://www.reddit.com/');
      }
    }

    const origPush = history.pushState;
    history.pushState = function(...args) {
      const url = args[2] ? String(args[2]) : '';
      if (url.includes('/r/nsfw') || url.includes('/over18')) {
        window.location.replace('https://www.reddit.com/');
        return;
      }
      origPush.apply(this, args);
      checkRedditRoute();
    };

    window.addEventListener('popstate', checkRedditRoute);
    checkRedditRoute();
    setInterval(checkRedditRoute, 400);

    // Hide NSFW posts on Reddit feeds
    const redditCSS = `
      shreddit-post[nsfw],
      shreddit-post:has(svg[icon-name="nsfw"]),
      shreddit-post:has(span:contains("NSFW")),
      div[data-nsfw="true"],
      div[data-subreddit-nsfw="true"] {
        display: none !important;
        visibility: hidden !important;
      }
    `;

    function injectRedditStyle() {
      if (document.getElementById('blocker-reddit-style')) return;
      const st = document.createElement('style');
      st.id = 'blocker-reddit-style';
      st.textContent = redditCSS;
      const root = document.head || document.documentElement;
      if (root) root.appendChild(st);
    }
    injectRedditStyle();
    document.addEventListener('DOMContentLoaded', injectRedditStyle);
    const redditObs = new MutationObserver(injectRedditStyle);
    redditObs.observe(document.documentElement, { childList: true, subtree: true });
  }
})();
