// instagram_content.js - Blocker Isolated World Content Script for Instagram
// Zero-flash Explore icon removal & SPA click navigation guard

(function() {
  'use strict';

  // 1. Zero-flash CSS injection at document_start
  const igCSS = `
    /* Instantly hide Explore icon and links before first paint */
    a[href="/explore/"],
    a[href="/explore"],
    a[href^="/explore/"],
    a[href^="/explore?"],
    svg[aria-label="Explore"],
    svg[aria-label*="Explore" i] {
      display: none !important;
      visibility: hidden !important;
      pointer-events: none !important;
      opacity: 0 !important;
      width: 0 !important;
      height: 0 !important;
      max-width: 0 !important;
      max-height: 0 !important;
      overflow: hidden !important;
    }

    /* Target navigation item containers holding explore links */
    div:has(> a[href^="/explore"]),
    div:has(> div > a[href^="/explore"]),
    span:has(> a[href^="/explore"]),
    div:has(> svg[aria-label="Explore"]),
    div:has(> * > svg[aria-label="Explore"]) {
      display: none !important;
      visibility: hidden !important;
      pointer-events: none !important;
    }
  `;

  function injectIGStyles() {
    if (document.getElementById('blocker-ig-explore-shield')) return;
    const st = document.createElement('style');
    st.id = 'blocker-ig-explore-shield';
    st.textContent = igCSS;
    const target = document.head || document.documentElement;
    if (target) target.appendChild(st);
  }
  injectIGStyles();

  // 2. Dynamic React MutationObserver: remove Explore nav item wrapper cleanly
  // Covers desktop left sidebar, collapsed icon rail, and mobile-web bottom nav bar.
  // Preserves Home, Direct/Messages, Notifications, Reels, Create, and Profile.
  function cleanExploreNavItems() {
    injectIGStyles();

    const exploreElements = document.querySelectorAll(
      'a[href="/explore/"], a[href="/explore"], a[href^="/explore/"], a[href^="/explore?"], svg[aria-label="Explore"]'
    );

    for (let i = 0; i < exploreElements.length; i++) {
      const el = exploreElements[i];
      let curr = el;
      let navWrapper = null;

      // Climb parent chain up to 8 levels to find the individual nav item wrapper
      for (let depth = 0; depth < 8 && curr && curr !== document.body && curr !== document.documentElement; depth++) {
        const parent = curr.parentElement;
        if (!parent) break;

        // Check if parent contains sibling navigation items (Home, Direct, Reels, Profile)
        const siblingLinks = parent.querySelectorAll(
          'a[href="/"], a[href^="/direct"], a[href^="/reels"], a[href^="/notifications"], svg[aria-label="Home"], svg[aria-label="Messages"], svg[aria-label="Reels"], svg[aria-label="Profile"]'
        );

        if (siblingLinks.length > 0) {
          navWrapper = curr;
          break;
        }
        curr = parent;
      }

      const targetToHide = navWrapper || el;
      targetToHide.style.setProperty('display', 'none', 'important');
      targetToHide.style.setProperty('visibility', 'hidden', 'important');
      targetToHide.style.setProperty('pointer-events', 'none', 'important');
      targetToHide.setAttribute('data-blocker-explore-hidden', 'true');
    }
  }

  // 3. Capture-phase click interceptor
  document.addEventListener('click', function(e) {
    const a = e.target && e.target.closest ? e.target.closest('a') : null;
    if (a && a.href) {
      let path = '';
      try {
        const u = new URL(a.href, window.location.origin);
        path = u.pathname.toLowerCase();
      } catch (_) {
        path = String(a.href).toLowerCase();
      }
      if (path === '/explore' || path.startsWith('/explore/')) {
        e.preventDefault();
        e.stopPropagation();
        e.stopImmediatePropagation();
        window.location.replace('https://www.instagram.com/');
        return false;
      }
    }
  }, true);

  // 4. Initial and recurring observer setup
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', cleanExploreNavItems);
  } else {
    cleanExploreNavItems();
  }

  const observer = new MutationObserver(function() {
    cleanExploreNavItems();
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true
  });
})();
