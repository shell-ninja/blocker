// reddit_main.js - Runs in Reddit's MAIN execution world at document_start
// Intercepts fetch & XHR preference updates, verifies account state, and forces over18=0
(function() {
  'use strict';

  // 1. Override document.cookie to strictly force and keep over18=0
  try {
    const proto = Document.prototype;
    const cookieDesc = Object.getOwnPropertyDescriptor(proto, 'cookie');
    if (cookieDesc && cookieDesc.set) {
      const origSet = cookieDesc.set;
      const origGet = cookieDesc.get;
      Object.defineProperty(document, 'cookie', {
        get: function() {
          const val = origGet.call(this);
          return val ? val.replace(/(^|;\s*)over18=1/g, '$1over18=0') : val;
        },
        set: function(val) {
          if (typeof val === 'string') {
            val = val.replace(/(^|;\s*)over18=1/g, '$1over18=0');
            if (val.includes('over18=') && !val.includes('over18=0')) {
              val = val.replace(/over18=[^;]*/g, 'over18=0');
            }
          }
          return origSet.call(this, val);
        },
        configurable: true
      });
    }
  } catch (_) {}

  try {
    document.cookie = "over18=0; domain=.reddit.com; path=/; max-age=31536000; SameSite=Lax";
  } catch (_) {}

  const BLOCKED_SEARCH_TERMS = new Set([
    "nsfw", "porn", "porno", "xxx", "hentai", "ecchi", "ahegao", "doujin", "doujinshi", "yiff",
    "erotic", "erotica", "sexy", "gonewild", "nude", "nudes", "naked", "nudist", "nudism",
    "pawg", "pawgs", "pawgie", "thicc", "bbw", "ssbbw", "ebony", "milf", "milfs", "gilf", "gilfs",
    "dilf", "baddie", "baddies", "busty", "petite", "teen", "teens", "barelylegal",
    "boob", "boobs", "tit", "tits", "titties", "breasts", "cleavage", "nipple", "nipples", "areola",
    "areolas", "ass", "asses", "booty", "booties", "butt", "butts", "butthole", "asshole", "anus",
    "pussy", "pussies", "vagina", "cunt", "clit", "clitoris", "labia", "dick", "dicks", "cock",
    "cocks", "penis", "shaft", "balls", "testicles",
    "creampie", "creampies", "blowjob", "blowjobs", "deepthroat", "cuck", "cuckold", "cuckolding",
    "cum", "cumshot", "cumshots", "jizz", "facial", "facials", "bukkake", "gokkun", "gangbang",
    "orgy", "threesome", "hotwife", "bull", "swinger", "swingers", "handjob", "footjob", "titfuck",
    "rimjob", "rimming", "anal", "bdsm", "bondage", "fetish", "fetishes", "dominatrix", "domme",
    "submissive", "chastity", "spank", "spanking", "dildo", "dildos", "vibrator", "fleshlight",
    "masturbat", "masturbation", "orgasm", "orgasms", "squirt", "squirting", "grool", "pegging",
    "strapon", "voyeur", "exhibitionist", "flashing", "upskirt", "downblouse", "cameltoe", "shemale",
    "ladyboy", "transporn", "femboy", "femboys", "sissy", "sissies", "trap", "twink", "twinks",
    "crossdresser", "incest", "taboo", "breeding", "hucow", "futanari", "futa",
    "rule34", "r34", "redgifs", "erome", "onlyfans", "onlyfan", "fansly", "manyvids", "chaturbate",
    "cam4", "bongacams", "myfreecams", "camgirl", "camgirls", "camsoda", "fapello", "pornhub",
    "xvideos", "xnxx", "xhamster", "spankbang", "eporner", "scrolller"
  ]);

  function isBlockedSearchQuery(query) {
    if (!query || typeof query !== 'string') return false;
    const tokens = query.toLowerCase().replace(/[^a-z0-9]/g, ' ').split(/\s+/);
    for (let i = 0; i < tokens.length; i++) {
      const t = tokens[i];
      if (!t) continue;
      if (BLOCKED_SEARCH_TERMS.has(t)) return true;
      if (t.endsWith('s') && t.length > 3 && BLOCKED_SEARCH_TERMS.has(t.slice(0, -1))) return true;
      if (t.endsWith('ies') && t.length > 4 && BLOCKED_SEARCH_TERMS.has(t.slice(0, -3) + 'y')) return true;
    }
    const compact = query.toLowerCase().replace(/[^a-z0-9]/g, '');
    const stems = ['pawg', 'porn', 'nsfw', 'hentai', 'gonewild', 'rule34', 'redgifs'];
    for (let j = 0; j < stems.length; j++) {
      if (compact.includes(stems[j])) return true;
    }
    return false;
  }

  function cleanUrl(rawUrl) {
    if (!rawUrl || typeof rawUrl !== 'string') return rawUrl;
    try {
      const isRelative = !rawUrl.startsWith('http://') && !rawUrl.startsWith('https://');
      const u = new URL(rawUrl, 'https://www.reddit.com');
      let changed = false;

      // If search query contains blocked terms, redirect to homepage
      if (u.pathname.startsWith('/search')) {
        const q = u.searchParams.get('q');
        if (q && isBlockedSearchQuery(q)) {
          return 'https://www.reddit.com/';
        }
      }

      const params = u.searchParams;
      if (params.get('type') === 'media' || params.get('type') === 'video') {
        params.delete('type');
        changed = true;
      }
      if (params.has('include_over_18')) {
        params.delete('include_over_18');
        changed = true;
      }
      if (params.has('nsfw')) {
        params.delete('nsfw');
        changed = true;
      }
      if (!changed) return rawUrl;
      if (isRelative) {
        return u.pathname + (u.search ? u.search : '') + (u.hash ? u.hash : '');
      }
      return u.toString();
    } catch (_) {
      return rawUrl
        .replace(/([?&])type=(?:media|video)(&|$)/g, '$1')
        .replace(/([?&])include_over_18=[^&]*(&|$)/g, '$1')
        .replace(/([?&])nsfw=[^&]*(&|$)/g, '$1')
        .replace(/\?&/, '?')
        .replace(/[?&]$/, '');
    }
  }

  function sanitizePayloadObject(obj) {
    if (!obj || typeof obj !== 'object') return obj;
    if (Array.isArray(obj)) {
      for (let i = 0; i < obj.length; i++) {
        obj[i] = sanitizePayloadObject(obj[i]);
      }
      return obj;
    }
    for (const k of Object.keys(obj)) {
      const lower = k.toLowerCase().replace(/[^a-z0-9]/g, '');
      if (
        lower.includes('over18') ||
        lower.includes('maturecontent') ||
        lower.includes('shownsfw') ||
        lower.includes('allownsfw') ||
        lower.includes('nsfwenabled') ||
        lower === 'nsfw' ||
        lower === 'over18' ||
        lower.includes('adultcontent') ||
        lower.includes('searchincludeover18')
      ) {
        if (typeof obj[k] === 'boolean' || typeof obj[k] === 'string' || typeof obj[k] === 'number') {
          obj[k] = false;
        }
      } else if (
        lower.includes('blurnsfw') ||
        lower.includes('blurmature') ||
        lower.includes('labelnsfw') ||
        lower.includes('noprofanity') ||
        lower.includes('safesearch') ||
        lower.includes('isnsfwblurred')
      ) {
        obj[k] = true;
      } else if (typeof obj[k] === 'object' && obj[k] !== null) {
        obj[k] = sanitizePayloadObject(obj[k]);
      }
    }
    return obj;
  }

  function sanitizeBody(body) {
    if (!body) return body;

    // Handle string bodies (JSON or urlencoded)
    if (typeof body === 'string') {
      try {
        const parsed = JSON.parse(body);
        sanitizePayloadObject(parsed);
        return JSON.stringify(parsed);
      } catch (_) {
        return body
          .replace(/"([^"]*(?:over_?18|mature_?content|show_?nsfw|allow_?nsfw|search_?include_?over_?18|is_?over_?18)[^"]*)"\s*:\s*(true|"true"|1|"1"|"on")/gi, '"$1":false')
          .replace(/"([^"]*(?:blur_?nsfw|blur_?mature|label_?nsfw|no_?profanity|is_?nsfw_?blurred)[^"]*)"\s*:\s*(false|"false"|0|"0")/gi, '"$1":true')
          .replace(/([?&])(over_?18|search_?include_?over_?18|include_?over_?18|show_?nsfw)=(?:1|true|on)/gi, '$1$2=0');
      }
    }

    // Handle URLSearchParams
    if (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams) {
      for (const [k] of body.entries()) {
        const lower = k.toLowerCase().replace(/[^a-z0-9]/g, '');
        if (lower.includes('over18') || lower.includes('nsfw') || lower.includes('mature')) {
          body.set(k, '0');
        }
        if (lower.includes('blur') || lower.includes('label') || lower.includes('profanity')) {
          body.set(k, '1');
        }
      }
      return body;
    }

    // Handle FormData
    if (typeof FormData !== 'undefined' && body instanceof FormData) {
      for (const [k] of body.entries()) {
        const lower = k.toLowerCase().replace(/[^a-z0-9]/g, '');
        if (lower.includes('over18') || lower.includes('nsfw') || lower.includes('mature')) {
          body.set(k, '0');
        }
        if (lower.includes('blur') || lower.includes('label') || lower.includes('profanity')) {
          body.set(k, '1');
        }
      }
      return body;
    }

    return body;
  }

  function isPreferenceTarget(url) {
    if (!url) return false;
    const str = typeof url === 'string' ? url : (url.url || '');
    return str.includes('/prefs') || str.includes('graphql') || str.includes('/api/v1/me');
  }

  // -------------------------------------------------------------------------
  // 2. Monkey-patch window.fetch in Page Context (Fast-path Zero Overhead)
  // -------------------------------------------------------------------------
  if (typeof window.fetch === 'function') {
    const origFetch = window.fetch;
    window.fetch = function(resource, init) {
      const method = (init && init.method) || (resource instanceof Request && resource.method) || 'GET';
      const isMutation = method === 'POST' || method === 'PUT' || method === 'PATCH';

      // Clean adult search params on string URLs
      if (typeof resource === 'string' && (resource.includes('include_over_18') || resource.includes('type=media') || resource.includes('nsfw='))) {
        resource = cleanUrl(resource);
      }

      // FAST PATH: For 99.9% of requests (GETs, media, chunks, feed posts, comments, telemetry)
      // bypass immediately and synchronously with zero overhead
      if (!isMutation || !isPreferenceTarget(resource)) {
        return origFetch.call(this, resource, init);
      }

      // SLOW PATH: Only preference mutations (PATCH /prefs, POST /graphql)
      try {
        if (init && init.body) {
          init.body = sanitizeBody(init.body);
          return origFetch.call(this, resource, init);
        }

        if (resource instanceof Request) {
          return resource.clone().text().then(function(text) {
            const sanitized = sanitizeBody(text);
            if (sanitized !== text) {
              const headers = new Headers(resource.headers);
              const newInit = Object.assign({}, init, {
                method: method,
                headers: headers,
                body: sanitized,
                credentials: resource.credentials || 'include'
              });
              return origFetch.call(window, resource.url, newInit);
            }
            return origFetch.call(window, resource, init);
          }).catch(function() {
            return origFetch.call(window, resource, init);
          });
        }
      } catch (_) {}

      return origFetch.call(this, resource, init);
    };
  }

  // -------------------------------------------------------------------------
  // 3. Monkey-patch XMLHttpRequest in Page Context (Fast-path Zero Overhead)
  // -------------------------------------------------------------------------
  if (typeof XMLHttpRequest !== 'undefined' && XMLHttpRequest.prototype) {
    const origOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url, ...rest) {
      if (typeof url === 'string') {
        if (url.includes('include_over_18') || url.includes('type=media') || url.includes('nsfw=')) {
          url = cleanUrl(url);
        }
        this._isPrefUrl = isPreferenceTarget(url);
      }
      return origOpen.call(this, method, url, ...rest);
    };

    const origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function(body) {
      if (body && this._isPrefUrl) {
        try {
          body = sanitizeBody(body);
        } catch (_) {}
      }
      return origSend.call(this, body);
    };
  }

  // -------------------------------------------------------------------------
  // 4. Proactive Session Account Preferences Sync (Single Idle Check)
  // -------------------------------------------------------------------------
  function enforceSafeAccountPreferences() {
    try {
      if (sessionStorage.getItem('blocker_reddit_prefs_checked')) return;
    } catch (_) {}

    fetch('https://www.reddit.com/api/v1/me/prefs', {
      method: 'GET',
      credentials: 'include',
      headers: { 'Accept': 'application/json' }
    })
    .then(function(res) {
      if (!res.ok) {
        // If not authenticated or error, mark checked for this session and stop
        try { sessionStorage.setItem('blocker_reddit_prefs_checked', '1'); } catch (_) {}
        return null;
      }
      return res.json();
    })
    .then(function(data) {
      try { sessionStorage.setItem('blocker_reddit_prefs_checked', '1'); } catch (_) {}
      if (!data || typeof data !== 'object') return;

      const isOver18 = data.over_18 === true || data.search_include_over_18 === true;
      if (isOver18) {
        const payload = JSON.stringify({
          over_18: false,
          search_include_over_18: false,
          label_nsfw: true,
          no_profanity: true,
          media_preview: 'partial'
        });

        fetch('https://www.reddit.com/api/v1/me/prefs', {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: payload
        }).catch(function() {});
      }
    })
    .catch(function() {
      try { sessionStorage.setItem('blocker_reddit_prefs_checked', '1'); } catch (_) {}
    });
  }

  // Defer preference verification to idle time so it never competes with initial page render
  setTimeout(enforceSafeAccountPreferences, 3500);

  // -------------------------------------------------------------------------
  // 5. Client-side Navigation Guard (history.pushState & replaceState)
  // -------------------------------------------------------------------------
  const origPush = history.pushState;
  history.pushState = function(...args) {
    if (args[2] && typeof args[2] === 'string') {
      args[2] = cleanUrl(args[2]);
    }
    return origPush.apply(this, args);
  };

  const origReplace = history.replaceState;
  history.replaceState = function(...args) {
    if (args[2] && typeof args[2] === 'string') {
      args[2] = cleanUrl(args[2]);
    }
    return origReplace.apply(this, args);
  };
})();
