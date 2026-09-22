# blocker — system-wide adult-content blocker for Linux

`blocker` is a single self-contained C++17 binary (no third-party libraries) that turns a Linux
machine into a filtered one:

* a **local DNS proxy** on `127.0.0.1:53` that blocks names, forwards everything else to a filtering upstream,
  and caches answers;
* a **landing-page redirect**: blocked sites resolve to loopback and a built-in web server sends the browser to a page
  of your choice (default `https://youtu.be/z7f0ADlstfo?autoplay=1`);
* a **hot-reloading rule engine**: domains, wildcards, keywords, plus a **whitelist** for exceptions — kept
  **hidden**: in a root-only vault, scrambled at rest, never a plain file, and protected against tampering;
* an optional **blocked-site popup** on your desktop (off by default now that the redirect exists);
* **tamper resistance** in the style of BlockerHero / Cold Turkey: a systemd service that restarts
  in 1 s and refuses `systemctl stop`, a watchdog timer, immutable (`chattr +i`) files, a rule file
  that can only get *stricter*, and a **password and/or delayed-unlock** gate on anything that loosens
  protection.

> **Read this first — what it is and isn't.** On a machine where you have `root`, nothing can be
> made unbreakable; `blocker` adds *friction and time* between an impulse and a workaround, and logs
> every attempt. The single most effective hardening step is to make the friction real: let an
> accountability partner choose the unlock password (`--random-password`), and remove your own
> account's `sudo` rights afterwards (see [Hardening](#hardening-optional-but-recommended)).
> See also [What DNS cannot see](#what-dns-cannot-see) and [Limits](#limits-and-known-bypasses).

---

## 1. Requirements

| | |
|---|---|
| OS | Linux with **systemd** (Debian/Ubuntu/Fedora/Arch/openSUSE …), x86-64 or arm64 |
| Build | `g++` ≥ 9 (or clang ≥ 10) and GNU `make`. Nothing to download. |
| Runtime | root; `nftables` (`nft`) is optional (used for the DNS-bypass firewall) |
| Filesystem | ext4, xfs, btrfs, f2fs … (anything that supports `chattr +i`). On tmpfs/overlayfs the immutable flag is unavailable: blocker logs a warning and runs with the remaining protections. |
| Popup (optional) | a graphical session and `zenity` (or `yad`, `kdialog`, `notify-send`) |
| Port 80 on loopback | free, for the redirect (if taken, blocked names just fail to load instead) |
| Port 53 | `127.0.0.1:53` must be free. `systemd-resolved` uses `127.0.0.53` and does not conflict; `dnsmasq`/`bind`/`unbound` on 127.0.0.1 must be stopped. |

## 2. Build

```sh
make            # -> build/blocker   (hardened, PIE, RELRO)
make check      # optional (needs python3): 200 unit + 101 end-to-end + 21 upgrade + 30 redirect + 4 list-corpus checks, +8 privilege-drop checks when run as root
make static     # optional: fully static binary
```

## 3. Install

### One-step setup script

`setup.sh` checks the system, builds as your normal user, asks for
confirmation, installs with `sudo`, and verifies that blocking works:

```sh
./setup.sh                                   # interactive (asks for the unlock password)
./setup.sh --random-password --delay-hours 72
./setup.sh --yes --random-password           # no confirmation prompt (automation)
./setup.sh --build-only                      # compile, install nothing
./setup.sh --dry-run                         # show what would happen
./setup.sh --install-deps                    # apt/dnf/pacman/zypper: fetch g++, make, nftables first
./setup.sh --upgrade                         # replace an existing install (needs the unlock password/window)
```

Any option it doesn't handle itself (`--mode`, `--delay-hours`, `--window-minutes`, `--random-password`,
`--password-stdin`, `--upstream`, `--no-firewall`) is passed on to `blocker install`. It refuses to run if
systemd is not the init system or if something already listens on `127.0.0.1:53`, before changing anything.
A generated password is printed the moment it is created, before any step that could fail. It also warns if no
popup helper is installed (`--install-deps` adds `zenity`) and if the baseline table at `src/core/compat/tables/iana_punycode_tables.inc` has no active entries
(see [The whitelist](#the-whitelist): fix false positives *before* installing).

### Manual install

```sh
sudo ./build/blocker install                    # interactive: asks for an unlock password
```

Useful options:

| option | meaning |
|---|---|
| `--mode password\|delay\|both` | how loosening is gated (default `both`, see [Lock modes](#5-the-lock)) |
| `--delay-hours N` | how long an unlock request must age before the window opens (default 24) |
| `--window-minutes N` | how long the window stays open (default 30) |
| `--random-password` | generate a 24-character password and show it **once** — hand it to a partner |
| `--password-stdin` | read the password from stdin (automation) |
| `--upstream ip[,ip]` | upstream resolvers (default `1.1.1.3, 1.0.0.3`, Cloudflare Families) |
| `--no-firewall` | skip the nftables DNS-bypass rules |
| `--redirect-url URL` | where blocked sites send the browser (default `https://youtu.be/z7f0ADlstfo?autoplay=1`) |
| `--no-redirect` | plain blocking (`0.0.0.0`), no redirect server |
| `--popup` | also show the blocked-site popup (off by default) |
| `--popup-message TEXT` | the popup text (`\n` = new line, `{host}` = blocked name; no `#`) |

Recommended for real accountability:

```sh
sudo ./build/blocker install --mode both --delay-hours 24 --random-password
```

`install` copies the binary to `/usr/local/sbin/blocker` (mode `0700`), writes the config, the hidden rule vault and the units, runs
`systemctl enable --now blocker.service blocker-guard.timer`, waits for the daemon and prints
its status. Within a few seconds the daemon has armed all protections (`blocker status` shows them).

Verify:

```sh
getent hosts pornhub.com          # -> 127.0.0.1 (redirect) or 0.0.0.0 (redirect off / port 80 busy)
curl -sI http://pornhub.com/      # -> 302 Found, Location: <your landing page>
getent hosts example.com          # -> a real address
sudo blocker status
sudo journalctl -u blocker -f     # live log, including every blocked lookup
```

### Upgrading an existing installation

`./setup.sh` refuses to run over an existing install — what it finds on `127.0.0.1:53` is blocker itself — and
tells you so. To replace it with a newer build:

```sh
./setup.sh --upgrade
```

The installed blocker is asked to **stop, which is protected like any other loosening**: it needs the unlock
password and, in `delay`/`both` mode, an open unlock window (`sudo blocker unlock-request`, wait `unlock_delay`,
then upgrade inside the window). Then the new binary is installed and started, and:

* your **password, `blocker.conf` and rules are kept** (options such as `--mode` or `--delay-hours` do not change
  them); a config from an older version gets the missing blocks appended — the **redirect** settings (landing page
  on) and, if needed, the popup settings; an enabled popup is switched **off** (set `popup = yes` to keep both);
* plain-text rule files of the old layout (`/etc/blocker/keywords.txt`, `whitelist.txt`, baselines) are **moved into
  the hidden vault** and deleted;
* the **new default block list is merged in** (`blocker add --defaults`, the list built into the new binary; adding rules needs no
  password, duplicates are skipped);
* the whitelist is created from `src/core/compat/tables/iana_punycode_tables.inc` only if none exists yet.

**Testing in a VM?** The protection is the point, so there is no bypass flag. The fastest reset is a VM snapshot
taken before the install. Otherwise install test builds with `--mode password` (an upgrade then needs only the
password, no waiting), or use [Offline recovery](#offline-recovery-lost-password-or-you-truly-want-it-gone).
`sudo blocker status` shows the lock mode you chose.

## 4. Rules and whitelist

The **block rules** say what to block, the **whitelist** lists exceptions. One entry per line; `#` starts a comment.
Both live in a hidden, scrambled store (see [Where the rules are hidden](#where-the-rules-are-hidden)) — there is no
`keywords.txt` to open in an editor. You change them with `blocker add | allow | remove | unallow`, and the shipped
defaults are compiled into the program: the block list from the scrambled table `src/charset_tables.inc` (the project
has **no readable copy of it**), the whitelist template from `src/core/compat/tables/iana_punycode_tables.inc`. Changes are live **within ~1 second** (no restart).

| rule | matches |
|---|---|
| `example.com` | the domain **and all subdomains** (`www.example.com`, `a.b.example.com`) |
| `.xxx` | a whole TLD / suffix: everything under `.xxx` |
| `porn` or `kw:porn` | a **bare word (no dot) is a keyword**: any host name containing it. Hyphens are ignored, so `freeporn` also hits `free-porn.net` (min. 3 chars) |
| `=example.com` | exactly that host, nothing below it |
| `*.example.com` | glob over the whole host name: `*` = any run of characters, `?` = one character |
| `*word*` | any host name containing `word` |
| `!example.com`, `!word`, `!=host`, `!*glob*` | **allow** entries (see [The whitelist](#the-whitelist)); in the whitelist the `!` is implied |
| `0.0.0.0 host` | hosts-file lines are accepted, so community blocklists can be imported |

Matching is case-insensitive; internationalised names must be written in punycode (`xn--…`).
Rules with `/` or a scheme (`https://…/search?q=…`) are rejected with a message: DNS never sees paths
(see [What DNS cannot see](#what-dns-cannot-see)). Check any file before importing it:

```sh
blocker lint mylist.txt                  # counts rules, lists invalid lines (never touches the system)
blocker lint mylist.txt --whitelist      # same, reading every line as a whitelist entry
```

### The shipped list

The built-in list is the one you supplied, **unchanged**: 180 distinct rules — 4 TLDs (`.xxx .adult .sex .sexy`), 60 keywords
and 118 domain lines (a few repeated lines collapse into one rule). The project ships it only as a scrambled data table,
`src/charset_tables.inc` (numbers that look like any generated lookup table and say "do not edit"); the program decodes
it at run time and writes it into the vault at install time. There is no readable copy in the project folder.

* **Read it** after installing: `sudo blocker list` (needs the unlock authorisation).
* **Change the built-in defaults** (rarely needed — use `blocker add/remove` day to day):
  `make tables-show > list.txt`, edit `list.txt`, `make tables-pack FILE=list.txt`, `make`, then delete `list.txt`.
* A hand-edited table is caught: `blocker install` refuses a built-in list with invalid lines or fewer than 100 rules.
  (A change that leaves the list valid, e.g. one changed letter of a domain, is not detectable.)

> **Short keywords have a cost.** `cam`, `anal`, `cock`, `dick`, `sex`, `adult`, `bare`, `naked`, `xxx` and others also
> occur inside ordinary words. Tested against ~195 well-known host names, 54 (28 %) were blocked without exceptions,
> e.g. `google-analytics.com`, `camo.githubusercontent.com` (GitHub's image proxy), `cambridge.org`, `cam.ac.uk`,
> `campaign-archive.com` (Mailchimp), `peacocktv.com`, `essex.ac.uk`, `cocktails.com`, `dickssportinggoods.com`,
> `xxxlutz.at` (a furniture chain), `adultswim.com`. That is what the whitelist is for — and because loosening needs the
> unlock delay after installation, **prepare the whitelist before you install** (below).

### Adding rules

Adding block rules never needs a password (it only tightens things):

```sh
sudo blocker add badsite.example '*.cam' kw:somewords
sudo blocker add --file ~/hosts-blocklist.txt      # bulk import (hosts-file or one-rule-per-line format)
sudo blocker check somewords-forever.net           # blocked? which rule (or whitelist entry) decided?
```

The stored files are scrambled, so there is nothing to open in an editor — use the commands above. (Replacing the
store with a plain-text file also works and is handled like any edit: a *stricter* file is accepted and re-scrambled,
a looser one is reverted. See [The tamper ratchet](#the-tamper-ratchet).)

### Seeing the rules

```sh
sudo blocker list          # the whole list + whitelist; needs authorisation while hide_rules = yes (default)
```

While `hide_rules = yes`, `list` is gated exactly like `remove`: the password (`password` mode), an open unlock window
(`delay`), or both. `blocker check <hostname>` needs no authorisation — it tells you what happens to *one* name, and
which rule or whitelist entry decided it, which is what you need to fix a false positive.

### Removing rules (loosening → gated)

```sh
sudo blocker remove badsite.example        # needs the lock to be open (section 5)
```

### The whitelist

Every whitelist entry is an exception (no `!` needed):

| entry | effect |
|---|---|
| `essex.ac.uk` | that domain and its subdomains are never blocked, whatever rule matches |
| `=www.example.com` | exactly that host |
| `analytics` (bare word) | keyword blocks are lifted **where they hit inside this word** |
| `*.edu`, `*word*` | a glob over the host name: lifts keyword/glob blocks for matching hosts |

How word entries work — the "covered" rule. Suppose `anal` is a keyword and `analytics` is whitelisted:

| host | result | why |
|---|---|---|
| `google-analytics.com` | allowed | the only `anal` sits inside `analytics` |
| `analytics-anal.example.com` | **blocked** | the second `anal` is not inside the whitelisted word |
| `anal.example.com` | **blocked** | no whitelisted word covers it |

Precedence: a whitelisted **domain or exact host** wins over everything. Word and glob entries only lift
**keyword and glob** blocks; a site blocked by name (a domain line) stays blocked unless you whitelist that exact
domain. `blocker check <host>` prints the deciding rule, or why a matching keyword was overridden.

Workflow:

1. **Before installing** open `src/core/compat/tables/iana_punycode_tables.inc` in the project folder. It ships with **suggested
   exceptions** (`analytics`, `analys`, `came`, `cam.ac.uk`, `cambodia`, `essex`, `peacock`, `cocktail`, `dickens`,
   `xxxl`, …). Add your own at the bottom, then run `./setup.sh`. The file you install
   becomes the baseline.
2. **After installing**, adding entries loosens the filter and is gated like everything else (section 5):

   ```sh
   sudo blocker unlock-request                # then wait for the window
   sudo blocker allow essex analytics '=api.example.org'
   ```

   Removing entries only tightens the filter, so it is always allowed: `sudo blocker unallow analytics`.

### The tamper ratchet

While the daemon runs, both stores only ever get stricter. On every change blocker compares the store with the
last *authorised* copy (kept in the vault, `r.b` and `w.b`):

* block rules: rules **added** → accepted and hot-loaded; any block rule **removed**, or any allow entry **added**,
  without an open unlock window → treated as tampering;
* whitelist: entries **removed** → accepted; any entry **added** without an open unlock window → tampering;
* tampering means the store is **restored** (keeping legitimate additions from the same edit), the attempt is logged
  (`journalctl -u blocker | grep TAMPER`), and blocking never lapses;
* a store that is **corrupted** (a flipped bit, appended text, truncated), **emptied or deleted** is restored the same
  way, also across daemon restarts;
* a store replaced by **plain text** is read as an edit: accepted if stricter, then scrambled again.

## 5. The lock

Anything that weakens protection is gated: `remove`, `allow` (whitelist additions, or `!x` rules), `stop`,
`uninstall` — and `list` while `hide_rules = yes` (seeing the hidden rules needs the same authorisation).
Free operations: `add` (block rules), `unallow`, `check`, `lint`, `status`, `unlock-cancel`.

Set with `lock_mode` in `/etc/blocker/blocker.conf` (chosen at install):

| mode | to loosen you need |
|---|---|
| `password` | the password, every time |
| `delay` | an **unlock window**: run `blocker unlock-request`, wait `unlock_delay` (default 24 h), then act within `unlock_window` (default 30 min). No password. |
| `both` (default) | the password to *request* unlock, **and** the password again for the action inside the window |

```sh
sudo blocker unlock-request        # start the timer  (both/delay)
sudo blocker status                # shows "opens in 23h 41m" / "WINDOW OPEN: closes in 12m"
sudo blocker unlock-cancel         # abort (no password needed — cancelling only tightens)
sudo blocker remove badsite.example
```

Details worth knowing:

* The delay is counted with a **monotonic clock while the daemon is running**. Changing the system
  clock does not shorten it; time the machine spends off or suspended does not count.
* The password is stored as **PBKDF2-HMAC-SHA256** (200 000 rounds, random salt) in `/etc/blocker/auth`
  (`0600`, immutable). After 3 wrong attempts the daemon locks the gate for 15 s, doubling per failure up
  to 1 h; the failure counter survives restarts.
* Requests travel over a root-only Unix socket (`/run/blocker/control.sock`, mode `0600`, peer uid checked).
  There is no network-reachable control channel.
* **Forgotten password + `password`/`both` mode = you cannot loosen anything.** That is the feature.
  The last resort is offline recovery (below).

### Pausing and uninstalling

```sh
sudo blocker stop          # authorised: lifts every protection, restores DNS, daemon exits (status 42)
sudo blocker start         # resume (also happens automatically at the next boot)
sudo blocker uninstall     # authorised: removes units, binary, config; restores resolv.conf
```

While paused the watchdog stays idle (marker file `/var/lib/blocker/disabled`). Rebooting or
`blocker start` re-arms everything.

## 6. Starting, stopping, operating the daemon

The service is `blocker.service` (enabled at install, so it starts at boot, before name resolution).

```sh
systemctl status blocker           # state
journalctl -u blocker -f           # log
sudo blocker status                # rules, counters, lock state, protection health
```

* `systemctl stop blocker` / `restart` are **refused** (`RefuseManualStop=yes`) — use `blocker stop`.
* `kill -9`, `systemctl kill`, crashes: back up in **1 s** (`Restart=always`, `RestartSec=1s`,
  `StartLimitIntervalSec=0` so systemd never gives up).
* Port 53 taken by something else: the daemon logs the bind error and exits; systemd retries every
  second. Stop the other resolver, then it comes up on its own.

Configuration (`/etc/blocker/blocker.conf`, read at start; immutable — change it via
`blocker stop` → edit → `blocker start`):

| key | default | meaning |
|---|---|---|
| `listen` | `127.0.0.1:53` | UDP+TCP listen address |
| `upstream` | `1.1.1.3, 1.0.0.3` | resolvers for allowed names, tried in order with failover |
| `workers` | `32` | UDP worker threads |
| `upstream_timeout_ms` | `1500` | per-upstream timeout |
| `cache_entries` / `cache_max_ttl` | `16384` / `300` | answer cache size / TTL ceiling (s) |
| `safesearch`, `youtube_restrict` | `yes` | force SafeSearch / YouTube Restricted Mode |
| `block_doh` | `yes` | sinkhole DoH/DoT provider names + Firefox canary |
| `firewall` | `yes` | nftables: only root may send plain DNS / DoT off-box |
| `browser_policies` | `yes` | managed policies disabling browser DoH |
| `takeover_resolver` | `yes` | keep `/etc/resolv.conf` on 127.0.0.1 |
| `log_blocked` / `log_queries` | `yes` / `no` | journal every block / every query |
| `redirect` | `yes` | blocked names → loopback + local redirect server (see [redirect](#the-landing-page-redirect)) |
| `redirect_url` | `https://youtu.be/z7f0ADlstfo?autoplay=1` | the landing page |
| `redirect_port` | `80` | redirect server port (only ever changed by the test-suite) |
| `hide_rules` | `yes` | `blocker list` needs authorisation; the journal does not print the matching rule |
| `popup`, `popup_title`, `popup_message`, `popup_seconds`, `popup_cooldown`, `popup_helper` | `no`, … | optional [blocked-site popup](#the-blocked-site-popup-optional) |
| `lock_mode`, `unlock_delay`, `unlock_window` | `both`, `86400`, `1800` | see section 5 |

## 7. Enforcement mechanics

**DNS path** (per query, microseconds for blocks and cache hits):

1. parse the question (malformed → `FORMERR`, non-queries dropped);
2. Firefox canary `use-application-dns.net` → `NXDOMAIN` (tells Firefox to switch DoH off);
3. rule engine: allow-list first, then exact / suffix / glob / keyword rules. Blocked → with the redirect
   `A 127.0.0.1`, `AAAA ::1` (or `A 0.0.0.0`, `AAAA ::` when the redirect is off, unavailable, or the name is on the built-in
   DoH list); other types (incl. `HTTPS`/`SVCB`) → `NOERROR` with no data, so browsers fall straight back;
4. SafeSearch hosts (`google.*`, `bing.com`, `duckduckgo.com`, `youtube.com` …) are answered with a
   `CNAME` to the vendor's enforcement name (`forcesafesearch.google.com`, `strict.bing.com`,
   `safe.duckduckgo.com`, `restrict.youtube.com`) and its addresses; failure → `SERVFAIL`, never the
   unfiltered site;
5. everything else → upstream over a fresh randomly-ported UDP socket (txid and question verified),
   failover between upstreams, TCP for TCP clients, 16-shard TTL cache (TTLs decremented on hits).

**Persistence and anti-kill**

| threat | countermeasure |
|---|---|
| `kill -9` / crash | `Restart=always`, `RestartSec=1s`, no start-rate limit, `OOMScoreAdjust=-900` |
| `systemctl stop/restart` | `RefuseManualStop=yes`; authorised stop = daemon exits 42 (`RestartPreventExitStatus=42`) |
| `systemctl disable` | daemon re-enables itself (every ≤10 s) and the watchdog timer does too |
| stopping the watchdog | daemon restores and restarts `blocker-guard.timer`; the timer (every 15 s) restarts the daemon, kills it if it is frozen (`SIGSTOP`), re-writes missing unit files |
| `systemctl edit` / drop-ins / shadow units | our `*.service.d` directories are empty + immutable; any override found in systemd's search paths is deleted and systemd reloaded |
| `systemctl mask` | fails: the unit file exists and is immutable |
| deleting the binary | immutable; if it is removed anyway it is re-created from the running image |

**Immutable (`chattr +i`) and root-owned:** the binary, `blocker.conf`, `auth`, the vault files (`r`, `w`, `r.b`, `w.b`,
key `k`), the three unit files, the `*.d` directories, `/etc/resolv.conf`, the NetworkManager /
systemd-resolved drop-ins and browser policy files. The daemon re-asserts the flag every 2 s
(the rule and whitelist stores are re-locked right after a processed edit, or 60 s after being unlocked).

**Resolver takeover.** `/etc/resolv.conf` (symlink or file) is backed up, replaced by
`nameserver 127.0.0.1`, and locked. NetworkManager is told `dns=none, rc-manager=unmanaged`;
`systemd-resolved` is pointed at 127.0.0.1 with no fallback DNS and its stub listener off.

**DNS-bypass firewall (nftables, table `inet blocker`).** Non-root processes cannot send UDP/TCP 53 or 853
anywhere except loopback. (The daemon runs as root, so it can reach its upstreams.) The table is re-created
if deleted.

**Browser policies.** Chrome/Chromium/Brave/Edge: `DnsOverHttpsMode=off` (+ Google SafeSearch and
YouTube restrict). Firefox: `DNSOverHTTPS` disabled and locked.

## The landing-page redirect

Blocked sites send the browser to a page of your choice (default `https://youtu.be/z7f0ADlstfo?autoplay=1`)
instead of showing an error.

DNS cannot redirect a browser by itself, so blocker does it in two steps: (1) a blocked name is answered with the
**loopback address** (`A → 127.0.0.1`, `AAAA → ::1`); (2) a tiny built-in web server on `127.0.0.1:80` and `[::1]:80`
answers every request with `302 Found` and `Location: <redirect_url>`. The answer is never cacheable
(`Cache-Control: no-store`), listens on loopback only (unreachable from the network), reads at most 8 KB per request,
gives up on stalled clients after 3 s, and drains uploads before closing so the browser never sees a reset.

| what the browser does | result |
|---|---|
| opens `http://blocked.site/…` | **redirected** to the landing page |
| you type `blocked.site` (no scheme): Chrome/Firefox try `https://`, get "connection refused", fall back to `http://` | **redirected** (behaviour of the browser; usually true) |
| follows an `https://blocked.site/…` link, or the site is on the HSTS preload list | **connection error** — the browser does not fall back |
| `curl`/apps using `http://` | `302` + `Location` header |

**Why not HTTPS too?** Showing a page for `https://blocked.site` requires answering TLS *as* that site, i.e. installing a
certificate authority into the system and every browser and intercepting HTTPS. blocker deliberately does not do that:
it would weaken every secure connection on the machine. The complete fix for HTTPS links is a browser extension that
redirects before the request is made; that is not part of blocker (it can be added as a separate step).

Details:

* **Only your own rules redirect.** The built-in DoH/DoT provider names stay `0.0.0.0` (a DoH client must fail, not reach a
  web server). `HTTPS`/`SVCB` lookups get an empty answer so browsers do not learn an upgrade path.
* **The landing page is never blocked.** The site of `redirect_url` — its host without a leading `www.`, plus every
  subdomain — is exempt from all rules, even if a keyword would match. Third-party assets the page loads
  (fonts, video hosts, CDNs) are *not* exempt: check them with `blocker check <host>` and whitelist what you need.
* **Port 80 taken** (a local web server): the redirect cannot start, blocked names fall back to `0.0.0.0`, the journal says
  `redirect disabled…` and `blocker status` shows `redirect: inactive`. Blocked names are never pointed at another server.
* **Set at install:** `./setup.sh --redirect-url 'https://…'`, or `--no-redirect` for plain blocking. To change it later:
  `blocker stop` → edit `redirect_url` in `/etc/blocker/blocker.conf` → `blocker start` (the config is immutable).
  Only `http://`/`https://` URLs without spaces, quotes or angle brackets are accepted.
* **Check it:**

  ```sh
  getent hosts pornhub.com                 # 127.0.0.1  pornhub.com
  curl -sI http://pornhub.com/             # HTTP/1.1 302 Found  +  Location: https://youtu.be/…
  sudo blocker status                      # "redirect : -> https://… (N served)"
  ```

* The [popup](#the-blocked-site-popup-optional) is off by default now; `--popup` turns it on as well.

## Where the rules are hidden

The point: nobody browsing the machine should be able to *find* the list, read it, or quietly edit it.

| what | how |
|---|---|
| location | a root-only directory `/var/lib/.fc-cache/` (mode `0700`, a dot-directory with an unrelated name) with neutral file names: `r` (block rules), `w` (whitelist), `r.b`, `w.b` (authorised copies), `k` (key) |
| not plain text | each file is `nonce ‖ ciphertext ‖ tag`: the text XOR an HMAC-SHA256 keystream, authenticated. `cat`, `grep -r`, `find`, `strings` and editors show only noise; a hand edit breaks the tag |
| permissions | vault files `0600`, `/etc/blocker` `0700`, `blocker.conf` `0600`, the program `/usr/local/sbin/blocker` `0700` — other users cannot list, read or run any of it |
| the built-in copy | the shipped list inside the binary is scrambled too (`strings blocker` does not list it); in the project it exists only as a scrambled table, `src/charset_tables.inc` |
| the CLI | `blocker list` needs the unlock authorisation (`hide_rules = yes`); the journal says `BLOCKED <host>` without spelling out the rule |
| tamper | files are immutable (`chattr +i`); a changed, corrupted or deleted file is reverted from the authorised copy; the daemon puts a deleted/changed key file back from memory |

**Honest limits.** This is obscurity plus integrity, **not secrecy against root who has this source code**: the key sits
next to the data, so someone with root, this repository and enough determination can decode the files. What actually stops
*changes* is the immutable flag, the ratchet and the lock. Hiding raises the effort from "open a file" to "know the format
and defeat the ratchet", and keeps the list out of casual sight (other users, `grep`, backups, a glance in a file manager).

Further things worth knowing:

* **The project folder has no readable copy of the block list** — only the scrambled table `src/charset_tables.inc`.
  The default exception rules reside in `src/core/compat/tables/iana_punycode_tables.inc`.
  Move or delete the folder after installing if that matters (an upgrade needs it again — keep a copy somewhere out of the way).
* **If the key is lost** (or the vault damaged offline) the daemon cannot decode the stored rules. It then treats them as
  *missing* and restores the **built-in default list** — never an empty list; rules you added yourself are gone. The
  daemon logs a warning. `sudo blocker list` output (inside an unlock window) is the way to keep your own backup.
* **Upgrading from an earlier version** moves the old plain-text files (`/etc/blocker/keywords.txt`, `whitelist.txt`,
  and their baselines under `/var/lib/blocker`) into the vault and deletes them — `install` does this even for files the
  old version had made immutable.
* `hide_rules = no` in `blocker.conf` makes `list` and the journal open again (the files stay scrambled).

## The blocked-site popup (optional)

**Off by default** since the [landing-page redirect](#the-landing-page-redirect) replaced it; turn it on with
`./setup.sh --popup` (or `popup = yes`). It can run alongside the redirect.

When a lookup is blocked by one of *your* rules, blocker shows a small popup with your custom message on the
desktop of the user who made the lookup. It closes itself after `popup_seconds` (default **5**), and the daemon
kills it if it does not.

```
┌────────────────────────────────────┐
│ Website blocked                    │
│ This site is blocked by Blocker.   │
│ Stay focused - you set this up for │
│ a reason.                          │
└────────────────────────────────────┘
```

**Your message.** Set it at install time (`./setup.sh --popup --popup-message 'No. Breathe.\nCall your partner.'`) or
in `/etc/blocker/blocker.conf`:

| key | default | meaning |
|---|---|---|
| `popup` | `no` | turn the popup on/off (`--popup` at install) |
| `popup_title` | `Website blocked` | window title |
| `popup_message` | `This site is blocked by Blocker.\nStay focused - you set this up for a reason.` | `\n` = new line, `{host}` = the blocked name; do not use `#` (it starts a comment) |
| `popup_seconds` | `5` | how long it stays (1–60) |
| `popup_cooldown` | `30` | minimum seconds before the same host may pop up again |
| `popup_helper` | *(auto)* | custom program, called as `helper <title> <message> <seconds> <host>` |

`blocker.conf` is immutable and read at start, so changing the text later means `blocker stop` (authorised) →
edit → `blocker start`. `blocker status` shows whether a helper was found and how many popups were shown.

**Requirements.** A graphical session and one of `zenity` (default), `yad`, `kdialog` (preferred on KDE) or
`notify-send`. `./setup.sh --install-deps` installs `zenity`. Without a helper blocking still works; the journal
says `popup for …: no popup helper installed`. (`notify-send` uses your desktop's notification server, and
GNOME ignores the 5-second timeout for those — prefer `zenity`.)

**How it works.**

1. The DNS engine blocks a name because of a *user rule* (not the built-in DoH list) for an `A`, `AAAA` or
   `HTTPS` lookup and hands the host name and the client's UDP port to the popup thread — the DNS path never waits.
2. The port is looked up in `/proc/net/udp{,6}` to find **which user** asked. If that fails (TCP lookups, a system
   resolver in between) the popup goes to every logged-in graphical user.
3. Graphical sessions are found by scanning `/proc` for processes of regular users (uid 1000–65533) that have a
   local `DISPLAY` (`:0`, not an SSH-forwarded one) or a `WAYLAND_DISPLAY`; their `DISPLAY`, `WAYLAND_DISPLAY`,
   `XAUTHORITY`, `DBUS_SESSION_BUS_ADDRESS` and `XDG_RUNTIME_DIR` are reused.
4. The helper is started **as that user**: groups, gid and uid dropped, no way back to root, a session of its own
   (so the whole process group can be killed), and every inherited file descriptor closed — notably the root-only
   control socket.
5. Only **one popup per desktop at a time**, and a per-host cooldown, so a browser's burst of lookups (A + AAAA +
   HTTPS, retries) or a page pulling in five blocked hosts yields one popup, not a stack.

**Limits — read before relying on it.**

* It reacts to **lookups**, not page views. Prefetching, link previews, background apps or a sync client can
  trigger it without you visiting anything; the cooldown limits the noise but cannot remove it.
* It is a separate window, not a page in the browser tab. Showing a message *inside* the tab would need a browser
  extension, and an HTTPS site cannot be replaced with a page from DNS without intercepting TLS.
* No popup on headless machines, over plain SSH, for root's own desktop, or for system users (uid < 1000).
* On Wayland the compositor decides stacking and focus; a popup may open behind a full-screen window.
* Popup outcomes are logged (`journalctl -u blocker | grep popup`).
* The unit file therefore does **not** use `PrivateTmp`, `ProtectHome`, `RestrictNamespaces` or
  `MemoryDenyWriteExecute`: the helper inherits the daemon's sandbox and needs the real `/tmp` (X11), `/run/user`,
  and a toolkit that may JIT.

## What DNS cannot see

(One consequence for the redirect: a browser that connects to `https://blocked.site` never reaches the redirect server —
see [the redirect](#the-landing-page-redirect) for what is and is not redirected.)

A DNS proxy sees **host names only**. HTTPS hides URLs, paths and search queries from everything
between the browser and the site, so `https://www.google.com/search?q=badword` and
`https://www.google.com/search?q=cats` produce the *same* DNS lookup. Consequently:

* rules match domains and words **inside host names** (`kw:`, `*word*`), never words in a URL path or a
  search box — such rules are rejected rather than silently doing nothing;
* the practical DNS-level answer to "filter what people search for" is **forced SafeSearch** (enabled by
  default), plus a filtering upstream resolver;
* true per-search-term or per-URL filtering needs a TLS-intercepting proxy or a browser extension, which is
  deliberately out of scope for a system-wide DNS filter.

## Limits and known bypasses

`blocker` is friction, not a vault. Things it does **not** stop:

* a determined root user: a script that clears the immutable flags, overrides the unit and kills the daemon
  faster than the 2-second repair loop can react will win the race. The lock gates the *supported* paths
  and makes the casual ones fail; it cannot stop an attacker who already owns the machine (see Hardening);
* booting a live USB / editing the disk offline, reinstalling the OS, or another operating system;
* VPNs, Tor, proxies and DoH clients that use **IP literals** (no DNS lookup to intercept);
* other devices on the network (this protects one machine; use a filtering router/DNS for the rest);
* applications with hard-coded IPs; containers/VMs with their own network stack.

## Hardening (optional but recommended)

1. Install with `--random-password` and give the password to a person you trust; don't keep a copy.
2. Remove your daily account from `sudo`/`wheel` after install (or have the partner set the root password).
3. Set a GRUB/UEFI password so the boot menu and firmware can't be used to bypass the OS.
4. Use `--mode both` with a long delay (`--delay-hours 72`) — the cost of a weak moment becomes days.
5. Keep the filtering upstream (`1.1.1.3`, CleanBrowsing Adult, …) for defence in depth.

## Offline recovery (lost password, or you truly want it gone)

Boot a live system or `init=/bin/bash` kernel option, mount the root filesystem, then:

```sh
cd /mnt/root      # or your mount point
chattr -i usr/local/sbin/blocker etc/blocker/* var/lib/blocker/* var/lib/.fc-cache/* etc/resolv.conf \
          etc/systemd/system/blocker.service etc/systemd/system/blocker-guard.service \
          etc/systemd/system/blocker-guard.timer etc/NetworkManager/conf.d/90-blocker-dns.conf \
          etc/systemd/resolved.conf.d/90-blocker.conf 2>/dev/null
chattr -i etc/systemd/system/blocker*.d etc/firefox/policies/policies.json \
          etc/opt/chrome/policies/managed/blocker.json etc/chromium/policies/managed/blocker.json 2>/dev/null
rm -rf usr/local/sbin/blocker etc/blocker var/lib/blocker var/lib/.fc-cache etc/systemd/system/blocker*.service \
       etc/systemd/system/blocker*.timer etc/systemd/system/blocker*.d \
       etc/systemd/system/multi-user.target.wants/blocker.service etc/systemd/system/timers.target.wants/blocker-guard.timer \
       etc/NetworkManager/conf.d/90-blocker-dns.conf etc/systemd/resolved.conf.d/90-blocker.conf \
       etc/opt/chrome/policies/managed/blocker.json etc/chromium/policies/managed/blocker.json
rm -f etc/resolv.conf && printf 'nameserver 1.1.1.1\n' > etc/resolv.conf
```

Reboot; `nft delete table inet blocker` is unnecessary (the table does not survive a reboot).

## 8. Files

| path | purpose |
|---|---|
| `/usr/local/sbin/blocker` | the binary (`0700`, immutable) |
| `/etc/blocker/blocker.conf` | settings (`0600`, immutable; `/etc/blocker` is `0700`) |
| `/etc/blocker/auth` | password hash (`0600`, immutable) |
| `/var/lib/.fc-cache/r`, `w` | the hidden, scrambled block rules and whitelist (`0600`, immutable, ratchet-protected) |
| `/var/lib/.fc-cache/r.b`, `w.b` | last authorised copies, scrambled (the ratchet's reference) |
| `/var/lib/.fc-cache/k` | the vault key (`0600`, immutable) |
| `/var/lib/blocker/state` | unlock-timer progress, failed-attempt counter |
| `/var/lib/blocker/resolv.conf.orig` / `.link` | backup of the original resolver setup |
| `/var/lib/blocker/disabled` | marker: authorised pause (watchdog idle) |
| `/run/blocker/control.sock` | root-only control socket |
| `/etc/systemd/system/blocker.service`, `blocker-guard.service`, `blocker-guard.timer` | units (immutable) |

## Troubleshooting

| symptom | check |
|---|---|
| No internet right after install | `journalctl -u blocker -n 50`. Most often port 53 is held by another resolver; stop it. The watchdog retries automatically. |
| A legitimate site is blocked | `blocker check host` shows the deciding rule. Whitelist it: `blocker allow host` for a domain, or `blocker allow word` when a short keyword hit inside a longer word (needs the lock open — see [The whitelist](#the-whitelist)). |
| Blocked sites show "can't connect" instead of the landing page | Only `http://` requests are redirected; an `https://` link cannot be ([why](#the-landing-page-redirect)). Check `curl -sI http://pornhub.com/` (expect 302) and `sudo blocker status` (`redirect:` must not say inactive — something else may hold port 80). |
| `blocker list` says the rules are hidden | Expected: it needs the unlock authorisation ([hidden rules](#where-the-rules-are-hidden)). Open an unlock window, or set `hide_rules = no` (`blocker stop` → edit → `blocker start`). |
| Log says "store unreadable (key lost or data damaged)" | The vault key or a store file was damaged. The daemon fell back to the built-in default list; re-add your own rules with `blocker add`. |
| No popup appears | `blocker status` lists the helper and shows why. Install `zenity`; check `journalctl -u blocker \| grep popup`. Remember: one popup per desktop at a time, and a per-host cooldown. |
| Popup appears for sites I did not open | Browsers and apps look names up in the background (prefetch, previews). Raise `popup_cooldown`, or set `popup = no`. |
| `chattr` warnings in the log | The filesystem does not support immutable flags (tmpfs/overlay). Protections that rely on them are inactive. |
| `blocker status` shows a protection as `NO` | Give it up to 10 s; the daemon repairs drift itself. Persisting `NO` on `firewall` means `nft` is missing. |
| VPN client can't resolve names | Run it as root, or set `firewall = no` (requires `blocker stop` → edit → `blocker start`). |

## License / safety note

This tool changes system-wide DNS, firewall and file attributes. Try it on a non-critical machine first,
keep the recovery procedure above at hand, and remember it filters DNS names only.
