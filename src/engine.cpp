#include "engine.hpp"
#include "popup.hpp"
#include "redirect.hpp"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

#include "util.hpp"

namespace blk {

// ============================================================================ cache
Cache::Cache(size_t max_entries, uint32_t max_ttl)
    : per_shard_(max_entries / kShards), max_ttl_(max_ttl) {}

Cache::Shard& Cache::shard(const std::string& key) { return shards_[std::hash<std::string>{}(key) % kShards]; }

bool Cache::get(const std::string& key, std::vector<uint8_t>& out) {
    if (per_shard_ == 0) return false;
    Shard& s = shard(key);
    std::lock_guard<std::mutex> g(s.m);
    auto it = s.map.find(key);
    if (it == s.map.end()) return false;
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - it->second.stored).count();
    if (elapsed < 0 || uint64_t(elapsed) >= it->second.ttl) {
        s.map.erase(it);
        return false;
    }
    out = it->second.resp;
    dns::patch_ttls(out, uint32_t(elapsed));
    return true;
}

void Cache::put(const std::string& key, std::vector<uint8_t> resp) {
    if (per_shard_ == 0 || max_ttl_ == 0) return;
    uint8_t rc = dns::rcode_of(resp);
    if ((rc != dns::RC_NOERROR && rc != dns::RC_NXDOMAIN) || dns::is_truncated(resp)) return;
    uint32_t ttl = 0;
    if (!dns::min_ttl(resp, ttl) || ttl == 0) return;
    if (ttl > max_ttl_) ttl = max_ttl_;
    Shard& s = shard(key);
    std::lock_guard<std::mutex> g(s.m);
    if (s.map.size() >= per_shard_) {
        auto now = std::chrono::steady_clock::now();
        for (auto it = s.map.begin(); it != s.map.end();) {
            auto age = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.stored).count();
            if (age < 0 || uint64_t(age) >= it->second.ttl) it = s.map.erase(it);
            else ++it;
        }
        if (s.map.size() >= per_shard_) s.map.clear();
    }
    s.map[key] = Entry{std::move(resp), std::chrono::steady_clock::now(), ttl};
}

// ============================================================================ built-in lists
const std::vector<std::string>& builtin_bypass_domains() {
    static const std::vector<std::string> v = {
        "dns.google", "cloudflare-dns.com", "one.one.one.one", "1dot1dot1dot1.cloudflare-dns.com",
        "dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net", "doh.opendns.com",
        "doh.familyshield.opendns.com", "dns.adguard.com", "dns.adguard-dns.com", "family.adguard-dns.com",
        "unfiltered.adguard-dns.com", "dns.nextdns.io", "doh.cleanbrowsing.org", "dns.cleanbrowsing.org",
        "doh.libredns.gr", "dns.sb", "doh.dns.sb", "doh.mullvad.net", "dns.mullvad.net", "dns.controld.com",
        "freedns.controld.com", "dns0.eu", "doh.applied-privacy.net", "dns.alidns.com", "doh.pub",
        "dns.twnic.tw", "dnsforge.de", "doh.li", "doh.tiar.app", "jp.tiar.app"};
    return v;
}

namespace {
bool is_cctld(std::string_view s) {
    return s.size() == 2 && s[0] >= 'a' && s[0] <= 'z' && s[1] >= 'a' && s[1] <= 'z';
}
// google.com, www.google.de, google.co.uk, www.google.com.au ... but not google.dev / mail.google.com
bool is_google_search_host(std::string_view h) {
    if (starts_with(h, "www.")) h.remove_prefix(4);
    if (!starts_with(h, "google.")) return false;
    h.remove_prefix(7);
    if (h == "com" || is_cctld(h)) return true;
    size_t dot = h.find('.');
    if (dot == std::string_view::npos) return false;
    std::string_view a = h.substr(0, dot), b = h.substr(dot + 1);
    return (a == "co" || a == "com") && is_cctld(b);
}
}  // namespace

const char* safesearch_target(const std::string& h, bool search, bool youtube) {
    if (search) {
        if (is_google_search_host(h)) return "forcesafesearch.google.com";
        if (h == "bing.com" || h == "www.bing.com") return "strict.bing.com";
        if (h == "duckduckgo.com" || h == "www.duckduckgo.com" || h == "start.duckduckgo.com") return "safe.duckduckgo.com";
        if (h == "pixabay.com" || h == "www.pixabay.com") return "safesearch.pixabay.com";
    }
    if (youtube) {
        if (h == "www.youtube.com" || h == "m.youtube.com" || h == "youtube.com" || h == "youtubei.googleapis.com" ||
            h == "youtube.googleapis.com" || h == "www.youtube-nocookie.com")
            return "restrict.youtube.com";
    }
    return nullptr;
}

// ============================================================================ socket helpers
namespace {
bool send_all(int fd, const uint8_t* p, size_t n) {
    while (n) {
        ssize_t w = send(fd, p, n, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        p += w;
        n -= size_t(w);
    }
    return true;
}

bool recv_all(int fd, uint8_t* p, size_t n) {
    while (n) {
        ssize_t r = recv(fd, p, n, 0);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return false;
        p += r;
        n -= size_t(r);
    }
    return true;
}

int tcp_connect(const Endpoint& ep, int timeout_ms) {
    int fd = socket(ep.family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) return -1;
    int rc = connect(fd, reinterpret_cast<const sockaddr*>(&ep.ss), ep.len);
    if (rc != 0 && errno != EINPROGRESS) { close(fd); return -1; }
    if (rc != 0) {
        pollfd p{fd, POLLOUT, 0};
        int pr;
        do { pr = poll(&p, 1, timeout_ms); } while (pr < 0 && errno == EINTR);
        int err = 0;
        socklen_t el = sizeof err;
        if (pr <= 0 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err != 0) { close(fd); return -1; }
    }
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    return fd;
}

std::string cache_key(const uint8_t* pkt, const dns::Query& q) {
    std::string k(reinterpret_cast<const char*>(pkt + 12), q.qend - 12);  // wire-format question, case-folded
    for (char& c : k)
        if (c >= 'A' && c <= 'Z') c = char(c + 32);
    k.push_back(char(q.edns.present ? (q.edns.do_bit ? 2 : 1) : 0));
    k.push_back(char(((q.flags >> 8) & 1) | (((q.flags >> 4) & 1) << 1)));  // RD, CD
    return k;
}
}  // namespace

// ============================================================================ engine
Engine::Engine(const Config& cfg) : cfg_(cfg), cache_(cfg.cache_entries, cfg.cache_max_ttl) {
    rules_ = RuleSet::build({}, {});
}

void Engine::set_rules(std::shared_ptr<const RuleSet> rs) {
    std::lock_guard<std::mutex> g(rules_mu_);
    rules_ = std::move(rs);
}

std::shared_ptr<const RuleSet> Engine::rules() const {
    std::lock_guard<std::mutex> g(rules_mu_);
    return rules_;
}

bool Engine::udp_exchange(const Endpoint& up, const uint8_t* pkt, size_t len, const dns::Query& q, std::vector<uint8_t>& out) {
    // A fresh socket per query gives a random source port; connect() filters out spoofed senders.
    int fd = socket(up.family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return false;
    if (connect(fd, reinterpret_cast<const sockaddr*>(&up.ss), up.len) != 0 || send(fd, pkt, len, 0) < 0) {
        close(fd);
        return false;
    }
    uint64_t deadline = mono_ms() + uint64_t(cfg_.upstream_timeout_ms);
    uint8_t buf[8192];
    bool ok = false;
    for (;;) {
        uint64_t now = mono_ms();
        if (now >= deadline) break;
        pollfd p{fd, POLLIN, 0};
        int r = poll(&p, 1, int(deadline - now));
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        ssize_t n = recv(fd, buf, sizeof buf, 0);
        if (n < 0) break;  // e.g. ECONNREFUSED from an ICMP error: fail over immediately
        if (dns::response_matches(pkt, q, buf, size_t(n))) {
            out.assign(buf, buf + n);
            ok = true;
            break;
        }
    }
    close(fd);
    return ok;
}

bool Engine::tcp_exchange(const Endpoint& up, const uint8_t* pkt, size_t len, const dns::Query& q, std::vector<uint8_t>& out) {
    int fd = tcp_connect(up, cfg_.upstream_timeout_ms);
    if (fd < 0) return false;
    bool ok = false;
    uint8_t hdr[2] = {uint8_t(len >> 8), uint8_t(len)};
    if (send_all(fd, hdr, 2) && send_all(fd, pkt, len) && recv_all(fd, hdr, 2)) {
        size_t n = dns::rd16(hdr);
        if (n >= 12) {
            out.resize(n);
            ok = recv_all(fd, out.data(), n) && dns::response_matches(pkt, q, out.data(), n);
        }
    }
    close(fd);
    return ok;
}

bool Engine::upstream_query(const uint8_t* pkt, size_t len, const dns::Query& q, bool tcp, std::vector<uint8_t>& out) {
    size_t n = cfg_.upstreams.size();
    if (n == 0) return false;
    size_t start = pref_.load() % n;
    for (size_t k = 0; k < n; ++k) {
        size_t i = (start + k) % n;
        bool ok = tcp ? tcp_exchange(cfg_.upstreams[i], pkt, len, q, out) : udp_exchange(cfg_.upstreams[i], pkt, len, q, out);
        if (ok) {
            pref_.store(i);
            return true;
        }
        LOG_D("upstream %s failed for %s", cfg_.upstreams[i].text.c_str(), q.name.c_str());
    }
    return false;
}

std::vector<uint8_t> Engine::forward_cached(const uint8_t* pkt, size_t len, const dns::Query& q, bool tcp) {
    std::string key = cache_key(pkt, q);
    std::vector<uint8_t> resp;
    if (cache_.get(key, resp)) {
        resp[0] = uint8_t(q.id >> 8);
        resp[1] = uint8_t(q.id);
        stats.cached++;
        return resp;
    }
    if (!upstream_query(pkt, len, q, tcp, resp)) {
        stats.failed++;
        return {};
    }
    stats.forwarded++;
    cache_.put(key, resp);
    return resp;
}

std::vector<uint8_t> Engine::safesearch_reply(const uint8_t* pkt, const dns::Query& q, const char* target) {
    using namespace dns;
    // Only A/AAAA/CNAME are answered; everything else (notably HTTPS/SVCB, whose address hints could
    // point straight at the unfiltered service) gets NODATA so clients fall back to the CNAME path.
    if (q.qtype != T_A && q.qtype != T_AAAA && q.qtype != T_CNAME) return reply_rcode(pkt, q, RC_NOERROR);
    std::vector<Addr> addrs;
    uint32_t ttl = 300;
    if (q.qtype != T_CNAME) {
        uint16_t id = 0;
        random_bytes(&id, sizeof id);
        std::vector<uint8_t> tq = make_query(target, q.qtype, id);
        Query tqq;
        if (tq.empty() || parse_query(tq.data(), tq.size(), tqq) != Parse::Ok) return reply_rcode(pkt, q, RC_SERVFAIL);
        std::vector<uint8_t> resp = forward_cached(tq.data(), tq.size(), tqq, false);
        if (resp.empty() || rcode_of(resp) != RC_NOERROR) return reply_rcode(pkt, q, RC_SERVFAIL);  // fail closed
        addrs = extract_addrs(resp.data(), resp.size(), q.qtype);
        for (const Addr& a : addrs) ttl = std::min(ttl, std::max<uint32_t>(a.ttl, 1));
        for (Addr& a : addrs) a.ttl = ttl;
    }
    return reply_cname(pkt, q, target, ttl, addrs);
}

bool Engine::is_exempt(const std::string& name) const {
    for (const std::string& h : exempt_)
        if (name == h || (name.size() > h.size() && name[name.size() - h.size() - 1] == '.' && name.compare(name.size() - h.size(), h.size(), h) == 0))
            return true;
    return false;
}

std::vector<uint8_t> Engine::resolve(const uint8_t* pkt, size_t len, const dns::Query& q, bool tcp, uint16_t client_port) {
    using namespace dns;
    if (q.qclass == 1 && !q.name.empty()) {
        if (cfg_.block_doh && q.name == "use-application-dns.net")  // Firefox canary: NXDOMAIN => "disable DoH"
            return reply_rcode(pkt, q, RC_NXDOMAIN);

        auto rs = rules();
        Verdict v = rs->check(q.name);
        if (v.blocked && !v.builtin && is_exempt(q.name)) v.blocked = false;  // the redirect target must stay reachable
        if (v.blocked) {
            stats.blocked++;
            if (cfg_.log_blocked) {  // the journal can be readable by other admins: do not spell out the hidden rule
                if (cfg_.hide_rules) LOG_I("BLOCKED %s type=%u", q.name.c_str(), unsigned(q.qtype));
                else LOG_I("BLOCKED %s type=%u (%s)", q.name.c_str(), unsigned(q.qtype), v.reason.c_str());
            }
            // Popup only for lookups a browser makes for a page (not for the built-in DoH list or odd record types).
            if (popup_ && !v.builtin && (q.qtype == T_A || q.qtype == T_AAAA || q.qtype == T_HTTPS))
                popup_->notify_blocked(q.name, client_port);
            if (redirect_ && !v.builtin && redirect_->v4()) {  // point the browser at the local redirect server
                static const uint8_t lo4[4] = {127, 0, 0, 1};
                static const uint8_t lo6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
                if (q.qtype == T_A || q.qtype == T_AAAA) stats.redirected++;
                return reply_addrs(pkt, q, 60, lo4, redirect_->v6() ? lo6 : nullptr);
            }
            return reply_sinkhole(pkt, q, 60);
        }
        if (cfg_.safesearch || cfg_.youtube_restrict) {
            if (const char* target = safesearch_target(q.name, cfg_.safesearch, cfg_.youtube_restrict)) {
                stats.safesearch++;
                LOG_D("safesearch %s -> %s", q.name.c_str(), target);
                return safesearch_reply(pkt, q, target);
            }
        }
    }
    if (cfg_.log_queries) LOG_I("query %s type=%u", q.name.c_str(), unsigned(q.qtype));
    return forward_cached(pkt, len, q, tcp);
}

std::vector<uint8_t> Engine::handle(const uint8_t* pkt, size_t len, bool tcp, uint16_t client_port) {
    using namespace dns;
    stats.total++;
    Query q;
    switch (parse_query(pkt, len, q)) {
        case Parse::Drop: return {};
        case Parse::FormErr: return reply_formerr(pkt, len);
        case Parse::Ok: break;
    }
    if (((q.flags >> 11) & 0xF) != 0) return reply_rcode(pkt, q, RC_NOTIMP);
    std::vector<uint8_t> reply = resolve(pkt, len, q, tcp, client_port);
    if (reply.empty()) reply = reply_rcode(pkt, q, RC_SERVFAIL);
    if (!tcp) {
        size_t max_udp = q.edns.present ? q.edns.udp_size : 512;
        if (reply.size() > max_udp) reply = reply_truncated(reply, q.qend);
    }
    return reply;
}

// ============================================================================ server
bool Server::start(std::string& err) {
    const Endpoint& ep = cfg_.listen;
    int ufd = socket(ep.family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    int tfd = socket(ep.family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (ufd < 0 || tfd < 0) {
        err = std::string("socket: ") + strerror(errno);
        return false;
    }
    int one = 1, rcvbuf = 1 << 20;
    setsockopt(tfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    setsockopt(ufd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf);
    if (bind(ufd, reinterpret_cast<const sockaddr*>(&ep.ss), ep.len) != 0) {
        err = "cannot bind UDP " + ep.text + ": " + strerror(errno);
        return false;
    }
    if (bind(tfd, reinterpret_cast<const sockaddr*>(&ep.ss), ep.len) != 0 || listen(tfd, 128) != 0) {
        err = "cannot bind TCP " + ep.text + ": " + strerror(errno);
        return false;
    }
    try {
        for (int i = 0; i < cfg_.workers; ++i) std::thread(&Server::udp_worker, this, ufd).detach();
        std::thread(&Server::tcp_acceptor, this, tfd).detach();
    } catch (const std::exception& e) {
        err = std::string("cannot start worker threads: ") + e.what();
        return false;
    }
    LOG_I("DNS proxy listening on %s (udp+tcp, %d workers)", ep.text.c_str(), cfg_.workers);
    return true;
}

void Server::udp_worker(int fd) {
    std::vector<uint8_t> buf(4096);
    for (;;) {
        sockaddr_storage src;
        socklen_t sl = sizeof src;
        ssize_t n = recvfrom(fd, buf.data(), buf.size(), 0, reinterpret_cast<sockaddr*>(&src), &sl);
        if (n < 0) {
            if (errno != EINTR) usleep(10000);
            continue;
        }
        uint16_t port = 0;
        if (src.ss_family == AF_INET) port = ntohs(reinterpret_cast<sockaddr_in*>(&src)->sin_port);
        else if (src.ss_family == AF_INET6) port = ntohs(reinterpret_cast<sockaddr_in6*>(&src)->sin6_port);
        std::vector<uint8_t> reply = eng_.handle(buf.data(), size_t(n), false, port);
        if (!reply.empty()) sendto(fd, reply.data(), reply.size(), 0, reinterpret_cast<sockaddr*>(&src), sl);
    }
}

void Server::tcp_acceptor(int fd) {
    for (;;) {
        int c = accept4(fd, nullptr, nullptr, SOCK_CLOEXEC);
        if (c < 0) {
            if (errno != EINTR) usleep(10000);
            continue;
        }
        if (tcp_active_.load() >= 128) { close(c); continue; }
        tcp_active_++;
        try {
            std::thread(&Server::tcp_conn, this, c).detach();
        } catch (...) {
            tcp_active_--;
            close(c);
        }
    }
}

void Server::tcp_conn(int fd) {
    timeval tv{5, 0};  // idle connections are dropped after 5 s
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    std::vector<uint8_t> buf;
    for (;;) {
        uint8_t hdr[2];
        if (!recv_all(fd, hdr, 2)) break;
        size_t n = dns::rd16(hdr);
        if (n < 12) break;
        buf.resize(n);
        if (!recv_all(fd, buf.data(), n)) break;
        std::vector<uint8_t> reply = eng_.handle(buf.data(), n, true);
        if (reply.empty()) break;
        hdr[0] = uint8_t(reply.size() >> 8);
        hdr[1] = uint8_t(reply.size());
        if (!send_all(fd, hdr, 2) || !send_all(fd, reply.data(), reply.size())) break;
    }
    close(fd);
    tcp_active_--;
}

}  // namespace blk
