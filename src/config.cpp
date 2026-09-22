#include "config.hpp"

#include <arpa/inet.h>
#include <cstring>

#include "util.hpp"

namespace blk {

bool parse_endpoint(const std::string& input, uint16_t default_port, Endpoint& out) {
    std::string s = trim(input);
    if (s.empty()) return false;
    std::string host;
    uint64_t port = default_port;
    if (s[0] == '[') {
        size_t rb = s.find(']');
        if (rb == std::string::npos) return false;
        host = s.substr(1, rb - 1);
        if (rb + 1 < s.size()) {
            if (s[rb + 1] != ':' || !parse_u64(s.substr(rb + 2), port)) return false;
        }
    } else {
        size_t colons = 0;
        for (char c : s) colons += (c == ':');
        if (colons == 1) {
            size_t c = s.find(':');
            host = s.substr(0, c);
            if (!parse_u64(s.substr(c + 1), port)) return false;
        } else {
            host = s;  // IPv4 without port, or a bare IPv6 literal
        }
    }
    if (port == 0 || port > 65535) return false;
    out = Endpoint{};
    sockaddr_in* a4 = reinterpret_cast<sockaddr_in*>(&out.ss);
    sockaddr_in6* a6 = reinterpret_cast<sockaddr_in6*>(&out.ss);
    if (inet_pton(AF_INET, host.c_str(), &a4->sin_addr) == 1) {
        a4->sin_family = AF_INET;
        a4->sin_port = htons(uint16_t(port));
        out.len = sizeof(sockaddr_in);
        out.family = AF_INET;
        out.text = host + ":" + std::to_string(port);
        return true;
    }
    if (inet_pton(AF_INET6, host.c_str(), &a6->sin6_addr) == 1) {
        a6->sin6_family = AF_INET6;
        a6->sin6_port = htons(uint16_t(port));
        out.len = sizeof(sockaddr_in6);
        out.family = AF_INET6;
        out.text = "[" + host + "]:" + std::to_string(port);
        return true;
    }
    return false;
}

const char* lock_mode_name(LockMode m) {
    switch (m) {
        case LockMode::Password: return "password";
        case LockMode::Delay: return "delay";
        default: return "both";
    }
}

bool parse_lock_mode(const std::string& s, LockMode& m) {
    std::string v = to_lower(trim(s));
    if (v == "password") { m = LockMode::Password; return true; }
    if (v == "delay") { m = LockMode::Delay; return true; }
    if (v == "both") { m = LockMode::Both; return true; }
    return false;
}

Config Config::defaults() {
    Config c;
    parse_endpoint("127.0.0.1:53", 53, c.listen);
    Endpoint e;
    if (parse_endpoint("1.1.1.3", 53, e)) c.upstreams.push_back(e);  // Cloudflare "Families" (malware + adult)
    if (parse_endpoint("1.0.0.3", 53, e)) c.upstreams.push_back(e);
    return c;
}

Config Config::load(const std::string& path, std::vector<std::string>& warnings) {
    Config c = defaults();
    std::string text;
    if (!read_file(path, text)) {
        warnings.push_back("cannot read " + path + ": using built-in defaults");
        return c;
    }
    bool upstream_set = false;
    int lineno = 0;
    for (const std::string& raw : split(text, '\n')) {
        ++lineno;
        std::string line = raw;
        size_t hash = line.find('#');
        if (hash != std::string::npos) line.erase(hash);
        line = trim(line);
        if (line.empty()) continue;
        size_t eq = line.find('=');
        if (eq == std::string::npos) {
            warnings.push_back("config line " + std::to_string(lineno) + ": expected key = value");
            continue;
        }
        std::string key = to_lower(trim(line.substr(0, eq))), val = trim(line.substr(eq + 1));
        auto bad = [&](const char* why) {
            warnings.push_back("config line " + std::to_string(lineno) + " (" + key + "): " + why);
        };
        uint64_t n = 0;
        bool b = false;
        if (key == "listen") {
            if (!parse_endpoint(val, 53, c.listen)) bad("invalid address");
        } else if (key == "upstream") {
            std::vector<Endpoint> list;
            for (const std::string& part : split(val, ',')) {
                Endpoint e;
                if (trim(part).empty()) continue;
                if (parse_endpoint(part, 53, e)) list.push_back(e);
                else bad("invalid upstream address");
            }
            if (!list.empty()) { c.upstreams = list; upstream_set = true; }
        } else if (key == "workers") {
            if (parse_u64(val, n) && n >= 1 && n <= 512) c.workers = int(n); else bad("expected 1..512");
        } else if (key == "upstream_timeout_ms") {
            if (parse_u64(val, n) && n >= 100 && n <= 20000) c.upstream_timeout_ms = int(n); else bad("expected 100..20000");
        } else if (key == "cache_entries") {
            if (parse_u64(val, n) && n <= 10000000) c.cache_entries = size_t(n); else bad("expected a number");
        } else if (key == "cache_max_ttl") {
            if (parse_u64(val, n) && n <= 86400) c.cache_max_ttl = uint32_t(n); else bad("expected 0..86400");
        } else if (key == "safesearch") { if (parse_bool(val, b)) c.safesearch = b; else bad("expected yes/no");
        } else if (key == "youtube_restrict") { if (parse_bool(val, b)) c.youtube_restrict = b; else bad("expected yes/no");
        } else if (key == "block_doh") { if (parse_bool(val, b)) c.block_doh = b; else bad("expected yes/no");
        } else if (key == "firewall") { if (parse_bool(val, b)) c.firewall = b; else bad("expected yes/no");
        } else if (key == "browser_policies") { if (parse_bool(val, b)) c.browser_policies = b; else bad("expected yes/no");
        } else if (key == "takeover_resolver") { if (parse_bool(val, b)) c.takeover_resolver = b; else bad("expected yes/no");
        } else if (key == "redirect") { if (parse_bool(val, b)) c.redirect = b; else bad("expected yes/no");
        } else if (key == "redirect_url") { if (valid_redirect_url(val)) c.redirect_url = val; else bad("expected an http:// or https:// URL without spaces or quotes");
        } else if (key == "redirect_port") { if (parse_u64(val, n) && n >= 1 && n <= 65535) c.redirect_port = int(n); else bad("expected 1..65535");
        } else if (key == "hide_rules") { if (parse_bool(val, b)) c.hide_rules = b; else bad("expected yes/no");
        } else if (key == "popup") { if (parse_bool(val, b)) c.popup = b; else bad("expected yes/no");
        } else if (key == "popup_title") { if (!val.empty() && val.size() <= 80) c.popup_title = val; else bad("expected 1..80 characters");
        } else if (key == "popup_message") { if (!val.empty() && val.size() <= 600) c.popup_message = val; else bad("expected 1..600 characters");
        } else if (key == "popup_seconds") { if (parse_u64(val, n) && n >= 1 && n <= 60) c.popup_seconds = int(n); else bad("expected 1..60");
        } else if (key == "popup_cooldown") { if (parse_u64(val, n) && n <= 3600) c.popup_cooldown = int(n); else bad("expected 0..3600");
        } else if (key == "popup_helper") { c.popup_helper = val;
        } else if (key == "log_blocked") { if (parse_bool(val, b)) c.log_blocked = b; else bad("expected yes/no");
        } else if (key == "log_queries") { if (parse_bool(val, b)) c.log_queries = b; else bad("expected yes/no");
        } else if (key == "lock_mode") {
            if (!parse_lock_mode(val, c.lock_mode)) bad("expected password, delay or both");
        } else if (key == "unlock_delay") {
            if (parse_u64(val, n) && n <= 365ull * 86400) c.unlock_delay = n; else bad("expected seconds");
        } else if (key == "unlock_window") {
            if (parse_u64(val, n) && n >= 1 && n <= 7ull * 86400) c.unlock_window = n; else bad("expected seconds");
        } else if (key == "kdf_iterations") {
            if (parse_u64(val, n) && n >= 1000 && n <= 50000000) c.kdf_iterations = uint32_t(n); else bad("expected 1000..50000000");
        } else {
            warnings.push_back("config line " + std::to_string(lineno) + ": unknown key '" + key + "'");
        }
    }
    (void)upstream_set;
    return c;
}

bool valid_redirect_url(const std::string& url) {
    if (url.size() < 9 || url.size() > 1000) return false;
    if (url.compare(0, 7, "http://") != 0 && url.compare(0, 8, "https://") != 0) return false;
    for (unsigned char c : url)
        if (c <= 0x20 || c >= 0x7f || c == '"' || c == '<' || c == '>' || c == '\\' || c == '`' || c == '\'' || c == '{' || c == '}' || c == '|')
            return false;
    return !redirect_host(url).empty();
}

std::string redirect_host(const std::string& url) {
    size_t b = url.compare(0, 8, "https://") == 0 ? 8 : (url.compare(0, 7, "http://") == 0 ? 7 : std::string::npos);
    if (b == std::string::npos) return "";
    size_t e = url.find_first_of("/?#", b);
    std::string auth = url.substr(b, e == std::string::npos ? std::string::npos : e - b);
    size_t at = auth.rfind('@');
    if (at != std::string::npos) auth = auth.substr(at + 1);
    if (!auth.empty() && auth[0] == '[') return "";  // IP literals: nothing to exempt
    size_t colon = auth.find(':');
    if (colon != std::string::npos) auth = auth.substr(0, colon);
    std::string h;
    for (char c : auth) h.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    return h;
}

std::string redirect_config_block(bool redirect, const std::string& url) {
    std::string t;
    t += "# Landing redirect: blocked names resolve to 127.0.0.1 and a tiny local web server answers every request\n";
    t += "# with a redirect (302) to redirect_url. Applies to http:// requests; a browser that insists on https:// for\n";
    t += "# the blocked name still shows a connection error. redirect_port is for testing only.\n";
    t += std::string("redirect = ") + (redirect ? "yes" : "no") + "\n";
    t += "redirect_url = " + (url.empty() ? Config::defaults().redirect_url : url) + "\n";
    t += "redirect_port = 80\n\n";
    t += "# Rule files are kept scrambled in a root-only place; `blocker list` needs the unlock window when yes.\n";
    t += "hide_rules = yes\n";
    return t;
}

static bool has_key(const std::string& text, const std::string& key) {
    for (const std::string& l : split(text, '\n')) {
        std::string t = trim(l);
        if (t.compare(0, key.size(), key) == 0 && t.size() > key.size() && (t[key.size()] == ' ' || t[key.size()] == '=' || t[key.size()] == '\t'))
            return true;
    }
    return false;
}

bool upgrade_config_text(std::string& text, bool popup, const std::string& popup_message, bool redirect,
                         const std::string& redirect_url, std::vector<std::string>& notes) {
    bool changed = false;
    if (!text.empty() && text.back() != '\n') text.push_back('\n');
    if (!has_key(text, "redirect")) {
        // The redirect replaces the popup: switch an enabled popup off (the person can turn it back on).
        std::string out;
        bool turned_off = false;
        std::vector<std::string> lines = split(text, '\n');
        if (!lines.empty() && lines.back().empty()) lines.pop_back();
        for (const std::string& l : lines) {
            std::string t = trim(l);
            size_t eq = t.find('=');
            if (has_key(t, "popup") && eq != std::string::npos) {
                std::string val = to_lower(trim(t.substr(eq + 1)));
                if (val == "yes" || val == "true" || val == "on" || val == "1") {
                    out += "popup = no\n";
                    turned_off = true;
                    continue;
                }
            }
            out += l + "\n";
        }
        text = out + "\n" + redirect_config_block(redirect, redirect_url);
        notes.push_back("added the redirect settings");
        if (turned_off) notes.push_back("switched the popup off (the redirect replaces it; set popup = yes to keep both)");
        changed = true;
    }
    if (!has_key(text, "popup")) {
        text += "\n" + popup_config_block(popup, popup_message);
        notes.push_back("added the popup settings");
        changed = true;
    }
    return changed;
}

std::string popup_config_block(bool popup, const std::string& popup_message) {
    std::string t;
    t += "# Desktop popup shown to the user when a blocked site is visited. \"\\n\" = new line, {host} = the blocked\n";
    t += "# name; do not use '#' in the text. The popup closes itself after popup_seconds; popup_cooldown is the\n";
    t += "# minimum gap between popups for the same host. popup_helper (optional) = custom program called as\n";
    t += "#   helper <title> <message> <seconds> <host>   (default: zenity, yad, kdialog or notify-send if installed)\n";
    t += std::string("popup = ") + (popup ? "yes" : "no") + "\n";
    t += "popup_title = Website blocked\n";
    t += "popup_message = " + (popup_message.empty() ? Config::defaults().popup_message : popup_message) + "\n";
    t += "popup_seconds = 5\n";
    t += "popup_cooldown = 30\n";
    return t;
}

std::string default_config_text(LockMode mode, uint64_t delay_secs, uint64_t window_secs,
                                const std::string& upstreams, bool firewall, bool popup,
                                const std::string& popup_message, bool redirect, const std::string& redirect_url) {
    std::string t;
    t += "# /etc/blocker/blocker.conf - read once when the daemon starts.\n";
    t += "# This file is root-owned and immutable (chattr +i) while blocker is running.\n\n";
    t += "# Where the DNS proxy listens. /etc/resolv.conf is pointed here.\n";
    t += "listen = 127.0.0.1:53\n\n";
    t += "# Upstream resolvers (comma separated, tried in order, port defaults to 53).\n";
    t += "# Use a filtering resolver for defence in depth. Examples:\n";
    t += "#   Cloudflare Families      1.1.1.3, 1.0.0.3\n";
    t += "#   CleanBrowsing Adult      185.228.168.10, 185.228.169.11\n";
    t += "#   OpenDNS FamilyShield     208.67.222.123, 208.67.220.123\n";
    t += "upstream = " + upstreams + "\n\n";
    t += "workers = 32\n";
    t += "upstream_timeout_ms = 1500\n";
    t += "cache_entries = 16384\n";
    t += "cache_max_ttl = 300\n\n";
    t += "# Force SafeSearch (Google, Bing, DuckDuckGo, Pixabay) and YouTube Restricted Mode.\n";
    t += "safesearch = yes\n";
    t += "youtube_restrict = yes\n\n";
    t += "# Sinkhole well-known DNS-over-HTTPS/TLS provider names and the Firefox DoH canary domain.\n";
    t += "block_doh = yes\n\n";
    t += "# nftables: drop plain DNS (53) and DoT (853) leaving the machine unless sent by root.\n";
    t += std::string("firewall = ") + (firewall ? "yes" : "no") + "\n\n";
    t += "# Managed browser policies: disable browser-level DoH, force Google SafeSearch/YouTube restrict.\n";
    t += "browser_policies = yes\n\n";
    t += "# Keep /etc/resolv.conf pointing at this proxy (and immutable).\n";
    t += "takeover_resolver = yes\n\n";
    t += redirect_config_block(redirect, redirect_url) + "\n";
    t += popup_config_block(popup, popup_message) + "\n";
    t += "log_blocked = yes\n";
    t += "log_queries = no\n\n";
    t += "# Lock: password | delay | both  (see USAGE.md)\n";
    t += std::string("lock_mode = ") + lock_mode_name(mode) + "\n";
    t += "# Seconds an unlock request must age before the window opens (counted only while the\n";
    t += "# daemon runs, so changing the system clock does not shorten it), and how long it stays open.\n";
    t += "unlock_delay = " + std::to_string(delay_secs) + "\n";
    t += "unlock_window = " + std::to_string(window_secs) + "\n";
    return t;
}

}  // namespace blk
