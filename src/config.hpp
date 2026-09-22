// config.hpp - /etc/blocker/blocker.conf ("key = value" lines, '#' comments).
#pragma once

#include <cstdint>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <vector>

namespace blk {

struct Endpoint {
    sockaddr_storage ss{};
    socklen_t len = 0;
    int family = AF_INET;
    std::string text;
};
bool parse_endpoint(const std::string& in, uint16_t default_port, Endpoint& out);

enum class LockMode { Password, Delay, Both };
const char* lock_mode_name(LockMode m);
bool parse_lock_mode(const std::string& s, LockMode& m);

struct Config {
    Endpoint listen;
    std::vector<Endpoint> upstreams;
    int workers = 32;
    int upstream_timeout_ms = 1500;
    size_t cache_entries = 16384;
    uint32_t cache_max_ttl = 300;
    bool safesearch = true;         // force SafeSearch on Google/Bing/DuckDuckGo/Pixabay
    bool youtube_restrict = true;   // force YouTube Restricted Mode
    bool block_doh = true;          // sinkhole well-known DoH/DoT provider names + Firefox canary
    bool firewall = true;           // nftables: only root (the daemon) may send plain DNS/DoT off-box
    bool browser_policies = true;   // managed policies: disable browser DoH, force SafeSearch
    bool takeover_resolver = true;  // point /etc/resolv.conf at 127.0.0.1 and keep it there
    bool log_blocked = true;
    // Landing redirect (see redirect.hpp): blocked names resolve to loopback and a local HTTP server answers 302.
    bool redirect = true;
    std::string redirect_url = "https://youtu.be/z7f0ADlstfo?autoplay=1";
    int redirect_port = 80;         // only ever changed by the test-suite (browsers use 80)
    bool hide_rules = true;         // `blocker list` needs the unlock window (rule files are also scrambled at rest)
    // Desktop popup when a blocked site is visited (see popup.hpp); off by default now that the redirect exists
    bool popup = false;
    std::string popup_title = "Website blocked";
    std::string popup_message = "This site is blocked by Blocker.\\nStay focused - you set this up for a reason.";  // "\\n" = new line, {host} = name
    int popup_seconds = 5;      // how long the popup stays (1..60)
    int popup_cooldown = 30;    // seconds before the same host may trigger another popup
    std::string popup_helper;   // optional custom program: helper <title> <message> <seconds> <host>
    bool log_queries = false;
    LockMode lock_mode = LockMode::Both;
    uint64_t unlock_delay = 24 * 3600;  // seconds the unlock request must "age" (only counted while running)
    uint64_t unlock_window = 30 * 60;   // seconds the window stays open afterwards
    uint32_t kdf_iterations = 200000;   // PBKDF2 rounds used when the password is created

    static Config defaults();
    static Config load(const std::string& path, std::vector<std::string>& warnings);
};

// Redirect URL rules: http(s) only, no spaces/quotes/angle brackets or control characters, at most 1000 bytes.
bool valid_redirect_url(const std::string& url);
std::string redirect_host(const std::string& url);  // lower-case host of a valid URL ("" if none)
// The redirect settings block; also appended to a config written by a version without the redirect.
std::string redirect_config_block(bool redirect, const std::string& url = "");
// Brings a config written by an older version up to date: appends the redirect/popup blocks that are missing.
// When the redirect block is added, a "popup = yes" line is switched to "no" (the redirect replaces the popup).
// Returns true if the text changed; human-readable notes about what was done go to `notes`.
bool upgrade_config_text(std::string& text, bool popup, const std::string& popup_message, bool redirect,
                         const std::string& redirect_url, std::vector<std::string>& notes);
// Updates or inserts a key = value line in existing config text. Returns true if modified.
bool set_config_value(std::string& text, const std::string& key, const std::string& val);
// The popup settings block; also appended to a config written by a version that had no popup support.
std::string popup_config_block(bool popup, const std::string& popup_message = "");
std::string default_config_text(LockMode mode, uint64_t delay_secs, uint64_t window_secs,
                                const std::string& upstreams, bool firewall, bool popup = false,
                                const std::string& popup_message = "", bool redirect = true,
                                const std::string& redirect_url = "");

}  // namespace blk
