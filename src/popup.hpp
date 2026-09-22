// popup.hpp - "this site is blocked" desktop popup.
//
// When the DNS engine sinkholes a name because of a user rule, a short popup with a custom message is shown on
// the desktop of the user who made the lookup (attributed through /proc/net/udp; if that is not possible, every
// logged-in graphical user). The popup runs as that user, closes itself after `popup_seconds`, and is killed by
// the daemon if it does not. A per-host cooldown keeps browsers' repeated lookups from stacking popups.
//
// Helpers, first one installed wins: zenity, yad, kdialog (preferred on KDE), notify-send - or the program named
// by `popup_helper`, which is called as:  helper <title> <message> <seconds> <host>
#pragma once

#include <sys/types.h>

#include <atomic>
#include <condition_variable>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "config.hpp"

namespace blk {

// ---- pure helpers (unit-tested)
std::string popup_render(const std::string& tmpl, const std::string& host);  // "\n" -> newline, {host} -> host name
std::string popup_escape_markup(const std::string& s);                       // & < > for markup-based dialogs
std::map<std::string, std::string> popup_parse_environ(const std::string& raw);  // NUL-separated KEY=VALUE block
bool uid_of_udp_port(uint16_t port, uid_t& uid);  // owner of a local UDP socket, from /proc/net/udp{,6}

struct GuiSession {
    uid_t uid = 0;
    std::vector<std::pair<std::string, std::string>> env;  // DISPLAY, WAYLAND_DISPLAY, XAUTHORITY, DBUS_... of the session
    std::string desktop;                                   // XDG_CURRENT_DESKTOP
};
std::vector<GuiSession> find_gui_sessions();  // one entry per regular user with a running graphical session

class Popup {
public:
    explicit Popup(const Config& cfg) : cfg_(cfg) {}
    void start();  // spawns the worker thread (no-op when popups are disabled)
    bool enabled() const { return cfg_.popup; }
    // Called from DNS threads: must stay cheap. client_port = UDP source port of the query (0 = unknown).
    void notify_blocked(const std::string& host, uint16_t client_port);
    std::string describe();

private:
    struct Job { std::string host; uint16_t port; };
    struct Child { pid_t pid; uid_t uid; uint64_t deadline_ms; };
    void run();
    std::string show(const std::string& host, uint16_t port, bool force);
    void reap_locked();
    std::vector<GuiSession> sessions(bool refresh);
    std::string helper_name() const;

    Config cfg_;
    std::mutex mu_;
    std::condition_variable cv_;
    std::deque<Job> queue_;
    std::unordered_map<std::string, uint64_t> last_;  // host -> last time a popup was queued (ms)
    std::vector<Child> running_;
    std::vector<GuiSession> cache_;
    uint64_t cache_at_ = 0;
    std::atomic<uint64_t> shown_{0};
    std::string last_result_;
};

}  // namespace blk
