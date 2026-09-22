#include "popup.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <thread>

#include "dns.hpp"
#include "paths.hpp"
#include "util.hpp"

namespace blk {

// ------------------------------------------------------------------ pure helpers
std::string popup_render(const std::string& tmpl, const std::string& host) {
    std::string out;
    for (size_t i = 0; i < tmpl.size() && out.size() < 800; ++i) {
        if (tmpl[i] == '\\' && i + 1 < tmpl.size() && tmpl[i + 1] == 'n') {
            out.push_back('\n');
            ++i;
        } else if (tmpl.compare(i, 6, "{host}") == 0) {
            out += host;
            i += 5;
        } else {
            out.push_back(tmpl[i]);
        }
    }
    return out;
}

std::string popup_escape_markup(const std::string& s) {
    std::string o;
    for (char c : s) {
        switch (c) {
            case '&': o += "&amp;"; break;
            case '<': o += "&lt;"; break;
            case '>': o += "&gt;"; break;
            default: o.push_back(c);
        }
    }
    return o;
}

std::map<std::string, std::string> popup_parse_environ(const std::string& raw) {
    std::map<std::string, std::string> out;
    size_t i = 0;
    while (i < raw.size()) {
        size_t e = raw.find('\0', i);
        if (e == std::string::npos) e = raw.size();
        std::string kv = raw.substr(i, e - i);
        i = e + 1;
        size_t eq = kv.find('=');
        if (eq != std::string::npos && eq > 0) out[kv.substr(0, eq)] = kv.substr(eq + 1);
    }
    return out;
}

bool uid_of_udp_port(uint16_t port, uid_t& uid) {
    for (const char* f : {"/proc/net/udp", "/proc/net/udp6"}) {
        std::string t;
        if (!read_file(f, t, 16u << 20)) continue;
        bool header = true;
        for (const std::string& line : split(t, '\n')) {
            if (header) { header = false; continue; }
            std::vector<std::string> tok = split_ws(line);  // sl local rem st queues tr retrnsmt uid timeout inode ...
            if (tok.size() < 8) continue;
            size_t colon = tok[1].rfind(':');
            if (colon == std::string::npos) continue;
            const char* port_str = tok[1].c_str() + colon + 1;
            char* port_end = nullptr;
            errno = 0;
            unsigned long port_val = strtoul(port_str, &port_end, 16);
            if (errno || port_end == port_str || port_val != port) continue;
            char* uid_end = nullptr;
            errno = 0;
            unsigned long uid_val = strtoul(tok[7].c_str(), &uid_end, 10);
            if (errno || uid_end == tok[7].c_str()) continue;
            uid = static_cast<uid_t>(uid_val);
            return true;
        }
    }
    return false;
}

namespace {

bool regular_uid(uid_t u) { return u >= 1000 && u < 65534; }

std::string find_exe(const char* name) {
    for (const char* d : {"/usr/bin", "/usr/local/bin", "/bin"}) {
        std::string p = std::string(d) + "/" + name;
        if (access(p.c_str(), X_OK) == 0) return p;
    }
    return "";
}

// The environment variables a GUI program needs to reach the user's display and session bus.
const char* const kGuiVars[] = {"DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR",
                                "XDG_CURRENT_DESKTOP", "XDG_SESSION_TYPE", "XDG_DATA_DIRS", "LANG", "LANGUAGE", "LC_ALL"};

// Builds the helper's argv, or an empty vector when nothing suitable is installed.
std::vector<std::string> helper_argv(const Config& cfg, const std::string& desktop, const std::string& title,
                                     const std::string& msg, const std::string& host) {
    const std::string secs = std::to_string(cfg.popup_seconds);
    if (!cfg.popup_helper.empty()) return {cfg.popup_helper, title, msg, secs, host};

    const std::string esc = popup_escape_markup(msg);
    const bool kde = desktop.find("KDE") != std::string::npos;
    std::vector<const char*> order = kde ? std::vector<const char*>{"kdialog", "zenity", "yad", "notify-send"}
                                         : std::vector<const char*>{"zenity", "yad", "kdialog", "notify-send"};
    for (const char* name : order) {
        std::string exe = find_exe(name);
        if (exe.empty()) continue;
        std::string n = name;
        if (n == "zenity")
            return {exe, "--info", "--title=" + title, "--text=" + esc, "--timeout=" + secs, "--width=420"};
        if (n == "yad")
            return {exe, "--title=" + title, "--text=" + esc, "--timeout=" + secs, "--button=OK:0", "--center", "--on-top", "--width=420"};
        if (n == "kdialog") {
            std::string html;
            for (char c : esc) { if (c == '\n') html += "<br>"; else html.push_back(c); }
            return {exe, "--title", title, "--passivepopup", html, secs};
        }
        return {exe, "--app-name=Blocker", "--urgency=critical", "--expire-time=" + std::to_string(cfg.popup_seconds * 1000), title, esc};
    }
    return {};
}

// Starts argv as `uid` (dropping root) with the session's environment, in its own session/process group.
pid_t spawn_as(uid_t uid, const std::vector<std::pair<std::string, std::string>>& env, const std::vector<std::string>& argv) {
    passwd* pw = getpwuid(uid);
    if (!pw) return -1;
    const std::string name = pw->pw_name, home = pw->pw_dir;
    const gid_t gid = pw->pw_gid;
    int ng = 64;
    std::vector<gid_t> groups(static_cast<size_t>(ng));
    if (getgrouplist(name.c_str(), gid, groups.data(), &ng) < 0) {
        groups.resize(static_cast<size_t>(ng));
        getgrouplist(name.c_str(), gid, groups.data(), &ng);
    }
    groups.resize(static_cast<size_t>(ng));
    const bool drop = uid != geteuid();
    if (drop && geteuid() != 0) return -1;  // cannot switch users without root

    std::vector<std::string> envs;
    bool has_rt = false, has_bus = false;
    for (const auto& kv : env) {
        envs.push_back(kv.first + "=" + kv.second);
        has_rt |= kv.first == "XDG_RUNTIME_DIR";
        has_bus |= kv.first == "DBUS_SESSION_BUS_ADDRESS";
    }
    if (!has_rt) envs.push_back("XDG_RUNTIME_DIR=/run/user/" + std::to_string(uid));
    if (!has_bus) envs.push_back("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/" + std::to_string(uid) + "/bus");
    envs.push_back("HOME=" + home);
    envs.push_back("USER=" + name);
    envs.push_back("LOGNAME=" + name);
    envs.push_back("PATH=/usr/local/bin:/usr/bin:/bin");

    std::vector<char*> envp, args;
    for (auto& e : envs) envp.push_back(const_cast<char*>(e.c_str()));
    envp.push_back(nullptr);
    for (auto& a : argv) args.push_back(const_cast<char*>(a.c_str()));
    args.push_back(nullptr);
    long maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd < 0 || maxfd > 65536) maxfd = 65536;

    pid_t pid = fork();
    if (pid != 0) return pid;
    // ---- child: only async-signal-safe calls from here on
    setsid();
    signal(SIGPIPE, SIG_DFL);
    int dn = open("/dev/null", O_RDWR);
    if (dn >= 0) { dup2(dn, 0); dup2(dn, 1); dup2(dn, 2); }
#ifdef SYS_close_range
    if (syscall(SYS_close_range, 3u, ~0u, 0u) != 0)
#endif
        for (int fd = 3; fd < maxfd; ++fd) close(fd);  // never leak the control socket / DNS sockets to a user process
    if (drop) {
        if (setgroups(groups.size(), groups.data()) != 0 || setgid(gid) != 0 || setuid(uid) != 0) _exit(126);
        if (uid != 0 && setuid(0) == 0) _exit(126);  // must not be able to get root back
    }
    umask(077);
    if (chdir("/") != 0) {}
    execve(args[0], args.data(), envp.data());
    _exit(127);
}

}  // namespace

std::vector<GuiSession> find_gui_sessions() {
    std::vector<GuiSession> out;
#ifdef BLOCKER_DEV
    if (const char* d = getenv("BLOCKER_TEST_DISPLAY")) {  // test hook: pretend the current user has a desktop
        GuiSession s;
        s.uid = getenv("BLOCKER_TEST_UID") ? static_cast<uid_t>(atoi(getenv("BLOCKER_TEST_UID"))) : geteuid();
        s.env = {{"DISPLAY", d}};
        out.push_back(s);
        return out;
    }
#endif
    DIR* d = opendir("/proc");
    if (!d) return out;
    std::map<uid_t, std::pair<int, GuiSession>> best;
    while (dirent* e = readdir(d)) {
        const char* n = e->d_name;
        if (*n < '1' || *n > '9') continue;
        bool digits = true;
        for (const char* c = n; *c; ++c) digits &= (*c >= '0' && *c <= '9');
        if (!digits) continue;
        struct stat st;
        if (stat((std::string("/proc/") + n).c_str(), &st) != 0 || !regular_uid(st.st_uid)) continue;
        std::string raw;
        if (!read_file(std::string("/proc/") + n + "/environ", raw, 1u << 20)) continue;
        auto env = popup_parse_environ(raw);
        const bool x11 = env.count("DISPLAY") && !env["DISPLAY"].empty() && env["DISPLAY"][0] == ':';  // local X only
        const bool wl = env.count("WAYLAND_DISPLAY") && !env["WAYLAND_DISPLAY"].empty();
        if (!x11 && !wl) continue;
        int score = 1 + int(env.count("DBUS_SESSION_BUS_ADDRESS")) + int(env.count("XDG_RUNTIME_DIR")) + int(env.count("XAUTHORITY"));
        auto it = best.find(st.st_uid);
        if (it != best.end() && it->second.first >= score) continue;
        GuiSession s;
        s.uid = st.st_uid;
        for (const char* v : kGuiVars)
            if (env.count(v)) s.env.emplace_back(v, env[v]);
        s.desktop = env.count("XDG_CURRENT_DESKTOP") ? env["XDG_CURRENT_DESKTOP"] : "";
        best[st.st_uid] = {score, s};
    }
    closedir(d);
    for (auto& kv : best) out.push_back(kv.second.second);
    return out;
}

// ------------------------------------------------------------------ Popup
void Popup::start() {
    if (!cfg_.popup) return;
    std::thread(&Popup::run, this).detach();
}

void Popup::notify_blocked(const std::string& host, uint16_t client_port) {
    if (!cfg_.popup) return;
    const uint64_t now = mono_ms(), cool = uint64_t(cfg_.popup_cooldown) * 1000;
    std::lock_guard<std::mutex> g(mu_);
    uint64_t& t = last_[host];
    if (t && now - t < cool) return;
    t = now;
    if (last_.size() > 2048)
        for (auto it = last_.begin(); it != last_.end();) it = (now - it->second >= cool && it->first != host) ? last_.erase(it) : std::next(it);
    if (queue_.size() < 8) queue_.push_back({host, client_port});
    cv_.notify_one();
}

void Popup::run() {
    std::unique_lock<std::mutex> lk(mu_);
    for (;;) {
        cv_.wait_for(lk, std::chrono::milliseconds(250), [&] { return !queue_.empty(); });
        reap_locked();
        while (!queue_.empty()) {
            Job j = queue_.front();
            queue_.pop_front();
            lk.unlock();
            std::string res = show(j.host, j.port, false);
            LOG_I("popup for %s: %s", j.host.c_str(), res.c_str());
            lk.lock();
            last_result_ = res;
        }
    }
}

void Popup::reap_locked() {
    const uint64_t now = mono_ms();
    for (auto it = running_.begin(); it != running_.end();) {
        int st = 0;
        pid_t r = waitpid(it->pid, &st, WNOHANG);
        if (r == it->pid || (r < 0 && errno == ECHILD)) {
            it = running_.erase(it);
            continue;
        }
        if (now >= it->deadline_ms) {  // the dialog did not close itself: end it
            kill(-it->pid, SIGKILL);
            kill(it->pid, SIGKILL);
        }
        ++it;
    }
}

std::vector<GuiSession> Popup::sessions(bool refresh) {
    const uint64_t now = mono_ms();
    {
        std::lock_guard<std::mutex> g(mu_);
        if (!refresh && now - cache_at_ < 20000 && cache_at_) return cache_;
    }
    std::vector<GuiSession> s = find_gui_sessions();  // scans /proc: keep it outside the lock
    std::lock_guard<std::mutex> g(mu_);
    cache_ = s;
    cache_at_ = now;
    return s;
}

std::string Popup::show(const std::string& host, uint16_t port, bool force) {
    uid_t target = 0;
    bool known = false;
    if (port && uid_of_udp_port(port, target) && (regular_uid(target) || paths::dev())) known = true;

    std::vector<GuiSession> ss = sessions(force);
    if (ss.empty()) return "no graphical session found";
    const std::string title = cfg_.popup_title, msg = popup_render(cfg_.popup_message, host);
    std::string result;
    int shown = 0;
    for (const GuiSession& s : ss) {
        if (known && s.uid != target) continue;
        std::vector<std::string> argv = helper_argv(cfg_, s.desktop, title, msg, host);
        if (argv.empty()) { result += "no popup helper installed (install zenity); "; continue; }
        {
            std::lock_guard<std::mutex> g(mu_);
            reap_locked();
            bool busy = false;
            std::string who;
            for (const Child& c : running_) {
                if (c.uid != s.uid) continue;
                if (force) { kill(-c.pid, SIGKILL); kill(c.pid, SIGKILL); } else { busy = true; who = " (pid " + std::to_string(c.pid) + ")"; }
            }
            if (busy) {
                last_.erase(host);  // nothing was shown: do not burn this host's cooldown, a retry may pop up later
                result += "uid " + std::to_string(s.uid) + " already has a popup open" + who + "; ";
                continue;
            }
        }
        pid_t pid = spawn_as(s.uid, s.env, argv);
        if (pid < 0) { result += "cannot start helper for uid " + std::to_string(s.uid) + "; "; continue; }
        {
            std::lock_guard<std::mutex> g(mu_);
            running_.push_back({pid, s.uid, mono_ms() + uint64_t(cfg_.popup_seconds + 2) * 1000});
        }
        ++shown;
        shown_++;
        LOG_D("popup for %s shown to uid %u via %s", host.c_str(), unsigned(s.uid), argv[0].c_str());
        result += "shown to uid " + std::to_string(s.uid) + " via " + argv[0] + "; ";
    }
    if (result.empty()) result = known ? "no graphical session for the querying user" : "nothing to show";
    (void)shown;
    return result;
}

std::string Popup::helper_name() const {
    if (!cfg_.popup_helper.empty()) return cfg_.popup_helper;
    for (const char* n : {"zenity", "yad", "kdialog", "notify-send"})
        if (!find_exe(n).empty()) return n;
    return "NONE FOUND - install zenity";
}

std::string Popup::describe() {
    if (!cfg_.popup) return "off";
    std::lock_guard<std::mutex> g(mu_);
    return "on, " + std::to_string(cfg_.popup_seconds) + " s, cooldown " + std::to_string(cfg_.popup_cooldown) + " s, helper: " +
           helper_name() + ", shown " + std::to_string(shown_.load()) + (last_result_.empty() ? "" : ", last: " + last_result_);
}

}  // namespace blk
