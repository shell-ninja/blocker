#include "control.hpp"

#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>

#include "paths.hpp"
#include "protect.hpp"
#include "util.hpp"

namespace blk {

namespace {

bool send_all(int fd, const std::string& s) {
    size_t off = 0;
    while (off < s.size()) {
        ssize_t w = send(fd, s.data() + off, s.size() - off, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        off += size_t(w);
    }
    return true;
}

Reply fail(const std::string& t) { return Reply{false, t + "\n"}; }
Reply okay(const std::string& t) { return Reply{true, t + "\n"}; }

Reply from_lock(const Lock::Result& r) {
    if (r.ok()) return okay(r.msg);
    if (r.err == Lock::Err::PasswordRequired) return fail("PASSWORD_REQUIRED");
    return fail(r.msg);
}

}  // namespace

std::string ControlServer::status_text() {
    std::string s;
    Stats& st = c_.engine->stats;
    s += std::string("blocker ") + kVersion + ", up " + human_duration((mono_ms() - c_.started_ms) / 1000) + "\n";
    std::string ups;
    for (const Endpoint& e : c_.cfg.upstreams) ups += (ups.empty() ? "" : ", ") + e.text;
    s += "  listening  : " + c_.cfg.listen.text + "   upstreams: " + ups + "\n";
    s += "  rules      : " + c_.mgr->summary() + "\n";
    s += "  queries    : total " + std::to_string(st.total.load()) + ", blocked " + std::to_string(st.blocked.load()) +
         ", cache hits " + std::to_string(st.cached.load()) + ", forwarded " + std::to_string(st.forwarded.load()) +
         ", safesearch " + std::to_string(st.safesearch.load()) + ", upstream failures " + std::to_string(st.failed.load()) + "\n";
    s += "  redirect   : " + (c_.redirect ? c_.redirect->describe() : std::string("off")) + "\n";
    s += "  popup      : " + (c_.popup ? c_.popup->describe() : std::string("off")) + "\n";
    s += "  lock       : " + c_.lock->describe() + "\n";
    s += "  protection :\n" + protect::report(c_.cfg);
    return s;
}

Reply ControlServer::handle(const std::string& req, int& exit_code) {
    size_t nl = req.find('\n');
    std::string header = nl == std::string::npos ? req : req.substr(0, nl);
    std::string body = nl == std::string::npos ? std::string() : req.substr(nl + 1);
    std::vector<std::string> f = split(header, '\t');
    std::string cmd = f[0], pw = f.size() > 1 ? f[1] : "";

    if (cmd == "PING") return okay("pong");
    if (cmd == "STATUS") return okay(status_text());
    if (cmd == "LIST") {
        // The rule list is hidden: seeing it needs the same authorisation as loosening it (see hide_rules).
        if (c_.cfg.hide_rules) {
            Lock::Result a = c_.lock->authorize(pw);
            if (!a.ok()) return from_lock(a);
        }
        return okay("# ---- rules ----\n" + c_.mgr->authorized_text() + "\n# ---- whitelist ----\n" + c_.mgr->whitelist_text());
    }
    if (cmd == "RELOAD") { c_.mgr->poll(c_.lock->window_open(), true); return okay("reloaded"); }

    if (cmd == "CHECK") {
        std::string host = to_lower(trim(body));
        while (!host.empty() && host.back() == '.') host.pop_back();
        if (host.empty()) return fail("usage: check <hostname>");
        Verdict v = c_.engine->rules()->check(host);
        if (v.blocked) return okay("BLOCKED (" + v.reason + ")");
        if (const char* t = safesearch_target(host, c_.cfg.safesearch, c_.cfg.youtube_restrict))
            return okay(std::string("allowed, but rewritten to ") + t + " (SafeSearch/Restricted Mode)");
        return okay(v.reason.empty() ? "allowed" : "allowed (" + v.reason + ")");
    }

    if (cmd == "ADD" || cmd == "REMOVE") {
        std::vector<Rule> rules;
        std::string warnings;
        bool any_allow = false;
        for (const std::string& line : split(body, '\n')) {
            LineResult lr = parse_rule_line(line);
            if (!lr.error.empty()) warnings += "  skipped '" + trim(line) + "': " + lr.error + "\n";
            else if (lr.rule) { rules.push_back(*lr.rule); any_allow |= lr.rule->is_allow(); }
        }
        if (rules.empty()) return fail(warnings.empty() ? "no rules given" : "no valid rules:\n" + warnings);
        if (cmd == "ADD") {
            // Blocking more is always allowed; exempting anything (!allow) loosens the filter and needs authorisation.
            if (any_allow) {
                Lock::Result a = c_.lock->authorize(pw);
                if (!a.ok()) return from_lock(a);
            }
            RulesMgr::Edit e = c_.mgr->add(rules);
            return e.ok ? okay(e.msg + (warnings.empty() ? "" : "\n" + warnings)) : fail(e.msg);
        }
        Lock::Result a = c_.lock->authorize(pw);
        if (!a.ok()) return from_lock(a);
        std::set<std::string> canons;
        for (const Rule& r : rules) canons.insert(r.canon());
        RulesMgr::Edit e = c_.mgr->remove(canons);
        return e.ok ? okay(e.msg + (warnings.empty() ? "" : "\n" + warnings)) : fail(e.msg);
    }

    if (cmd == "ALLOW" || cmd == "UNALLOW") {
        // whitelist: adding entries loosens the filter (authorised); removing them only tightens it.
        std::vector<Rule> rules;
        std::string warnings;
        for (const std::string& line : split(body, '\n')) {
            LineResult lr = parse_rule_line(line);
            if (!lr.error.empty()) warnings += "  skipped '" + trim(line) + "': " + lr.error + "\n";
            else if (lr.rule) rules.push_back(as_allow(*lr.rule));
        }
        if (rules.empty()) return fail(warnings.empty() ? "no entries given" : "no valid entries:\n" + warnings);
        RulesMgr::Edit e;
        if (cmd == "ALLOW") {
            Lock::Result a = c_.lock->authorize(pw);
            if (!a.ok()) return from_lock(a);
            e = c_.mgr->allow(rules);
        } else {
            std::set<std::string> canons;
            for (const Rule& r : rules) canons.insert(r.canon());
            e = c_.mgr->unallow(canons);
        }
        return e.ok ? okay(e.msg + (warnings.empty() ? "" : "\n" + warnings)) : fail(e.msg);
    }

    if (cmd == "UNLOCK_REQUEST") return from_lock(c_.lock->request_unlock(pw));
    if (cmd == "UNLOCK_CANCEL") { c_.lock->cancel_unlock(); return okay("unlock request cancelled"); }

    if (cmd == "STOP" || cmd == "UNINSTALL") {
        Lock::Result a = c_.lock->authorize(pw);
        if (!a.ok()) return from_lock(a);
        bool uninstall = cmd == "UNINSTALL";
        LOG_W("authorised %s requested", uninstall ? "uninstall" : "stop");
        protect::disarm(c_.cfg, uninstall);
        exit_code = 42;  // RestartPreventExitStatus=42 in the unit
        return okay(uninstall ? "blocker uninstalled; DNS settings restored"
                              : "blocker stopped and protections lifted; run 'blocker start' (or reboot) to re-arm");
    }
    return fail("unknown command: " + cmd);
}

void ControlServer::loop() {
    for (;;) {
        int c = accept4(fd_, nullptr, nullptr, SOCK_CLOEXEC);
        if (c < 0) {
            if (errno != EINTR) usleep(100000);
            continue;
        }
        ucred uc{};
        socklen_t ul = sizeof uc;
        if (getsockopt(c, SOL_SOCKET, SO_PEERCRED, &uc, &ul) != 0 || uc.uid != geteuid()) {
            LOG_W("rejected control connection from uid %d", int(uc.uid));
            close(c);
            continue;
        }
        timeval tv{5, 0};
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        std::string req;
        char buf[65536];
        bool complete = false;
        while (req.size() < (8u << 20)) {
            ssize_t r = recv(c, buf, sizeof buf, 0);
            if (r < 0 && errno == EINTR) continue;
            if (r == 0) { complete = true; break; }
            if (r < 0) break;
            req.append(buf, size_t(r));
        }
        if (!complete) { close(c); continue; }
        int exit_code = -1;
        Reply rep = handle(req, exit_code);
        send_all(c, std::string(rep.ok ? "OK\n" : "ERR\n") + rep.text);
        shutdown(c, SHUT_RDWR);
        close(c);
        if (exit_code >= 0) std::_Exit(exit_code);
    }
}

bool ControlServer::start(std::string& err) {
    make_dirs(paths::sock_dir(), 0700);
    std::string path = paths::sock();
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (path.size() >= sizeof addr.sun_path) { err = "socket path too long: " + path; return false; }
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path.c_str());
    unlink(path.c_str());
    fd_ = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd_ < 0) { err = std::string("socket: ") + strerror(errno); return false; }
    if (bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0) { err = "cannot bind " + path + ": " + strerror(errno); return false; }
    chmod(path.c_str(), 0600);
    if (listen(fd_, 16) != 0) { err = std::string("listen: ") + strerror(errno); return false; }
    try {
        std::thread(&ControlServer::loop, this).detach();
    } catch (const std::exception& e) {
        err = e.what();
        return false;
    }
    return true;
}

bool control_call(const std::string& header, const std::string& body, Reply& out, std::string& err, int timeout_s) {
    std::string path = paths::sock();
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (path.size() >= sizeof addr.sun_path) { err = "socket path too long"; return false; }
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path.c_str());
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { err = strerror(errno); return false; }
    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0) {
        err = "cannot reach the blocker daemon (" + std::string(strerror(errno)) + ")";
        close(fd);
        return false;
    }
    timeval tv{timeout_s, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    if (!send_all(fd, header + "\n" + body)) { err = "write failed"; close(fd); return false; }
    shutdown(fd, SHUT_WR);
    std::string resp;
    char buf[65536];
    for (;;) {
        ssize_t r = recv(fd, buf, sizeof buf, 0);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        resp.append(buf, size_t(r));
    }
    close(fd);
    size_t nl = resp.find('\n');
    if (nl == std::string::npos) { err = "empty reply from the daemon"; return false; }
    out.ok = resp.substr(0, nl) == "OK";
    out.text = resp.substr(nl + 1);
    return true;
}

}  // namespace blk
