#include "redirect.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include "util.hpp"

namespace blk {

namespace {

constexpr size_t kMaxConns = 256;
constexpr size_t kMaxRequest = 8192;
constexpr uint64_t kReadMs = 3000, kDrainMs = 1000;

std::string html_attr(const std::string& s) {
    std::string o;
    for (char c : s) {
        if (c == '&') o += "&amp;";
        else if (c == '"') o += "&quot;";
        else if (c == '<') o += "&lt;";
        else if (c == '>') o += "&gt;";
        else o.push_back(c);
    }
    return o;
}

enum class St { Read, Write, Drain };
struct Conn {
    int fd = -1;
    St st = St::Read;
    std::string in, out;
    size_t off = 0;
    uint64_t deadline = 0;
};

bool looks_like_http(const std::string& in) {  // request lines start with a method: letters
    return !in.empty() && ((in[0] >= 'A' && in[0] <= 'Z') || (in[0] >= 'a' && in[0] <= 'z'));
}

bool request_complete(const std::string& in) {
    return in.find("\r\n\r\n") != std::string::npos || in.find("\n\n") != std::string::npos || in.size() >= kMaxRequest;
}

}  // namespace

std::string build_redirect_response(const std::string& url, bool head_only) {
    std::string esc = html_attr(url);
    std::string body = "<!doctype html><meta charset=\"utf-8\"><meta http-equiv=\"refresh\" content=\"0;url=" + esc +
                       "\"><title>Redirecting</title><a href=\"" + esc + "\">Continue</a>\n";
    std::string r = "HTTP/1.1 302 Found\r\n";
    r += "Location: " + url + "\r\n";
    r += "Cache-Control: no-store, max-age=0\r\n";
    r += "Content-Type: text/html; charset=utf-8\r\n";
    r += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    r += "Connection: close\r\n\r\n";
    if (!head_only) r += body;
    return r;
}

int Redirector::listen_on(int family, uint16_t port, std::string& err) {
    int fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) { err = std::string("socket: ") + strerror(errno); return -1; }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    int rc;
    if (family == AF_INET) {
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = htons(port);
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        rc = bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof a);
    } else {
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
        sockaddr_in6 a{};
        a.sin6_family = AF_INET6;
        a.sin6_port = htons(port);
        a.sin6_addr = in6addr_loopback;
        rc = bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof a);
    }
    if (rc != 0 || listen(fd, 64) != 0) {
        err = std::string(family == AF_INET ? "127.0.0.1:" : "[::1]:") + std::to_string(port) + ": " + strerror(errno);
        close(fd);
        return -1;
    }
    return fd;
}

bool Redirector::start(std::string& err) {
    if (!cfg_.redirect || th_.joinable()) return true;
    fd4_ = listen_on(AF_INET, static_cast<uint16_t>(cfg_.redirect_port), err);
    if (fd4_ < 0) return false;
    std::string e6;
    fd6_ = listen_on(AF_INET6, static_cast<uint16_t>(cfg_.redirect_port), e6);
    if (fd6_ < 0) LOG_I("redirect: no IPv6 listener (%s); AAAA answers will be empty", e6.c_str());
    v4_ = true;
    v6_ = fd6_ >= 0;
    stop_ = false;
    th_ = std::thread([this] { loop(); });
    return true;
}

void Redirector::stop() {
    stop_ = true;
    if (th_.joinable()) th_.join();
    for (int* fd : {&fd4_, &fd6_})
        if (*fd >= 0) { close(*fd); *fd = -1; }
    v4_ = v6_ = false;
}

std::string Redirector::describe() const {
    if (!cfg_.redirect) return "off";
    if (!v4_) return "inactive (could not listen on 127.0.0.1:" + std::to_string(cfg_.redirect_port) + "; blocked sites just fail to load)";
    return "-> " + cfg_.redirect_url + " (" + std::to_string(served_.load()) + " served)";
}

void Redirector::loop() {
    const std::string get_resp = build_redirect_response(cfg_.redirect_url, false);
    const std::string head_resp = build_redirect_response(cfg_.redirect_url, true);
    std::vector<Conn> conns;

    auto finish = [&](Conn& c) { if (c.fd >= 0) { close(c.fd); c.fd = -1; } };
    auto respond = [&](Conn& c) {
        bool head = c.in.compare(0, 5, "HEAD ") == 0 || c.in.compare(0, 5, "head ") == 0;
        c.out = head ? head_resp : get_resp;
        c.off = 0;
        c.st = St::Write;
    };
    auto do_write = [&](Conn& c) {
        while (c.off < c.out.size()) {
            ssize_t n = send(c.fd, c.out.data() + c.off, c.out.size() - c.off, MSG_NOSIGNAL);
            if (n > 0) { c.off += size_t(n); continue; }
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;  // wait for POLLOUT
            finish(c);
            return;
        }
        ++served_;
        // Answer sent. Half-close and drain what the client is still sending (e.g. a POST body) so that closing
        // does not turn into a TCP reset that could wipe the response before the browser has read it.
        shutdown(c.fd, SHUT_WR);
        c.st = St::Drain;
        c.deadline = mono_ms() + kDrainMs;
    };

    while (!stop_) {
        std::vector<pollfd> pf;
        for (int fd : {fd4_, fd6_})
            if (fd >= 0) pf.push_back({fd, POLLIN, 0});
        const size_t nl = pf.size(), nold = conns.size();
        for (const Conn& c : conns) pf.push_back({c.fd, short(c.st == St::Write ? POLLOUT : POLLIN), 0});
        poll(pf.data(), pf.size(), 200);
        const uint64_t now = mono_ms();

        for (size_t j = 0; j < nold; ++j) {
            Conn& c = conns[j];
            short re = pf[nl + j].revents;
            if (c.st == St::Read && (re & (POLLIN | POLLHUP | POLLERR))) {
                char buf[2048];
                ssize_t n = recv(c.fd, buf, sizeof buf, 0);
                if (n > 0) {
                    c.in.append(buf, size_t(n));
                    if (!looks_like_http(c.in)) { finish(c); continue; }  // TLS hello, garbage: say nothing
                    if (request_complete(c.in)) { respond(c); do_write(c); }
                } else if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
                    finish(c);
                }
            } else if (c.st == St::Write && (re & (POLLOUT | POLLERR | POLLHUP))) {
                do_write(c);
            } else if (c.st == St::Drain && (re & (POLLIN | POLLHUP | POLLERR))) {
                char buf[2048];
                ssize_t n = recv(c.fd, buf, sizeof buf, 0);
                if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) finish(c);
            }
            if (c.fd >= 0 && now > c.deadline) {
                if (c.st == St::Read && looks_like_http(c.in)) { respond(c); c.deadline = now + kReadMs; do_write(c); }
                else finish(c);
            }
        }
        for (size_t i = 0; i < nl; ++i) {
            if (!(pf[i].revents & POLLIN)) continue;
            for (;;) {
                int cfd = accept4(pf[i].fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
                if (cfd < 0) break;
                if (conns.size() >= kMaxConns) { close(cfd); ++dropped_; continue; }
                Conn c;
                c.fd = cfd;
                c.deadline = now + kReadMs;
                conns.push_back(std::move(c));
            }
        }
        std::vector<Conn> keep;
        keep.reserve(conns.size());
        for (Conn& c : conns)
            if (c.fd >= 0) keep.push_back(std::move(c));
        conns.swap(keep);
    }
    for (Conn& c : conns) finish(c);
}

}  // namespace blk
