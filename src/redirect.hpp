// redirect.hpp - the "blocked site" landing redirect.
//
// DNS cannot send a browser to another page, so blocked names are answered with the loopback address and this tiny
// HTTP server (127.0.0.1:80 and, when available, [::1]:80) answers every request with
//     302 Found, Location: <redirect_url>
// The redirect is never cached (302 + Cache-Control: no-store), so changing redirect_url takes effect at once.
// Plain-HTTP requests - and https:// requests a browser falls back from - therefore land on the configured page.
// A browser that insists on https:// for the blocked name still sees a connection error: answering TLS for an
// arbitrary host would need certificate interception, which blocker deliberately does not do.
#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>

#include "config.hpp"

namespace blk {

// The complete HTTP response for one request (exposed for tests). head_only: answer to HEAD, no body.
std::string build_redirect_response(const std::string& url, bool head_only);

class Redirector {
public:
    explicit Redirector(const Config& cfg) : cfg_(cfg) {}
    ~Redirector() { stop(); }
    // Binds the loopback listeners and starts the server thread. Returns false (with err) if the IPv4 listener cannot
    // be bound (port taken by a local web server, ...); the daemon then falls back to plain blocking.
    bool start(std::string& err);
    void stop();
    bool v4() const { return v4_.load(); }  // answer A queries with 127.0.0.1
    bool v6() const { return v6_.load(); }  // answer AAAA queries with ::1
    uint64_t served() const { return served_.load(); }
    std::string describe() const;

private:
    void loop();
    static int listen_on(int family, uint16_t port, std::string& err);

    const Config& cfg_;
    int fd4_ = -1, fd6_ = -1;
    std::atomic<bool> v4_{false}, v6_{false}, stop_{false};
    std::atomic<uint64_t> served_{0}, dropped_{0};
    std::thread th_;
};

}  // namespace blk
