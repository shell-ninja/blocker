// daemon.cpp - `blocker daemon`: wires everything together and runs the guardian loop.
#include <csignal>
#include <thread>
#include <unistd.h>

#include "control.hpp"
#include "paths.hpp"
#include "protect.hpp"
#include "util.hpp"

namespace blk {

int run_daemon() {
    signal(SIGPIPE, SIG_IGN);  // never die because a client hung up mid-reply
    std::vector<std::string> warnings;
    Config cfg = Config::load(paths::conf(), warnings);
    for (const std::string& w : warnings) LOG_W("%s", w.c_str());
    LOG_I("blocker %s starting (lock mode: %s)", kVersion, lock_mode_name(cfg.lock_mode));

    unlink(paths::disabled_flag().c_str());  // (re)starting means protection is on again

    Engine engine(cfg);
    Lock lock(cfg);
    lock.load();
    RulesMgr mgr(engine, cfg.block_doh);
    mgr.init();

    Popup popup(cfg);
    engine.set_popup(&popup);
    popup.start();

    // Blocked names resolve to loopback where this server answers with a redirect to cfg.redirect_url.
    Redirector redirect(cfg);
    if (cfg.redirect) {
        std::string rerr;
        if (redirect.start(rerr)) {
            engine.set_redirect(&redirect);
            std::string host = redirect_host(cfg.redirect_url);
            // The landing page must stay reachable, including the hosts it loads assets from: exempt its site
            // (host without a leading "www.") and everything below it from blocking.
            if (host.compare(0, 4, "www.") == 0 && host.find('.', 4) != std::string::npos) host = host.substr(4);
            if (!host.empty()) engine.set_exempt({host});
            LOG_I("redirect: blocked sites -> %s", cfg.redirect_url.c_str());
        } else {
            LOG_W("redirect disabled, blocked sites will just fail to load: cannot listen on %s", rerr.c_str());
        }
    }

    Server server(engine, cfg);
    std::string err;
    if (!server.start(err)) { LOG_E("%s", err.c_str()); return 1; }

    Ctx ctx;
    ctx.cfg = cfg;
    ctx.engine = &engine;
    ctx.mgr = &mgr;
    ctx.lock = &lock;
    ctx.popup = &popup;
    ctx.redirect = &redirect;
    ctx.started_ms = mono_ms();
    ControlServer control(ctx);
    if (!control.start(err)) { LOG_E("%s", err.c_str()); return 1; }

    protect::arm(cfg);  // after the sockets are up, so switching resolv.conf never leaves DNS dead

    unsigned processed = 0;
    for (uint64_t tick = 1;; ++tick) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        lock.tick();
        mgr.poll(lock.window_open());
        processed |= mgr.take_processed();
        if (tick % 2 == 0) {
            protect::maintain_fast(cfg, processed);
            processed = 0;
        }
        if (tick % 10 == 0) protect::maintain_slow(cfg);
    }
}

}  // namespace blk
