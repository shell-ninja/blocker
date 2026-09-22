// control.hpp - root-only Unix-socket control channel between the CLI and the daemon.
//
// Wire format: request  = "<COMMAND>\t<password>\n<body...>"  (client then shuts down its write side)
//              response = "OK\n<text>" or "ERR\n<text>"
#pragma once

#include <string>

#include "config.hpp"
#include "engine.hpp"
#include "lock.hpp"
#include "popup.hpp"
#include "redirect.hpp"
#include "rulesmgr.hpp"

namespace blk {

constexpr const char* kVersion = "1.0.0";

struct Ctx {
    Config cfg;
    Engine* engine = nullptr;
    RulesMgr* mgr = nullptr;
    Lock* lock = nullptr;
    Popup* popup = nullptr;
    Redirector* redirect = nullptr;
    uint64_t started_ms = 0;
};

struct Reply {
    bool ok = false;
    std::string text;
};

class ControlServer {
public:
    explicit ControlServer(Ctx& c) : c_(c) {}
    bool start(std::string& err);  // creates the socket and spawns the serving thread

private:
    void loop();
    Reply handle(const std::string& req, int& exit_code);
    std::string status_text();
    Ctx& c_;
    int fd_ = -1;
};

// Client side. Returns false (and fills err) if the daemon cannot be reached.
bool control_call(const std::string& header, const std::string& body, Reply& out, std::string& err, int timeout_s = 120);

}  // namespace blk
