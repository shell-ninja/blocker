// curfew.hpp - Night Curfew enforcement & automatic shutdown guardian.
//
// Automatically enforces a nightly curfew between 12:00 AM and 03:00 AM.
// Sends staged warnings leading up to midnight (11:30 PM, 11:45 PM, 11:55 PM final warning),
// shuts down the PC at 12:00 AM, and if the PC is powered on during the curfew window (12 AM - 3 AM),
// alerts the user and shuts down immediately.
#pragma once

#include <cstdint>
#include <string>

#include "config.hpp"
#include "popup.hpp"

namespace blk {

class Curfew {
public:
    explicit Curfew(const Config& cfg);

    // Called once per second by the guardian loop in run_daemon().
    void tick(Popup* popup);

    // Returns true if the current time falls inside the curfew window.
    bool in_curfew_window() const;

private:
    void trigger_poweroff(Popup* popup, const std::string& reason);

    Config cfg_;
    bool warned_30m_ = false;
    bool warned_15m_ = false;
    bool warned_5m_ = false;
    bool warned_1m_ = false;
    uint64_t last_retry_mono_ms_ = 0;
    bool shutdown_initiated_ = false;
    uint64_t poweroff_at_ms_ = 0;
};

}  // namespace blk
