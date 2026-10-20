// curfew.cpp - Night Curfew enforcement & automatic shutdown guardian.
#include "curfew.hpp"

#include <ctime>
#include <unistd.h>

#include "util.hpp"

namespace blk {

Curfew::Curfew(const Config& cfg) : cfg_(cfg) {}

bool Curfew::in_curfew_window() const {
    if (!cfg_.curfew) return false;
    time_t now_sec = time(nullptr);
    tm lt{};
    if (!localtime_r(&now_sec, &lt)) return false;
    int hour = lt.tm_hour;
    if (cfg_.curfew_start_hour <= cfg_.curfew_end_hour) {
        return hour >= cfg_.curfew_start_hour && hour < cfg_.curfew_end_hour;
    }
    return hour >= cfg_.curfew_start_hour || hour < cfg_.curfew_end_hour;
}

void Curfew::tick(Popup* popup) {
    if (!cfg_.curfew) return;

    time_t now_sec = time(nullptr);
    tm lt{};
    if (!localtime_r(&now_sec, &lt)) return;

    if (lt.tm_yday != last_yday_) {
        last_yday_ = lt.tm_yday;
        warned_2330_ = false;
        warned_2345_ = false;
        warned_2355_ = false;
        shutdown_initiated_ = false;
        poweroff_at_ms_ = 0;
    }

    int hour = lt.tm_hour;
    int min = lt.tm_min;

    bool in_window = (cfg_.curfew_start_hour <= cfg_.curfew_end_hour)
                         ? (hour >= cfg_.curfew_start_hour && hour < cfg_.curfew_end_hour)
                         : (hour >= cfg_.curfew_start_hour || hour < cfg_.curfew_end_hour);

    if (in_window) {
        if (!shutdown_initiated_) {
            shutdown_initiated_ = true;
            int grace = cfg_.curfew_boot_grace_sec > 0 ? cfg_.curfew_boot_grace_sec : 15;
            poweroff_at_ms_ = mono_ms() + uint64_t(grace) * 1000;
            LOG_W("curfew: night curfew active (12 AM - 3 AM). Poweroff in %d seconds.", grace);
            if (popup) {
                popup->broadcast_alert(
                    "Blocker: Night Curfew Active",
                    "Night Curfew is active (12:00 AM - 03:00 AM).\n"
                    "The PC is locked and will shut down in " + std::to_string(grace) + " seconds.",
                    grace, true);
            }
        }
        if (poweroff_at_ms_ > 0 && mono_ms() >= poweroff_at_ms_) {
            trigger_poweroff(popup, "curfew window active");
        }
        return;
    }

    // Outside curfew window: reset shutdown trigger and check evening warnings
    shutdown_initiated_ = false;
    poweroff_at_ms_ = 0;

    // Evening countdown warnings leading up to 12:00 AM (midnight)
    if (hour == 23) {
        if (min >= 30 && min < 45 && !warned_2330_) {
            warned_2330_ = true;
            LOG_I("curfew: sending 11:30 PM reminder");
            if (popup) {
                popup->broadcast_alert(
                    "Blocker: Bedtime Reminder",
                    "Night Curfew begins at 12:00 AM (30 minutes remaining).\nPlease start wrapping up your activities.",
                    15, false);
            }
        } else if (min >= 45 && min < 55 && !warned_2345_) {
            warned_2345_ = true;
            LOG_I("curfew: sending 11:45 PM warning");
            if (popup) {
                popup->broadcast_alert(
                    "Blocker: Bedtime Warning",
                    "Night Curfew begins at 12:00 AM (15 minutes remaining).\nPlease wrap up and close your applications.",
                    15, false);
            }
        } else if (min >= 55 && !warned_2355_) {
            warned_2355_ = true;
            LOG_W("curfew: sending 11:55 PM final warning");
            if (popup) {
                popup->broadcast_alert(
                    "Blocker: FINAL WARNING",
                    "FINAL WARNING: PC will automatically shut down in 5 minutes at 12:00 AM!\n"
                    "Save all your work and open projects immediately.",
                    30, true);
            }
        }
    }
}

void Curfew::trigger_poweroff(Popup* popup, const std::string& reason) {
    LOG_W("curfew: initiating system poweroff (%s)", reason.c_str());
    if (popup) {
        popup->broadcast_alert("Blocker: Night Curfew", "Night Curfew: Shutting down PC now...", 5, true);
    }
    sync();
    // Primary: systemd poweroff
    run_cmd({"systemctl", "poweroff"});
    // Secondary fallbacks if systemd poweroff was delayed or blocked
    run_cmd({"shutdown", "-h", "now"});
    run_cmd({"poweroff"});
}

}  // namespace blk
