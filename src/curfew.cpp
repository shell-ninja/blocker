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
    int now_m = lt.tm_hour * 60 + lt.tm_min;
    int start_m = cfg_.curfew_start_hour * 60 + cfg_.curfew_start_min;
    int end_m = cfg_.curfew_end_hour * 60 + cfg_.curfew_end_min;
    if (start_m <= end_m) {
        return now_m >= start_m && now_m < end_m;
    }
    return now_m >= start_m || now_m < end_m;
}

void Curfew::tick(Popup* popup) {
    if (!cfg_.curfew) return;

    time_t now_sec = time(nullptr);
    tm lt{};
    if (!localtime_r(&now_sec, &lt)) return;

    int now_m = lt.tm_hour * 60 + lt.tm_min;
    int start_m = cfg_.curfew_start_hour * 60 + cfg_.curfew_start_min;
    int end_m = cfg_.curfew_end_hour * 60 + cfg_.curfew_end_min;

    bool in_window = (start_m <= end_m)
                         ? (now_m >= start_m && now_m < end_m)
                         : (now_m >= start_m || now_m < end_m);

    if (in_window) {
        if (!shutdown_initiated_) {
            shutdown_initiated_ = true;
            int grace = cfg_.curfew_boot_grace_sec > 0 ? cfg_.curfew_boot_grace_sec : 15;
            poweroff_at_ms_ = mono_ms() + uint64_t(grace) * 1000;
            char time_buf[64];
            snprintf(time_buf, sizeof(time_buf), "%02d:%02d - %02d:%02d",
                     cfg_.curfew_start_hour, cfg_.curfew_start_min,
                     cfg_.curfew_end_hour, cfg_.curfew_end_min);
            LOG_W("curfew: night curfew active (%s). Poweroff in %d seconds.", time_buf, grace);
            if (popup) {
                popup->broadcast_alert(
                    "Blocker: Night Curfew Active",
                    "Night Curfew is active (" + std::string(time_buf) + ").\n"
                    "The PC is locked and will shut down in " + std::to_string(grace) + " seconds.",
                    grace, true);
            }
        }
        if (poweroff_at_ms_ > 0 && mono_ms() >= poweroff_at_ms_) {
            poweroff_at_ms_ = 0;
            trigger_poweroff(popup, "curfew window active");
        }
        return;
    }

    // Outside curfew window: reset shutdown trigger and check countdown warnings
    shutdown_initiated_ = false;
    poweroff_at_ms_ = 0;

    // Calculate minutes until auto-shutdown
    int mins_until = (start_m - now_m + 1440) % 1440;

    // Outside 30-minute pre-shutdown countdown window: reset warning flags
    if (mins_until > 30) {
        warned_30m_ = false;
        warned_15m_ = false;
        warned_5m_ = false;
        warned_1m_ = false;
        return;
    }

    std::string target_time = format_time_hm(cfg_.curfew_start_hour, cfg_.curfew_start_min);

    // Stage 1: 30 minutes remaining (between 16 and 30 minutes remaining)
    if (mins_until <= 30 && mins_until > 15 && !warned_30m_) {
        warned_30m_ = true;
        LOG_I("curfew: sending 30-minute reminder for auto-shutdown at %s", target_time.c_str());
        if (popup) {
            popup->broadcast_alert(
                "Blocker: Bedtime Reminder",
                "Night Curfew begins in " + std::to_string(mins_until) + " minutes (at " + target_time + ").\n"
                "Please start wrapping up your activities.",
                15, false);
        }
    }
    // Stage 2: 15 minutes remaining (between 6 and 15 minutes remaining)
    else if (mins_until <= 15 && mins_until > 5 && !warned_15m_) {
        warned_15m_ = true;
        LOG_I("curfew: sending 15-minute warning for auto-shutdown at %s", target_time.c_str());
        if (popup) {
            popup->broadcast_alert(
                "Blocker: Bedtime Warning",
                "Night Curfew begins in " + std::to_string(mins_until) + " minutes (at " + target_time + ").\n"
                "Please wrap up and close your applications.",
                15, false);
        }
    }
    // Stage 3: 5 minutes remaining (between 2 and 5 minutes remaining)
    else if (mins_until <= 5 && mins_until > 1 && !warned_5m_) {
        warned_5m_ = true;
        LOG_W("curfew: sending 5-minute final warning for auto-shutdown at %s", target_time.c_str());
        if (popup) {
            popup->broadcast_alert(
                "Blocker: FINAL WARNING",
                "FINAL WARNING: PC will automatically shut down in " + std::to_string(mins_until) + " minutes at " + target_time + "!\n"
                "Save all your work and open projects immediately.",
                30, true);
        }
    }
    // Stage 4: 1 minute remaining (urgent final countdown)
    else if (mins_until <= 1 && mins_until > 0 && !warned_1m_) {
        warned_1m_ = true;
        LOG_W("curfew: sending 1-minute shutdown imminent alert for auto-shutdown at %s", target_time.c_str());
        if (popup) {
            popup->broadcast_alert(
                "Blocker: SHUTDOWN IMMINENT",
                "CRITICAL: PC is shutting down in 1 minute (at " + target_time + ")!\n"
                "Save all work and close open files NOW.",
                30, true);
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
