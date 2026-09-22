// ui.hpp - terminal styling, ANSI colors, Unicode box formatting and CLI components
#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace blk::ui {

// Terminal capabilities
bool color_enabled(int fd = 1);

// ANSI Codes (returns empty string if color_enabled(fd) is false)
const char* reset(int fd = 1);
const char* bold(int fd = 1);
const char* dim(int fd = 1);
const char* italic(int fd = 1);
const char* underline(int fd = 1);

const char* red(int fd = 1);
const char* green(int fd = 1);
const char* yellow(int fd = 1);
const char* blue(int fd = 1);
const char* magenta(int fd = 1);
const char* cyan(int fd = 1);
const char* white(int fd = 1);
const char* gray(int fd = 1);

const char* bright_red(int fd = 1);
const char* bright_green(int fd = 1);
const char* bright_yellow(int fd = 1);
const char* bright_blue(int fd = 1);
const char* bright_magenta(int fd = 1);
const char* bright_cyan(int fd = 1);
const char* bright_white(int fd = 1);

const char* bg_red(int fd = 1);
const char* bg_green(int fd = 1);
const char* bg_blue(int fd = 1);
const char* bg_cyan(int fd = 1);
const char* bg_gray(int fd = 1);

// String helpers that measure display width excluding ANSI escape codes
size_t visible_width(std::string_view s);
std::string pad_right(const std::string& s, size_t target_width);
std::string strip_ansi(std::string_view s);

// Stylers
std::string paint(std::string_view text, const char* code, int fd = 1);
std::string bold_paint(std::string_view text, const char* code, int fd = 1);

// Status Badges & Pills
std::string badge_blocked(int fd = 1);
std::string badge_allowed(int fd = 1);
std::string badge_safesearch(int fd = 1);
std::string badge_active(int fd = 1);
std::string badge_inactive(int fd = 1);
std::string badge_locked(int fd = 1);
std::string badge_unlocked(int fd = 1);
std::string checkmark(int fd = 1);
std::string crossmark(int fd = 1);
std::string bullet(int fd = 1);

// Structured Box Formatting
struct BoxSection {
    std::string title;
    std::vector<std::pair<std::string, std::string>> items; // command/key, description/value
    std::vector<std::string> raw_lines;
};

std::string render_box(const std::string& banner_title,
                       const std::string& subtitle,
                       const std::vector<BoxSection>& sections,
                       const std::string& footer_tip = "",
                       size_t width = 86,
                       int fd = 1);

// High-level CLI formatting helpers
std::string ascii_banner(int fd = 1);
std::string format_help(const char* version, int fd = 1);
std::string format_check_verdict(const std::string& host, const std::string& verdict, bool offline = false, int fd = 1);
std::string format_lint_report(const std::string& file, size_t block_rules, size_t allow_rules,
                               const std::vector<std::string>& warnings, int fd = 1);
std::string format_status_dashboard(const std::string& version,
                                   const std::string& uptime,
                                   const std::string& listen,
                                   const std::string& upstreams,
                                   const std::string& rules_summary,
                                   const std::string& queries_summary,
                                   const std::string& redirect_desc,
                                   const std::string& popup_desc,
                                   const std::string& lock_desc,
                                   const std::string& protect_report,
                                   int fd = 1);
std::string format_password_card(const std::string& password, int fd = 1);
std::string format_status_from_raw(const std::string& raw, int fd = 1);

}  // namespace blk::ui
