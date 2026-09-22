// ui.cpp - terminal styling, ANSI colors, Unicode box formatting and CLI components
#include "ui.hpp"

#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <algorithm>
#include <sstream>
#include <cstdint>

namespace blk::ui {

bool color_enabled(int fd) {
    static int cached[3] = {-1, -1, -1};
    if (fd >= 0 && fd <= 2 && cached[fd] != -1) {
        return cached[fd] == 1;
    }
    if (!isatty(fd)) {
        if (fd >= 0 && fd <= 2) cached[fd] = 0;
        return false;
    }
    const char* no_color = std::getenv("NO_COLOR");
    if (no_color && no_color[0] != '\0') {
        if (fd >= 0 && fd <= 2) cached[fd] = 0;
        return false;
    }
    const char* term = std::getenv("TERM");
    if (term && std::strcmp(term, "dumb") == 0) {
        if (fd >= 0 && fd <= 2) cached[fd] = 0;
        return false;
    }
    if (fd >= 0 && fd <= 2) cached[fd] = 1;
    return true;
}

#define DEF_ANSI(name, code) \
    const char* name(int fd) { return color_enabled(fd) ? code : ""; }

DEF_ANSI(reset, "\033[0m")
DEF_ANSI(bold, "\033[1m")
DEF_ANSI(dim, "\033[2m")
DEF_ANSI(italic, "\033[3m")
DEF_ANSI(underline, "\033[4m")

DEF_ANSI(red, "\033[31m")
DEF_ANSI(green, "\033[32m")
DEF_ANSI(yellow, "\033[33m")
DEF_ANSI(blue, "\033[34m")
DEF_ANSI(magenta, "\033[35m")
DEF_ANSI(cyan, "\033[36m")
DEF_ANSI(white, "\033[37m")
DEF_ANSI(gray, "\033[90m")

DEF_ANSI(bright_red, "\033[91m")
DEF_ANSI(bright_green, "\033[92m")
DEF_ANSI(bright_yellow, "\033[93m")
DEF_ANSI(bright_blue, "\033[94m")
DEF_ANSI(bright_magenta, "\033[95m")
DEF_ANSI(bright_cyan, "\033[96m")
DEF_ANSI(bright_white, "\033[97m")

DEF_ANSI(bg_red, "\033[41m")
DEF_ANSI(bg_green, "\033[42m")
DEF_ANSI(bg_blue, "\033[44m")
DEF_ANSI(bg_cyan, "\033[46m")
DEF_ANSI(bg_gray, "\033[100m")

#undef DEF_ANSI

std::string strip_ansi(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    bool in_esc = false;
    for (size_t i = 0; i < s.size(); ++i) {
        if (!in_esc) {
            if (s[i] == '\033') {
                in_esc = true;
            } else {
                out.push_back(s[i]);
            }
        } else {
            if ((s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z') || s[i] == '~') {
                in_esc = false;
            }
        }
    }
    return out;
}

// Decode one UTF-8 code point starting at i, advances i to the last byte of the sequence
static uint32_t next_utf8_codepoint(std::string_view s, size_t& i) {
    unsigned char c = static_cast<unsigned char>(s[i]);
    if (c < 0x80) {
        return c;
    }
    if ((c & 0xE0) == 0xC0 && i + 1 < s.size()) {
        uint32_t cp = ((c & 0x1F) << 6) | (static_cast<unsigned char>(s[i + 1]) & 0x3F);
        i += 1;
        return cp;
    }
    if ((c & 0xF0) == 0xE0 && i + 2 < s.size()) {
        uint32_t cp = ((c & 0x0F) << 12) |
                      ((static_cast<unsigned char>(s[i + 1]) & 0x3F) << 6) |
                      (static_cast<unsigned char>(s[i + 2]) & 0x3F);
        i += 2;
        return cp;
    }
    if ((c & 0xF8) == 0xF0 && i + 3 < s.size()) {
        uint32_t cp = ((c & 0x07) << 18) |
                      ((static_cast<unsigned char>(s[i + 1]) & 0x3F) << 12) |
                      ((static_cast<unsigned char>(s[i + 2]) & 0x3F) << 6) |
                      (static_cast<unsigned char>(s[i + 3]) & 0x3F);
        i += 3;
        return cp;
    }
    return c;
}

static int codepoint_width(uint32_t cp) {
    // Control characters / null
    if (cp < 0x20 || (cp >= 0x7F && cp < 0xA0)) return 0;

    // Combining characters / zero-width characters / variation selectors
    if (cp == 0x200B || cp == 0x200C || cp == 0x200D || (cp >= 0xFE00 && cp <= 0xFE0F)) return 0;
    if ((cp >= 0x0300 && cp <= 0x036F) || (cp >= 0x1AB0 && cp <= 0x1AFF) ||
        (cp >= 0x1DC0 && cp <= 0x1DFF) || (cp >= 0x20D0 && cp <= 0x20FF) ||
        (cp >= 0xFE20 && cp <= 0xFE2F)) return 0;

    // Wide characters (East Asian Wide / Fullwidth and Emojis):
    // Standard emoji ranges (2 columns in terminal)
    if (cp >= 0x1F300 && cp <= 0x1FAFF) return 2;
    if (cp >= 0x2600 && cp <= 0x27BF) {
        // Most symbols like ✔ (0x2714), ✖ (0x2716), ⚑ (0x2691) are 1 column in terminal fonts
        return 1;
    }
    // CJK ranges
    if ((cp >= 0x1100 && cp <= 0x115F) ||
        (cp >= 0x2E80 && cp <= 0xA4CF && cp != 0x303F) ||
        (cp >= 0xAC00 && cp <= 0xD7A3) ||
        (cp >= 0xF900 && cp <= 0xFAFF) ||
        (cp >= 0xFE10 && cp <= 0xFE19) ||
        (cp >= 0xFE30 && cp <= 0xFE6F) ||
        (cp >= 0xFF00 && cp <= 0xFF60) ||
        (cp >= 0xFFE0 && cp <= 0xFFE6) ||
        (cp >= 0x20000 && cp <= 0x2FFFD) ||
        (cp >= 0x30000 && cp <= 0x3FFFD)) {
        return 2;
    }

    return 1;
}

// Computes display column width of a UTF-8 string, skipping ANSI escapes
size_t visible_width(std::string_view s) {
    size_t w = 0;
    bool in_esc = false;
    for (size_t i = 0; i < s.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (in_esc) {
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '~') {
                in_esc = false;
            }
            continue;
        }
        if (c == '\033') {
            in_esc = true;
            continue;
        }

        uint32_t cp = next_utf8_codepoint(s, i);
        w += codepoint_width(cp);
    }
    return w;
}

std::string pad_right(const std::string& s, size_t target_width) {
    size_t cur = visible_width(s);
    if (cur >= target_width) return s;
    std::string res = s;
    res.append(target_width - cur, ' ');
    return res;
}

std::string paint(std::string_view text, const char* code, int fd) {
    if (!color_enabled(fd) || !code || code[0] == '\0') {
        return std::string(text);
    }
    return std::string(code) + std::string(text) + reset(fd);
}

std::string bold_paint(std::string_view text, const char* code, int fd) {
    if (!color_enabled(fd)) {
        return std::string(text);
    }
    return std::string(bold(fd)) + (code ? code : "") + std::string(text) + reset(fd);
}

std::string badge_blocked(int fd) {
    if (!color_enabled(fd)) return "[BLOCKED]";
    return std::string(bold(fd)) + bg_red(fd) + bright_white(fd) + " BLOCKED " + reset(fd);
}

std::string badge_allowed(int fd) {
    if (!color_enabled(fd)) return "[ALLOWED]";
    return std::string(bold(fd)) + bg_green(fd) + bright_white(fd) + " ALLOWED " + reset(fd);
}

std::string badge_safesearch(int fd) {
    if (!color_enabled(fd)) return "[SAFESEARCH]";
    return std::string(bold(fd)) + bg_cyan(fd) + bright_white(fd) + " SAFESEARCH " + reset(fd);
}

std::string badge_active(int fd) {
    if (!color_enabled(fd)) return "[ACTIVE]";
    return std::string(bright_green(fd)) + "● " + bold(fd) + "ACTIVE" + reset(fd);
}

std::string badge_inactive(int fd) {
    if (!color_enabled(fd)) return "[INACTIVE]";
    return std::string(bright_red(fd)) + "○ " + bold(fd) + "INACTIVE" + reset(fd);
}

std::string badge_locked(int fd) {
    if (!color_enabled(fd)) return "[LOCKED]";
    return std::string(yellow(fd)) + "🔒 " + bold(fd) + "LOCKED" + reset(fd);
}

std::string badge_unlocked(int fd) {
    if (!color_enabled(fd)) return "[UNLOCKED]";
    return std::string(bright_green(fd)) + "🔓 " + bold(fd) + "UNLOCKED" + reset(fd);
}

std::string checkmark(int fd) {
    return color_enabled(fd) ? std::string(bright_green(fd)) + "✔" + reset(fd) : "✔";
}

std::string crossmark(int fd) {
    return color_enabled(fd) ? std::string(bright_red(fd)) + "✖" + reset(fd) : "✖";
}

std::string bullet(int fd) {
    return color_enabled(fd) ? std::string(bright_cyan(fd)) + "▸" + reset(fd) : "▸";
}

static std::string make_border_line(const char* left, const char* right, size_t width, int fd) {
    std::string s;
    if (color_enabled(fd)) s += gray(fd);
    s += left;
    for (size_t i = 0; i < width - 2; ++i) {
        s += "\xe2\x94\x80";
    }
    s += right;
    if (color_enabled(fd)) s += reset(fd);
    s += "\n";
    return s;
}

static std::string make_content_line(const std::string& line, size_t width, int fd, const char* border_color = nullptr) {
    const char* c_border = border_color ? border_color : gray(fd);
    const char* c_reset = reset(fd);
    std::string s;
    std::istringstream lstream(line);
    std::string subline;
    bool any = false;
    while (std::getline(lstream, subline)) {
        any = true;
        while (!subline.empty() && (subline.back() == '\r' || subline.back() == ' ')) subline.pop_back();
        if (color_enabled(fd)) s += c_border;
        s += "\xe2\x94\x82 ";
        if (color_enabled(fd)) s += c_reset;
        s += subline;
        size_t w = visible_width(subline);
        size_t inner = width - 4;
        if (w < inner) {
            s.append(inner - w, ' ');
        }
        if (color_enabled(fd)) s += c_border;
        s += " \xe2\x94\x82\n";
        if (color_enabled(fd)) s += c_reset;
    }
    if (!any) {
        if (color_enabled(fd)) s += c_border;
        s += "\xe2\x94\x82 ";
        if (color_enabled(fd)) s += c_reset;
        size_t inner = width - 4;
        s.append(inner, ' ');
        if (color_enabled(fd)) s += c_border;
        s += " \xe2\x94\x82\n";
        if (color_enabled(fd)) s += c_reset;
    }
    return s;
}

std::string render_box(const std::string& banner_title,
                       const std::string& subtitle,
                       const std::vector<BoxSection>& sections,
                       const std::string& footer_tip,
                       size_t width,
                       int fd) {
    // Measure maximum content line width
    size_t max_w = 0;
    auto check_w = [&](const std::string& l) {
        std::istringstream ls(l);
        std::string sl;
        while (std::getline(ls, sl)) {
            size_t w = visible_width(sl);
            if (w > max_w) max_w = w;
        }
    };
    if (!banner_title.empty()) check_w("  " + bold_paint(banner_title, bright_white(fd), fd));
    if (!subtitle.empty()) check_w("  " + paint(subtitle, gray(fd), fd));
    for (const auto& sec : sections) {
        check_w(" " + bold_paint(sec.title, bright_yellow(fd), fd));
        for (const auto& item : sec.items) {
            std::string cmd_str = "   " + bold_paint(item.first, bright_cyan(fd), fd);
            size_t cmd_vis = visible_width(cmd_str);
            std::string line = cmd_str;
            if (cmd_vis < 42) {
                line.append(42 - cmd_vis, ' ');
            } else {
                line.append("  ");
            }
            line += paint(item.second, white(fd), fd);
            check_w(line);
        }
        for (const auto& raw : sec.raw_lines) {
            check_w("   " + raw);
        }
    }
    if (!footer_tip.empty()) check_w(" " + footer_tip);

    if (max_w + 4 > width) {
        width = max_w + 4;
    }

    std::string out;
    // Top border: ╭─────╮
    out += make_border_line("\xe2\x95\xad", "\xe2\x95\xae", width, fd);

    // Title banner
    if (!banner_title.empty()) {
        std::string title_line = "  " + bold_paint(banner_title, bright_white(fd), fd);
        out += make_content_line(title_line, width, fd);
    }
    if (!subtitle.empty()) {
        std::string sub_line = "  " + paint(subtitle, gray(fd), fd);
        out += make_content_line(sub_line, width, fd);
    }

    // Sections
    for (size_t s = 0; s < sections.size(); ++s) {
        const auto& sec = sections[s];
        // Divider: ├─────┤
        out += make_border_line("\xe2\x94\x9c", "\xe2\x94\xa4", width, fd);

        // Section Title
        std::string sec_title = " " + bold_paint(sec.title, bright_yellow(fd), fd);
        out += make_content_line(sec_title, width, fd);
        out += make_content_line("", width, fd); // spacer

        // Items
        for (const auto& item : sec.items) {
            std::string cmd_str = "   " + bold_paint(item.first, bright_cyan(fd), fd);
            size_t cmd_vis = visible_width(cmd_str);
            std::string line = cmd_str;
            if (cmd_vis < 42) {
                line.append(42 - cmd_vis, ' ');
            } else {
                line.append("  ");
            }
            line += paint(item.second, white(fd), fd);
            out += make_content_line(line, width, fd);
        }

        // Raw lines if any
        for (const auto& raw : sec.raw_lines) {
            out += make_content_line("   " + raw, width, fd);
        }
    }

    // Optional Footer Tip
    if (!footer_tip.empty()) {
        out += make_border_line("\xe2\x94\x9c", "\xe2\x94\xa4", width, fd);
        out += make_content_line(" " + footer_tip, width, fd);
    }

    // Bottom border: ╰─────╯
    out += make_border_line("\xe2\x95\xb0", "\xe2\x95\xaf", width, fd);

    return out;
}

std::string ascii_banner(int fd) {
    const char* c1 = bright_cyan(fd);
    const char* c2 = cyan(fd);
    const char* c3 = bright_blue(fd);
    const char* cr = reset(fd);

    std::string out;
    out += "\n";
    if (color_enabled(fd)) {
        out += std::string(c1) + "    ____  __           __            \n";
        out += std::string(c1) + "   / __ )/ /___  _____/ /_____  _____\n";
        out += std::string(c2) + "  / __  / / __ \\/ ___/ //_/ _ \\/ ___/\n";
        out += std::string(c2) + " / /_/ / / /_/ / /__/ ,< /  __/ /    \n";
        out += std::string(c3) + "/_____/_/\\____/\\___/_/|_|\\___/_/     \n" + cr;
    } else {
        out += "    ____  __           __            \n";
        out += "   / __ )/ /___  _____/ /_____  _____\n";
        out += "  / __  / / __ \\/ ___/ //_/ _ \\/ ___/\n";
        out += " / /_/ / / /_/ / /__/ ,< /  __/ /    \n";
        out += "/_____/_/\\____/\\___/_/|_|\\___/_/     \n";
    }
    return out;
}

std::string format_help(const char* version, int fd) {
    std::string banner = "blocker " + std::string(version) + "  •  Adult-Content DNS Filter with Tamper Protection";
    std::string subtitle = "High-performance kernel & systemd defended filter with delayed unlocking";

    std::vector<BoxSection> sections;

    // 1. Everyday (root)
    {
        BoxSection s;
        s.title = "Everyday (root):";
        s.items = {
            {"blocker status", "show daemon, rules, lock and protection state"},
            {"blocker add <rule>... | --file F | --defaults", "block more (always allowed)"},
            {"blocker check <hostname>", "would this name be blocked? (shows deciding rule)"},
            {"blocker lint <file> [--whitelist]", "validate a rule file before importing it"},
            {"blocker unallow <entry>...", "remove whitelist entries (tightens filter)"},
        };
        sections.push_back(std::move(s));
    }

    // 2. Loosening
    {
        BoxSection s;
        s.title = "Loosening (needs the password and/or an open unlock window - see 'lock_mode'):";
        s.items = {
            {"blocker unlock-request", "start the delay timer"},
            {"blocker unlock-cancel", "cancel a pending unlock"},
            {"blocker list", "print the hidden block list and whitelist"},
            {"blocker remove <rule>...", "delete rules"},
            {"blocker allow <entry>... | --file F", "add whitelist entries (domain, word, glob)"},
            {"blocker stop", "pause: lift all protections and stop the daemon"},
            {"blocker start", "resume protection after a stop"},
            {"blocker uninstall", "remove blocker and restore DNS settings"},
        };
        sections.push_back(std::move(s));
    }

    // 3. Setup
    {
        BoxSection s;
        s.title = "Setup:";
        s.items = {
            {"blocker install [options]", "configure & activate filter with security model"},
        };
        s.raw_lines = {
            paint("Options:", dim(fd), fd),
            "  " + paint("--mode <password|delay|both>", bright_white(fd), fd) + "   security authorization model",
            "  " + paint("--delay-hours <N>", bright_white(fd), fd) + "              delay hours before window opens (default 24)",
            "  " + paint("--window-minutes <N>", bright_white(fd), fd) + "           window duration in minutes (default 30)",
            "  " + paint("--random-password", bright_white(fd), fd) + "              generate unrecoverable one-time password",
            "  " + paint("--password-stdin", bright_white(fd), fd) + "               read password from stdin",
            "  " + paint("--upstream <ip[,ip]>", bright_white(fd), fd) + "          custom upstream DNS resolvers",
            "  " + paint("--redirect-url <URL>", bright_white(fd), fd) + "           redirect blocked requests to landing page",
            "  " + paint("--no-redirect", bright_white(fd), fd) + "                  disable HTTP landing page redirector",
            "  " + paint("--popup / --no-popup", bright_white(fd), fd) + "           enable / disable desktop alert notifications",
            "  " + paint("--popup-message <TEXT>", bright_white(fd), fd) + "         custom message template for desktop alerts",
            "  " + paint("--no-firewall", bright_white(fd), fd) + "                  skip nftables DNS-bypass defense rules",
        };
        sections.push_back(std::move(s));
    }

    // 4. Internal
    {
        BoxSection s;
        s.title = "Internal (run by systemd):";
        s.items = {
            {"blocker daemon", "core DNS proxy and rule engine (blocker.service)"},
            {"blocker guard", "system watchdog process (blocker-guard.timer)"},
        };
        sections.push_back(std::move(s));
    }

    std::string tip = paint("💡 Quick start: ", bright_yellow(fd), fd) +
                      bold_paint("blocker check example.com", bright_cyan(fd), fd) +
                      paint("   •   Status: ", gray(fd), fd) +
                      bold_paint("blocker status", bright_cyan(fd), fd);

    std::string box = render_box(banner, subtitle, sections, tip, 96, fd);
    return ascii_banner(fd) + box;
}

std::string format_check_verdict(const std::string& host_in, const std::string& verdict_in, bool offline, int fd) {
    std::string host = host_in;
    while (!host.empty() && (host.back() == '\r' || host.back() == '\n' || host.back() == ' ')) host.pop_back();
    std::string verdict = verdict_in;
    while (!verdict.empty() && (verdict.back() == '\r' || verdict.back() == '\n' || verdict.back() == ' ')) verdict.pop_back();

    bool blocked = (verdict.find("BLOCKED") != std::string::npos);
    bool safesearch = (verdict.find("rewritten") != std::string::npos);

    std::string title;
    if (blocked) {
        title = badge_blocked(fd) + "  " + bold_paint(host, bright_white(fd), fd);
    } else if (safesearch) {
        title = badge_safesearch(fd) + "  " + bold_paint(host, bright_white(fd), fd);
    } else {
        title = badge_allowed(fd) + "  " + bold_paint(host, bright_white(fd), fd);
    }

    std::string line_verdict = paint("Verdict    : ", dim(fd), fd) + verdict;

    std::string line_action;
    if (blocked) {
        line_action = paint("Action     : ", dim(fd), fd) + paint("Sinkholed to 0.0.0.0 (A) and :: (AAAA)", bright_red(fd), fd);
    } else if (safesearch) {
        line_action = paint("Action     : ", dim(fd), fd) + paint("Enforcing SafeSearch / Restricted Mode", bright_cyan(fd), fd);
    } else {
        line_action = paint("Action     : ", dim(fd), fd) + paint("Forwarded to upstream DNS resolver", bright_green(fd), fd);
    }

    std::string line_off;
    if (offline) {
        line_off = paint("Notice     : ", dim(fd), fd) + paint("daemon not running; evaluated stored rules", yellow(fd), fd);
    }

    size_t max_w = visible_width(title);
    auto check_w = [&](const std::string& l) {
        if (!l.empty()) {
            size_t w = visible_width(l);
            if (w > max_w) max_w = w;
        }
    };
    check_w(line_verdict);
    check_w(line_action);
    check_w(line_off);

    size_t width = std::max((size_t)78, max_w + 4);

    std::string out;
    out += make_border_line("\xe2\x95\xad", "\xe2\x95\xae", width, fd);
    out += make_content_line(title, width, fd);
    out += make_border_line("\xe2\x94\x9c", "\xe2\x94\xa4", width, fd);
    out += make_content_line(line_verdict, width, fd);
    out += make_content_line(line_action, width, fd);
    if (offline && !line_off.empty()) {
        out += make_content_line(line_off, width, fd);
    }
    out += make_border_line("\xe2\x95\xb0", "\xe2\x95\xaf", width, fd);
    return out;
}

std::string format_lint_report(const std::string& file, size_t block_rules, size_t allow_rules,
                               const std::vector<std::string>& warnings, int fd) {
    bool ok = warnings.empty();

    std::string title = (ok ? checkmark(fd) + " " + bold_paint("RULE LINT PASSED", bright_green(fd), fd)
                            : crossmark(fd) + " " + bold_paint("RULE LINT ISSUES DETECTED", bright_red(fd), fd)) +
                        "  " + paint(file, dim(fd), fd);

    std::string r1 = paint("Block Rules  : ", dim(fd), fd) + bold_paint(std::to_string(block_rules), bright_white(fd), fd);
    std::string r2 = paint("Allow Rules  : ", dim(fd), fd) + bold_paint(std::to_string(allow_rules), bright_white(fd), fd);
    std::string r3 = paint("Invalid Lines: ", dim(fd), fd) + (warnings.empty()
        ? bold_paint("0 invalid line(s)", bright_green(fd), fd)
        : bold_paint(std::to_string(warnings.size()) + " invalid line(s)", bright_red(fd), fd));

    std::vector<std::string> warn_lines;
    for (const auto& w : warnings) {
        warn_lines.push_back("  " + paint("⚠ ", bright_yellow(fd), fd) + w);
    }

    size_t max_w = visible_width(title);
    auto check_w = [&](const std::string& l) {
        size_t w = visible_width(l);
        if (w > max_w) max_w = w;
    };
    check_w(r1);
    check_w(r2);
    check_w(r3);
    for (const auto& wl : warn_lines) check_w(wl);

    size_t width = std::max((size_t)78, max_w + 4);

    std::string out;
    out += make_border_line("\xe2\x95\xad", "\xe2\x95\xae", width, fd);
    out += make_content_line(title, width, fd);
    out += make_border_line("\xe2\x94\x9c", "\xe2\x94\xa4", width, fd);
    out += make_content_line(r1, width, fd);
    out += make_content_line(r2, width, fd);
    out += make_content_line(r3, width, fd);
    if (!warnings.empty()) {
        out += make_border_line("\xe2\x94\x9c", "\xe2\x94\xa4", width, fd);
        out += make_content_line(bold_paint("Warnings:", bright_yellow(fd), fd), width, fd);
        for (const auto& wl : warn_lines) {
            out += make_content_line(wl, width, fd);
        }
    }
    out += make_border_line("\xe2\x95\xb0", "\xe2\x95\xaf", width, fd);
    return out;
}

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
                                   int fd) {
    // Header banner: blocker v1.0.0, up 2h 15m, Status: ACTIVE
    std::string header = bold_paint("blocker " + version, bright_white(fd), fd) +
                         paint("  •  up " + uptime, dim(fd), fd) +
                         "   " + badge_active(fd);

    // Section 1: Network & Resolution
    std::string sec1_title = bold_paint("NETWORK & RESOLUTION", bright_cyan(fd), fd);
    std::string sec1_listen = "  " + paint("listening  : ", dim(fd), fd) + bold_paint(listen, bright_white(fd), fd) +
                              paint("   upstreams: ", dim(fd), fd) + bold_paint(upstreams, bright_white(fd), fd);
    std::string sec1_redirect = "  " + paint("redirect   : ", dim(fd), fd) + redirect_desc;
    std::string sec1_popup = "  " + paint("popup      : ", dim(fd), fd) + popup_desc;

    // Section 2: Rules & Filter Engine
    std::string sec2_title = bold_paint("RULES & TRAFFIC ENGINE", bright_cyan(fd), fd);
    std::string sec2_rules = "  " + paint("rules      : ", dim(fd), fd) + rules_summary;
    std::string sec2_queries = "  " + paint("queries    : ", dim(fd), fd) + queries_summary;

    // Section 3: Lock & Authorization
    std::string sec3_title = bold_paint("SECURITY & ACCESS LOCK", bright_cyan(fd), fd);
    std::string sec3_lock = "  " + paint("lock       : ", dim(fd), fd) + lock_desc;

    // Section 4: Tamper Protection Matrix
    std::string sec4_title = bold_paint("TAMPER PROTECTION MATRIX", bright_cyan(fd), fd);
    std::vector<std::string> prot_lines;
    std::istringstream pstream(protect_report);
    std::string pline;
    while (std::getline(pstream, pline)) {
        while (!pline.empty() && (pline.back() == '\r' || pline.back() == ' ')) pline.pop_back();
        if (pline.empty()) continue;
        if (pline.find("yes") != std::string::npos) {
            prot_lines.push_back("  " + checkmark(fd) + " " + pline);
        } else if (pline.find("NO") != std::string::npos) {
            prot_lines.push_back("  " + crossmark(fd) + " " + paint(pline, bright_red(fd), fd));
        } else {
            prot_lines.push_back("  " + pline);
        }
    }

    size_t max_w = visible_width(header);
    auto check_w = [&](const std::string& l) {
        size_t w = visible_width(l);
        if (w > max_w) max_w = w;
    };
    check_w(sec1_title);
    check_w(sec1_listen);
    check_w(sec1_redirect);
    check_w(sec1_popup);
    check_w(sec2_title);
    check_w(sec2_rules);
    check_w(sec2_queries);
    check_w(sec3_title);
    check_w(sec3_lock);
    check_w(sec4_title);
    for (const auto& pl : prot_lines) check_w(pl);

    size_t width = std::max((size_t)86, max_w + 4);

    std::string out;
    out += make_border_line("\xe2\x95\xad", "\xe2\x95\xae", width, fd);
    out += make_content_line(header, width, fd);
    out += make_border_line("\xe2\x94\x9c", "\xe2\x94\xa4", width, fd);
    out += make_content_line(sec1_title, width, fd);
    out += make_content_line(sec1_listen, width, fd);
    out += make_content_line(sec1_redirect, width, fd);
    out += make_content_line(sec1_popup, width, fd);
    out += make_border_line("\xe2\x94\x9c", "\xe2\x94\xa4", width, fd);
    out += make_content_line(sec2_title, width, fd);
    out += make_content_line(sec2_rules, width, fd);
    out += make_content_line(sec2_queries, width, fd);
    out += make_border_line("\xe2\x94\x9c", "\xe2\x94\xa4", width, fd);
    out += make_content_line(sec3_title, width, fd);
    out += make_content_line(sec3_lock, width, fd);
    out += make_border_line("\xe2\x94\x9c", "\xe2\x94\xa4", width, fd);
    out += make_content_line(sec4_title, width, fd);
    for (const auto& pl : prot_lines) {
        out += make_content_line(pl, width, fd);
    }
    out += make_border_line("\xe2\x95\xb0", "\xe2\x95\xaf", width, fd);
    return out;
}

std::string format_password_card(const std::string& password, int fd) {
    const char* c_border = color_enabled(fd) ? bright_yellow(fd) : "";

    std::string l1 = "  " + bold_paint("🔒 UNLOCK PASSWORD (shown once, cannot be recovered):", bright_yellow(fd), fd);
    std::string l2 = "      " + bold_paint(password, bright_white(fd), fd);
    std::string l3 = "  Give it to an accountability partner or store it somewhere";
    std::string l4 = "  that is genuinely inconvenient to reach.";

    size_t max_w = visible_width(l1);
    auto check_w = [&](const std::string& l) {
        size_t w = visible_width(l);
        if (w > max_w) max_w = w;
    };
    check_w(l2);
    check_w(l3);
    check_w(l4);

    size_t width = std::max((size_t)72, max_w + 4);

    std::string out = "\n";
    out += make_border_line("\xe2\x95\xad", "\xe2\x95\xae", width, fd);
    out += make_content_line(l1, width, fd, c_border);
    out += make_border_line("\xe2\x94\x9c", "\xe2\x94\xa4", width, fd);
    out += make_content_line("", width, fd, c_border);
    out += make_content_line(l2, width, fd, c_border);
    out += make_content_line("", width, fd, c_border);
    out += make_border_line("\xe2\x94\x9c", "\xe2\x94\xa4", width, fd);
    out += make_content_line(l3, width, fd, c_border);
    out += make_content_line(l4, width, fd, c_border);
    out += make_border_line("\xe2\x95\xb0", "\xe2\x95\xaf", width, fd);
    out += "\n";
    return out;
}

std::string format_status_from_raw(const std::string& raw, int fd) {
    std::string version = "1.0.0";
    std::string uptime = "unknown";
    std::string listen = "127.0.0.1:53";
    std::string upstreams;
    std::string rules_summary;
    std::string queries_summary;
    std::string redirect_desc = "off";
    std::string popup_desc = "off";
    std::string lock_desc = "unlocked";
    std::string protect_report;

    std::istringstream stream(raw);
    std::string line;
    bool in_protect = false;

    while (std::getline(stream, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
        if (line.empty()) continue;

        if (in_protect) {
            protect_report += line + "\n";
            continue;
        }

        if (line.rfind("blocker ", 0) == 0) {
            size_t comma = line.find(',');
            if (comma != std::string::npos) {
                version = line.substr(8, comma - 8);
                size_t up_pos = line.find("up ", comma);
                if (up_pos != std::string::npos) {
                    uptime = line.substr(up_pos + 3);
                }
            }
            continue;
        }

        auto extract_val = [&](const std::string& prefix) -> std::string {
            size_t pos = line.find(prefix);
            if (pos == std::string::npos) return "";
            std::string val = line.substr(pos + prefix.size());
            size_t start = val.find_first_not_of(" \t");
            if (start != std::string::npos) val = val.substr(start);
            return val;
        };

        if (line.find("listening  :") != std::string::npos) {
            size_t up_pos = line.find("upstreams:");
            if (up_pos != std::string::npos) {
                std::string lpart = line.substr(0, up_pos);
                size_t lidx = lpart.find("listening  :");
                if (lidx != std::string::npos) {
                    listen = lpart.substr(lidx + 12);
                    size_t s1 = listen.find_first_not_of(" \t");
                    if (s1 != std::string::npos) listen = listen.substr(s1);
                    while (!listen.empty() && (listen.back() == ' ' || listen.back() == '\t')) listen.pop_back();
                }
                upstreams = line.substr(up_pos + 10);
                size_t ustart = upstreams.find_first_not_of(" \t");
                if (ustart != std::string::npos) upstreams = upstreams.substr(ustart);
            } else {
                listen = extract_val("listening  :");
            }
            continue;
        }

        if (line.find("rules      :") != std::string::npos) {
            rules_summary = extract_val("rules      :");
            continue;
        }
        if (line.find("queries    :") != std::string::npos) {
            queries_summary = extract_val("queries    :");
            continue;
        }
        if (line.find("redirect   :") != std::string::npos) {
            redirect_desc = extract_val("redirect   :");
            continue;
        }
        if (line.find("popup      :") != std::string::npos) {
            popup_desc = extract_val("popup      :");
            continue;
        }
        if (line.find("lock       :") != std::string::npos) {
            lock_desc = extract_val("lock       :");
            continue;
        }
        if (line.find("protection :") != std::string::npos) {
            in_protect = true;
            continue;
        }
    }

    if (rules_summary.empty() && queries_summary.empty()) {
        return raw;
    }

    return format_status_dashboard(version, uptime, listen, upstreams, rules_summary,
                                  queries_summary, redirect_desc, popup_desc, lock_desc,
                                  protect_report, fd);
}

}  // namespace blk::ui
