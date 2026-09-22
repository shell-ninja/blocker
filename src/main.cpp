// main.cpp - command line front end: install / uninstall / start / stop / add / remove / status ...
#include <termios.h>
#include <unistd.h>

#include <cstdio>
#include <filesystem>
#include <chrono>
#include <cstring>
#include <iostream>
#include <thread>
#include <sys/stat.h>

#include "../gen/embedded.hpp"
#include "control.hpp"
#include "paths.hpp"
#include "protect.hpp"
#include "ui.hpp"
#include "util.hpp"
#include "vault.hpp"

namespace fs = std::filesystem;

namespace blk {
int run_daemon();
}

using namespace blk;

static void usage() {
    std::fputs(ui::format_help(kVersion).c_str(), stdout);
}

// ---------------------------------------------------------------- helpers
static std::string prompt_password(const char* prompt) {
    bool tty = isatty(STDIN_FILENO);
    std::fprintf(stderr, "%s", prompt);
    std::fflush(stderr);
    termios oldt{};
    bool changed = false;
    if (tty && tcgetattr(STDIN_FILENO, &oldt) == 0) {
        termios t = oldt;
        t.c_lflag &= ~tcflag_t(ECHO);
        changed = tcsetattr(STDIN_FILENO, TCSAFLUSH, &t) == 0;
    }
    std::string s;
    std::getline(std::cin, s);
    if (changed) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldt);
        std::fputc('\n', stderr);
    }
    while (!s.empty() && (s.back() == '\r' || s.back() == '\n')) s.pop_back();
    return s;
}

static bool valid_password(const std::string& p) { return p.find_first_of("\t\n\r") == std::string::npos; }

static int print_reply(const Reply& r) {
    std::fputs(r.text.c_str(), r.ok ? stdout : stderr);
    return r.ok ? 0 : 1;
}

// Sends a command; if the daemon answers PASSWORD_REQUIRED, prompts once and retries.
static int call(const std::string& cmd, const std::string& body, bool may_prompt = true) {
    Reply r;
    std::string err;
    if (!control_call(cmd + "\t", body, r, err)) {
        std::fprintf(stderr, "blocker: %s\n", err.c_str());
        return 1;
    }
    if (!r.ok && may_prompt && starts_with(r.text, "PASSWORD_REQUIRED")) {
        std::string pw = prompt_password("Password: ");
        if (pw.empty() || !valid_password(pw)) { std::fprintf(stderr, "blocker: no password given\n"); return 1; }
        if (!control_call(cmd + "\t" + pw, body, r, err)) {
            std::fprintf(stderr, "blocker: %s\n", err.c_str());
            return 1;
        }
    }
    return print_reply(r);
}

static bool require_root() {
    if (paths::dev() || geteuid() == 0) return true;
    std::fprintf(stderr, "blocker: this command must be run as root (try sudo)\n");
    return false;
}

static std::string random_password() {
    // 32 characters: & 31 gives a perfectly uniform, in-bounds index (2^5 = 32).
    // No 0/O/1/I to avoid visual confusion.
    static const char alphabet[33] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    static_assert(sizeof(alphabet) - 1 == 32, "alphabet must have exactly 32 characters");
    uint8_t b[24];
    random_bytes(b, sizeof b);
    std::string p;
    for (int i = 0; i < 24; ++i) {
        if (i && i % 4 == 0) p.push_back('-');
        p.push_back(alphabet[b[i] & 31]);
    }
    return p;
}

// ---------------------------------------------------------------- guard (watchdog, run by the timer)
static int cmd_guard() {
    if (path_exists(paths::disabled_flag())) return 0;  // authorised pause
    Reply r;
    std::string err;
    if (control_call("PING", "", r, err, 3) && r.ok) return 0;
    LOG_W("watchdog: daemon is not answering");
    protect::ensure_units();  // restore unit files / drop-in defences if someone removed them
    if (protect::sysctl({"is-active", "--quiet", "blocker.service"}) == 0) {
        std::this_thread::sleep_for(std::chrono::seconds(3));
        if (!(control_call("PING", "", r, err, 3) && r.ok)) {
            LOG_W("watchdog: daemon is frozen - killing it so systemd restarts it");
            protect::sysctl({"kill", "--signal=SIGKILL", "blocker.service"});
        }
    } else {
        LOG_W("watchdog: daemon is down - starting it");
        protect::sysctl({"enable", "blocker.service"});
        protect::sysctl({"start", "blocker.service"});
    }
    return 0;
}

// ---------------------------------------------------------------- install
static bool copy_self_to(const std::string& dest) {
    std::error_code ec;
    if (fs::exists(dest, ec) && fs::equivalent("/proc/self/exe", dest, ec)) return true;
    if (path_exists(dest)) protect::set_immutable(dest, false);
    make_dirs(dir_of(dest), 0755);
    std::string tmp = dest + ".new";
    fs::copy_file("/proc/self/exe", tmp, fs::copy_options::overwrite_existing, ec);
    if (ec) { std::fprintf(stderr, "blocker: cannot copy binary: %s\n", ec.message().c_str()); return false; }
    chmod(tmp.c_str(), 0700);  // root only: other users cannot even read the program
    if (rename(tmp.c_str(), dest.c_str()) != 0) { std::fprintf(stderr, "blocker: cannot install %s: %s\n", dest.c_str(), strerror(errno)); return false; }
    return true;
}

static int cmd_install(const std::vector<std::string>& args) {
    if (!require_root()) return 1;
    LockMode mode = LockMode::Both;
    uint64_t delay_h = 24, window_m = 30;
    bool random_pw = false, pw_stdin = false, firewall = true, popup = false, redirect = true;
    bool popup_set = false, popup_msg_set = false, redirect_set = false, redirect_url_set = false;
    std::string popup_message, redirect_url;
    std::string upstream = "1.1.1.3, 1.0.0.3";
    for (size_t i = 0; i < args.size(); ++i) {
        const std::string& a = args[i];
        auto next = [&](std::string& out) { if (i + 1 >= args.size()) return false; out = args[++i]; return true; };
        std::string v;
        if (a == "--mode" && next(v)) { if (!parse_lock_mode(v, mode)) { std::fprintf(stderr, "blocker: --mode must be password, delay or both\n"); return 2; } }
        else if (a == "--delay-hours" && next(v)) { if (!parse_u64(v, delay_h) || delay_h == 0) { std::fprintf(stderr, "blocker: bad --delay-hours\n"); return 2; } }
        else if (a == "--window-minutes" && next(v)) { if (!parse_u64(v, window_m) || window_m == 0) { std::fprintf(stderr, "blocker: bad --window-minutes\n"); return 2; } }
        else if (a == "--upstream" && next(v)) upstream = v;
        else if (a == "--random-password") random_pw = true;
        else if (a == "--password-stdin") pw_stdin = true;
        else if (a == "--no-firewall") firewall = false;
        else if (a == "--no-popup") { popup = false; popup_set = true; }
        else if (a == "--popup") { popup = true; popup_set = true; }
        else if (a == "--no-redirect") { redirect = false; redirect_set = true; }
        else if (a == "--redirect-url" && next(v)) {
            if (!valid_redirect_url(v)) {
                std::fprintf(stderr, "blocker: --redirect-url must be an http:// or https:// URL without spaces or quotes\n");
                return 2;
            }
            redirect_url = v;
            redirect_url_set = true;
        }
        else if (a == "--popup-message" && next(v)) {
            if (v.empty() || v.size() > 600 || v.find('#') != std::string::npos) {
                std::fprintf(stderr, "blocker: --popup-message must be 1..600 characters and must not contain '#'\n");
                return 2;
            }
            for (size_t p; (p = v.find('\n')) != std::string::npos;) v.replace(p, 1, "\\n");  // newline -> the two characters \n
            popup_message = v;
            popup_msg_set = true;
            if (!popup_set) popup = true;  // Passing a custom message implies popup should be enabled
        }
        else { std::fprintf(stderr, "blocker: unknown or incomplete option '%s'\n", a.c_str()); return 2; }
    }
    // validate upstreams early
    for (const std::string& u : split(upstream, ',')) {
        Endpoint e;
        if (!trim(u).empty() && !parse_endpoint(u, 53, e)) { std::fprintf(stderr, "blocker: invalid upstream '%s'\n", u.c_str()); return 2; }
    }

    Reply r;
    std::string err;
    if (control_call("PING", "", r, err, 2) && r.ok) {
        std::fprintf(stderr, "blocker is already installed and running. Use 'blocker stop' (authorised) before reinstalling.\n");
        return 1;
    }

    make_dirs(paths::etc_dir(), 0700);
    make_dirs(paths::state_dir(), 0700);
    make_dirs(paths::vault_dir(), 0700);
    for (const std::string& d : {paths::etc_dir(), paths::state_dir(), paths::vault_dir()}) chmod(d.c_str(), 0700);  // also when they already existed
    for (const std::string& f : {paths::conf(), paths::keywords(), paths::whitelist(), paths::auth(), paths::baseline(), paths::wl_baseline(),
                                 paths::vault_key(), paths::legacy_keywords(), paths::legacy_whitelist(), paths::legacy_baseline(),
                                 paths::legacy_wl_baseline()})
        if (path_exists(f)) protect::set_immutable(f, false);

    if (!path_exists(paths::conf())) {
        if (!write_file_atomic(paths::conf(), default_config_text(mode, delay_h * 3600, window_m * 60, upstream, firewall, popup, popup_message, redirect, redirect_url), 0600)) {
            std::fprintf(stderr, "blocker: cannot write %s\n", paths::conf().c_str());
            return 1;
        }
    } else {
        std::string cur;
        read_file(paths::conf(), cur);
        std::vector<std::string> notes;
        bool upgraded = upgrade_config_text(cur, popup, popup_message, redirect, redirect_url, notes);
        if (popup_set || popup_msg_set) {
            set_config_value(cur, "popup", popup ? "yes" : "no");
            if (popup_msg_set) set_config_value(cur, "popup_message", popup_message);
            notes.push_back(std::string("updated popup settings (popup = ") + (popup ? "yes" : "no") + ")");
            upgraded = true;
        }
        if (redirect_set || redirect_url_set) {
            if (redirect_set) set_config_value(cur, "redirect", redirect ? "yes" : "no");
            if (redirect_url_set) set_config_value(cur, "redirect_url", redirect_url);
            notes.push_back(std::string("updated redirect settings (redirect = ") + (redirect ? "yes" : "no") + ")");
            upgraded = true;
        }
        if (!upgraded) {
            std::printf("keeping existing %s\n", paths::conf().c_str());
        } else {
            if (!write_file_atomic(paths::conf(), cur, 0600)) {
                std::fprintf(stderr, "blocker: cannot update %s\n", paths::conf().c_str());
                return 1;
            }
            std::printf("updated %s\n", paths::conf().c_str());
            for (const std::string& n : notes) std::printf("  config: %s\n", n.c_str());
        }
    }
    chmod(paths::conf().c_str(), 0600);  // settings (lock mode, delays, landing page) are private too
    std::vector<std::string> warn;
    Config cfg = Config::load(paths::conf(), warn);
    {   // the built-in list must be intact (a hand-edited data table would install garbage): refuse otherwise
        ParsedText dp = parse_text(embedded::default_keywords());
        auto drs = RuleSet::build(dp.rules, {});
        if (!dp.warnings.empty() || drs->block_rules() < 100) {
            std::fprintf(stderr, "blocker: the built-in block list is damaged (%zu rules, %zu invalid lines) - rebuild from an untouched copy of the project\n",
                         drs->block_rules(), dp.warnings.size());
            return 1;
        }
    }
    if (!vault::ensure_key(true)) { std::fprintf(stderr, "blocker: cannot create the rule vault\n"); return 1; }
    int migrated = vault::migrate_legacy();  // rule files of an earlier version (plain text in /etc/blocker) move into the vault
    if (migrated) std::printf("moved %d rule file(s) of the previous install into the hidden vault\n", migrated);
    if (!path_exists(paths::keywords())) vault::write(paths::keywords(), embedded::default_keywords(), 0600, false);
    if (!path_exists(paths::whitelist())) vault::write(paths::whitelist(), embedded::DEFAULT_WHITELIST, 0600, false);

    std::string generated;
    if (cfg.lock_mode != LockMode::Delay && !path_exists(paths::auth())) {
        std::string pw;
        if (random_pw) {
            pw = random_password();
            generated = pw;
        } else if (pw_stdin) {
            std::getline(std::cin, pw);
            while (!pw.empty() && (pw.back() == '\r' || pw.back() == '\n')) pw.pop_back();
        } else {
            pw = prompt_password("Choose an unlock password (min 8 chars): ");
            std::string again = prompt_password("Repeat password: ");
            if (pw != again) { std::fprintf(stderr, "blocker: passwords do not match\n"); return 1; }
        }
        if (pw.size() < 8 || !valid_password(pw)) {
            std::fprintf(stderr, "blocker: password must be at least 8 characters (no tabs/newlines)\n");
            return 1;
        }
        std::fprintf(stderr, "hashing password (PBKDF2-HMAC-SHA256, %u rounds)...\n", cfg.kdf_iterations);
        AuthRecord rec = AuthRecord::create(pw, cfg.kdf_iterations);
        if (!write_file_atomic(paths::auth(), rec.serialize(), 0600)) { std::fprintf(stderr, "blocker: cannot write %s\n", paths::auth().c_str()); return 1; }
        if (!generated.empty()) {  // show it NOW: a later failure (e.g. systemctl) must never lose it
            std::fputs(ui::format_password_card(generated).c_str(), stdout);
            std::fflush(stdout);
        }
    }

    if (!paths::dev()) {
        if (!copy_self_to(paths::bin())) return 1;
        for (const auto& u : {std::pair<const char*, const char*>{"blocker.service", embedded::SERVICE},
                              {"blocker-guard.service", embedded::GUARD_SERVICE}, {"blocker-guard.timer", embedded::GUARD_TIMER}}) {
            std::string p = paths::unit_dir() + "/" + u.first;
            if (path_exists(p)) protect::set_immutable(p, false);
            if (!write_file_atomic(p, u.second, 0644)) { std::fprintf(stderr, "blocker: cannot write %s\n", p.c_str()); return 1; }
        }
        unlink(paths::disabled_flag().c_str());
        if (run_cmd({"systemctl", "daemon-reload"}) != 0 || run_cmd({"systemctl", "enable", "--now", "blocker.service"}) != 0 ||
            run_cmd({"systemctl", "enable", "--now", "blocker-guard.timer"}) != 0) {
            std::fprintf(stderr, "blocker: systemctl failed - is this a systemd system? Check 'journalctl -u blocker'.\n");
            return 1;
        }
        bool up = false;
        for (int i = 0; i < 20 && !up; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            up = control_call("PING", "", r, err, 2) && r.ok;
        }
        if (!up) { std::fprintf(stderr, "blocker: the daemon did not come up; see 'journalctl -u blocker -n 50'\n"); return 1; }
        std::this_thread::sleep_for(std::chrono::seconds(3));  // let the first protection pass finish
        control_call("STATUS", "", r, err, 10);
        std::fputs(ui::format_status_from_raw(r.text).c_str(), stdout);
    } else {
        std::printf("dev root: files written under %s; not starting systemd units\n", paths::root().c_str());
    }
    std::printf("\n%s Installed. lock mode: %s. Try:  %s   |   %s\n",
                ui::checkmark().c_str(),
                lock_mode_name(cfg.lock_mode),
                ui::bold_paint("blocker check example.com", ui::bright_cyan()).c_str(),
                ui::bold_paint("blocker status", ui::bright_cyan()).c_str());
    return 0;
}

// ---------------------------------------------------------------- other commands
static int cmd_start() {
    if (!require_root()) return 1;
    unlink(paths::disabled_flag().c_str());
    if (protect::sysctl({"start", "blocker.service"}) != 0 && !paths::dev()) {
        std::fprintf(stderr, "blocker: 'systemctl start blocker' failed - see 'journalctl -u blocker'\n");
        return 1;
    }
    std::printf("blocker starting; protections re-arm within a few seconds\n");
    return 0;
}

static int cmd_uninstall() {
    Reply r;
    std::string err;
    if (control_call("PING", "", r, err, 2) && r.ok) return call("UNINSTALL", "");
    if (path_exists(paths::disabled_flag())) {  // daemon was stopped with authorisation: nothing left to gate
        if (!require_root()) return 1;
        std::vector<std::string> w;
        protect::disarm(Config::load(paths::conf(), w), true);
        std::printf("blocker removed\n");
        return 0;
    }
    std::fprintf(stderr, "blocker: the daemon is not answering. Start it ('systemctl start blocker') and retry, so the lock can be checked.\n");
    return 1;
}

static int cmd_add_remove(const std::string& cmd, const std::vector<std::string>& args) {
    std::string body;
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--file" && i + 1 < args.size()) {
            std::string content;
            if (!read_file(args[i + 1], content)) { std::fprintf(stderr, "blocker: cannot read %s\n", args[i + 1].c_str()); return 1; }
            body += content + "\n";
            ++i;
        } else if (args[i] == "--defaults" && cmd == "ADD") {  // the list built into this binary (used by upgrades)
            body += embedded::default_keywords() + "\n";
        } else {
            body += args[i] + "\n";
        }
    }
    if (body.empty()) { std::fprintf(stderr, "usage: blocker %s <rule>... | --file <path>\n", to_lower(cmd).c_str()); return 2; }
    return call(cmd, body);
}

// blocker lint <file> [--whitelist]: validates a rule file (e.g. a list you want to import) without touching anything.
static int cmd_lint(const std::vector<std::string>& args) {
    if (args.empty()) { std::fprintf(stderr, "usage: blocker lint <file> [--whitelist]\n"); return 2; }
    std::string text;
    if (!read_file(args[0], text)) { std::fprintf(stderr, "blocker: cannot read %s\n", args[0].c_str()); return 1; }
    const bool wl = args.size() > 1 && args[1] == "--whitelist";
    ParsedText p = parse_text(text, wl, args[0].c_str());
    auto rs = RuleSet::build(p.rules, {});
    std::fputs(ui::format_lint_report(args[0], rs->block_rules(), rs->allow_rules(), p.warnings).c_str(), stdout);
    return p.warnings.empty() ? 0 : 1;
}

static int cmd_check(const std::string& host) {
    Reply r;
    std::string err;
    if (control_call("CHECK\t", host, r, err, 5)) {
        if (!r.ok) return print_reply(r);
        std::fputs(ui::format_check_verdict(host, trim(r.text), false).c_str(), stdout);
        return 0;
    }
    // daemon down: evaluate the rule file offline
    std::string text;
    vault::ensure_key(false);
    vault::Kind kk = vault::read(paths::keywords(), text);
    if (kk != vault::Kind::Decoded && kk != vault::Kind::Plain) { std::fprintf(stderr, "blocker: cannot read the rules (%s)\n", err.c_str()); return 1; }
    std::string wl;
    vault::read(paths::whitelist(), wl);
    std::vector<Rule> rules = parse_text(text).rules, wrules = parse_text(wl, true, "whitelist").rules;
    rules.insert(rules.end(), wrules.begin(), wrules.end());
    auto rs = RuleSet::build(rules, builtin_bypass_domains());
    Verdict v = rs->check(to_lower(trim(host)));
    std::string vtext = v.blocked ? ("BLOCKED (" + v.reason + ")") : (v.reason.empty() ? "allowed" : ("allowed (" + v.reason + ")"));
    std::fputs(ui::format_check_verdict(host, vtext, true).c_str(), stdout);
    return 0;
}

static int cmd_status() {
    Reply r;
    std::string err;
    if (!control_call("STATUS\t", "", r, err)) {
        std::fprintf(stderr, "blocker: %s\n", err.c_str());
        return 1;
    }
    if (!r.ok) return print_reply(r);
    std::fputs(ui::format_status_from_raw(r.text).c_str(), stdout);
    return 0;
}

int main(int argc, char** argv) {
    std::vector<std::string> args(argv + 1, argv + argc);
    if (args.empty() || args[0] == "help" || args[0] == "--help" || args[0] == "-h") { usage(); return args.empty() ? 2 : 0; }
    std::string cmd = args[0];
    args.erase(args.begin());
    if (cmd == "version" || cmd == "--version") {
        std::fputs(ui::ascii_banner().c_str(), stdout);
        std::printf("blocker %s (%s)\n\n", kVersion, ui::paint("adult-content DNS filter with tamper protection", ui::dim()).c_str());
        return 0;
    }
    if (cmd == "daemon") return run_daemon();
    if (cmd == "guard") return cmd_guard();
    if (cmd == "install") return cmd_install(args);
    if (cmd == "uninstall") return cmd_uninstall();
    if (cmd == "start") return cmd_start();
    if (cmd == "stop") return call("STOP", "");
    if (cmd == "status") return cmd_status();
    if (cmd == "list") return call("LIST", "", true);
    if (cmd == "unlock-request") return call("UNLOCK_REQUEST", "");
    if (cmd == "unlock-cancel") return call("UNLOCK_CANCEL", "", false);
    if (cmd == "add") return cmd_add_remove("ADD", args);
    if (cmd == "remove") return cmd_add_remove("REMOVE", args);
    if (cmd == "allow") return cmd_add_remove("ALLOW", args);
    if (cmd == "unallow") return cmd_add_remove("UNALLOW", args);
    if (cmd == "lint") return cmd_lint(args);
    if (cmd == "check") { if (args.size() != 1) { std::fprintf(stderr, "usage: blocker check <hostname>\n"); return 2; } return cmd_check(args[0]); }
    std::fprintf(stderr, "blocker: unknown command '%s' (try 'blocker help')\n", cmd.c_str());
    return 2;
}
