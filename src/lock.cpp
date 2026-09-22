#include "lock.hpp"

#include <algorithm>

#include "paths.hpp"
#include "protect.hpp"
#include "sha256.hpp"
#include "util.hpp"

namespace blk {

// ---------------------------------------------------------------- AuthRecord
AuthRecord AuthRecord::create(const std::string& password, uint32_t iterations) {
    AuthRecord r;
    r.iterations = iterations;
    r.salt.resize(16);
    random_bytes(r.salt.data(), r.salt.size());
    r.hash.resize(32);
    pbkdf2_sha256(password, r.salt.data(), r.salt.size(), iterations, r.hash.data(), r.hash.size());
    return r;
}

bool AuthRecord::parse(const std::string& text, AuthRecord& out) {
    std::vector<std::string> f = split(trim(text), '$');
    uint64_t it = 0;
    if (f.size() != 4 || f[0] != "pbkdf2-sha256" || !parse_u64(f[1], it) || it < 1000 || it > 100000000) return false;
    AuthRecord r;
    r.iterations = uint32_t(it);
    if (!hex_decode(f[2], r.salt) || !hex_decode(f[3], r.hash) || r.salt.empty() || r.hash.size() != 32) return false;
    out = r;
    return true;
}

std::string AuthRecord::serialize() const {
    return "pbkdf2-sha256$" + std::to_string(iterations) + "$" + hex_encode(salt.data(), salt.size()) + "$" +
           hex_encode(hash.data(), hash.size()) + "\n";
}

bool AuthRecord::verify(const std::string& password) const {
    if (hash.size() != 32) return false;
    uint8_t d[32];
    pbkdf2_sha256(password, salt.data(), salt.size(), iterations, d, 32);
    return ct_equal(d, hash.data(), 32);
}

// ---------------------------------------------------------------- Lock
Lock::Lock(const Config& cfg)
    : mode_(cfg.lock_mode), delay_ms_(cfg.unlock_delay * 1000), window_ms_(cfg.unlock_window * 1000) {
    last_tick_ms_ = last_save_ms_ = mono_ms();
}

void Lock::load() {
    std::lock_guard<std::mutex> g(mu_);
    std::string text;
    if (read_file(paths::auth(), text) && AuthRecord::parse(text, auth_)) have_auth_ = true;
    else if (needs_password()) LOG_E("lock_mode=%s but %s is missing or invalid: privileged operations are disabled",
                                     lock_mode_name(mode_), paths::auth().c_str());
    std::string st;
    if (read_file(paths::state(), st)) {
        uint64_t requested_at = 0;
        for (const std::string& line : split(st, '\n')) {
            size_t eq = line.find('=');
            if (eq == std::string::npos) continue;
            std::string k = trim(line.substr(0, eq)), v = trim(line.substr(eq + 1));
            uint64_t n = 0;
            if (k == "fail_count" && parse_u64(v, n)) fail_count_ = uint32_t(n);
            // unlock_requested_at is wall-clock seconds (unix_now()) recorded when the user ran
            // 'blocker unlock-request'. Restoring it means a reboot does NOT reset the countdown.
            if (k == "unlock_requested_at" && parse_u64(v, n)) requested_at = n;
        }
        if (requested_at) {
            uint64_t now_wall = unix_now();
            uint64_t elapsed_ms = (now_wall > requested_at) ? (now_wall - requested_at) * 1000 : 0;
            // Cap to just past the full window so an overly-long sleep doesn't keep it open forever
            uint64_t cap = delay_ms_ + window_ms_;
            progress_ms_ = std::min(elapsed_ms, cap + 1000);
            pending_ = true;
            LOG_I("unlock request restored from state file: %.0f s elapsed of %.0f s delay",
                  elapsed_ms / 1000.0, delay_ms_ / 1000.0);
        }
    }
    last_tick_ms_ = last_save_ms_ = mono_ms();
}

void Lock::save_locked() {
    std::string t;
    t += "fail_count=" + std::to_string(fail_count_) + "\n";
    // Persist the wall-clock start time so the countdown survives reboots.
    if (pending_ && unlock_requested_at_) {
        t += "unlock_requested_at=" + std::to_string(unlock_requested_at_) + "\n";
    }
    make_dirs(paths::state_dir(), 0700);
    if (!write_file_atomic(paths::state(), t, 0600)) LOG_W("cannot persist lock state");
    last_save_ms_ = mono_ms();
}

void Lock::tick() {
    std::lock_guard<std::mutex> g(mu_);
    uint64_t now = mono_ms();
    // Only monotonic time counts and a single step is capped, so neither changing the wall clock nor
    // stopping/continuing the process can fast-forward the delay.
    uint64_t delta = std::min<uint64_t>(now - last_tick_ms_, 10000);
    last_tick_ms_ = now;
    if (!pending_) return;
    progress_ms_ += delta;
    if (progress_ms_ >= delay_ms_ + window_ms_) {  // window expired: lock again
        pending_ = false;
        progress_ms_ = 0;
        LOG_I("unlock window expired; protection is fully locked again");
        save_locked();
    } else if (now - last_save_ms_ >= 30000) {
        save_locked();
    }
}

bool Lock::window_open_locked() const { return pending_ && progress_ms_ >= delay_ms_ && progress_ms_ < delay_ms_ + window_ms_; }
bool Lock::window_open() const { std::lock_guard<std::mutex> g(mu_); return window_open_locked(); }

Lock::Result Lock::check_password_locked(const std::string& pw) {
    if (!have_auth_) return {Err::NotConfigured, "no password is configured (" + paths::auth() + " missing)"};
    uint64_t now = mono_ms();
    if (locked_until_ms_ > now)
        return {Err::LockedOut, "too many wrong passwords; try again in " + human_duration((locked_until_ms_ - now + 999) / 1000)};
    if (pw.empty()) return {Err::PasswordRequired, ""};
    if (auth_.verify(pw)) {
        if (fail_count_) { fail_count_ = 0; save_locked(); }
        return {};
    }
    ++fail_count_;
    save_locked();
    std::string msg = "wrong password (failed attempts: " + std::to_string(fail_count_) + ")";
    if (fail_count_ >= 3) {
        uint64_t secs = std::min<uint64_t>(15ull << std::min<uint32_t>(fail_count_ - 3, 8), 3600);
        locked_until_ms_ = mono_ms() + secs * 1000;
        msg += "; locked out for " + human_duration(secs);
    }
    LOG_W("%s", msg.c_str());
    return {Err::BadPassword, msg};
}

Lock::Result Lock::authorize(const std::string& pw) {
    std::lock_guard<std::mutex> g(mu_);
    if (needs_delay() && !window_open_locked()) {
        if (!pending_)
            return {Err::WindowClosed, "locked: run 'blocker unlock-request' first; the unlock window opens after " +
                                           human_duration(delay_ms_ / 1000) + " and stays open for " + human_duration(window_ms_ / 1000)};
        if (progress_ms_ < delay_ms_)
            return {Err::WindowClosed, "locked: the unlock window opens in " + human_duration((delay_ms_ - progress_ms_ + 999) / 1000)};
        return {Err::WindowClosed, "locked: the unlock window has closed"};
    }
    if (needs_password()) return check_password_locked(pw);
    return {};
}

Lock::Result Lock::request_unlock(const std::string& pw) {
    std::lock_guard<std::mutex> g(mu_);
    if (!needs_delay()) return {Err::NotApplicable, "lock_mode is 'password': no delay is configured, just run the command and enter the password"};
    if (pending_) return {Err::None, "an unlock request is already pending"};
    if (needs_password()) {
        Result r = check_password_locked(pw);
        if (!r.ok()) return r;
    }
    pending_ = true;
    progress_ms_ = 0;
    unlock_requested_at_ = unix_now();  // wall-clock anchor: survives reboots
    last_tick_ms_ = mono_ms();
    save_locked();
    LOG_W("unlock requested: window opens in %s", human_duration(delay_ms_ / 1000).c_str());
    return {Err::None, "unlock requested: the window opens in " + human_duration(delay_ms_ / 1000) + " and stays open for " +
                           human_duration(window_ms_ / 1000) + " (the timer advances in real time and survives reboots)"};
}

void Lock::cancel_unlock() {
    std::lock_guard<std::mutex> g(mu_);
    if (!pending_) return;
    pending_ = false;
    progress_ms_ = 0;
    unlock_requested_at_ = 0;
    save_locked();
    LOG_I("unlock request cancelled");
}

std::string Lock::describe() const {
    std::lock_guard<std::mutex> g(mu_);
    std::string s = std::string("mode=") + lock_mode_name(mode_);
    if (!needs_delay()) return s + " (password required for every privileged action)";
    if (!pending_) return s + ", locked (no unlock requested)";
    if (progress_ms_ < delay_ms_) return s + ", unlock pending: window opens in " + human_duration((delay_ms_ - progress_ms_ + 999) / 1000);
    return s + ", UNLOCK WINDOW OPEN: closes in " + human_duration((delay_ms_ + window_ms_ - progress_ms_ + 999) / 1000);
}

}  // namespace blk
