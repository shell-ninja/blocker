// lock.hpp - password hash + delayed-unlock state machine that gates every "loosening" operation.
#pragma once

#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include "config.hpp"

namespace blk {

// "pbkdf2-sha256$<iterations>$<salt hex>$<hash hex>"
struct AuthRecord {
    uint32_t iterations = 0;
    std::vector<uint8_t> salt, hash;
    static AuthRecord create(const std::string& password, uint32_t iterations);
    static bool parse(const std::string& text, AuthRecord& out);
    std::string serialize() const;
    bool verify(const std::string& password) const;
};

class Lock {
public:
    enum class Err { None, PasswordRequired, BadPassword, LockedOut, WindowClosed, NotConfigured, NotApplicable };
    struct Result {
        Err err = Err::None;
        std::string msg;
        bool ok() const { return err == Err::None; }
    };

    Lock(const Config& cfg);
    void load();  // reads the auth record and persisted state
    void tick();  // call about once a second: ages a pending unlock using the monotonic clock

    Result authorize(const std::string& password);       // gate for privileged operations
    Result request_unlock(const std::string& password);  // start the delay timer
    void cancel_unlock();
    bool window_open() const;
    std::string describe() const;  // one-line human status
    LockMode mode() const { return mode_; }

private:
    bool needs_password() const { return mode_ != LockMode::Delay; }
    bool needs_delay() const { return mode_ != LockMode::Password; }
    Result check_password_locked(const std::string& pw);  // mutex held
    bool window_open_locked() const;
    void save_locked();

    mutable std::mutex mu_;
    LockMode mode_;
    uint64_t delay_ms_, window_ms_;
    AuthRecord auth_;
    bool have_auth_ = false;
    bool pending_ = false;
    uint64_t progress_ms_ = 0;       // monotonic time accumulated since the unlock request
    uint64_t unlock_requested_at_ = 0;  // wall-clock (unix_now()) when the request was made; 0 = none
    uint64_t last_tick_ms_ = 0, last_save_ms_ = 0;
    uint32_t fail_count_ = 0;
    uint64_t locked_until_ms_ = 0;
};

}  // namespace blk
