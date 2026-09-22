#include "vault.hpp"

#include <cstring>
#include <mutex>
#include <unistd.h>

#include "paths.hpp"
#include "protect.hpp"
#include "sha256.hpp"
#include "util.hpp"

namespace blk::vault {

namespace {

std::mutex g_mu;
std::string g_key;  // 32 bytes once loaded

constexpr size_t kNonce = 16, kTag = 16;

void hmac(const std::string& key, const std::string& msg, uint8_t out[32]) {
    hmac_sha256(reinterpret_cast<const uint8_t*>(key.data()), key.size(), reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), out);
}

std::string keystream(const std::string& key, const std::string& nonce, size_t n) {
    std::string ks;
    for (uint64_t blk = 0; ks.size() < n; ++blk) {
        std::string msg = "blk-ks" + nonce;
        for (int i = 7; i >= 0; --i) msg.push_back(static_cast<char>((blk >> (8 * i)) & 0xFF));
        uint8_t out[32];
        hmac(key, msg, out);
        ks.append(reinterpret_cast<const char*>(out), 32);
    }
    ks.resize(n);
    return ks;
}

std::string tag_of(const std::string& key, const std::string& nonce, const std::string& ct) {
    uint8_t out[32];
    hmac(key, "blk-mac" + nonce + ct, out);
    return std::string(reinterpret_cast<const char*>(out), kTag);
}

bool looks_like_text(const std::string& s) {
    size_t i = 0;
    while (i < s.size()) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {
            if (c == 0 || (c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7f) return false;
            ++i;
            continue;
        }
        size_t need = (c & 0xE0) == 0xC0 ? 1 : (c & 0xF0) == 0xE0 ? 2 : (c & 0xF8) == 0xF0 ? 3 : 0;
        if (need == 0 || c == 0xC0 || c == 0xC1) return false;
        for (size_t k = 1; k <= need; ++k)
            if (i + k >= s.size() || (static_cast<unsigned char>(s[i + k]) & 0xC0) != 0x80) return false;
        i += need + 1;
    }
    return true;
}

std::string current_key() {
    std::lock_guard<std::mutex> g(g_mu);
    return g_key;
}

}  // namespace

bool ensure_key(bool create) {
    std::lock_guard<std::mutex> g(g_mu);
    if (g_key.size() == 32) return true;
    std::string raw;
    if (read_file(paths::vault_key(), raw) && raw.size() == 32) {
        g_key = raw;
        return true;
    }
    if (!create) return false;
    if (!raw.empty()) LOG_W("vault key unreadable - creating a new one (rule files will be restored from the built-in list)");
    uint8_t k[32];
    random_bytes(k, sizeof k);
    std::string key(reinterpret_cast<const char*>(k), sizeof k);
    make_dirs(paths::vault_dir(), 0700);
    if (!protect::write_protected(paths::vault_key(), key, 0600, true)) return false;
    g_key = key;
    return true;
}

void forget_key() {
    std::lock_guard<std::mutex> g(g_mu);
    g_key.clear();
}

bool verify_key() {
    std::string key = current_key();
    if (key.size() != 32) return false;
    std::string raw;
    if (read_file(paths::vault_key(), raw) && raw == key) return false;
    LOG_W("TAMPER: vault key changed or removed - restoring it");
    make_dirs(paths::vault_dir(), 0700);
    protect::write_protected(paths::vault_key(), key, 0600, true);
    return true;
}

std::string encode(const std::string& plain) {
    std::string key = current_key();
    uint8_t n[kNonce];
    random_bytes(n, sizeof n);
    std::string nonce(reinterpret_cast<const char*>(n), kNonce);
    std::string ks = keystream(key, nonce, plain.size());
    std::string ct(plain.size(), '\0');
    for (size_t i = 0; i < plain.size(); ++i) ct[i] = static_cast<char>(plain[i] ^ ks[i]);
    return nonce + ct + tag_of(key, nonce, ct);
}

Kind decode(const std::string& raw, std::string& plain) {
    std::string key = current_key();
    if (key.size() == 32 && raw.size() >= kNonce + kTag) {
        std::string nonce = raw.substr(0, kNonce);
        std::string ct = raw.substr(kNonce, raw.size() - kNonce - kTag);
        std::string tag = raw.substr(raw.size() - kTag);
        std::string want = tag_of(key, nonce, ct);
        unsigned char diff = 0;
        for (size_t i = 0; i < kTag; ++i) diff |= static_cast<unsigned char>(tag[i] ^ want[i]);
        if (diff == 0) {
            std::string ks = keystream(key, nonce, ct.size());
            plain.assign(ct.size(), '\0');
            for (size_t i = 0; i < ct.size(); ++i) plain[i] = static_cast<char>(ct[i] ^ ks[i]);
            return Kind::Decoded;
        }
    }
    if (looks_like_text(raw)) {
        plain = raw;
        return Kind::Plain;
    }
    plain.clear();
    return Kind::Undecodable;
}

Kind read(const std::string& path, std::string& plain) {
    std::string raw;
    plain.clear();
    if (!read_file(path, raw)) return Kind::Missing;
    return decode(raw, plain);
}

bool write(const std::string& path, const std::string& plain, unsigned mode, bool lock) {
    if (current_key().size() != 32) return false;
    make_dirs(paths::vault_dir(), 0700);
    return protect::write_protected(path, encode(plain), static_cast<mode_t>(mode), lock);
}

int migrate_legacy() {
    struct Job { std::string legacy_file, legacy_base, file, base; const char* what; };
    const Job jobs[] = {
        {paths::legacy_keywords(), paths::legacy_baseline(), paths::keywords(), paths::baseline(), "block rules"},
        {paths::legacy_whitelist(), paths::legacy_wl_baseline(), paths::whitelist(), paths::wl_baseline(), "whitelist"},
    };
    int moved = 0;
    for (const Job& j : jobs) {
        bool have_legacy = path_exists(j.legacy_file) || path_exists(j.legacy_base);
        if (!have_legacy) continue;
        if (!path_exists(j.file) && !path_exists(j.base)) {
            std::string f, b;
            bool hf = read_file(j.legacy_file, f), hb = read_file(j.legacy_base, b);
            if (!hf && !hb) continue;
            if (!hf) f = b;  // the baseline is the authorised text; the on-disk file (a stricter edit) wins if present
            if (!hb) b = f;
            if (!ensure_key(true) || !write(j.file, f, 0600, true) || !write(j.base, b, 0600, true)) {
                LOG_E("cannot move the %s into the vault - keeping the old files", j.what);
                continue;
            }
            ++moved;
        }
        // the vault has (or now has) the data: the plain-text copies must not stay around
        for (const std::string& p : {j.legacy_file, j.legacy_base}) {
            if (!path_exists(p)) continue;
            protect::set_immutable(p, false);
            unlink(p.c_str());
        }
    }
    return moved;
}

}  // namespace blk::vault
