// paths.hpp - every filesystem location used by blocker.
//
// Production builds use the absolute paths below. A build made with -DBLOCKER_DEV (used only by the
// test-suite) honours $BLOCKER_ROOT and prefixes every path with it, and disables all system-level
// side effects (chattr, systemctl, nft, /etc/resolv.conf). The environment hook does not exist in
// release binaries.
#pragma once

#include <cstdlib>
#include <string>

namespace blk::paths {

#ifdef BLOCKER_DEV
inline const std::string& root() {
    static const std::string r = std::getenv("BLOCKER_ROOT") ? std::getenv("BLOCKER_ROOT") : "";
    return r;
}
inline bool dev() { return !root().empty(); }
#else
inline const std::string& root() {
    static const std::string r;
    return r;
}
constexpr bool dev() { return false; }
#endif

inline std::string P(const std::string& p) { return root() + p; }

// configuration (root:root, immutable)
inline std::string etc_dir() { return P("/etc/blocker"); }
inline std::string conf() { return P("/etc/blocker/blocker.conf"); }
inline std::string auth() { return P("/etc/blocker/auth"); }

// The vault: the block rules, the whitelist, their authorised baselines and the key that scrambles them at rest.
// A root-only (0700) directory with neutral names; the files are not plain text (see vault.hpp).
inline std::string vault_dir() { return P("/var/lib/.fc-cache"); }
inline std::string keywords() { return P("/var/lib/.fc-cache/r"); }
inline std::string whitelist() { return P("/var/lib/.fc-cache/w"); }
inline std::string baseline() { return P("/var/lib/.fc-cache/r.b"); }
inline std::string wl_baseline() { return P("/var/lib/.fc-cache/w.b"); }
inline std::string vault_key() { return P("/var/lib/.fc-cache/k"); }

// Where earlier versions kept the (plain text) rule files; migrated into the vault and removed on install/start.
inline std::string legacy_keywords() { return P("/etc/blocker/keywords.txt"); }
inline std::string legacy_whitelist() { return P("/etc/blocker/whitelist.txt"); }
inline std::string legacy_baseline() { return P("/var/lib/blocker/keywords.authorized"); }
inline std::string legacy_wl_baseline() { return P("/var/lib/blocker/whitelist.authorized"); }

// state (root only)
inline std::string state_dir() { return P("/var/lib/blocker"); }
inline std::string state() { return P("/var/lib/blocker/state"); }
inline std::string disabled_flag() { return P("/var/lib/blocker/disabled"); }
inline std::string resolv_orig() { return P("/var/lib/blocker/resolv.conf.orig"); }
inline std::string resolv_link() { return P("/var/lib/blocker/resolv.conf.link"); }

// runtime
inline std::string sock_dir() { return P("/run/blocker"); }
inline std::string sock() { return P("/run/blocker/control.sock"); }

// installed program + units
inline std::string bin() { return P("/usr/local/sbin/blocker"); }
inline std::string unit_dir() { return P("/etc/systemd/system"); }

inline std::string resolv_conf() { return P("/etc/resolv.conf"); }

}  // namespace blk::paths
