// protect.hpp - system-level tamper resistance: chattr +i, resolver takeover, nftables, systemd
// self-repair, browser policies. Everything here is a no-op unless running as root on a real system
// (see protect::active()), so the test-suite can run unprivileged.
#pragma once

#include <string>
#include <sys/types.h>

#include "config.hpp"

namespace blk::protect {

bool active();  // root && not a BLOCKER_ROOT test run

// Immutable ("chattr +i") flag helpers. set_immutable returns false when unsupported or refused.
bool set_immutable(const std::string& path, bool on);
bool is_immutable(const std::string& path);

// Atomically (re)write a file, clearing the immutable flag first and restoring it afterwards.
bool write_protected(const std::string& path, const std::string& data, mode_t mode, bool lock);

void arm(const Config& cfg);                                   // apply every protection (daemon start)
// every ~2 s: files, resolv.conf, units. processed_files: bit0 rules, bit1 whitelist were just processed.
void maintain_fast(const Config& cfg, unsigned processed_files);
void maintain_slow(const Config& cfg);                         // every ~10 s: systemd state, firewall, drop-ins
void disarm(const Config& cfg, bool uninstall);                // lift protections (authorised stop / uninstall)

bool ensure_units();  // (re)write missing/altered unit files; true if anything changed
bool ensure_binary(); // restore /usr/local/sbin/blocker from the running image if it vanished
int sysctl(const std::vector<std::string>& args);  // systemctl wrapper (no-op returning -1 when inactive)
std::string report(const Config& cfg);             // multi-line human summary for `blocker status`

}  // namespace blk::protect
