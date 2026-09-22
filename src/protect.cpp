#include "protect.hpp"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../gen/embedded.hpp"
#include "paths.hpp"
#include "util.hpp"

namespace fs = std::filesystem;

namespace blk::protect {

using namespace paths;

namespace {

const char* kResolvConf =
    "# Managed by blocker - edits are reverted automatically.\n"
    "nameserver 127.0.0.1\n"
    "options timeout:2 attempts:2\n";

const char* kNmConf =
    "# Managed by blocker: stop NetworkManager from rewriting /etc/resolv.conf\n"
    "[main]\n"
    "dns=none\n"
    "rc-manager=unmanaged\n";

const char* kResolvedConf =
    "# Managed by blocker: systemd-resolved forwards everything to the local filter\n"
    "[Resolve]\n"
    "DNS=127.0.0.1\n"
    "FallbackDNS=\n"
    "Domains=~.\n"
    "DNSStubListener=no\n"
    "DNSOverTLS=no\n";

const char* kUnits[] = {"blocker.service", "blocker-guard.service", "blocker-guard.timer"};

std::string unit_text(const std::string& name) {
    if (name == "blocker.service") return embedded::SERVICE;
    if (name == "blocker-guard.service") return embedded::GUARD_SERVICE;
    return embedded::GUARD_TIMER;
}

std::string nm_conf() { return P("/etc/NetworkManager/conf.d/90-blocker-dns.conf"); }
std::string resolved_conf() { return P("/etc/systemd/resolved.conf.d/90-blocker.conf"); }

struct PolicyTarget { const char* dir; const char* file; bool firefox; };
const PolicyTarget kPolicies[] = {
    {"/etc/firefox/policies", "policies.json", true},
    {"/etc/opt/chrome/policies/managed", "blocker.json", false},
    {"/etc/chromium/policies/managed", "blocker.json", false},
    {"/etc/chromium-browser/policies/managed", "blocker.json", false},
    {"/etc/brave/policies/managed", "blocker.json", false},
    {"/etc/opt/edge/policies/managed", "blocker.json", false},
};

bool warned_unsupported = false;

std::string slurp(const std::string& p) {
    std::string s;
    read_file(p, s);
    return s;
}

// Files that must stay root-owned + immutable at all times (rewritten by us, so they may be re-locked immediately).
std::vector<std::string> locked_files() {
    std::vector<std::string> v = {bin(), conf(), auth(), baseline(), wl_baseline(), vault_key()};
    for (const char* u : kUnits) v.push_back(unit_dir() + "/" + u);
    return v;
}

bool file_is(const std::string& path, const std::string& want) {
    struct stat st;
    if (lstat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) return false;
    return slurp(path) == want;
}

// Write `want` to path (if different) and lock it. Returns true if the file was changed.
bool ensure_file(const std::string& path, const std::string& want, mode_t mode) {
    bool changed = false;
    if (!file_is(path, want)) {
        if (!write_protected(path, want, mode, true)) {
            LOG_W("cannot write %s: %s", path.c_str(), strerror(errno));
            return false;
        }
        changed = true;
    } else if (!is_immutable(path)) {
        set_immutable(path, true);
    }
    return changed;
}

bool systemd_present() { return path_exists("/run/systemd/system"); }

}  // namespace

bool active() { return !dev() && geteuid() == 0; }

bool set_immutable(const std::string& path, bool on) {
    int fd = open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    int flags = 0;
    if (ioctl(fd, FS_IOC_GETFLAGS, &flags) != 0) {
        if (!warned_unsupported) {
            warned_unsupported = true;
            LOG_W("filesystem of %s does not support immutable flags (%s)", path.c_str(), strerror(errno));
        }
        close(fd);
        return false;
    }
    int want = on ? (flags | FS_IMMUTABLE_FL) : (flags & ~FS_IMMUTABLE_FL);
    bool ok = want == flags || ioctl(fd, FS_IOC_SETFLAGS, &want) == 0;
    if (!ok) LOG_W("chattr %ci %s failed: %s", on ? '+' : '-', path.c_str(), strerror(errno));
    close(fd);
    return ok;
}

bool is_immutable(const std::string& path) {
    int fd = open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    int flags = 0;
    bool r = ioctl(fd, FS_IOC_GETFLAGS, &flags) == 0 && (flags & FS_IMMUTABLE_FL);
    close(fd);
    return r;
}

bool write_protected(const std::string& path, const std::string& data, mode_t mode, bool lock) {
    if (path_exists(path) && active()) set_immutable(path, false);
    make_dirs(dir_of(path), 0755);
    if (!write_file_atomic(path, data, mode)) return false;
    if (lock && active()) set_immutable(path, true);
    return true;
}

int sysctl(const std::vector<std::string>& args) {
    if (!active() || !systemd_present()) return -1;
    std::vector<std::string> a = {"systemctl"};
    a.insert(a.end(), args.begin(), args.end());
    return run_cmd(a);
}

// ---------------------------------------------------------------- binary + units
bool ensure_binary() {
    if (!active()) return false;
    std::string b = bin();
    if (!path_exists(b)) {
        LOG_W("%s vanished - restoring it from the running image", b.c_str());
        make_dirs(dir_of(b), 0755);
        std::error_code ec;
        std::string tmp = b + ".restore";
        fs::copy_file("/proc/self/exe", tmp, fs::copy_options::overwrite_existing, ec);
        if (ec) return false;
        chmod(tmp.c_str(), 0700);  // root-only, consistent with the initial install
        if (rename(tmp.c_str(), b.c_str()) != 0) return false;
        set_immutable(b, true);
        return true;
    }
    if (!is_immutable(b)) set_immutable(b, true);
    return false;
}

// Remove any systemd override that could neuter our units (drop-ins, shadowing unit files).
static bool scrub_overrides() {
    bool changed = false;
    std::error_code ec;
    const char* shadow_dirs[] = {"/etc/systemd/system.control", "/run/systemd/system.control", "/run/systemd/transient",
                                 "/run/systemd/generator.early"};
    const char* dropin_dirs[] = {"/etc/systemd/system.control", "/run/systemd/system.control", "/run/systemd/transient",
                                 "/run/systemd/generator.early", "/run/systemd/generator", "/run/systemd/system",
                                 "/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"};
    for (const char* u : kUnits) {
        std::string unit = u;
        for (const char* d : shadow_dirs) {
            std::string p = std::string(d) + "/" + unit;
            if (path_exists(p) && fs::remove(p, ec)) { LOG_W("removed unit override %s", p.c_str()); changed = true; }
        }
        std::string dash = unit.substr(0, unit.find('-') == std::string::npos ? 0 : unit.find('-') + 1);  // "blocker-"
        std::vector<std::string> names = {unit + ".d"};
        if (!dash.empty()) names.push_back(dash + unit.substr(unit.rfind('.')) + ".d");  // blocker-.service.d
        for (const char* d : dropin_dirs) {
            for (const std::string& n : names) {
                std::string p = std::string(d) + "/" + n;
                if (p == unit_dir() + "/" + unit + ".d") continue;  // our own (immutable, empty) directory: handled below
                if (path_exists(p) && fs::remove_all(p, ec) > 0) { LOG_W("removed unit drop-in %s", p.c_str()); changed = true; }
            }
        }
        // Our own drop-in directory stays present, empty and immutable so nobody can add an override file.
        std::string own = unit_dir() + "/" + unit + ".d";
        if (!path_exists(own)) { make_dirs(own, 0755); changed = true; }
        else if (!is_immutable(own)) {
            for (auto& e : fs::directory_iterator(own, ec)) { fs::remove_all(e.path(), ec); changed = true; }
        }
        set_immutable(own, true);
    }
    return changed;
}

bool ensure_units() {
    if (!active()) return false;
    bool changed = false;
    for (const char* u : kUnits) changed |= ensure_file(unit_dir() + "/" + u, unit_text(u), 0644);
    changed |= scrub_overrides();
    if (changed) sysctl({"daemon-reload"});
    return changed;
}

// ---------------------------------------------------------------- resolver
static bool resolv_ok() {
    struct stat st;
    std::string p = resolv_conf();
    if (lstat(p.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) return false;
    return slurp(p) == kResolvConf;
}

static void backup_resolver() {
    if (path_exists(resolv_orig()) || path_exists(resolv_link())) return;
    std::string p = resolv_conf();
    struct stat st;
    if (lstat(p.c_str(), &st) != 0) return;
    make_dirs(state_dir(), 0700);
    if (S_ISLNK(st.st_mode)) {
        char buf[4096];
        ssize_t n = readlink(p.c_str(), buf, sizeof buf - 1);
        if (n > 0) write_file_atomic(resolv_link(), std::string(buf, size_t(n)), 0600);
    } else {
        std::string cur = slurp(p);
        if (cur.find("Managed by blocker") == std::string::npos) write_file_atomic(resolv_orig(), cur, 0600);
    }
}

static void takeover_resolver() {
    std::string p = resolv_conf();
    if (!resolv_ok()) {
        backup_resolver();
        struct stat st;
        if (lstat(p.c_str(), &st) == 0 && !S_ISLNK(st.st_mode)) set_immutable(p, false);
        unlink(p.c_str());
        if (!write_file_atomic(p, kResolvConf, 0644)) LOG_E("cannot write %s: %s", p.c_str(), strerror(errno));
        else LOG_I("%s now points at 127.0.0.1", p.c_str());
    }
    if (!is_immutable(p)) set_immutable(p, true);
}

static void restore_resolver() {
    std::string p = resolv_conf();
    struct stat st;
    if (lstat(p.c_str(), &st) == 0 && !S_ISLNK(st.st_mode)) set_immutable(p, false);
    unlink(p.c_str());
    std::string link = slurp(resolv_link()), orig = slurp(resolv_orig());
    if (!link.empty() && symlink(link.c_str(), p.c_str()) == 0) {
    } else if (!orig.empty() && write_file_atomic(p, orig, 0644)) {
    } else {
        write_file_atomic(p, "nameserver 1.1.1.1\nnameserver 9.9.9.9\n", 0644);  // last resort so the box keeps working
    }
    unlink(resolv_link().c_str());
    unlink(resolv_orig().c_str());
    LOG_I("restored %s", p.c_str());
}

static void manage_network_daemons(bool on) {
    bool nm_changed = false, rs_changed = false;
    if (on) {
        if (path_exists(P("/etc/NetworkManager"))) nm_changed = ensure_file(nm_conf(), kNmConf, 0644);
        if (sysctl({"is-enabled", "--quiet", "systemd-resolved.service"}) == 0 || sysctl({"is-active", "--quiet", "systemd-resolved.service"}) == 0)
            rs_changed = ensure_file(resolved_conf(), kResolvedConf, 0644);
    } else {
        for (const std::string& f : {nm_conf(), resolved_conf()}) {
            if (!path_exists(f)) continue;
            set_immutable(f, false);
            unlink(f.c_str());
            (f == nm_conf() ? nm_changed : rs_changed) = true;
        }
    }
    if (nm_changed) sysctl({"reload", "NetworkManager.service"});
    if (rs_changed) sysctl({"restart", "systemd-resolved.service"});
}

// ---------------------------------------------------------------- firewall
static bool firewall_present() { return run_cmd({"nft", "list", "table", "inet", "blocker"}) == 0; }

static void firewall_apply() {
    static const char* rules =
        "table inet blocker\n"
        "delete table inet blocker\n"
        "table inet blocker {\n"
        "  chain output {\n"
        "    type filter hook output priority 0; policy accept;\n"
        "    meta skuid 0 accept\n"       // the daemon (root) may talk to its upstreams
        "    oifname \"lo\" accept\n"      // local clients reach 127.0.0.1:53
        "    udp dport { 53, 853 } reject\n"
        "    tcp dport { 53, 853 } reject with tcp reset\n"
        "  }\n"
        "}\n";
    std::string in = rules;
    int rc = run_cmd({"nft", "-f", "-"}, &in);
    if (rc == 127) LOG_W("nft not found: skipping the DNS-bypass firewall");
    else if (rc != 0) LOG_W("nft rejected the ruleset (exit %d)", rc);
    else LOG_I("firewall: only root may send plain DNS/DoT off-box");
}

static void firewall_remove() { run_cmd({"nft", "delete", "table", "inet", "blocker"}); }

// ---------------------------------------------------------------- browser policies
static std::string policy_json(bool firefox, const Config& cfg) {
    if (firefox)
        return "{\n  \"blocker-managed\": true,\n  \"policies\": {\n    \"DNSOverHTTPS\": { \"Enabled\": false, \"Locked\": true }\n  }\n}\n";
    std::string j = "{\n  \"DnsOverHttpsMode\": \"off\",\n  \"BuiltInDnsClientEnabled\": false";
    if (cfg.safesearch) j += ",\n  \"ForceGoogleSafeSearch\": true";
    if (cfg.youtube_restrict) j += ",\n  \"ForceYouTubeRestrict\": 2";
    return j + "\n}\n";
}

static void policies_apply(const Config& cfg) {
    for (const PolicyTarget& t : kPolicies) {
        std::string dir = P(t.dir), file = dir + "/" + t.file;
        if (t.firefox && path_exists(file) && slurp(file).find("blocker-managed") == std::string::npos) continue;  // admin's own file
        if (!file_is(file, policy_json(t.firefox, cfg)) || !is_immutable(file)) {
            make_dirs(dir, 0755);
            ensure_file(file, policy_json(t.firefox, cfg), 0644);
        }
    }
}

static void policies_remove() {
    for (const PolicyTarget& t : kPolicies) {
        std::string file = P(t.dir) + "/" + t.file;
        if (!path_exists(file)) continue;
        if (t.firefox && slurp(file).find("blocker-managed") == std::string::npos) continue;
        set_immutable(file, false);
        unlink(file.c_str());
    }
}

// ---------------------------------------------------------------- systemd state
static void ensure_systemd_state() {
    if (!systemd_present()) return;
    if (sysctl({"is-enabled", "--quiet", "blocker.service"}) != 0) {
        LOG_W("blocker.service was disabled - re-enabling");
        sysctl({"enable", "blocker.service"});
    }
    if (sysctl({"is-enabled", "--quiet", "blocker-guard.timer"}) != 0 || sysctl({"is-active", "--quiet", "blocker-guard.timer"}) != 0) {
        LOG_W("watchdog timer was stopped or disabled - restoring it");
        sysctl({"enable", "--now", "blocker-guard.timer"});
    }
}

// ---------------------------------------------------------------- public orchestration
void arm(const Config& cfg) {
    if (!active()) {
        LOG_W("protection inactive (%s): running as a plain DNS filter", dev() ? "test build" : "not root");
        return;
    }
    unlink(disabled_flag().c_str());
    make_dirs(etc_dir(), 0700);
    make_dirs(state_dir(), 0700);
    make_dirs(vault_dir(), 0700);
    chmod(etc_dir().c_str(), 0700);
    chmod(vault_dir().c_str(), 0700);
    ensure_binary();
    ensure_units();
    ensure_systemd_state();
    if (cfg.takeover_resolver) { takeover_resolver(); manage_network_daemons(true); }
    if (cfg.browser_policies) policies_apply(cfg);
    if (cfg.firewall) firewall_apply();
    for (const std::string& f : locked_files())
        if (path_exists(f)) { if (chown(f.c_str(), 0, 0) != 0) {} set_immutable(f, true); }
    for (const std::string& f : {keywords(), whitelist()})
        if (path_exists(f)) { if (chown(f.c_str(), 0, 0) != 0) {} set_immutable(f, true); }
    LOG_I("tamper protection armed");
}

void maintain_fast(const Config& cfg, unsigned processed) {
    if (!active()) return;
    // NOTE: unlocked_since is only safe as a static local because maintain_fast is
    // called exclusively from the single-threaded daemon main loop. If concurrency is
    // ever introduced here, move this into a class member and protect with a mutex.
    static uint64_t unlocked_since[2] = {0, 0};
    ensure_binary();
    ensure_units();
    if (cfg.takeover_resolver) takeover_resolver();
    for (const std::string& f : locked_files())
        if (path_exists(f) && !is_immutable(f)) set_immutable(f, true);
    // rule store files (vault): after a processed edit (or if left unlocked > 60 s) re-lock. The grace
    // period is what makes "chattr -i; edit; save" workable. Bit 0 = rules, bit 1 = whitelist.
    const std::string files[2] = {keywords(), whitelist()};
    for (int i = 0; i < 2; ++i) {
        const std::string& f = files[i];
        if (path_exists(f) && !is_immutable(f)) {
            if (!unlocked_since[i]) unlocked_since[i] = unix_now();
            if ((processed & (1u << i)) || unix_now() - unlocked_since[i] >= 60) {
                if (chown(f.c_str(), 0, 0) != 0) {}
                chmod(f.c_str(), 0644);
                set_immutable(f, true);
                unlocked_since[i] = 0;
            }
        } else {
            unlocked_since[i] = 0;
        }
    }
}

void maintain_slow(const Config& cfg) {
    if (!active()) return;
    ensure_systemd_state();
    if (cfg.takeover_resolver) manage_network_daemons(true);
    if (cfg.browser_policies) policies_apply(cfg);
    if (cfg.firewall && !firewall_present()) {
        LOG_W("firewall table was removed - restoring it");
        firewall_apply();
    }
}

void disarm(const Config& cfg, bool uninstall) {
    (void)cfg;
    LOG_W("lifting protections (%s)", uninstall ? "uninstall" : "authorised stop");
    if (active()) {
        firewall_remove();
        policies_remove();
        restore_resolver();
        manage_network_daemons(false);
        for (const std::string& f : locked_files()) set_immutable(f, false);
        set_immutable(keywords(), false);
        set_immutable(whitelist(), false);
        for (const char* u : kUnits) set_immutable(unit_dir() + "/" + u + ".d", false);
    }
    unlink(baseline().c_str());
    unlink(wl_baseline().c_str());
    make_dirs(state_dir(), 0700);
    if (!uninstall) write_file_atomic(disabled_flag(), "paused\n", 0600);  // tells the watchdog not to resurrect us

    if (uninstall) {
        std::error_code ec;
        if (active()) {
            sysctl({"disable", "--now", "blocker-guard.timer"});
            sysctl({"disable", "blocker.service"});
        }
        for (const char* u : kUnits) {
            fs::remove(unit_dir() + "/" + u, ec);
            fs::remove_all(unit_dir() + "/" + u + ".d", ec);
        }
        fs::remove_all(etc_dir(), ec);
        fs::remove_all(state_dir(), ec);
        fs::remove_all(vault_dir(), ec);
        fs::remove(bin(), ec);
        if (active()) sysctl({"daemon-reload"});
    }
}

std::string report(const Config& cfg) {
    std::string s;
    auto yn = [](bool b) { return b ? "yes" : "NO"; };
    if (!active()) return "  (system protections inactive: not running as root on a real system)\n";
    s += std::string("  resolv.conf -> 127.0.0.1, immutable : ") + yn(resolv_ok() && is_immutable(resolv_conf())) + "\n";
    std::string files;
    bool all = true;
    for (const std::string& f : locked_files()) {
        if (!path_exists(f)) continue;
        if (!is_immutable(f)) { all = false; files += " " + f; }
    }
    for (const std::string& f : {keywords(), whitelist()})
        if (path_exists(f) && !is_immutable(f)) { all = false; files += " " + f + "(unlocked, will re-lock)"; }
    s += std::string("  binary/config/units immutable       : ") + yn(all) + (files.empty() ? "" : " (not yet:" + files + ")") + "\n";
    if (cfg.firewall) s += std::string("  nftables DNS-bypass table           : ") + yn(firewall_present()) + "\n";
    s += std::string("  watchdog timer active               : ") + yn(sysctl({"is-active", "--quiet", "blocker-guard.timer"}) == 0) + "\n";
    return s;
}

}  // namespace blk::protect
