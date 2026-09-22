// rulesmgr.hpp - owns the block rules and the whitelist (scrambled files in the vault, see vault.hpp): hot reload +
// the "tamper ratchet".
//
// For each file the manager remembers the last *authorised* text (persisted in /var/lib/blocker/*.authorized).
// A change on disk is accepted only if it is at least as strict:
//   block rules  : every previously blocked rule is still there and no allow rule was added;
//   whitelist    : no entry was added (removing entries only tightens the filter).
// Anything looser is reverted (block rules added in the same edit are kept) unless an unlock window is open.
// Both files feed one combined rule set that is published to the DNS engine.
#pragma once

#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "engine.hpp"
#include "rules.hpp"

namespace blk {

class RulesMgr {
public:
    enum : unsigned { KEYWORDS = 1, WHITELIST = 2 };

    RulesMgr(Engine& engine, bool block_doh);
    void init();                                       // startup: load baselines, revert offline tampering, publish
    void poll(bool window_open, bool force = false);   // call ~1/s: detects and processes file changes
    unsigned take_processed();                         // bit mask of files processed since the last call (re-lock trigger)

    struct Edit { bool ok = false; std::string msg; };
    Edit add(const std::vector<Rule>& rules);          // rules: append (caller authorised any !allow rule)
    Edit remove(const std::set<std::string>& canons);  // rules: delete by canonical text (caller authorised)
    Edit allow(const std::vector<Rule>& rules);        // whitelist: append (caller authorised)
    Edit unallow(const std::set<std::string>& canons); // whitelist: delete (tightening, no authorisation needed)
    std::string authorized_text();
    std::string whitelist_text();
    std::string summary();

private:
    struct Sig {
        bool valid = false;
        long long mtime = 0, size = 0, ino = 0;
        bool operator==(const Sig& o) const { return valid == o.valid && mtime == o.mtime && size == o.size && ino == o.ino; }
    };
    struct Src {
        std::string path, baseline, label, defaults;
        bool allow_only = false;  // every line is an allow rule (the whitelist)
        unsigned bit = 0;
        std::string authorized;
        Sig last_sig;
    };
    static Sig file_sig(const std::string& path);
    ParsedText parse(const Src& s, const std::string& text) const;
    std::string line_for(const Src& s, const Rule& r) const;
    void init_src(Src& s);
    void process_locked(Src& s, bool window_open);
    void publish_locked(bool log);
    void persist_locked(const Src& s);
    Edit add_to(Src& s, const std::vector<Rule>& rules);
    Edit remove_from(Src& s, const std::set<std::string>& canons);

    Engine& engine_;
    std::vector<std::string> builtin_;
    std::mutex mu_;
    Src kw_, wl_;
    unsigned processed_ = 0;
    uint64_t reloaded_at_ = 0;
    size_t blocks_ = 0, allows_ = 0;
};

}  // namespace blk
