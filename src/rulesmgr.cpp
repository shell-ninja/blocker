#include "rulesmgr.hpp"

#include <sys/stat.h>

#include "../gen/embedded.hpp"
#include "paths.hpp"
#include "protect.hpp"
#include "util.hpp"
#include "vault.hpp"

namespace blk {

RulesMgr::RulesMgr(Engine& engine, bool block_doh) : engine_(engine) {
    if (block_doh) builtin_ = builtin_bypass_domains();
    kw_.path = paths::keywords();
    kw_.baseline = paths::baseline();
    kw_.label = "rules";
    kw_.defaults = embedded::default_keywords();
    kw_.bit = KEYWORDS;
    wl_.path = paths::whitelist();
    wl_.baseline = paths::wl_baseline();
    wl_.label = "whitelist";
    wl_.defaults = embedded::DEFAULT_WHITELIST;
    wl_.allow_only = true;
    wl_.bit = WHITELIST;
}

RulesMgr::Sig RulesMgr::file_sig(const std::string& path) {
    Sig s;
    struct stat st;
    if (stat(path.c_str(), &st) == 0) {
        s.valid = true;
        s.mtime = static_cast<long long>(st.st_mtim.tv_sec) * 1000000000LL + st.st_mtim.tv_nsec;
        s.size = st.st_size;
        s.ino = static_cast<long long>(st.st_ino);
    }
    return s;
}

ParsedText RulesMgr::parse(const Src& s, const std::string& text) const {
    return parse_text(text, s.allow_only, s.label.c_str());
}

// Whitelist lines are written bare ("kw:analytics"), keyword lines in canonical form.
std::string RulesMgr::line_for(const Src& s, const Rule& r) const {
    std::string c = r.canon();
    return (s.allow_only && !c.empty() && c[0] == '!') ? c.substr(1) : c;
}

void RulesMgr::persist_locked(const Src& s) {
    if (!vault::write(s.baseline, s.authorized, 0600, true)) LOG_W("cannot persist baseline of %s", s.label.c_str());
}

void RulesMgr::publish_locked(bool log) {
    ParsedText k = parse(kw_, kw_.authorized), w = parse(wl_, wl_.authorized);
    if (log)
        for (const auto* p : {&k, &w})
            for (const std::string& m : p->warnings) LOG_W("%s", m.c_str());
    std::vector<Rule> all = k.rules;
    all.insert(all.end(), w.rules.begin(), w.rules.end());
    auto rs = RuleSet::build(all, builtin_);
    blocks_ = rs->block_rules();
    allows_ = rs->allow_rules();
    reloaded_at_ = unix_now();
    engine_.set_rules(rs);
    if (log) LOG_I("rules loaded: %zu block, %zu allow (%zu whitelist entries) (+%zu built-in)", blocks_, allows_,
                   RuleSet::build(w.rules, {})->allow_rules(), builtin_.size());
}

void RulesMgr::init_src(Src& s) {
    std::string disk, base;
    vault::Kind dk = vault::read(s.path, disk), bk = vault::read(s.baseline, base);
    bool have_disk = dk == vault::Kind::Decoded || dk == vault::Kind::Plain;
    bool have_base = bk == vault::Kind::Decoded || bk == vault::Kind::Plain;
    if (dk == vault::Kind::Undecodable || bk == vault::Kind::Undecodable)
        LOG_W("%s store unreadable (key lost or data damaged) - restoring what can be restored", s.label.c_str());
    if (have_base) {
        s.authorized = base;
    } else if (have_disk) {
        s.authorized = disk;  // first run: whatever is on disk becomes the baseline
    } else {
        s.authorized = s.defaults;  // never start with an empty list: fall back to the list built into the binary
        LOG_W("%s missing: writing the default", s.label.c_str());
    }
    if (!have_base) persist_locked(s);
    if (!have_disk && !have_base) {  // brand-new install (or lost data): materialise the default
        vault::write(s.path, s.authorized, 0600, true);
        disk = s.authorized;
        have_disk = true;
        dk = vault::Kind::Decoded;
    }
    if (!have_disk || disk != s.authorized || dk == vault::Kind::Plain) {
        s.last_sig = Sig{};  // force a comparison
        process_locked(s, false);  // reverts offline tampering, accepts a stricter edit, re-scrambles plain text
    } else {
        s.last_sig = file_sig(s.path);
    }
}

void RulesMgr::init() {
    std::lock_guard<std::mutex> g(mu_);
    vault::ensure_key(true);
    if (int moved = vault::migrate_legacy()) LOG_I("moved %d rule file(s) of an earlier version into the vault", moved);
    init_src(kw_);
    init_src(wl_);
    publish_locked(true);
}

void RulesMgr::poll(bool window_open, bool force) {
    vault::verify_key();
    std::lock_guard<std::mutex> g(mu_);
    bool changed = false;
    for (Src* s : {&kw_, &wl_}) {
        Sig now = file_sig(s->path);
        if (!force && now == s->last_sig) continue;
        process_locked(*s, window_open);
        changed = true;
    }
    if (changed) publish_locked(false);
}

void RulesMgr::process_locked(Src& s, bool window_open) {
    std::string disk;
    vault::Kind k = vault::read(s.path, disk);
    bool have = k == vault::Kind::Decoded || k == vault::Kind::Plain;  // damaged / undecodable data counts as missing
    if (have && disk == s.authorized) {
        if (k == vault::Kind::Plain) vault::write(s.path, s.authorized, 0600, true);  // same rules, but not scrambled
        s.last_sig = file_sig(s.path);
        processed_ |= s.bit;
        return;
    }
    ParsedText np = parse(s, have ? disk : std::string());
    ParsedText bp = parse(s, s.authorized);
    auto ns = RuleSet::build(np.rules, {});
    auto bs = RuleSet::build(bp.rules, {});

    std::vector<std::string> removed, new_allows, new_blocks;
    for (const std::string& c : bs->block_canon) if (!ns->block_canon.count(c)) removed.push_back(c);
    for (const std::string& c : ns->allow_canon) if (!bs->allow_canon.count(c)) new_allows.push_back(c);
    for (const std::string& c : ns->block_canon) if (!bs->block_canon.count(c)) new_blocks.push_back(c);

    if ((removed.empty() && new_allows.empty()) || (window_open && have)) {
        s.authorized = have ? disk : std::string();
        persist_locked(s);
        for (const std::string& m : np.warnings) LOG_W("%s", m.c_str());
        if (!removed.empty() || !new_allows.empty()) LOG_W("%s loosened inside an authorised unlock window", s.label.c_str());
        else LOG_I("%s reloaded", s.label.c_str());
        if (k == vault::Kind::Plain && !vault::write(s.path, s.authorized, 0600, true)) LOG_E("cannot re-scramble %s", s.label.c_str());
    } else {
        // Loosening without authorisation = tampering. Restore the authorised text, keep any added block rules.
        LOG_W("TAMPER: %s changed without authorisation (%zu block rule(s) removed, %zu allow entr%s added) - reverting",
              s.label.c_str(), removed.size(), new_allows.size(), new_allows.size() == 1 ? "y" : "ies");
        std::string text = s.authorized;
        if (!text.empty() && text.back() != '\n') text.push_back('\n');
        for (const std::string& c : new_blocks) text += c + "\n";
        s.authorized = text;
        persist_locked(s);
        if (!vault::write(s.path, s.authorized, 0600, true)) LOG_E("cannot restore %s", s.label.c_str());
    }
    s.last_sig = file_sig(s.path);
    processed_ |= s.bit;
}

unsigned RulesMgr::take_processed() {
    std::lock_guard<std::mutex> g(mu_);
    unsigned r = processed_;
    processed_ = 0;
    return r;
}

RulesMgr::Edit RulesMgr::add_to(Src& s, const std::vector<Rule>& rules) {
    auto cur = RuleSet::build(parse(s, s.authorized).rules, {});
    std::string text = s.authorized;
    if (!text.empty() && text.back() != '\n') text.push_back('\n');
    std::set<std::string> seen;
    size_t added = 0, dup = 0;
    for (const Rule& r0 : rules) {
        Rule r = s.allow_only ? as_allow(r0) : r0;
        std::string c = r.canon();
        bool exists = r.is_allow() ? cur->allow_canon.count(c) : cur->block_canon.count(c);
        if (exists || !seen.insert(c).second) { ++dup; continue; }
        text += line_for(s, r) + "\n";
        ++added;
    }
    Edit e;
    if (added == 0) { e.ok = true; e.msg = "nothing to add (" + std::to_string(dup) + " already present)"; return e; }
    s.authorized = text;
    persist_locked(s);
    if (!vault::write(s.path, text, 0600, true)) { e.msg = "cannot write the " + s.label + " store"; return e; }
    publish_locked(true);
    s.last_sig = file_sig(s.path);
    processed_ |= s.bit;
    e.ok = true;
    e.msg = "added " + std::to_string(added) + " rule(s)" + (dup ? ", " + std::to_string(dup) + " already present" : "");
    return e;
}

RulesMgr::Edit RulesMgr::remove_from(Src& s, const std::set<std::string>& canons) {
    std::string out;
    size_t removed = 0;
    std::set<std::string> found;
    for (const std::string& line : split(s.authorized, '\n')) {
        LineResult lr = parse_rule_line(line);
        if (lr.rule) {
            std::string c = (s.allow_only ? as_allow(*lr.rule) : *lr.rule).canon();
            if (canons.count(c)) { ++removed; found.insert(c); continue; }
        }
        out += line + "\n";
    }
    while (out.size() > 1 && out[out.size() - 1] == '\n' && out[out.size() - 2] == '\n') out.pop_back();
    Edit e;
    if (removed == 0) { e.ok = true; e.msg = "no matching rules found"; return e; }
    s.authorized = out;
    persist_locked(s);
    if (!vault::write(s.path, out, 0600, true)) { e.msg = "cannot write the " + s.label + " store"; return e; }
    publish_locked(true);
    s.last_sig = file_sig(s.path);
    processed_ |= s.bit;
    e.ok = true;
    e.msg = "removed " + std::to_string(removed) + " rule line(s)";
    for (const std::string& c : canons) if (!found.count(c)) e.msg += "; not found: " + c;
    return e;
}

RulesMgr::Edit RulesMgr::add(const std::vector<Rule>& rules) { std::lock_guard<std::mutex> g(mu_); return add_to(kw_, rules); }
RulesMgr::Edit RulesMgr::remove(const std::set<std::string>& c) { std::lock_guard<std::mutex> g(mu_); return remove_from(kw_, c); }
RulesMgr::Edit RulesMgr::allow(const std::vector<Rule>& rules) { std::lock_guard<std::mutex> g(mu_); return add_to(wl_, rules); }
RulesMgr::Edit RulesMgr::unallow(const std::set<std::string>& c) { std::lock_guard<std::mutex> g(mu_); return remove_from(wl_, c); }

std::string RulesMgr::authorized_text() { std::lock_guard<std::mutex> g(mu_); return kw_.authorized; }
std::string RulesMgr::whitelist_text() { std::lock_guard<std::mutex> g(mu_); return wl_.authorized; }

std::string RulesMgr::summary() {
    std::lock_guard<std::mutex> g(mu_);
    size_t wl = RuleSet::build(parse(wl_, wl_.authorized).rules, {})->allow_rules();
    return std::to_string(blocks_) + " block rules, " + std::to_string(allows_) + " allow rules (" + std::to_string(wl) +
           " in the whitelist), +" + std::to_string(builtin_.size()) + " built-in; last reload " +
           human_duration(unix_now() - reloaded_at_) + " ago";
}

}  // namespace blk
