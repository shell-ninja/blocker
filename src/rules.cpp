#include "rules.hpp"

#include <arpa/inet.h>

#include "util.hpp"

namespace blk {

std::string Rule::canon() const {
    // Canonical forms must parse back to the same kind (a single label is only a TLD when written ".tld").
    const bool one_label = value.find('.') == std::string::npos;
    switch (kind) {
        case RuleKind::Exact: return "=" + value;
        case RuleKind::Keyword: return "kw:" + value;
        case RuleKind::Allow: return one_label ? "!." + value : "!" + value;
        case RuleKind::AllowExact: return "!=" + value;
        case RuleKind::AllowGlob: return "!" + value;
        case RuleKind::AllowKeyword: return "!kw:" + value;
        case RuleKind::Suffix: return one_label ? "." + value : value;
        default: return value;  // Glob
    }
}

Rule as_allow(const Rule& r) {
    Rule a = r;
    switch (r.kind) {
        case RuleKind::Suffix: a.kind = RuleKind::Allow; break;
        case RuleKind::Exact: a.kind = RuleKind::AllowExact; break;
        case RuleKind::Glob: a.kind = RuleKind::AllowGlob; break;
        case RuleKind::Keyword: a.kind = RuleKind::AllowKeyword; break;
        default: break;
    }
    return a;
}

namespace {

bool valid_char(char c, bool allow_wild) {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' ||
           (allow_wild && (c == '*' || c == '?'));
}

// Validates a plain domain: [a-z0-9_-] labels separated by single dots.
std::string check_domain(std::string& d) {
    while (!d.empty() && d.front() == '.') d.erase(d.begin());
    while (!d.empty() && d.back() == '.') d.pop_back();
    if (d.empty()) return "empty domain";
    if (d.size() > 253) return "domain too long";
    size_t label = 0;
    for (char c : d) {
        if (!valid_char(c, false)) return std::string("invalid character '") + c + "' (use punycode for non-ASCII names)";
        if (c == '.') {
            if (label == 0) return "empty label";
            label = 0;
        } else if (++label > 63) {
            return "label longer than 63 characters";
        }
    }
    if (label == 0) return "empty label";
    return "";
}

bool is_ip(const std::string& s) {
    unsigned char buf[16];
    return inet_pton(AF_INET, s.c_str(), buf) == 1 || inet_pton(AF_INET6, s.c_str(), buf) == 1;
}

bool is_hosts_boilerplate(const std::string& h) {
    static const char* names[] = {"localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost",
                                  "ip6-loopback", "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes",
                                  "ip6-allrouters", "ip6-allhosts", "0.0.0.0"};
    for (const char* n : names)
        if (h == n) return true;
    return false;
}

}  // namespace

LineResult parse_rule_line(std::string_view raw) {
    LineResult res;
    std::string s(raw);
    size_t hash = s.find('#');
    if (hash != std::string::npos) s.erase(hash);
    s = to_lower(trim(s));
    if (s.empty()) return res;

    std::vector<std::string> toks = split_ws(s);
    if (toks.size() == 2 && is_ip(toks[0])) {  // hosts-file format
        if (is_hosts_boilerplate(toks[1])) return res;
        s = toks[1];
    } else if (toks.size() != 1) {
        res.error = "unexpected whitespace";
        return res;
    }
    if (s.find('/') != std::string::npos || s.find("://") != std::string::npos) {
        res.error = "URL paths/queries cannot be enforced by a DNS filter; use a domain, glob or kw: rule";
        return res;
    }

    bool allow = false;
    if (s[0] == '!') {
        allow = true;
        s.erase(0, 1);
        if (s.empty()) { res.error = "empty allow rule"; return res; }
    }
    Rule r;
    if (s[0] == '=') {
        r.kind = RuleKind::Exact;
        s.erase(0, 1);
        std::string e = check_domain(s);
        if (!e.empty()) { res.error = e; return res; }
        r.value = s;
    } else if (starts_with(s, "kw:")) {
        r.kind = RuleKind::Keyword;
        s.erase(0, 3);
        if (s.size() < 3) { res.error = "keyword must be at least 3 characters"; return res; }
        for (char c : s)
            if (!valid_char(c, false)) { res.error = "keyword may only contain a-z 0-9 - _ ."; return res; }
        r.value = s;
    } else if (s.find_first_of("*?") != std::string::npos) {
        r.kind = RuleKind::Glob;
        size_t literal = 0;
        for (char c : s) {
            if (!valid_char(c, true)) { res.error = std::string("invalid character '") + c + "' in glob"; return res; }
            if (c != '*' && c != '?') ++literal;
        }
        if (literal < 3) { res.error = "glob needs at least 3 literal characters"; return res; }
        r.value = s;
    } else {
        const bool leading_dot = s[0] == '.';
        std::string e = check_domain(s);
        if (!e.empty()) { res.error = e; return res; }
        if (!leading_dot && s.find('.') == std::string::npos) {
            // A bare word is a keyword (substring of the hostname). TLDs are written ".xxx".
            r.kind = RuleKind::Keyword;
            if (s.size() < 3) { res.error = "a bare word must be at least 3 characters (write .tld for a TLD)"; return res; }
        } else {
            r.kind = RuleKind::Suffix;
        }
        r.value = s;
    }
    if (allow) r = as_allow(r);
    res.rule = r;
    return res;
}

ParsedText parse_text(std::string_view text, bool allow_only, const char* label) {
    ParsedText out;
    int lineno = 0;
    for (const std::string& line : split(text, '\n')) {
        ++lineno;
        LineResult lr = parse_rule_line(line);
        if (!lr.error.empty()) out.warnings.push_back(std::string(label) + " line " + std::to_string(lineno) + ": " + lr.error);
        else if (lr.rule) out.rules.push_back(allow_only ? as_allow(*lr.rule) : *lr.rule);
    }
    return out;
}

bool glob_match(std::string_view p, std::string_view s) {
    size_t pi = 0, si = 0, star = std::string_view::npos, mark = 0;
    while (si < s.size()) {
        if (pi < p.size() && p[pi] == '*') {
            star = pi++;
            mark = si;
        } else if (pi < p.size() && (p[pi] == '?' || p[pi] == s[si])) {
            ++pi;
            ++si;
        } else if (star != std::string_view::npos) {
            pi = star + 1;
            si = ++mark;
        } else {
            return false;
        }
    }
    while (pi < p.size() && p[pi] == '*') ++pi;
    return pi == p.size();
}

std::shared_ptr<const RuleSet> RuleSet::build(const std::vector<Rule>& rules, const std::vector<std::string>& builtin) {
    auto rs = std::make_shared<RuleSet>();
    // "*word*" (no other wildcard) is a plain substring search - much cheaper than a glob.
    auto substring_of = [](const std::string& g, std::string& out) {
        if (g.size() > 2 && g.front() == '*' && g.back() == '*' && g.find_first_of("*?", 1) == g.size() - 1) {
            out = g.substr(1, g.size() - 2);
            return true;
        }
        return false;
    };
    for (const Rule& r : rules) {
        std::string sub;
        switch (r.kind) {
            case RuleKind::Allow: rs->allow_.insert(r.value); rs->allow_canon.insert(r.canon()); break;
            case RuleKind::AllowExact: rs->allow_exact_.insert(r.value); rs->allow_canon.insert(r.canon()); break;
            case RuleKind::AllowKeyword: rs->allow_kw_.push_back(r.value); rs->allow_canon.insert(r.canon()); break;
            case RuleKind::AllowGlob:
                rs->allow_canon.insert(r.canon());
                if (substring_of(r.value, sub)) rs->allow_sub_.push_back(sub); else rs->allow_globs_.push_back(r.value);
                break;
            case RuleKind::Suffix: rs->suffix_.insert(r.value); rs->block_canon.insert(r.canon()); break;
            case RuleKind::Exact: rs->exact_.insert(r.value); rs->block_canon.insert(r.canon()); break;
            case RuleKind::Keyword: rs->keywords_.push_back(r.value); rs->block_canon.insert(r.canon()); break;
            case RuleKind::Glob:
                rs->block_canon.insert(r.canon());
                if (substring_of(r.value, sub)) rs->substrings_.push_back(sub); else rs->globs_.push_back(r.value);
                break;
        }
    }
    for (const std::string& b : builtin) rs->builtin_.insert(b);
    return rs;
}

// True if EVERY occurrence of `needle` inside `text` lies within an occurrence of some whitelisted word.
bool RuleSet::covered(std::string_view text, std::string_view needle) const {
    if (allow_kw_.empty() && allow_sub_.empty()) return false;
    size_t pos = 0;
    bool any = false;
    while ((pos = text.find(needle, pos)) != std::string_view::npos) {
        any = true;
        const size_t end = pos + needle.size();
        bool cov = false;
        for (const auto* list : {&allow_kw_, &allow_sub_}) {
            for (const std::string& a : *list) {
                size_t q = end > a.size() ? end - a.size() : 0;  // earliest start that still reaches `end`
                for (; q <= pos && q + a.size() <= text.size(); ++q)
                    if (text.compare(q, a.size(), a) == 0) { cov = true; break; }
                if (cov) break;
            }
            if (cov) break;
        }
        if (!cov) return false;
        ++pos;
    }
    return any;
}

Verdict RuleSet::check(std::string_view host) const {
    Verdict v;
    if (host.empty()) return v;
    thread_local std::string buf;
    auto walk = [&](const std::unordered_set<std::string>& set, std::string& hit) {
        std::string_view s = host;
        for (;;) {
            buf.assign(s.data(), s.size());
            if (set.count(buf)) { hit = buf; return true; }
            size_t dot = s.find('.');
            if (dot == std::string_view::npos) return false;
            s.remove_prefix(dot + 1);
        }
    };
    std::string hit;

    // 1) whitelisted domain / exact host wins over everything
    if (!allow_.empty() && walk(allow_, hit)) { v.reason = "whitelisted domain " + hit; return v; }
    if (!allow_exact_.empty()) {
        buf.assign(host.data(), host.size());
        if (allow_exact_.count(buf)) { v.reason = "whitelisted host " + buf; return v; }
    }
    // 2) built-in DoH/DoT bypass list
    if (!builtin_.empty() && walk(builtin_, hit)) { v.blocked = v.builtin = true; v.reason = "built-in bypass list " + hit; return v; }
    // 3) explicit blocks: exact host, domain + subdomains (never overridden by word/glob whitelists)
    if (!exact_.empty()) {
        buf.assign(host.data(), host.size());
        if (exact_.count(buf)) { v.blocked = true; v.reason = "host " + buf; return v; }
    }
    if (!suffix_.empty() && walk(suffix_, hit)) { v.blocked = true; v.reason = "domain " + hit; return v; }

    // 4) fuzzy blocks: keywords, *word* globs, general globs - subject to word/glob whitelists
    if (keywords_.empty() && substrings_.empty() && globs_.empty()) return v;
    for (const std::string& g : allow_globs_)
        if (glob_match(g, host)) { v.reason = "whitelisted by glob " + g; return v; }

    std::string note;
    const bool has_sep = host.find('-') != std::string_view::npos || host.find('_') != std::string_view::npos;
    std::string compact;
    std::string norm_host;
    if (has_sep && (!keywords_.empty() || !substrings_.empty())) {
        for (char c : host) {
            if (c != '-' && c != '_') compact.push_back(c);
            norm_host.push_back(c == '_' ? '-' : c);
        }
    }

    auto is_delim = [](char c) {
        return c == '-' || c == '_' || c == '.' || c == '\0';
    };

    for (const std::string& k : keywords_) {
        if (k.empty()) continue;

        // 1) Keyword has leading and/or trailing delimiters: e.g. _porn_, -porn-, _porn, porn_
        const bool lead_sep = (k.front() == '-' || k.front() == '_');
        const bool trail_sep = (k.back() == '-' || k.back() == '_');

        if (lead_sep || trail_sep) {
            size_t start = 0;
            while (start < k.size() && (k[start] == '-' || k[start] == '_')) ++start;
            size_t finish = k.size();
            while (finish > start && (k[finish - 1] == '-' || k[finish - 1] == '_')) --finish;
            std::string core = k.substr(start, finish - start);

            if (!core.empty()) {
                size_t pos = 0;
                bool found = false;
                while ((pos = host.find(core, pos)) != std::string_view::npos) {
                    const size_t end = pos + core.size();
                    const char left = (pos > 0) ? host[pos - 1] : '\0';
                    const char right = (end < host.size()) ? host[end] : '\0';
                    const bool left_ok = !lead_sep || is_delim(left);
                    const bool right_ok = !trail_sep || is_delim(right);
                    if (left_ok && right_ok) {
                        found = true;
                        break;
                    }
                    ++pos;
                }
                if (found) {
                    if (covered(host, core)) {
                        note = "keyword '" + k + "' only occurs inside whitelisted word(s)";
                    } else {
                        v.blocked = true;
                        v.reason = "keyword " + k;
                        return v;
                    }
                }
            }
            continue;
        }

        // 2) Exact substring match in host
        if (host.find(k) != std::string_view::npos) {
            if (covered(host, k)) { note = "keyword '" + k + "' only occurs inside whitelisted word(s)"; continue; }
            v.blocked = true; v.reason = "keyword " + k; return v;
        }

        // 3) Separator normalized match (_ and - interchangeable)
        const bool k_has_sep = k.find('-') != std::string::npos || k.find('_') != std::string::npos;
        if (has_sep || k_has_sep) {
            std::string norm_k = k;
            for (char& c : norm_k) if (c == '_') c = '-';
            const std::string& h_to_search = has_sep ? norm_host : std::string(host);
            if (h_to_search.find(norm_k) != std::string::npos) {
                if (covered(h_to_search, norm_k)) { note = "keyword '" + k + "' only occurs inside whitelisted word(s)"; continue; }
                v.blocked = true; v.reason = "keyword " + k; return v;
            }

            // 4) Compact match (ignoring - and _)
            std::string compact_k;
            for (char c : k) if (c != '-' && c != '_') compact_k.push_back(c);
            const std::string& c_to_search = has_sep ? compact : std::string(host);
            if (!compact_k.empty() && c_to_search.find(compact_k) != std::string::npos) {
                if (covered(c_to_search, compact_k)) { note = "keyword '" + k + "' only occurs inside whitelisted word(s)"; continue; }
                v.blocked = true; v.reason = "keyword " + k; return v;
            }
        }
    }

    for (const std::string& k : substrings_) {
        bool match = (host.find(k) != std::string_view::npos);
        const bool k_has_sep = k.find('-') != std::string::npos || k.find('_') != std::string::npos;
        if (!match && (has_sep || k_has_sep)) {
            std::string norm_k = k;
            for (char& c : norm_k) if (c == '_') c = '-';
            const std::string& h_to_search = has_sep ? norm_host : std::string(host);
            if (h_to_search.find(norm_k) != std::string::npos) match = true;
            if (!match) {
                std::string compact_k;
                for (char c : k) if (c != '-' && c != '_') compact_k.push_back(c);
                const std::string& c_to_search = has_sep ? compact : std::string(host);
                if (!compact_k.empty() && c_to_search.find(compact_k) != std::string::npos) match = true;
            }
        }
        if (!match) continue;
        if (covered(host, k)) { note = "glob *" + k + "* only matches inside whitelisted word(s)"; continue; }
        v.blocked = true; v.reason = "glob *" + k + "*"; return v;
    }
    for (const std::string& g : globs_) {
        if (!glob_match(g, host)) continue;
        bool rescued = false;  // coarse: any whitelisted word present in the host rescues a general glob
        for (const auto* list : {&allow_kw_, &allow_sub_})
            for (const std::string& a : *list)
                if (host.find(a) != std::string_view::npos) rescued = true;
        if (rescued) { note = "glob " + g + " overridden by a whitelisted word"; continue; }
        v.blocked = true; v.reason = "glob " + g; return v;
    }
    v.reason = note;
    return v;
}

}  // namespace blk
