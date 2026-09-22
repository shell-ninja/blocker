// rules.hpp - the keyword/domain rule language and the matching engine.
//
//   # comment                blank lines and trailing "# ..." are ignored
//   example.com              blocks example.com and every subdomain
//   .xxx                     blocks a whole TLD / suffix
//   porn   kw:porn           a bare word (no dot) is a KEYWORD: blocks any hostname containing it
//                            (also with '-' removed, so "free-porn.net" matches "freeporn")
//   =example.com             blocks exactly that host (subdomains stay allowed)
//   *.example.com            glob over the whole hostname: '*' = any run, '?' = one char
//   *porn*   sex?.net        (subdomains only for *.x; substring for *word*)
//   !example.com             ALLOW (whitelist): exempts example.com + subdomains from every block rule
//   !=host  !word  !*glob*   allow exactly that host / hostnames containing a word / a glob. Word and
//                            glob allows only exempt *keyword and glob* blocks, and only where the
//                            allowed word covers the blocked one ("analytics" rescues "anal" inside
//                            "analytics", nothing else). Explicit domain blocks are never overridden.
//   0.0.0.0 example.com      hosts-file lines are accepted too (handy for imported blocklists)
#pragma once

#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace blk {

enum class RuleKind { Suffix, Exact, Glob, Keyword, Allow, AllowExact, AllowGlob, AllowKeyword };

struct Rule {
    RuleKind kind = RuleKind::Suffix;
    std::string value;
    std::string canon() const;  // normalised text form; used for de-duplication and the tamper ratchet
    bool is_allow() const {
        return kind == RuleKind::Allow || kind == RuleKind::AllowExact || kind == RuleKind::AllowGlob || kind == RuleKind::AllowKeyword;
    }
};

struct LineResult {
    std::optional<Rule> rule;  // empty for blank/comment lines and for errors
    std::string error;         // non-empty when the line is invalid
};
LineResult parse_rule_line(std::string_view line);
Rule as_allow(const Rule& r);  // Suffix->Allow, Exact->AllowExact, Glob->AllowGlob, Keyword->AllowKeyword

struct ParsedText {
    std::vector<Rule> rules;
    std::vector<std::string> warnings;
};
// allow_only: every rule of the text is turned into an allow rule (used for the whitelist).
ParsedText parse_text(std::string_view text, bool allow_only = false, const char* label = "rules");

struct Verdict {
    bool blocked = false;
    bool builtin = false;  // blocked by the built-in DoH/DoT bypass list rather than a user rule
    std::string reason;    // for blocks: the rule; for allows: why a matching rule was overridden (may be empty)
};

class RuleSet {
public:
    // `builtin_suffixes` are extra, non-removable domain rules (e.g. DoH providers).
    static std::shared_ptr<const RuleSet> build(const std::vector<Rule>& rules,
                                                const std::vector<std::string>& builtin_suffixes);
    Verdict check(std::string_view host) const;  // host must be lower-case without trailing dot

    size_t block_rules() const { return block_canon.size(); }
    size_t allow_rules() const { return allow_canon.size(); }
    std::set<std::string> block_canon, allow_canon;  // file rules only (builtin excluded)

private:
    bool covered(std::string_view text, std::string_view needle) const;
    std::unordered_set<std::string> allow_, allow_exact_, suffix_, exact_, builtin_;
    std::vector<std::string> globs_, keywords_, substrings_;
    std::vector<std::string> allow_kw_, allow_sub_, allow_globs_;
};

bool glob_match(std::string_view pattern, std::string_view text);

}  // namespace blk
