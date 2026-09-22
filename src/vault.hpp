// vault.hpp - the hidden rule store.
//
// The block rules and the whitelist (and their authorised baselines) live in a root-only directory under neutral
// names and are never plain text on disk: each file is  nonce(16) | ciphertext | tag(16)  where the ciphertext is the
// text XOR an HMAC-SHA256 keystream and the tag authenticates it. The key is 32 random bytes made at install time
// and kept in the vault (0600, immutable). So `cat`, `grep -r`, `find` and an editor show nothing usable, a
// hand-edit breaks the tag (and is reverted by the tamper ratchet), and `blocker list` needs an unlock window.
//
// Honest limits: this is obscurity plus integrity, not secrecy against root who has this source code - root can read
// the key and decode. What actually stops *changes* is the immutable flag and the ratchet in rulesmgr.
//
// Robustness: a file that is neither valid vault data nor plain text (key lost, file corrupted) counts as *missing*;
// the daemon then falls back to the rule list compiled into the binary - never to an empty list.
// A plain-text file (someone replaced it by hand) is accepted as an edit and re-scrambled after the ratchet check.
#pragma once

#include <string>

namespace blk::vault {

enum class Kind { Missing, Decoded, Plain, Undecodable };

// Loads the key from the vault; creates it if `create` and missing. Returns false if there is no key afterwards.
bool ensure_key(bool create);
// Drops the in-memory key (tests: to simulate a lost key). The file, if any, is untouched.
void forget_key();
// Daemon housekeeping (~1/s): if the key file vanished or changed, rewrite it from memory. Returns true if it acted.
bool verify_key();

std::string encode(const std::string& plain);                  // needs the key
Kind decode(const std::string& raw, std::string& plain);        // Decoded / Plain / Undecodable
Kind read(const std::string& path, std::string& plain);         // Missing if the file does not exist
bool write(const std::string& path, const std::string& plain, unsigned mode = 0600, bool lock = true);

// Moves plain-text rule files of earlier versions (and their baselines) into the vault, then removes them.
// Safe to call repeatedly. Returns the number of files migrated.
int migrate_legacy();

}  // namespace blk::vault
