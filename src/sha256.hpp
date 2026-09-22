// sha256.hpp - SHA-256, HMAC-SHA256 and PBKDF2-HMAC-SHA256 (no external crypto dependency).
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace blk {

class Sha256 {
public:
    Sha256();
    void update(const void* data, size_t len);
    void final(uint8_t out[32]);
    void reset();  // restores to initial state; called automatically by final()

private:
    void compress(const uint8_t* block);
    uint32_t h_[8];
    uint8_t buf_[64];
    size_t buflen_;
    uint64_t total_;
};

void sha256(const void* data, size_t len, uint8_t out[32]);
void hmac_sha256(const uint8_t* key, size_t klen, const uint8_t* msg, size_t mlen, uint8_t out[32]);
void pbkdf2_sha256(const std::string& password, const uint8_t* salt, size_t saltlen, uint32_t iterations,
                   uint8_t* out, size_t outlen);
bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n);  // constant-time compare

}  // namespace blk
