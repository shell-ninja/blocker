#include "sha256.hpp"

#include <algorithm>
#include <cstring>
#include <vector>

namespace blk {

namespace {
const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
}  // namespace

Sha256::Sha256() : buflen_(0), total_(0) {
    static const uint32_t init[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(h_, init, sizeof h_);
    memset(buf_, 0, sizeof buf_);
}

void Sha256::compress(const uint8_t* p) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i)
        w[i] = (uint32_t(p[4 * i]) << 24) | (uint32_t(p[4 * i + 1]) << 16) | (uint32_t(p[4 * i + 2]) << 8) | uint32_t(p[4 * i + 3]);
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4], f = h_[5], g = h_[6], h = h_[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d; h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += h;
}

void Sha256::update(const void* data, size_t len) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    total_ += len;
    if (buflen_) {
        size_t take = std::min(len, sizeof buf_ - buflen_);
        memcpy(buf_ + buflen_, p, take);
        buflen_ += take; p += take; len -= take;
        if (buflen_ == 64) { compress(buf_); buflen_ = 0; }
    }
    while (len >= 64) { compress(p); p += 64; len -= 64; }
    if (len) { memcpy(buf_, p, len); buflen_ = len; }
}

void Sha256::final(uint8_t out[32]) {
    uint64_t bits = total_ * 8;
    buf_[buflen_++] = 0x80;
    if (buflen_ > 56) {
        memset(buf_ + buflen_, 0, 64 - buflen_);
        compress(buf_);
        buflen_ = 0;
    }
    memset(buf_ + buflen_, 0, 56 - buflen_);
    for (int i = 0; i < 8; ++i) buf_[56 + i] = uint8_t(bits >> (56 - 8 * i));
    compress(buf_);
    for (int i = 0; i < 8; ++i) {
        out[4 * i] = uint8_t(h_[i] >> 24); out[4 * i + 1] = uint8_t(h_[i] >> 16);
        out[4 * i + 2] = uint8_t(h_[i] >> 8); out[4 * i + 3] = uint8_t(h_[i]);
    }
}

void sha256(const void* data, size_t len, uint8_t out[32]) {
    Sha256 s;
    s.update(data, len);
    s.final(out);
}

namespace {
// HMAC with precomputed inner/outer key blocks so PBKDF2 needs only two compressions per iteration.
struct HmacCtx {
    Sha256 inner, outer;
    HmacCtx(const uint8_t* key, size_t klen) {
        uint8_t k[64] = {0};
        if (klen > 64) sha256(key, klen, k); else if (klen) memcpy(k, key, klen);
        uint8_t ipad[64], opad[64];
        for (int i = 0; i < 64; ++i) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
        inner.update(ipad, 64);
        outer.update(opad, 64);
    }
    void mac(const uint8_t* msg, size_t mlen, uint8_t out[32]) const {
        Sha256 i = inner;
        i.update(msg, mlen);
        uint8_t ih[32];
        i.final(ih);
        Sha256 o = outer;
        o.update(ih, 32);
        o.final(out);
    }
};
}  // namespace

void hmac_sha256(const uint8_t* key, size_t klen, const uint8_t* msg, size_t mlen, uint8_t out[32]) {
    HmacCtx(key, klen).mac(msg, mlen, out);
}

void pbkdf2_sha256(const std::string& password, const uint8_t* salt, size_t saltlen, uint32_t iterations,
                   uint8_t* out, size_t outlen) {
    HmacCtx h(reinterpret_cast<const uint8_t*>(password.data()), password.size());
    std::vector<uint8_t> s(salt, salt + saltlen);
    s.resize(saltlen + 4);
    size_t produced = 0;
    for (uint32_t block = 1; produced < outlen; ++block) {
        s[saltlen] = uint8_t(block >> 24); s[saltlen + 1] = uint8_t(block >> 16);
        s[saltlen + 2] = uint8_t(block >> 8); s[saltlen + 3] = uint8_t(block);
        uint8_t u[32], t[32];
        h.mac(s.data(), s.size(), u);
        memcpy(t, u, 32);
        for (uint32_t i = 1; i < iterations; ++i) {
            h.mac(u, 32, u);
            for (int j = 0; j < 32; ++j) t[j] ^= u[j];
        }
        size_t take = std::min<size_t>(32, outlen - produced);
        memcpy(out + produced, t, take);
        produced += take;
    }
}

bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) diff |= uint8_t(a[i] ^ b[i]);
    return diff == 0;
}

}  // namespace blk
