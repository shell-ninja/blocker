// dns.hpp - minimal DNS wire-format parsing and reply construction (RFC 1035 / 6891).
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace blk::dns {

constexpr uint16_t T_A = 1, T_CNAME = 5, T_AAAA = 28, T_OPT = 41, T_SVCB = 64, T_HTTPS = 65;
constexpr uint8_t RC_NOERROR = 0, RC_FORMERR = 1, RC_SERVFAIL = 2, RC_NXDOMAIN = 3, RC_NOTIMP = 4;

struct Edns {
    bool present = false;
    bool do_bit = false;
    uint16_t udp_size = 512;
};

struct Query {
    uint16_t id = 0;
    uint16_t flags = 0;
    std::string name;  // lower-case, dotted, no trailing dot ("" is the root)
    uint16_t qtype = 0, qclass = 0;
    size_t qend = 0;  // offset just past the question section
    Edns edns;
};

enum class Parse { Ok, Drop, FormErr };

inline uint16_t rd16(const uint8_t* p) { return uint16_t((p[0] << 8) | p[1]); }
inline uint32_t rd32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}
inline void put16(std::vector<uint8_t>& v, uint16_t x) { v.push_back(uint8_t(x >> 8)); v.push_back(uint8_t(x)); }
inline void put32(std::vector<uint8_t>& v, uint32_t x) { put16(v, uint16_t(x >> 16)); put16(v, uint16_t(x)); }

// Parses a client query. Responses are Drop; anything with != 1 question is FormErr.
Parse parse_query(const uint8_t* buf, size_t len, Query& q);

// A resource record located inside a message (offsets refer to the message buffer).
struct Rr {
    uint16_t type = 0, cls = 0;
    uint32_t ttl = 0;
    size_t ttl_off = 0, rdata_off = 0;
    uint16_t rdlen = 0;
    int section = 0;  // 0 answer, 1 authority, 2 additional
};
bool walk_records(const uint8_t* buf, size_t len, std::vector<Rr>& out);

struct Addr {
    uint16_t type = 0;  // T_A or T_AAAA
    uint32_t ttl = 0;
    std::vector<uint8_t> data;
};
std::vector<Addr> extract_addrs(const uint8_t* buf, size_t len, uint16_t want_type);

// Reply builders (all copy the client's question section and id).
std::vector<uint8_t> reply_sinkhole(const uint8_t* pkt, const Query& q, uint32_t ttl);  // A->0.0.0.0, AAAA->::, else NODATA
// Blocked-name answer with chosen addresses: A -> v4 (4 bytes) if given, AAAA -> v6 (16 bytes) if given, any other
// case (or a missing address) -> NODATA. Used to point blocked names at the local redirect server.
std::vector<uint8_t> reply_addrs(const uint8_t* pkt, const Query& q, uint32_t ttl, const uint8_t* v4, const uint8_t* v6);
std::vector<uint8_t> reply_rcode(const uint8_t* pkt, const Query& q, uint8_t rcode);
std::vector<uint8_t> reply_formerr(const uint8_t* pkt, size_t len);
std::vector<uint8_t> reply_cname(const uint8_t* pkt, const Query& q, const std::string& target, uint32_t ttl,
                                 const std::vector<Addr>& addrs);
std::vector<uint8_t> reply_truncated(const std::vector<uint8_t>& full, size_t qend);

bool encode_name(const std::string& name, std::vector<uint8_t>& out);
std::vector<uint8_t> make_query(const std::string& name, uint16_t qtype, uint16_t id);

// Does `resp` answer the question in `q` (same id, QR set, same question, ignoring case)?
bool response_matches(const uint8_t* qpkt, const Query& q, const uint8_t* resp, size_t rlen);

inline uint8_t rcode_of(const std::vector<uint8_t>& r) { return r.size() >= 4 ? uint8_t(r[3] & 0x0f) : uint8_t(RC_SERVFAIL); }
inline bool is_truncated(const std::vector<uint8_t>& r) { return r.size() >= 4 && (r[2] & 0x02); }

// Smallest TTL over all non-OPT records (false if there are none or the message is malformed).
bool min_ttl(const std::vector<uint8_t>& msg, uint32_t& ttl);
// Subtract `elapsed` seconds from every non-OPT TTL (floor of 1).
void patch_ttls(std::vector<uint8_t>& msg, uint32_t elapsed);

}  // namespace blk::dns
