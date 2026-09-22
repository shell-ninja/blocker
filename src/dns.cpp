#include "dns.hpp"

#include <cstring>

namespace blk::dns {

namespace {
char sanitize(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return char(c + 32);
    if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') return char(c);
    return '_';
}

bool skip_name(const uint8_t* b, size_t n, size_t& pos) {
    for (int guard = 0; guard < 130; ++guard) {
        if (pos >= n) return false;
        uint8_t l = b[pos];
        if (l == 0) { ++pos; return true; }
        if ((l & 0xC0) == 0xC0) {
            if (pos + 2 > n) return false;
            pos += 2;
            return true;
        }
        if (l & 0xC0) return false;
        pos += 1 + size_t(l);
        if (pos > n) return false;
    }
    return false;
}

std::vector<uint8_t> reply_head(const uint8_t* pkt, const Query& q, uint8_t rcode, uint16_t ancount) {
    std::vector<uint8_t> r;
    r.reserve(q.qend + 64);
    put16(r, q.id);
    uint16_t fl = uint16_t(0x8000 | (q.flags & 0x7800) | (q.flags & 0x0100) | 0x0080 | (q.flags & 0x0010) | rcode);
    put16(r, fl);
    put16(r, 1);
    put16(r, ancount);
    put16(r, 0);
    put16(r, 0);
    r.insert(r.end(), pkt + 12, pkt + q.qend);
    return r;
}
}  // namespace

bool walk_records(const uint8_t* b, size_t n, std::vector<Rr>& out) {
    out.clear();
    if (n < 12) return false;
    uint16_t qd = rd16(b + 4), an = rd16(b + 6), ns = rd16(b + 8), ar = rd16(b + 10);
    size_t pos = 12;
    for (uint16_t i = 0; i < qd; ++i) {
        if (!skip_name(b, n, pos) || pos + 4 > n) return false;
        pos += 4;
    }
    size_t total = size_t(an) + ns + ar;
    for (size_t i = 0; i < total; ++i) {
        if (!skip_name(b, n, pos) || pos + 10 > n) return false;
        Rr r;
        r.type = rd16(b + pos);
        r.cls = rd16(b + pos + 2);
        r.ttl_off = pos + 4;
        r.ttl = rd32(b + pos + 4);
        r.rdlen = rd16(b + pos + 8);
        r.rdata_off = pos + 10;
        if (r.rdata_off + r.rdlen > n) return false;
        r.section = i < an ? 0 : (i < size_t(an) + ns ? 1 : 2);
        out.push_back(r);
        pos = r.rdata_off + r.rdlen;
    }
    return true;
}

Parse parse_query(const uint8_t* b, size_t n, Query& q) {
    if (n < 12) return Parse::Drop;
    q.id = rd16(b);
    q.flags = rd16(b + 2);
    if (q.flags & 0x8000) return Parse::Drop;  // that is a response, not a query
    if (rd16(b + 4) != 1) return Parse::FormErr;
    size_t pos = 12, total = 0;
    std::string name;
    for (;;) {
        if (pos >= n) return Parse::FormErr;
        uint8_t len = b[pos++];
        if (len == 0) break;
        if ((len & 0xC0) || len > 63 || pos + len > n) return Parse::FormErr;  // no compression in a question
        total += size_t(len) + 1;
        if (total > 255) return Parse::FormErr;
        if (!name.empty()) name.push_back('.');
        for (size_t i = 0; i < len; ++i) name.push_back(sanitize(b[pos + i]));
        pos += len;
    }
    if (pos + 4 > n) return Parse::FormErr;
    q.qtype = rd16(b + pos);
    q.qclass = rd16(b + pos + 2);
    q.qend = pos + 4;
    q.name = name;
    q.edns = Edns{};
    std::vector<Rr> rrs;
    if (walk_records(b, n, rrs)) {
        for (const Rr& r : rrs) {
            if (r.type == T_OPT && r.section == 2) {
                q.edns.present = true;
                q.edns.udp_size = r.cls < 512 ? 512 : r.cls;
                q.edns.do_bit = (r.ttl & 0x8000) != 0;
            }
        }
    }
    return Parse::Ok;
}

std::vector<Addr> extract_addrs(const uint8_t* b, size_t n, uint16_t want) {
    std::vector<Addr> out;
    std::vector<Rr> rrs;
    if (!walk_records(b, n, rrs)) return out;
    size_t need = want == T_A ? 4 : 16;
    for (const Rr& r : rrs) {
        if (r.section == 0 && r.type == want && r.cls == 1 && r.rdlen == need && out.size() < 16) {
            Addr a;
            a.type = want;
            a.ttl = r.ttl;
            a.data.assign(b + r.rdata_off, b + r.rdata_off + r.rdlen);
            out.push_back(std::move(a));
        }
    }
    return out;
}

std::vector<uint8_t> reply_sinkhole(const uint8_t* pkt, const Query& q, uint32_t ttl) {
    bool a = q.qtype == T_A, aaaa = q.qtype == T_AAAA;
    auto r = reply_head(pkt, q, RC_NOERROR, (a || aaaa) ? 1 : 0);
    if (a || aaaa) {
        put16(r, 0xC00C);  // pointer to the question name
        put16(r, q.qtype);
        put16(r, 1);
        put32(r, ttl);
        put16(r, a ? 4 : 16);
        r.insert(r.end(), a ? 4 : 16, uint8_t(0));  // 0.0.0.0 / ::
    }
    return r;
}

std::vector<uint8_t> reply_addrs(const uint8_t* pkt, const Query& q, uint32_t ttl, const uint8_t* v4, const uint8_t* v6) {
    const uint8_t* addr = q.qtype == T_A ? v4 : (q.qtype == T_AAAA ? v6 : nullptr);
    auto r = reply_head(pkt, q, RC_NOERROR, addr ? 1 : 0);
    if (addr) {
        put16(r, 0xC00C);
        put16(r, q.qtype);
        put16(r, 1);
        put32(r, ttl);
        size_t n = q.qtype == T_A ? 4 : 16;
        put16(r, uint16_t(n));
        r.insert(r.end(), addr, addr + n);
    }
    return r;
}

std::vector<uint8_t> reply_rcode(const uint8_t* pkt, const Query& q, uint8_t rcode) {
    return reply_head(pkt, q, rcode, 0);
}

std::vector<uint8_t> reply_formerr(const uint8_t* pkt, size_t len) {
    if (len < 2) return {};
    std::vector<uint8_t> r;
    put16(r, rd16(pkt));
    put16(r, uint16_t(0x8000 | 0x0080 | RC_FORMERR));
    put16(r, 0); put16(r, 0); put16(r, 0); put16(r, 0);
    return r;
}

bool encode_name(const std::string& name, std::vector<uint8_t>& out) {
    if (name.size() > 253) return false;
    size_t start = 0;
    while (start < name.size()) {
        size_t dot = name.find('.', start);
        size_t end = dot == std::string::npos ? name.size() : dot;
        size_t l = end - start;
        if (l == 0 || l > 63) return false;
        out.push_back(uint8_t(l));
        out.insert(out.end(), name.begin() + long(start), name.begin() + long(end));
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    out.push_back(0);
    return true;
}

std::vector<uint8_t> make_query(const std::string& name, uint16_t qtype, uint16_t id) {
    std::vector<uint8_t> r;
    put16(r, id);
    put16(r, 0x0100);  // RD
    put16(r, 1); put16(r, 0); put16(r, 0); put16(r, 0);
    if (!encode_name(name, r)) return {};
    put16(r, qtype);
    put16(r, 1);
    return r;
}

std::vector<uint8_t> reply_cname(const uint8_t* pkt, const Query& q, const std::string& target, uint32_t ttl,
                                 const std::vector<Addr>& addrs) {
    auto r = reply_head(pkt, q, RC_NOERROR, uint16_t(1 + addrs.size()));
    std::vector<uint8_t> enc;
    if (!encode_name(target, enc)) return reply_rcode(pkt, q, RC_SERVFAIL);
    put16(r, 0xC00C);
    put16(r, T_CNAME);
    put16(r, 1);
    put32(r, ttl);
    put16(r, uint16_t(enc.size()));
    size_t target_off = r.size();
    r.insert(r.end(), enc.begin(), enc.end());
    for (const Addr& a : addrs) {
        // DNS compression pointers are 14-bit (max 0x3FFF). If the packet grew beyond
        // that (theoretically only possible with an enormous query section), bail safely.
        if (target_off > 0x3FFF) return reply_rcode(pkt, q, RC_SERVFAIL);
        put16(r, uint16_t(0xC000 | target_off));  // owner = the CNAME target name written above
        put16(r, a.type);
        put16(r, 1);
        put32(r, a.ttl);
        put16(r, uint16_t(a.data.size()));
        r.insert(r.end(), a.data.begin(), a.data.end());
    }
    return r;
}

std::vector<uint8_t> reply_truncated(const std::vector<uint8_t>& full, size_t qend) {
    if (full.size() < 12) return full;
    if (qend > full.size() || qend < 12) qend = 12;
    std::vector<uint8_t> r(full.begin(), full.begin() + long(qend));
    r[2] |= 0x02;  // TC
    if (qend == 12) { r[4] = r[5] = 0; }
    for (int i = 6; i < 12; ++i) r[size_t(i)] = 0;
    return r;
}

bool response_matches(const uint8_t* qpkt, const Query& q, const uint8_t* r, size_t rlen) {
    if (rlen < 12 || rd16(r) != q.id || !(r[2] & 0x80) || rd16(r + 4) != 1) return false;
    size_t ql = q.qend - 12;
    if (rlen < 12 + ql) return false;
    for (size_t i = 0; i < ql; ++i) {
        unsigned char a = qpkt[12 + i], b = r[12 + i];
        if (a >= 'A' && a <= 'Z') a = (unsigned char)(a + 32);
        if (b >= 'A' && b <= 'Z') b = (unsigned char)(b + 32);
        if (a != b) return false;
    }
    return true;
}

bool min_ttl(const std::vector<uint8_t>& msg, uint32_t& ttl) {
    std::vector<Rr> rrs;
    if (!walk_records(msg.data(), msg.size(), rrs)) return false;
    bool any = false;
    uint32_t m = 0;
    for (const Rr& r : rrs) {
        if (r.type == T_OPT) continue;
        if (!any || r.ttl < m) m = r.ttl;
        any = true;
    }
    ttl = m;
    return any;
}

void patch_ttls(std::vector<uint8_t>& msg, uint32_t elapsed) {
    if (elapsed == 0) return;
    std::vector<Rr> rrs;
    if (!walk_records(msg.data(), msg.size(), rrs)) return;
    for (const Rr& r : rrs) {
        if (r.type == T_OPT) continue;
        uint32_t t = r.ttl > elapsed ? r.ttl - elapsed : 1;
        if (t < 1) t = 1;
        msg[r.ttl_off] = uint8_t(t >> 24); msg[r.ttl_off + 1] = uint8_t(t >> 16);
        msg[r.ttl_off + 2] = uint8_t(t >> 8); msg[r.ttl_off + 3] = uint8_t(t);
    }
}

}  // namespace blk::dns
