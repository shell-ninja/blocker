// engine.hpp - the DNS decision engine (block / SafeSearch / forward+cache) and the UDP/TCP server.
#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "config.hpp"
#include "dns.hpp"
#include "rules.hpp"

namespace blk {

struct Stats {
    std::atomic<uint64_t> total{0}, blocked{0}, cached{0}, forwarded{0}, safesearch{0}, failed{0}, redirected{0};
};

// Sharded TTL cache for upstream answers (blocked names never reach it).
class Cache {
public:
    Cache(size_t max_entries, uint32_t max_ttl);
    bool get(const std::string& key, std::vector<uint8_t>& out);
    void put(const std::string& key, std::vector<uint8_t> resp);

private:
    struct Entry {
        std::vector<uint8_t> resp;
        std::chrono::steady_clock::time_point stored;
        uint32_t ttl;
    };
    struct Shard {
        std::mutex m;
        std::unordered_map<std::string, Entry> map;
    };
    static constexpr size_t kShards = 16;
    std::array<Shard, kShards> shards_;
    size_t per_shard_;
    uint32_t max_ttl_;
    Shard& shard(const std::string& key);
};

// Built-in, non-removable block list of DoH/DoT providers (used when block_doh = yes).
const std::vector<std::string>& builtin_bypass_domains();

// Returns the host a name must be CNAME'd to for SafeSearch/Restricted Mode, or nullptr.
const char* safesearch_target(const std::string& host, bool search, bool youtube);

class Popup;
class Redirector;

class Engine {
public:
    explicit Engine(const Config& cfg);
    void set_rules(std::shared_ptr<const RuleSet> rs);
    std::shared_ptr<const RuleSet> rules() const;
    // Full request -> reply pipeline. An empty result means "send nothing".
    // client_port: UDP source port of the query (0 if unknown); only used to attribute popups to a user.
    std::vector<uint8_t> handle(const uint8_t* pkt, size_t len, bool tcp, uint16_t client_port = 0);
    void set_popup(Popup* p) { popup_ = p; }
    void set_redirect(Redirector* r) { redirect_ = r; }
    void set_exempt(std::vector<std::string> hosts) { exempt_ = std::move(hosts); }  // never blocked (redirect target)
    const Config& config() const { return cfg_; }
    Stats stats;

private:
    std::vector<uint8_t> resolve(const uint8_t* pkt, size_t len, const dns::Query& q, bool tcp, uint16_t client_port);
    std::vector<uint8_t> forward_cached(const uint8_t* pkt, size_t len, const dns::Query& q, bool tcp);
    std::vector<uint8_t> safesearch_reply(const uint8_t* pkt, const dns::Query& q, const char* target);
    bool upstream_query(const uint8_t* pkt, size_t len, const dns::Query& q, bool tcp, std::vector<uint8_t>& out);
    bool udp_exchange(const Endpoint& up, const uint8_t* pkt, size_t len, const dns::Query& q, std::vector<uint8_t>& out);
    bool tcp_exchange(const Endpoint& up, const uint8_t* pkt, size_t len, const dns::Query& q, std::vector<uint8_t>& out);

    Config cfg_;
    Cache cache_;
    mutable std::mutex rules_mu_;
    std::shared_ptr<const RuleSet> rules_;
    std::atomic<size_t> pref_{0};  // upstream that answered last; tried first
    Popup* popup_ = nullptr;
    Redirector* redirect_ = nullptr;
    std::vector<std::string> exempt_;
    bool is_exempt(const std::string& name) const;
};

class Server {
public:
    Server(Engine& e, const Config& c) : eng_(e), cfg_(c) {}
    bool start(std::string& err);  // binds sockets and spawns worker threads

private:
    void udp_worker(int fd);
    void tcp_acceptor(int fd);
    void tcp_conn(int fd);
    Engine& eng_;
    const Config& cfg_;
    std::atomic<int> tcp_active_{0};
};

}  // namespace blk
