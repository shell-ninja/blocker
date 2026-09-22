#include "util.hpp"

#include <cctype>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <atomic>
#include <mutex>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace blk {

bool g_verbose = false;

void log_msg(Level lvl, const char* fmt, ...) {
    if (lvl == Level::Debug && !g_verbose) return;
    static const bool tty = isatty(STDERR_FILENO) != 0;
    char msg[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    for (char* p = msg; *p; ++p)
        if (*p == '\n' || *p == '\r') *p = ' ';
    char line[2200];
    if (tty) {
        const char* tag = lvl == Level::Error ? "ERROR" : lvl == Level::Warn ? "WARN " : lvl == Level::Info ? "INFO " : "DEBUG";
        snprintf(line, sizeof line, "[%s] %s\n", tag, msg);
    } else {
        snprintf(line, sizeof line, "<%d>%s\n", static_cast<int>(lvl), msg);
    }
    ssize_t r = write(STDERR_FILENO, line, strlen(line));  // single write keeps lines intact across threads
    (void)r;
}

std::string trim(std::string_view s) {
    size_t b = 0, e = s.size();
    while (b < e && isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return std::string(s.substr(b, e - b));
}

std::string to_lower(std::string_view s) {
    std::string r(s);
    for (char& c : r)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    return r;
}

std::vector<std::string> split(std::string_view s, char sep) {
    std::vector<std::string> out;
    size_t start = 0;
    for (;;) {
        size_t p = s.find(sep, start);
        if (p == std::string_view::npos) {
            out.emplace_back(s.substr(start));
            break;
        }
        out.emplace_back(s.substr(start, p - start));
        start = p + 1;
    }
    return out;
}

std::vector<std::string> split_ws(std::string_view s) {
    std::vector<std::string> out;
    size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && isspace(static_cast<unsigned char>(s[i]))) ++i;
        size_t j = i;
        while (j < s.size() && !isspace(static_cast<unsigned char>(s[j]))) ++j;
        if (j > i) out.emplace_back(s.substr(i, j - i));
        i = j;
    }
    return out;
}

bool starts_with(std::string_view s, std::string_view p) { return s.size() >= p.size() && s.compare(0, p.size(), p) == 0; }
bool ends_with(std::string_view s, std::string_view p) { return s.size() >= p.size() && s.compare(s.size() - p.size(), p.size(), p) == 0; }

std::string join(const std::vector<std::string>& v, const std::string& sep) {
    std::string r;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) r += sep;
        r += v[i];
    }
    return r;
}

bool parse_u64(std::string_view s, uint64_t& out) {
    if (s.empty() || s.size() > 20) return false;
    uint64_t v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
        uint64_t digit = static_cast<uint64_t>(c - '0');
        // Guard against overflow: v * 10 + digit > UINT64_MAX
        if (v > (UINT64_MAX - digit) / 10) return false;
        v = v * 10 + digit;
    }
    out = v;
    return true;
}

bool parse_bool(std::string_view s, bool& out) {
    std::string v = to_lower(trim(s));
    if (v == "yes" || v == "true" || v == "on" || v == "1") { out = true; return true; }
    if (v == "no" || v == "false" || v == "off" || v == "0") { out = false; return true; }
    return false;
}

std::string human_duration(uint64_t secs) {
    uint64_t d = secs / 86400, h = (secs % 86400) / 3600, m = (secs % 3600) / 60, s = secs % 60;
    char buf[64];
    if (d) snprintf(buf, sizeof buf, "%llud %lluh %llum", (unsigned long long)d, (unsigned long long)h, (unsigned long long)m);
    else if (h) snprintf(buf, sizeof buf, "%lluh %llum", (unsigned long long)h, (unsigned long long)m);
    else if (m) snprintf(buf, sizeof buf, "%llum %llus", (unsigned long long)m, (unsigned long long)s);
    else snprintf(buf, sizeof buf, "%llus", (unsigned long long)s);
    return buf;
}

std::string hex_encode(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string r;
    r.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        r.push_back(d[p[i] >> 4]);
        r.push_back(d[p[i] & 15]);
    }
    return r;
}

bool hex_decode(std::string_view s, std::vector<uint8_t>& out) {
    if (s.size() % 2) return false;
    out.clear();
    auto val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < s.size(); i += 2) {
        int a = val(s[i]), b = val(s[i + 1]);
        if (a < 0 || b < 0) return false;
        out.push_back(static_cast<uint8_t>(a * 16 + b));
    }
    return true;
}

void random_bytes(void* buf, size_t n) {
    uint8_t* p = static_cast<uint8_t*>(buf);
    size_t off = 0;
    while (off < n) {
        ssize_t r = getrandom(p + off, n - off, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        off += static_cast<size_t>(r);
    }
    if (off < n) {  // getrandom unavailable: fall back to /dev/urandom
        int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            while (off < n) {
                ssize_t r = read(fd, p + off, n - off);
                if (r <= 0) break;
                off += static_cast<size_t>(r);
            }
            close(fd);
        }
    }
    if (off < n) {  // should never happen; refuse to continue with weak randomness
        LOG_E("cannot obtain random bytes");
        _exit(70);
    }
}

uint64_t unix_now() { return static_cast<uint64_t>(time(nullptr)); }

uint64_t mono_ms() {
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000 + static_cast<uint64_t>(ts.tv_nsec) / 1000000;
}

bool read_file(const std::string& path, std::string& out, size_t max_bytes) {
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    out.clear();
    char buf[65536];
    for (;;) {
        ssize_t r = read(fd, buf, sizeof buf);
        if (r < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return false;
        }
        if (r == 0) break;
        out.append(buf, static_cast<size_t>(r));
        if (out.size() > max_bytes) {
            close(fd);
            errno = EFBIG;
            return false;
        }
    }
    close(fd);
    return true;
}

bool write_file_atomic(const std::string& path, const std::string& data, mode_t mode) {
    // PID + atomic counter gives a unique name per call; no global mutex needed.
    static std::atomic<uint64_t> seq{0};
    std::string tmp = path + ".tmp." + std::to_string(getpid()) + "." + std::to_string(seq++);
    int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0) return false;
    size_t off = 0;
    while (off < data.size()) {
        ssize_t w = write(fd, data.data() + off, data.size() - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            int e = errno;
            close(fd);
            unlink(tmp.c_str());
            errno = e;
            return false;
        }
        off += static_cast<size_t>(w);
    }
    fchmod(fd, mode);
    fsync(fd);
    close(fd);
    if (rename(tmp.c_str(), path.c_str()) != 0) {
        int e = errno;
        unlink(tmp.c_str());
        errno = e;
        return false;
    }
    return true;
}

bool path_exists(const std::string& p) {
    struct stat st;
    return lstat(p.c_str(), &st) == 0;
}

bool make_dirs(const std::string& p, mode_t mode) {
    if (p.empty()) return false;
    std::string cur;
    for (size_t i = 0; i <= p.size(); ++i) {
        if (i == p.size() || p[i] == '/') {
            if (!cur.empty()) {
                if (mkdir(cur.c_str(), mode) != 0 && errno != EEXIST) return false;
            }
        }
        if (i < p.size()) cur.push_back(p[i]);
    }
    struct stat st;
    return stat(p.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

std::string dir_of(const std::string& p) {
    size_t s = p.find_last_of('/');
    if (s == std::string::npos) return ".";
    if (s == 0) return "/";
    return p.substr(0, s);
}

int run_cmd(const std::vector<std::string>& argv, const std::string* stdin_data, std::string* stdout_data) {
    if (argv.empty()) return -1;
    int inp[2] = {-1, -1}, outp[2] = {-1, -1};
    if (stdin_data && pipe2(inp, O_CLOEXEC) != 0) return -1;
    if (stdout_data && pipe2(outp, O_CLOEXEC) != 0) {
        if (inp[0] >= 0) { close(inp[0]); close(inp[1]); }
        return -1;
    }
    std::vector<char*> args;
    for (const auto& a : argv) args.push_back(const_cast<char*>(a.c_str()));
    args.push_back(nullptr);

    pid_t pid = fork();
    if (pid < 0) {
        for (int fd : {inp[0], inp[1], outp[0], outp[1]})
            if (fd >= 0) close(fd);
        return -1;
    }
    if (pid == 0) {
        int devnull = open("/dev/null", O_RDWR);
        dup2(stdin_data ? inp[0] : devnull, 0);
        dup2(stdout_data ? outp[1] : devnull, 1);
        dup2(devnull, 2);
        if (devnull > 2) close(devnull);  // don't leak /dev/null fd into the child
        execvp(args[0], args.data());
        _exit(127);
    }
    if (inp[0] >= 0) close(inp[0]);
    if (outp[1] >= 0) close(outp[1]);
    if (stdin_data) {
        size_t off = 0;
        while (off < stdin_data->size()) {
            ssize_t w = write(inp[1], stdin_data->data() + off, stdin_data->size() - off);
            if (w < 0) {
                if (errno == EINTR) continue;
                break;
            }
            off += static_cast<size_t>(w);
        }
        close(inp[1]);
    }
    if (stdout_data) {
        stdout_data->clear();
        char buf[4096];
        for (;;) {
            ssize_t r = read(outp[0], buf, sizeof buf);
            if (r < 0 && errno == EINTR) continue;
            if (r <= 0) break;
            stdout_data->append(buf, static_cast<size_t>(r));
        }
        close(outp[0]);
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

}  // namespace blk
