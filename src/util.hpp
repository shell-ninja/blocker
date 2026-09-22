// util.hpp - small helpers shared by every module (logging, strings, files, subprocesses).
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <sys/types.h>
#include <vector>

namespace blk {

// ---- logging -------------------------------------------------------------
// Lines go to stderr. Under systemd the "<N>" prefix sets the journald priority.
enum class Level { Debug = 7, Info = 6, Warn = 4, Error = 3 };
extern bool g_verbose;
void log_msg(Level lvl, const char* fmt, ...) __attribute__((format(printf, 2, 3)));
#define LOG_D(...) ::blk::log_msg(::blk::Level::Debug, __VA_ARGS__)
#define LOG_I(...) ::blk::log_msg(::blk::Level::Info, __VA_ARGS__)
#define LOG_W(...) ::blk::log_msg(::blk::Level::Warn, __VA_ARGS__)
#define LOG_E(...) ::blk::log_msg(::blk::Level::Error, __VA_ARGS__)

// ---- strings -------------------------------------------------------------
std::string trim(std::string_view s);
std::string to_lower(std::string_view s);
std::vector<std::string> split(std::string_view s, char sep);  // keeps empty fields
std::vector<std::string> split_ws(std::string_view s);         // whitespace separated tokens
bool starts_with(std::string_view s, std::string_view p);
bool ends_with(std::string_view s, std::string_view p);
std::string join(const std::vector<std::string>& v, const std::string& sep);
bool parse_u64(std::string_view s, uint64_t& out);
bool parse_bool(std::string_view s, bool& out);
std::string human_duration(uint64_t secs);

// ---- encoding / randomness -----------------------------------------------
std::string hex_encode(const uint8_t* p, size_t n);
bool hex_decode(std::string_view s, std::vector<uint8_t>& out);
void random_bytes(void* buf, size_t n);

// ---- time ----------------------------------------------------------------
uint64_t unix_now();
uint64_t mono_ms();  // CLOCK_MONOTONIC in milliseconds

// ---- files ---------------------------------------------------------------
bool read_file(const std::string& path, std::string& out, size_t max_bytes = 64u << 20);
bool write_file_atomic(const std::string& path, const std::string& data, mode_t mode);
bool path_exists(const std::string& p);           // lstat based: true for dangling symlinks too
bool make_dirs(const std::string& p, mode_t mode);
std::string dir_of(const std::string& p);

// ---- subprocesses --------------------------------------------------------
// Runs argv (no shell). stdin_data is written to the child's stdin; stdout is captured if
// requested. Returns the exit status, 127 if the program is missing, -1 on other failures.
int run_cmd(const std::vector<std::string>& argv, const std::string* stdin_data = nullptr,
            std::string* stdout_data = nullptr);

}  // namespace blk
