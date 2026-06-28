#pragma once

#include <string>
#include <vector>
#include <regex>
#include <atomic>
#include <chrono>
#include <mutex>
#include <stdexcept>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>

static constexpr size_t MAX_BANNER_LEN   = 512;
static constexpr size_t MAX_DOMAIN_LEN   = 253;
static constexpr size_t MAX_PAYLOAD_LEN  = 65536;
static constexpr size_t MAX_OUTPUT_LEN   = 1048576;
static constexpr size_t MAX_PATH_LEN     = 4096;

struct InputGuard {
    static bool is_valid_host(const std::string& s) {
        if (s.empty() || s.size() > MAX_DOMAIN_LEN) return false;
        static const std::regex re(
            R"(^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$)"
        );
        if (std::regex_match(s, re)) return true;
        return is_valid_ipv4(s) || is_valid_ipv6(s);
    }

    static bool is_valid_ipv4(const std::string& s) {
        static const std::regex re(
            R"(^((25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)$)"
        );
        return std::regex_match(s, re);
    }

    static bool is_valid_ipv6(const std::string& s) {
        static const std::regex re(
            R"(^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$)"
        );
        return !s.empty() && s.size() <= 45 && std::regex_match(s, re);
    }

    static bool is_valid_port(int p) {
        return p >= 1 && p <= 65535;
    }

    static bool is_valid_username(const std::string& s) {
        if (s.empty() || s.size() > 64) return false;
        static const std::regex re(R"(^[a-zA-Z0-9_\-\.]{1,64}$)");
        return std::regex_match(s, re);
    }

    static bool is_valid_email(const std::string& s) {
        if (s.empty() || s.size() > 254) return false;
        static const std::regex re(R"(^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$)");
        return std::regex_match(s, re);
    }

    static bool is_valid_phone(const std::string& s) {
        if (s.size() < 7 || s.size() > 20) return false;
        size_t start = (s[0] == '+') ? 1 : 0;
        return std::all_of(s.begin() + start, s.end(), ::isdigit);
    }

    static bool is_safe_path(const std::string& s) {
        if (s.empty() || s.size() > MAX_PATH_LEN) return false;
        if (s.find("..") != std::string::npos) return false;
        if (s.find('\0') != std::string::npos) return false;
        static const std::regex re(R"(^[a-zA-Z0-9_\-\./]+$)");
        return std::regex_match(s, re);
    }

    static bool is_safe_url(const std::string& s) {
        if (s.empty() || s.size() > MAX_PAYLOAD_LEN) return false;
        if (s.find('\'') != std::string::npos) return false;
        if (s.find('"')  != std::string::npos) return false;
        if (s.find('\n') != std::string::npos) return false;
        if (s.find('\r') != std::string::npos) return false;
        if (s.find('\0') != std::string::npos) return false;
        return s.find("http://") == 0 || s.find("https://") == 0;
    }

    static std::string sanitize_output(const std::string& s,
                                       size_t max_len = MAX_OUTPUT_LEN) {
        std::string out;
        out.reserve(std::min(s.size(), max_len));
        for (size_t i = 0; i < s.size() && out.size() < max_len; ++i) {
            unsigned char c = static_cast<unsigned char>(s[i]);
            if (c == 0x1b) {
                size_t j = i + 1;
                if (j < s.size() && s[j] == '[') {
                    j++;
                    while (j < s.size() && (std::isdigit(s[j]) || s[j] == ';')) j++;
                    if (j < s.size() && std::isalpha(s[j])) { i = j; continue; }
                }
                continue;
            }
            if (c < 0x20 && c != '\n' && c != '\t') continue;
            if (c == 0x7f) continue;
            out += static_cast<char>(c);
        }
        return out;
                                       }

                                       static std::string sanitize_banner(const std::string& s) {
                                           return sanitize_output(s, MAX_BANNER_LEN);
                                       }

                                       static std::string sanitize_domain_output(const std::string& s) {
                                           return sanitize_output(s, MAX_DOMAIN_LEN * 4);
                                       }
};

struct SafeJson {
    static std::string escape(const std::string& s) {
        std::string out;
        out.reserve(s.size() * 2);
        for (size_t i = 0; i < s.size(); ) {
            unsigned char c = static_cast<unsigned char>(s[i]);
            if (c == '"')       { out += "\\\""; i++; }
            else if (c == '\\') { out += "\\\\"; i++; }
            else if (c == '\n') { out += "\\n";  i++; }
            else if (c == '\r') { out += "\\r";  i++; }
            else if (c == '\t') { out += "\\t";  i++; }
            else if (c < 0x20 || c == 0x7f) {
                char buf[8];
                snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf; i++;
            }
            else if (c >= 0x80) {
                unsigned char c2 = (i+1 < s.size()) ? static_cast<unsigned char>(s[i+1]) : 0;
                unsigned char c3 = (i+2 < s.size()) ? static_cast<unsigned char>(s[i+2]) : 0;
                unsigned char c4 = (i+3 < s.size()) ? static_cast<unsigned char>(s[i+3]) : 0;
                if ((c & 0xE0) == 0xC0 && (c2 & 0xC0) == 0x80) {
                    uint32_t cp = ((c & 0x1F) << 6) | (c2 & 0x3F);
                    if (cp >= 0x80) { out += s[i]; out += s[i+1]; }
                    i += 2;
                } else if ((c & 0xF0) == 0xE0 && (c2&0xC0)==0x80 && (c3&0xC0)==0x80) {
                    uint32_t cp = ((c&0x0F)<<12)|((c2&0x3F)<<6)|(c3&0x3F);
                    if (cp >= 0x0800 && (cp < 0xD800 || cp > 0xDFFF))
                    { out += s[i]; out += s[i+1]; out += s[i+2]; }
                    i += 3;
                } else if ((c&0xF8)==0xF0&&(c2&0xC0)==0x80&&(c3&0xC0)==0x80&&(c4&0xC0)==0x80) {
                    uint32_t cp=((c&0x07)<<18)|((c2&0x3F)<<12)|((c3&0x3F)<<6)|(c4&0x3F);
                    if (cp >= 0x10000 && cp <= 0x10FFFF) {
                        cp -= 0x10000;
                        char buf[14];
                        snprintf(buf, sizeof(buf), "\\u%04x\\u%04x",
                                 0xD800 + (cp >> 10), 0xDC00 + (cp & 0x3FF));
                        out += buf;
                    }
                    i += 4;
                } else {
                    char buf[8]; snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf; i++;
                }
            }
            else { out += static_cast<char>(c); i++; }
        }
        return out;
    }

    static std::string val(const std::string& key, const std::string& value) {
        return "\"" + escape(key) + "\":\"" + escape(value) + "\"";
    }
};
inline std::string sanitize(const std::string& s) {
    return InputGuard::sanitize_output(s);
}

class RateLimiter {
public:
    explicit RateLimiter(double rps, double burst_factor = 2.0)
    : rate_(rps)
    , max_tokens_(rps * burst_factor)
    , tokens_(rps * burst_factor)
    , last_(std::chrono::steady_clock::now())
    {}

    void acquire() {
        std::unique_lock<std::mutex> lk(mtx_);
        for (;;) {
            refill();
            if (tokens_ >= 1.0) {
                tokens_ -= 1.0;
                return;
            }
            double wait_s = (1.0 - tokens_) / rate_;
            lk.unlock();
            std::this_thread::sleep_for(
                std::chrono::microseconds(static_cast<long long>(wait_s * 1e6)));
            lk.lock();
        }
    }

    bool try_acquire() {
        std::lock_guard<std::mutex> lk(mtx_);
        refill();
        if (tokens_ >= 1.0) {
            tokens_ -= 1.0;
            return true;
        }
        return false;
    }

private:
    void refill() {
        auto now  = std::chrono::steady_clock::now();
        double dt = std::chrono::duration<double>(now - last_).count();
        last_     = now;
        tokens_ = std::min(max_tokens_, tokens_ + dt * rate_);
    }

    double rate_;
    double max_tokens_;
    double tokens_;
    std::chrono::steady_clock::time_point last_;
    std::mutex mtx_;
};

inline bool drop_privileges() {
    if (geteuid() != 0) return true;

    const char* sudo_uid = getenv("SUDO_UID");
    const char* sudo_gid = getenv("SUDO_GID");

    uid_t target_uid = sudo_uid ? (uid_t)std::stoul(sudo_uid) : 65534;
    gid_t target_gid = sudo_gid ? (gid_t)std::stoul(sudo_gid) : 65534;

    if (target_uid == 0 || target_gid == 0) {
        target_uid = 65534;
        target_gid = 65534;
    }

    if (setgroups(0, nullptr) != 0) return false;
    if (setgid(target_gid) != 0) return false;
    if (setuid(target_uid) != 0) return false;

    if (setuid(0) != -1) return false;
    if (setgid(0) != -1) return false;

    if (geteuid() != target_uid) return false;
    if (getegid() != target_gid) return false;

    return true;
}

class SecureBuffer {
public:
    explicit SecureBuffer(size_t cap) : buf_(cap, '\0'), used_(0) {}

    char*  data()     { return buf_.data(); }
    size_t capacity() { return buf_.size(); }
    size_t used()     { return used_; }

    bool append(const char* src, size_t n) {
        if (used_ + n > buf_.size()) n = buf_.size() - used_;
        if (n == 0) return false;
        std::memcpy(buf_.data() + used_, src, n);
        used_ += n;
        return true;
    }

    std::string str() const {
        return InputGuard::sanitize_output(std::string(buf_.data(), used_));
    }

    void clear() { std::fill(buf_.begin(), buf_.end(), '\0'); used_ = 0; }
    ~SecureBuffer() { clear(); }

private:
    std::vector<char> buf_;
    size_t            used_;
};

#include <sys/capability.h>

inline bool has_cap_net_raw() {
    if (geteuid() == 0) return true;

    struct __user_cap_header_struct hdr = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct data[2] = {};

    if (capget(&hdr, data) < 0) return false;
    return (data[0].effective & (1 << CAP_NET_RAW)) != 0;
}
