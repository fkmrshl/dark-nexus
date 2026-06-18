#include "../include/port_enrich.hpp"
#include "../include/port_probe.hpp"
#include "../include/security.hpp"
#include "../include/user_agents.hpp"
#include <cstdint>

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#endif

namespace {

const std::unordered_set<int> HTTP_PORTS = {
    80, 443, 8080, 8443, 8008, 8888, 3000, 5000, 9000, 9090, 10000,
    2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096,
    8880, 4443, 7443, 8081, 8181, 8888, 3001, 4000, 6001, 7000
};

const std::unordered_set<int> TLS_PORTS = {
    443, 8443, 465, 993, 995, 636, 5671, 6443, 4443, 7443, 2083, 2087, 2053, 2096
};

std::string lower_copy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

std::string build_http_get_request(const std::string& path, const std::string& host_header) {
    return "GET " + path + " HTTP/1.1\r\n"
           "Host: " + host_header + "\r\n"
           "User-Agent: " + random_ua() + "\r\n"
           "Accept: */*\r\n"
           "Connection: close\r\n\r\n";
}

void print_detail_prefix(const std::string& label) {
    std::cout << BLOOD_RED << "    | " << std::left << std::setw(9) << label << WHITE;
}

bool is_redirect_status(int code) {
    return code == 301 || code == 302 || code == 303 || code == 307 || code == 308;
}

void parse_http_response(const std::string& raw, HttpInfo& info) {
    if (raw.empty()) return;

    std::istringstream stream(raw);
    std::string line;
    if (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        static const std::regex status_re(R"(HTTP/\d(?:\.\d)?\s+(\d{3}))");
        std::smatch m;
        if (std::regex_search(line, m, status_re)) {
            try {
                info.status_code = std::stoi(m[1].str());
            } catch (...) {}
        }
    }

    while (std::getline(stream, line)) {
        if (line == "\r" || line.empty()) break;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::string l = line;
        std::transform(l.begin(), l.end(), l.begin(), ::tolower);

        if (l.find("server: ") == 0)
            info.server = InputGuard::sanitize_output(line.substr(8));
        else if (l.find("x-powered-by: ") == 0)
            info.powered_by = InputGuard::sanitize_output(line.substr(14));
        else if (l.find("strict-transport-security: ") == 0)
            info.hsts = true;
        else if (l.find("content-security-policy: ") == 0)
            info.csp = true;
        else if (l.find("x-frame-options: ") == 0)
            info.x_frame = true;
        else if (l.find("location: ") == 0)
            info.redirect_location = InputGuard::sanitize_output(line.substr(10));
    }

    auto title_start = raw.find("<title>");
    if (title_start != std::string::npos) {
        title_start += 7;
        auto title_end = raw.find("</title>", title_start);
        if (title_end != std::string::npos) {
            std::string title = raw.substr(title_start, title_end - title_start);
            if (title.size() > 80) title = title.substr(0, 80) + "...";
            info.title = InputGuard::sanitize_output(title);
        }
    }
}

bool resolve_redirect_target(const std::string& location, const std::string& base_host,
                             int base_port, std::string& path_out, std::string& host_out,
                             int& port_out) {
    if (location.empty()) return false;
    std::string loc = location;
    while (!loc.empty() && (loc.back() == ' ' || loc.back() == '\t')) loc.pop_back();

    if (loc.rfind("https://", 0) == 0 || loc.rfind("http://", 0) == 0) {
        bool https = loc.rfind("https://", 0) == 0;
        size_t start = loc.find("://") + 3;
        size_t slash = loc.find('/', start);
        std::string authority = slash == std::string::npos ? loc.substr(start) : loc.substr(start, slash - start);
        path_out = slash == std::string::npos ? "/" : loc.substr(slash);
        size_t colon = authority.find(':');
        if (colon == std::string::npos) {
            host_out = authority;
            port_out = https ? 443 : 80;
        } else {
            host_out = authority.substr(0, colon);
            try {
                port_out = std::stoi(authority.substr(colon + 1));
            } catch (...) {
                port_out = base_port;
            }
        }
        return true;
    }

    if (loc[0] == '/') {
        path_out = loc;
        host_out = base_host;
        port_out = base_port;
        return true;
    }

    path_out = "/" + loc;
    host_out = base_host;
    port_out = base_port;
    return true;
}

#ifdef HAVE_OPENSSL
struct SSL_CTX_Deleter {
    void operator()(SSL_CTX* ctx) const noexcept {
        if (ctx) SSL_CTX_free(ctx);
    }
};

struct SSL_Deleter {
    void operator()(SSL* ssl) const noexcept {
        if (ssl) SSL_free(ssl);
    }
};

struct X509_Deleter {
    void operator()(X509* cert) const noexcept {
        if (cert) X509_free(cert);
    }
};

using SSL_CTX_ptr = std::unique_ptr<SSL_CTX, SSL_CTX_Deleter>;
using SSL_ptr = std::unique_ptr<SSL, SSL_Deleter>;
using X509_ptr = std::unique_ptr<X509, X509_Deleter>;

std::string openssl_err_stack() {
    std::string msg;
    unsigned long err = 0;
    while ((err = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        if (!msg.empty()) msg += "; ";
        msg += buf;
    }
    return msg;
}

const char* ssl_error_label(int ssl_err) {
    switch (ssl_err) {
        case SSL_ERROR_NONE: return "NONE";
        case SSL_ERROR_SSL: return "SSL";
        case SSL_ERROR_WANT_READ: return "WANT_READ";
        case SSL_ERROR_WANT_WRITE: return "WANT_WRITE";
        case SSL_ERROR_WANT_X509_LOOKUP: return "WANT_X509_LOOKUP";
        case SSL_ERROR_SYSCALL: return "SYSCALL";
        case SSL_ERROR_ZERO_RETURN: return "ZERO_RETURN";
        case SSL_ERROR_WANT_CONNECT: return "WANT_CONNECT";
        case SSL_ERROR_WANT_ACCEPT: return "WANT_ACCEPT";
        default: return "UNKNOWN";
    }
}

void log_tls_handshake_fail(const std::string& context, SSL* ssl, int ssl_connect_ret, int ssl_err) {
    std::string msg = context + " ssl_err=" + ssl_error_label(ssl_err) +
                      "(" + std::to_string(ssl_err) + ")";
    if (ssl_connect_ret != 1)
        msg += " ret=" + std::to_string(ssl_connect_ret);
    if (ssl && ssl_err == SSL_ERROR_SYSCALL) {
        if (errno != 0) msg += " errno=" + std::string(strerror(errno));
    }
    std::string stack = openssl_err_stack();
    if (!stack.empty()) msg += " openssl=[" + stack + "]";
    LOG_WARN("port_scan_tls", msg);
}

std::string asn1_time_to_string(const ASN1_TIME* t) {
    if (!t) return "";
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "";
    if (ASN1_TIME_print(bio, const_cast<ASN1_TIME*>(t)) != 1) {
        BIO_free(bio);
        return "";
    }
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    std::string out;
    if (mem && mem->data && mem->length > 0)
        out.assign(mem->data, mem->length);
    BIO_free(bio);
    return InputGuard::sanitize_output(out);
}

bool ssl_connect_with_timeout(SSL* ssl, int fd, int timeout_ms, const std::string& log_ctx) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    int last_ret = -1;
    int last_err = SSL_ERROR_NONE;

    while (!g_cancel_token.cancelled) {
        auto now = std::chrono::steady_clock::now();
        int remaining = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
        if (remaining <= 0) {
            log_tls_handshake_fail(log_ctx + " deadline", ssl, last_ret, last_err);
            return false;
        }

        int ret = SSL_connect(ssl);
        last_ret = ret;
        if (ret == 1) return true;

        int err = SSL_get_error(ssl, ret);
        last_err = err;
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            struct pollfd pfd{};
            pfd.fd = fd;
            pfd.events = (err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
            if (poll(&pfd, 1, remaining) <= 0) {
                log_tls_handshake_fail(log_ctx + " poll", ssl, ret, err);
                return false;
            }
            continue;
        }
        log_tls_handshake_fail(log_ctx + " handshake", ssl, ret, err);
        return false;
    }
    log_tls_handshake_fail(log_ctx + " cancelled", ssl, last_ret, last_err);
    return false;
}

void populate_tls_cert_fields(TLSInfo& tls, X509* cert) {
    if (!cert) return;

    char buf[256];
    X509_NAME* subj = X509_get_subject_name(cert);
    if (subj) {
        if (X509_NAME_get_text_by_NID(subj, NID_commonName, buf, sizeof(buf)) > 0)
            tls.cn = InputGuard::sanitize_output(buf);
    }
    X509_NAME* issuer_name = X509_get_issuer_name(cert);
    if (issuer_name) {
        if (X509_NAME_get_text_by_NID(issuer_name, NID_commonName, buf, sizeof(buf)) > 0)
            tls.issuer = InputGuard::sanitize_output(buf);
    }

    STACK_OF(GENERAL_NAME)* sans = static_cast<STACK_OF(GENERAL_NAME)*>(
        X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
    if (sans) {
        int num_sans = sk_GENERAL_NAME_num(sans);
        for (int i = 0; i < num_sans; i++) {
            GENERAL_NAME* gen = sk_GENERAL_NAME_value(sans, i);
            if (gen && gen->type == GEN_DNS) {
                std::string san(
                    reinterpret_cast<const char*>(ASN1_STRING_get0_data(gen->d.dNSName)),
                    static_cast<size_t>(ASN1_STRING_length(gen->d.dNSName)));
                tls.sans.push_back(InputGuard::sanitize_output(san));
            }
        }
        sk_GENERAL_NAME_pop_free(sans, GENERAL_NAME_free);
    }

    tls.self_signed = (X509_check_issued(cert, cert) == X509_V_OK);

    const ASN1_TIME* not_after = X509_get0_notAfter(cert);
    if (not_after) {
        tls.expiry = asn1_time_to_string(not_after);
        int day = 0;
        int sec = 0;
        if (ASN1_TIME_diff(&day, &sec, nullptr, not_after))
            tls.expired = (day < 0 || sec < 0);
    }
}

void populate_tls_from_ssl(SSL* ssl, TLSInfo& tls) {
    if (!ssl) return;
    tls.tls_version = SSL_get_version(ssl);
    const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl);
    if (cipher) {
        const char* name = SSL_CIPHER_get_name(cipher);
        if (name) tls.cipher = InputGuard::sanitize_output(name);
    }
    X509_ptr cert(SSL_get_peer_certificate(ssl));
    populate_tls_cert_fields(tls, cert.get());
}

bool tls_handshake_on_socket(int fd, SSL_CTX_ptr& ctx, SSL_ptr& ssl, TLSInfo& tls,
                             const std::string& ip, int port, int timeout_ms,
                             const std::string& sni_host) {
    const std::string& host = sni_host.empty() ? ip : sni_host;
    std::string log_ctx = "port=" + std::to_string(port) + " sni=" + host;

    ctx = SSL_CTX_ptr(SSL_CTX_new(TLS_client_method()));
    if (!ctx) {
        LOG_WARN("port_scan_tls", log_ctx + " SSL_CTX_new failed " + openssl_err_stack());
        return false;
    }
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);

    ssl = SSL_ptr(SSL_new(ctx.get()));
    if (!ssl) {
        LOG_WARN("port_scan_tls", log_ctx + " SSL_new failed " + openssl_err_stack());
        return false;
    }

    SSL_set_fd(ssl.get(), fd);
    if (SSL_set_tlsext_host_name(ssl.get(), host.c_str()) != 1) {
        LOG_WARN("port_scan_tls", log_ctx + " SNI set failed " + openssl_err_stack());
        return false;
    }

    if (!ssl_connect_with_timeout(ssl.get(), fd, timeout_ms, log_ctx))
        return false;

    populate_tls_from_ssl(ssl.get(), tls);
    return true;
}

bool ssl_write_all(SSL* ssl, int fd, const std::string& data, int timeout_ms,
                   const std::string& log_ctx) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    size_t sent = 0;
    while (sent < data.size() && !g_cancel_token.cancelled) {
        auto now = std::chrono::steady_clock::now();
        int remaining = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
        if (remaining <= 0) return false;

        int ret = SSL_write(ssl, data.data() + sent, static_cast<int>(data.size() - sent));
        if (ret > 0) {
            sent += static_cast<size_t>(ret);
            continue;
        }
        int err = SSL_get_error(ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            struct pollfd pfd{};
            pfd.fd = fd;
            pfd.events = (err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
            if (poll(&pfd, 1, remaining) <= 0) return false;
            continue;
        }
        log_tls_handshake_fail(log_ctx + " write", ssl, ret, err);
        return false;
    }
    return sent == data.size();
}

bool ssl_read_http_response(SSL* ssl, int fd, std::string& out, int timeout_ms, size_t max_bytes) {
    out.clear();
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    std::vector<char> buf(4096);

    while (out.size() < max_bytes && !g_cancel_token.cancelled) {
        auto now = std::chrono::steady_clock::now();
        int remaining = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
        if (remaining <= 0) break;

        int ret = SSL_read(ssl, buf.data(), static_cast<int>(buf.size()));
        if (ret > 0) {
            out.append(buf.data(), static_cast<size_t>(ret));
            if (out.find("\r\n\r\n") != std::string::npos) {
                size_t hdr_end = out.find("\r\n\r\n") + 4;
                if (out.size() >= hdr_end + 512 || out.size() >= max_bytes) break;
                if (out.find("<title>", hdr_end) != std::string::npos) break;
            }
            continue;
        }
        if (ret == 0) break;
        int err = SSL_get_error(ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            struct pollfd pfd{};
            pfd.fd = fd;
            pfd.events = (err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
            if (poll(&pfd, 1, remaining) <= 0) break;
            continue;
        }
        break;
    }
    return !out.empty();
}
#endif

}

bool port_is_tls_http_port(int port) {
    return port_is_tls_candidate(port) && port_is_http_candidate(port);
}

bool port_is_http_candidate(int port) {
    return HTTP_PORTS.count(port) != 0;
}

bool port_is_tls_candidate(int port) {
    return TLS_PORTS.count(port) != 0;
}

int port_service_priority(int port) {
    if (port == 80 || port == 443 || port == 22 || port == 445 || port == 3389 || port == 8080)
        return 100;
    if (port == 21 || port == 25 || port == 53 || port == 110 || port == 143 || port == 3306 || port == 5432)
        return 50;
    return 10;
}

std::string port_extract_version(const std::string& banner_raw, int port) {
    if (banner_raw.empty()) return "";
    if (port == 22 && banner_raw.find("SSH-") == 0) {
        size_t end = banner_raw.find_first_of("\r\n");
        size_t len = (end == std::string::npos) ? banner_raw.size() : end;
        len = std::min(len, size_t{80});
        return banner_raw.substr(0, len);
    }
    std::regex re(R"(([A-Za-z0-9_\-]+[/\-][\d\.]+))");
    std::smatch m;
    if (std::regex_search(banner_raw, m, re)) return m[1].str();
    return "";
}

bool port_banner_usable(const std::string& s) {
    if (s.size() < 5) return false;
    size_t non_ws = 0;
    size_t printable = 0;
    for (unsigned char c : s) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            non_ws++;
            if (c >= 32 && c < 127) printable++;
        }
    }
    if (non_ws == 0) return false;
    return printable * 2 >= non_ws;
}

std::string port_resolve_sni_host(const std::string& scan_ip) {
    const std::string& target = g_result.target;
    if (!target.empty() && target != scan_ip &&
        !InputGuard::is_valid_ipv4(target) && !InputGuard::is_valid_ipv6(target)) {
        return target;
    }
    std::string ptr = ptr_lookup(scan_ip);
    if (!ptr.empty() && ptr != scan_ip) return ptr;
    return scan_ip;
}

std::string port_probe_redis_ping(const std::string& ip, int port, int timeout_ms) {
    if (g_cancel_token.cancelled) return {};
    FdGuard sock(port_tcp_socket(ip));
    if (sock.get() < 0) return {};
    if (!port_tcp_connect_to(ip, port, timeout_ms, sock.get())) return {};

    static const char kPing[] = "PING\r\n";
    if (send(sock.get(), kPing, sizeof(kPing) - 1, MSG_NOSIGNAL) < 0) return {};

    struct pollfd pfd{};
    pfd.fd = sock.get();
    pfd.events = POLLIN;
    if (poll(&pfd, 1, timeout_ms) <= 0 || !(pfd.revents & POLLIN)) return {};

    char buf[64];
    ssize_t n = recv(sock.get(), buf, sizeof(buf), 0);
    if (n <= 0) return {};
    return std::string(buf, static_cast<size_t>(n));
}

std::string port_probe_mongo_ping(const std::string& ip, int port, int timeout_ms) {
    if (g_cancel_token.cancelled) return {};
    static const uint8_t kMongoIsMasterProbe[] = {
        0x3a,0x00,0x00,0x00, 0x01,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00, 0xd4,0x07,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x61,0x64,0x6d,0x69,0x6e,0x2e,0x24,0x63,0x6d,0x64,0x00,
        0x00,0x00,0x00,0x00, 0x01,0x00,0x00,0x00,
        0x13,0x00,0x00,0x00, 0x10,0x69,0x73,0x4d,
        0x61,0x73,0x74,0x65,0x72,0x00, 0x01,0x00,0x00,0x00, 0x00
    };

    FdGuard sock(port_tcp_socket(ip));
    if (sock.get() < 0) return {};
    if (!port_tcp_connect_to(ip, port, timeout_ms, sock.get())) return {};

    if (send(sock.get(), kMongoIsMasterProbe, sizeof(kMongoIsMasterProbe), MSG_NOSIGNAL) < 0)
        return {};

    struct pollfd pfd{};
    pfd.fd = sock.get();
    pfd.events = POLLIN;
    if (poll(&pfd, 1, timeout_ms) <= 0 || !(pfd.revents & POLLIN)) return {};

    char buf[512];
    ssize_t n = recv(sock.get(), buf, sizeof(buf), 0);
    if (n < 4) return {};

    uint32_t msg_len = static_cast<uint32_t>(static_cast<uint8_t>(buf[0]))
        | (static_cast<uint32_t>(static_cast<uint8_t>(buf[1])) << 8)
        | (static_cast<uint32_t>(static_cast<uint8_t>(buf[2])) << 16)
        | (static_cast<uint32_t>(static_cast<uint8_t>(buf[3])) << 24);
    if (msg_len < 16 || msg_len > 65536) return {};

    std::string resp(buf, static_cast<size_t>(n));
    std::string low = lower_copy(resp);
    if (low.find("ismaster") != std::string::npos)
        return resp;
    return "mongodb-open";
}

std::string port_probe_ssh_banner(const std::string& ip, int port, int timeout_ms) {
    if (g_cancel_token.cancelled) return {};
    FdGuard sock(port_tcp_socket(ip));
    if (sock.get() < 0) return {};
    if (!port_tcp_connect_to(ip, port, timeout_ms, sock.get())) return {};

    struct pollfd pfd{};
    pfd.fd = sock.get();
    pfd.events = POLLIN;
    if (poll(&pfd, 1, timeout_ms) <= 0 || !(pfd.revents & POLLIN)) return {};

    char buf[256];
    ssize_t n = recv(sock.get(), buf, sizeof(buf) - 1, 0);
    if (n <= 0) return {};
    buf[n] = '\0';
    std::string resp(buf, static_cast<size_t>(n));
    if (resp.find("SSH-") == std::string::npos) return {};
    return InputGuard::sanitize_output(resp.substr(0, static_cast<size_t>(std::min(n, ssize_t{100}))));
}

std::string port_probe_ftp_banner(const std::string& ip, int port, int timeout_ms) {
    if (g_cancel_token.cancelled) return {};
    FdGuard sock(port_tcp_socket(ip));
    if (sock.get() < 0) return {};
    if (!port_tcp_connect_to(ip, port, timeout_ms, sock.get())) return {};

    struct pollfd pfd{};
    pfd.fd = sock.get();
    pfd.events = POLLIN;
    if (poll(&pfd, 1, timeout_ms) <= 0 || !(pfd.revents & POLLIN)) return {};

    char buf[256];
    ssize_t n = recv(sock.get(), buf, sizeof(buf) - 1, 0);
    if (n <= 0 || n >= 256) return {};
    buf[n] = '\0';
    std::string resp(buf, static_cast<size_t>(n));
    if (resp.find("220") == std::string::npos) return {};
    return InputGuard::sanitize_output(resp.substr(0, static_cast<size_t>(std::min(n, ssize_t{80}))));
}

std::string port_probe_smtp_banner(const std::string& ip, int port, int timeout_ms) {
    return port_probe_ftp_banner(ip, port, timeout_ms);
}

std::string port_probe_mysql_banner(const std::string& ip, int port, int timeout_ms) {
    if (g_cancel_token.cancelled) return {};
    FdGuard sock(port_tcp_socket(ip));
    if (sock.get() < 0) return {};
    if (!port_tcp_connect_to(ip, port, timeout_ms, sock.get())) return {};

    struct pollfd pfd{};
    pfd.fd = sock.get();
    pfd.events = POLLIN;
    if (poll(&pfd, 1, timeout_ms) <= 0 || !(pfd.revents & POLLIN)) return {};

    char buf[256];
    ssize_t n = recv(sock.get(), buf, sizeof(buf) - 1, 0);
    if (n <= 10 || static_cast<unsigned char>(buf[0]) >= 128) return {};
    size_t cap = static_cast<size_t>(std::min(n, ssize_t{100}));
    std::string resp(buf, cap);
    std::string low = lower_copy(resp);
    if (low.find("mysql") == std::string::npos && low.find("mariadb") == std::string::npos) return {};
    return InputGuard::sanitize_output(resp.substr(0, static_cast<size_t>(std::min(n, ssize_t{80}))));
}

std::string port_probe_postgres_banner(const std::string& ip, int port, int timeout_ms) {
    if (g_cancel_token.cancelled) return {};
    static const unsigned char kPgStartup[] = {
        0x58, 0x00, 0x00, 0x00, 0x04, 0x03, 0x00, 0x00, 0x00, 0x00
    };
    FdGuard sock(port_tcp_socket(ip));
    if (sock.get() < 0) return {};
    if (!port_tcp_connect_to(ip, port, timeout_ms, sock.get())) return {};

    if (send(sock.get(), kPgStartup, sizeof(kPgStartup), MSG_NOSIGNAL) < 0) return {};

    struct pollfd pfd{};
    pfd.fd = sock.get();
    pfd.events = POLLIN;
    if (poll(&pfd, 1, timeout_ms) <= 0 || !(pfd.revents & POLLIN)) return {};

    char buf[256];
    ssize_t n = recv(sock.get(), buf, sizeof(buf) - 1, 0);
    if (n <= 0) return {};
    size_t cap = static_cast<size_t>(std::min(n, ssize_t{100}));
    std::string resp(buf, cap);
    if (resp.find("FATAL") == std::string::npos) return {};
    return InputGuard::sanitize_output(resp.substr(0, static_cast<size_t>(std::min(n, ssize_t{80}))));
}

TLSInfo port_inspect_tls(const std::string& ip, int port, int timeout_ms, const std::string& sni_host) {
    TLSInfo tls{};
#ifdef HAVE_OPENSSL
    FdGuard sock(port_tcp_socket(ip));
    if (sock.get() < 0) return tls;
    if (!port_tcp_connect_to(ip, port, timeout_ms, sock.get())) return tls;

    SSL_CTX_ptr ctx;
    SSL_ptr ssl;
    if (!tls_handshake_on_socket(sock.get(), ctx, ssl, tls, ip, port, timeout_ms, sni_host))
        return tls;
    SSL_shutdown(ssl.get());
#endif
    return tls;
}

TlsHttpResult port_probe_tls_http(const std::string& ip, int port, int timeout_ms,
                                  const std::string& sni_host, int max_redirects) {
    TlsHttpResult result{};
#ifdef HAVE_OPENSSL
    auto t0 = std::chrono::steady_clock::now();
    auto ms_remaining = [&]() {
        int elapsed = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count());
        return std::max(0, timeout_ms - elapsed);
    };

    std::string connect_host = sni_host.empty() ? ip : sni_host;
    int connect_port = port;
    std::string path = "/";

    for (int hop = 0; hop <= max_redirects; ++hop) {
        int budget = ms_remaining();
        if (budget <= 0) break;

        FdGuard sock(port_tcp_socket(ip));
        if (sock.get() < 0) break;
        if (!port_tcp_connect_to(ip, connect_port, budget, sock.get())) break;

        SSL_CTX_ptr ctx;
        SSL_ptr ssl;
        TLSInfo hop_tls;
        if (!tls_handshake_on_socket(sock.get(), ctx, ssl, hop_tls, ip, connect_port, budget, connect_host))
            break;

        result.tls = hop_tls;
        result.tls_ok = !hop_tls.tls_version.empty() || !hop_tls.cn.empty();

        std::string log_ctx = "port=" + std::to_string(connect_port) + " sni=" + connect_host;
        std::string req = build_http_get_request(path, connect_host);
        if (!ssl_write_all(ssl.get(), sock.get(), req, budget, log_ctx))
            break;

        std::string raw;
        if (!ssl_read_http_response(ssl.get(), sock.get(), raw, ms_remaining(), 65536))
            break;

        HttpInfo hop_http;
        parse_http_response(raw, hop_http);
        result.http = hop_http;
        result.http_ok = hop_http.status_code > 0;

        SSL_shutdown(ssl.get());

        if (!is_redirect_status(hop_http.status_code) || hop >= max_redirects)
            break;

        std::string next_path;
        std::string next_host;
        int next_port = connect_port;
        if (!resolve_redirect_target(hop_http.redirect_location, connect_host, connect_port,
                                     next_path, next_host, next_port))
            break;

        path = next_path;
        connect_host = next_host;
        connect_port = next_port;
    }
#endif
    return result;
}

HttpInfo port_probe_http(const std::string& ip, int port, int timeout_ms, bool aggressive,
                         const std::string& host_header) {
    HttpInfo info{};
    if (port_is_tls_candidate(port)) return info;

    FdGuard sock(port_tcp_socket(ip));
    if (sock.get() < 0) return info;
    if (!port_tcp_connect_to(ip, port, timeout_ms, sock.get())) return info;

    struct pollfd pfd{};
    pfd.fd = sock.get();

    const std::string& host = host_header.empty() ? ip : host_header;
    std::string req = build_http_get_request("/", host);
    send(sock.get(), req.c_str(), req.size(), MSG_NOSIGNAL);

    pfd.events = POLLIN;
    std::string res;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    std::vector<char> buf(4096);
    while (res.size() < 65536) {
        auto now = std::chrono::steady_clock::now();
        int remaining = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
        if (remaining <= 0) break;
        pfd.revents = 0;
        if (poll(&pfd, 1, remaining) <= 0) break;
        ssize_t n = recv(sock.get(), buf.data(), buf.size(), 0);
        if (n > 0) {
            res.append(buf.data(), static_cast<size_t>(n));
            if (res.find("\r\n\r\n") != std::string::npos) break;
        } else if (n == 0) {
            break;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            break;
        }
    }

    parse_http_response(res, info);

    if (aggressive && (info.status_code == 200 || info.status_code == 403 || info.status_code == 401)) {
        std::vector<std::string> paths = {"/.git/HEAD", "/admin", "/.env", "/api/v1", "/swagger-ui.html"};
        for (const auto& path : paths) {
            FdGuard psock(port_tcp_socket(ip));
            if (psock.get() < 0) continue;
            if (!port_tcp_connect_to(ip, port, 1000, psock.get())) continue;

            pfd.fd = psock.get();

            std::string preq = build_http_get_request(path, host);
            send(psock.get(), preq.c_str(), preq.size(), MSG_NOSIGNAL);

            pfd.events = POLLIN;
            if (poll(&pfd, 1, 1000) > 0) {
                std::vector<char> pbuf(1024, 0);
                ssize_t n = recv(psock.get(), pbuf.data(), pbuf.size() - 1, 0);
                if (n > 0) {
                    std::string pres(pbuf.data(), n);
                    if (pres.find("HTTP/1.1 200") != std::string::npos ||
                        pres.find("HTTP/1.0 200") != std::string::npos) {
                        info.interesting_paths.push_back(InputGuard::sanitize_output(path));

                        if (path == "/.git/HEAD" && pres.find("ref: refs/") != std::string::npos) {
                            info.interesting_paths.back() += " (git repo exposed)";
                        } else if (path == "/.env" && pres.find("=") != std::string::npos) {
                            info.interesting_paths.back() += " (env file exposed)";
                        }
                    }
                }
            }
        }
    }

    return info;
}

void print_port_http_enrichment(const HttpInfo& http) {
    if (http.status_code <= 0) return;

    print_detail_prefix("http");
    std::cout << http.status_code;
    if (!http.redirect_location.empty())
        std::cout << " -> " << http.redirect_location;
    if (!http.server.empty())
        std::cout << " | Server: " << http.server;
    if (!http.title.empty())
        std::cout << " | Title: " << http.title;
    std::cout << RESET << "\n";

    if (!http.interesting_paths.empty()) {
        print_detail_prefix("paths");
        size_t limit = std::min(http.interesting_paths.size(), size_t{5});
        for (size_t i = 0; i < limit; ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << http.interesting_paths[i];
        }
        if (http.interesting_paths.size() > limit) std::cout << ", ...";
        std::cout << RESET << "\n";
    }

    print_detail_prefix("headers");
    std::cout
              << "HSTS=" << (http.hsts ? "yes" : "no")
              << " CSP=" << (http.csp ? "yes" : "no")
              << " X-Frame=" << (http.x_frame ? "yes" : "no")
              << RESET << "\n";
}

void print_port_powered_by_line(const HttpInfo& http) {
    if (http.powered_by.empty()) return;
    print_detail_prefix("stack");
    std::cout << sanitize(http.powered_by) << RESET << "\n";
}

void print_port_stack_disclosures(const ScanResults& r) {
    std::vector<std::pair<int, std::string>> rows;
    for (const auto& pr : r.open_ports) {
        if (!pr.http_port || pr.http.powered_by.empty()) continue;
        rows.push_back({pr.port, pr.http.powered_by});
    }
    if (rows.empty()) return;

    print_section("STACK DISCLOSURES");
    for (const auto& row : rows) {
        std::cout << BLOOD_RED << "  " << WHITE << std::left << std::setw(8) << row.first
                  << sanitize(row.second) << RESET << "\n";
    }
}

void print_port_tls_enrichment(const TLSInfo& tls) {
    if (tls.tls_version.empty() && tls.cn.empty() && tls.cipher.empty()) return;

    if (!tls.tls_version.empty() || !tls.cipher.empty()) {
        print_detail_prefix("tls");
        if (!tls.tls_version.empty()) std::cout << tls.tls_version;
        if (!tls.cipher.empty()) {
            if (!tls.tls_version.empty()) std::cout << " / ";
            std::cout << tls.cipher;
        }
        std::cout << RESET << "\n";
    }

    if (!tls.cn.empty() || !tls.issuer.empty() || !tls.expiry.empty() || tls.expired || tls.self_signed) {
        print_detail_prefix("cert");
        if (!tls.cn.empty()) std::cout << "CN=" << tls.cn;
        if (!tls.issuer.empty()) std::cout << " | Issuer: " << tls.issuer;
        if (!tls.expiry.empty()) std::cout << " | exp: " << tls.expiry;
        if (tls.expired) std::cout << " (expired)";
        if (tls.self_signed) std::cout << " (self-signed)";
        std::cout << RESET << "\n";
    }

    if (!tls.sans.empty()) {
        print_detail_prefix("sans");
        size_t limit = std::min(tls.sans.size(), size_t{8});
        for (size_t i = 0; i < limit; ++i) {
            if (i) std::cout << ", ";
            std::cout << tls.sans[i];
        }
        if (tls.sans.size() > 8) std::cout << ", ...";
        std::cout << RESET << "\n";
    }
}
