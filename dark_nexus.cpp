#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <sstream>
#include <iomanip>
#include <map>
#include <algorithm>
#include <fstream>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <regex>
#include <queue>
#include <functional>
#include <condition_variable>
#include <unordered_set>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <chrono>
 
#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define WHITE   "\033[97m"
#define BOLD    "\033[1m"
#define DIM     "\033[2m"
#define GRAY    "\033[90m"
 
std::mutex g_print_mtx;
 
// falls back to 80 if stdout isnt a tty (pipe, redirect, etc.)
static int term_width() {
    struct winsize w;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0 && w.ws_col > 0)
        return w.ws_col;
    return 80;
}
 
// ------------------------------------------------------------------
// sanitize(): proper csi/osc sequence parser
// which missed things like osc palette sequences used in some banners
// ------------------------------------------------------------------
std::string sanitize(const std::string &s) {
    std::string out;
    out.reserve(s.size());
    size_t i = 0;
    while (i < s.size()) {
        unsigned char c = (unsigned char)s[i];
        if (c == 0x1b) {
            i++;
            if (i >= s.size()) break;
            if (s[i] == '[') {
                // csi skip until final byte in range 0 40-0 7e
                i++;
                while (i < s.size() && !((unsigned char)s[i] >= 0x40 && (unsigned char)s[i] <= 0x7e))
                    i++;
                if (i < s.size()) i++; // skip the final byte
            } else if (s[i] == ']') {
                // osc: terminated by bel or esc '\'
                i++;
                while (i < s.size()) {
                    if (s[i] == '\x07') { i++; break; }
                    if (s[i] == '\x1b' && i + 1 < s.size() && s[i+1] == '\\') { i += 2; break; }
                    i++;
                }
            } else {
                // two byte sequence: esc and single char
                i++;
            }
            continue;
        }
        if ((c >= 32 && c <= 126) || c == '\n' || c == '\t') out += (char)c;
        i++;
    }
    return out;
}
 
// whitelist validation anything that could confuse execvp or curl gets rejected
bool valid_target(const std::string &s) {
    if (s.empty() || s.size() > 253) return false;
    static const std::regex ok(R"(^[a-zA-Z0-9.\-_:/@]+$)");
    return std::regex_match(s, ok);
}
 
bool valid_username(const std::string &s) {
    if (s.empty() || s.size() > 64) return false;
    static const std::regex ok(R"(^[a-zA-Z0-9.\-_]+$)");
    return std::regex_match(s, ok);
}
 
bool valid_port(int p) { return p >= 1 && p <= 65535; }
 
// ------------------------------------------------------------------
// safe exec fork+execvp no shell, pipe for stdout, select timeout
// ------------------------------------------------------------------
std::string safe_exec(const std::vector<std::string> &args, int timeout_sec = 8) {
    if (args.empty()) return "";
 
    std::vector<char *> argv;
    for (auto &a : args) argv.push_back(const_cast<char *>(a.c_str()));
    argv.push_back(nullptr);
 
    int pipefd[2];
    if (pipe(pipefd) < 0) return "";
 
    pid_t pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return ""; }
 
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, STDERR_FILENO); close(devnull); }
        execvp(argv[0], argv.data());
        _exit(1);
    }
 
    close(pipefd[1]);
    fcntl(pipefd[0], F_SETFL, O_NONBLOCK);
 
    std::string out;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_sec);
 
    while (true) {
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) { kill(pid, SIGKILL); break; }
 
        auto us = std::chrono::duration_cast<std::chrono::microseconds>(deadline - now);
        timeval tv{ us.count() / 1000000, us.count() % 1000000 };
        fd_set fds; FD_ZERO(&fds); FD_SET(pipefd[0], &fds);
 
        if (select(pipefd[0] + 1, &fds, nullptr, nullptr, &tv) <= 0) {
            kill(pid, SIGKILL); break;
        }
 
        char buf[4096];
        ssize_t n = read(pipefd[0], buf, sizeof(buf) - 1);
        if (n <= 0) break;
        buf[n] = 0;
        out += buf;
        if (out.size() > 65536) break;
    }
 
    close(pipefd[0]);
    waitpid(pid, nullptr, 0);
    return sanitize(out);
}
 
// ------------------------------------------------------------------
// safe exec with input(): like safe exec but writes to child stdin
// two pipes: parent→child stdin, child stdout parent
// ------------------------------------------------------------------
std::string safe_exec_with_input(const std::vector<std::string> &args,
                                  const std::string &input,
                                  int timeout_sec = 8) {
    if (args.empty()) return "";
 
    std::vector<char *> argv;
    for (auto &a : args) argv.push_back(const_cast<char *>(a.c_str()));
    argv.push_back(nullptr);
 
    int in_pipe[2], out_pipe[2];
    if (pipe(in_pipe)  < 0) return "";
    if (pipe(out_pipe) < 0) { close(in_pipe[0]); close(in_pipe[1]); return ""; }
 
    pid_t pid = fork();
    if (pid < 0) {
        close(in_pipe[0]);  close(in_pipe[1]);
        close(out_pipe[0]); close(out_pipe[1]);
        return "";
    }
 
    if (pid == 0) {
        dup2(in_pipe[0], STDIN_FILENO);
        close(in_pipe[0]); close(in_pipe[1]);
        dup2(out_pipe[1], STDOUT_FILENO);
        close(out_pipe[0]); close(out_pipe[1]);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, STDERR_FILENO); close(devnull); }
        execvp(argv[0], argv.data());
        _exit(1);
    }
 
    close(in_pipe[0]);
    close(out_pipe[1]);
 
    if (!input.empty())
        write(in_pipe[1], input.data(), input.size());
    close(in_pipe[1]); // EOF signals child to proceed
 
    fcntl(out_pipe[0], F_SETFL, O_NONBLOCK);
    std::string out;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_sec);
 
    while (true) {
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) { kill(pid, SIGKILL); break; }
        auto us = std::chrono::duration_cast<std::chrono::microseconds>(deadline - now);
        timeval tv{ us.count() / 1000000, us.count() % 1000000 };
        fd_set fds; FD_ZERO(&fds); FD_SET(out_pipe[0], &fds);
        if (select(out_pipe[0] + 1, &fds, nullptr, nullptr, &tv) <= 0) {
            kill(pid, SIGKILL); break;
        }
        char buf[4096];
        ssize_t n = read(out_pipe[0], buf, sizeof(buf) - 1);
        if (n <= 0) break;
        buf[n] = 0;
        out += buf;
        if (out.size() > 65536) break;
    }
 
    close(out_pipe[0]);
    waitpid(pid, nullptr, 0);
    return sanitize(out);
}
 
// curl via execvp
std::string safe_curl(const std::string &url, int timeout = 8) {
    if (url.find('\'') != std::string::npos) return "";
    return safe_exec({"curl", "-s", "--max-time", std::to_string(timeout),
                      "-L", "-A", "Mozilla/5.0", "--", url}, timeout + 2);
}
 
// ------------------------------------------------------------------
// network helpers
// ------------------------------------------------------------------
std::string resolve(const std::string &host) {
    addrinfo hints{}, *res;
    hints.ai_family = AF_INET;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0) return "";
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &((sockaddr_in *)res->ai_addr)->sin_addr, buf, sizeof(buf));
    freeaddrinfo(res);
    return buf;
}
 
bool tcp_probe(const std::string &ip, int port, int ms = 500) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;
    timeval tv{ ms / 1000, (ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    sockaddr_in sa{};
    sa.sin_family = AF_INET; sa.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
    fcntl(fd, F_SETFL, O_NONBLOCK);
    connect(fd, (sockaddr *)&sa, sizeof(sa));
    fd_set fds; FD_ZERO(&fds); FD_SET(fd, &fds);
    int r = select(fd + 1, nullptr, &fds, nullptr, &tv);
    close(fd);
    return r > 0;
}
 
std::pair<bool, int> tcp_probe_ms(const std::string &ip, int port, int ms = 1000) {
    auto t0 = std::chrono::high_resolution_clock::now();
    bool ok = tcp_probe(ip, port, ms);
    int elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now() - t0).count();
    return {ok, elapsed};
}
 
// ------------------------------------------------------------------
// json_val minimal flat key extractor, good enough for ip api responses
// doesnt handle nested keys with the same name, but we dont need that
// ------------------------------------------------------------------
std::string json_val(const std::string &json, const std::string &key) {
    auto pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return "";
    pos = json.find(':', pos);
    if (pos == std::string::npos) return "";
    while (++pos < json.size() && (json[pos] == ' ' || json[pos] == '\t'));
    if (pos >= json.size()) return "";
    if (json[pos] == '"') {
        auto end = json.find('"', ++pos);
        return end == std::string::npos ? "" : json.substr(pos, end - pos);
    }
    auto end = json.find_first_of(",}\n", pos);
    std::string v = json.substr(pos, (end == std::string::npos ? json.size() : end) - pos);
    while (!v.empty() && (v.back() == ' ' || v.back() == '\r' || v.back() == '\n')) v.pop_back();
    return v;
}
 
// ------------------------------------------------------------------
// ThreadPool
// replaces the "spawn N threads per call" pattern in osint and subdomain scans
// join_all() blocks until queue is empty and all workers are idle
// ------------------------------------------------------------------
class ThreadPool {
public:
    explicit ThreadPool(size_t n) : active_(0), stop_(false) {
        workers_.reserve(n);
        for (size_t i = 0; i < n; i++)
            workers_.emplace_back(&ThreadPool::loop, this);
    }
 
    template<class F>
    void push(F &&f) {
        {
            std::lock_guard<std::mutex> lk(mtx_);
            tasks_.emplace(std::forward<F>(f));
        }
        cv_.notify_one();
    }
 
    // blocks until queue drained and all workers idle
    void join_all() {
        std::unique_lock<std::mutex> lk(mtx_);
        done_.wait(lk, [this] { return tasks_.empty() && active_ == 0; });
    }
 
    ~ThreadPool() {
        {
            std::lock_guard<std::mutex> lk(mtx_);
            stop_ = true;
        }
        cv_.notify_all();
        for (auto &t : workers_) t.join();
    }
 
private:
    void loop() {
        for (;;) {
            std::function<void()> task;
            {
                std::unique_lock<std::mutex> lk(mtx_);
                cv_.wait(lk, [this] { return stop_ || !tasks_.empty(); });
                if (stop_ && tasks_.empty()) return;
                task = std::move(tasks_.front());
                tasks_.pop();
                ++active_;
            }
            task();
            {
                std::lock_guard<std::mutex> lk(mtx_);
                --active_;
            }
            done_.notify_all();
        }
    }
 
    std::vector<std::thread>          workers_;
    std::queue<std::function<void()>> tasks_;
    std::mutex                        mtx_;
    std::condition_variable           cv_, done_;
    size_t                            active_;
    bool                              stop_;
};
 
// ------------------------------------------------------------------
// JSON export — results accumulate here during scan
// ------------------------------------------------------------------
struct ScanResult {
    std::string target;
    std::string timestamp;
    std::vector<std::pair<int,std::string>> open_ports;
    std::vector<std::string> subdomains;
    std::vector<std::string> osint_hits;
    std::string geo_country, geo_city, geo_isp, geo_as;
    std::string os_guess;
    bool proxy = false, hosting = false;
};
 
ScanResult g_result;
 
// ------------------------------------------------------------------
// json_escape(): was missing entirely, causing broken output
// when isp names / city names / hostnames have quotes or backslashes
// ------------------------------------------------------------------
std::string json_escape(const std::string &s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += (char)c;
                }
        }
    }
    return out;
}
 
void export_json(const std::string &filename) {
    std::ofstream f(filename);
    if (!f) { std::cout << RED << "  failed to write " << filename << "\n" << RESET; return; }
 
    f << "{\n";
    f << "  \"target\": \""    << json_escape(g_result.target)      << "\",\n";
    f << "  \"timestamp\": \"" << json_escape(g_result.timestamp)   << "\",\n";
    f << "  \"geo\": {\n";
    f << "    \"country\": \"" << json_escape(g_result.geo_country) << "\",\n";
    f << "    \"city\": \""    << json_escape(g_result.geo_city)    << "\",\n";
    f << "    \"isp\": \""     << json_escape(g_result.geo_isp)     << "\",\n";
    f << "    \"as\": \""      << json_escape(g_result.geo_as)      << "\",\n";
    f << "    \"proxy\": "     << (g_result.proxy   ? "true" : "false") << ",\n";
    f << "    \"hosting\": "   << (g_result.hosting ? "true" : "false") << "\n";
    f << "  },\n";
    f << "  \"os\": \""        << json_escape(g_result.os_guess)    << "\",\n";
    f << "  \"open_ports\": [\n";
    for (size_t i = 0; i < g_result.open_ports.size(); i++) {
        f << "    {\"port\": " << g_result.open_ports[i].first
          << ", \"service\": \"" << json_escape(g_result.open_ports[i].second) << "\"}";
        if (i + 1 < g_result.open_ports.size()) f << ",";
        f << "\n";
    }
    f << "  ],\n";
    f << "  \"subdomains\": [";
    for (size_t i = 0; i < g_result.subdomains.size(); i++) {
        f << "\"" << json_escape(g_result.subdomains[i]) << "\"";
        if (i + 1 < g_result.subdomains.size()) f << ", ";
    }
    f << "],\n";
    f << "  \"osint\": [";
    for (size_t i = 0; i < g_result.osint_hits.size(); i++) {
        f << "\"" << json_escape(g_result.osint_hits[i]) << "\"";
        if (i + 1 < g_result.osint_hits.size()) f << ", ";
    }
    f << "]\n}\n";
 
    std::cout << GREEN << "  saved to " << filename << "\n" << RESET;
}
 
// ------------------------------------------------------------------
// progress bar
// ------------------------------------------------------------------
void draw_progress(int done, int total, const std::string &label = "") {
    if (total <= 0) return;
    int w = std::min(term_width() - 20, 50);
    int filled = (int)((double)done / total * w);
    std::string bar(filled, '=');
    if (filled < w) bar += '>';
    bar += std::string(std::max(0, w - filled - 1), ' ');
    int pct = (int)((double)done / total * 100);
    std::cout << "\r" << CYAN << "  [" << GREEN << bar << CYAN << "] "
              << WHITE << std::setw(3) << pct << "% "
              << GRAY << label << RESET << std::flush;
}
 
// ------------------------------------------------------------------
// service map + risk rating
// ------------------------------------------------------------------
std::string svc(int port) {
    static std::map<int, std::string> db = {
        {21,"FTP"},{22,"SSH"},{23,"Telnet"},{25,"SMTP"},{53,"DNS"},
        {80,"HTTP"},{110,"POP3"},{143,"IMAP"},{443,"HTTPS"},{445,"SMB"},
        {3306,"MySQL"},{3389,"RDP"},{5432,"Postgres"},{5900,"VNC"},
        {6379,"Redis"},{8080,"HTTP"},{8443,"HTTPS"},{27017,"MongoDB"},
        {1433,"MSSQL"},{9200,"Elastic"},{2375,"Docker"},{6443,"K8s"},
        {11211,"Memcached"},{161,"SNMP"},{389,"LDAP"},{111,"RPC"},
        {512,"rexec"},{513,"rlogin"},{514,"rsh"},{873,"rsync"},
        {1080,"SOCKS"},{1194,"OpenVPN"},{1521,"Oracle"},
        {2049,"NFS"},{2181,"ZooKeeper"},{3000,"Grafana"},{3690,"SVN"},
        {4444,"Metasploit"},{5000,"UPnP"},{5601,"Kibana"},
        {6000,"X11"},{7001,"WebLogic"},{8888,"Jupyter"},{9090,"Prometheus"},
        {9200,"Elasticsearch"},{50070,"Hadoop"}
    };
    auto it = db.find(port);
    return it != db.end() ? it->second : "unknown";
}
 
// use unordered_set for O(1) lookup instead of linear scan
std::string risk(int port) {
    static const std::unordered_set<int> hi = {
        21,23,512,513,514,3389,5900,445,2375,111,161,4444,6000,7001,50070
    };
    static const std::unordered_set<int> md = {
        22,3306,5432,27017,6379,1433,9200,1521,873,1080,5601,8888
    };
    if (hi.count(port)) return std::string(RED)    + "HIGH" + RESET;
    if (md.count(port)) return std::string(YELLOW) + "MED"  + RESET;
    return std::string(GREEN) + "LOW" + RESET;
}
 
// banner grab 2s timeout, always sanitized before display
std::string banner(const std::string &ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return "";
    timeval tv{2, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    sockaddr_in sa{};
    sa.sin_family = AF_INET; sa.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
    if (connect(fd, (sockaddr *)&sa, sizeof(sa)) < 0) { close(fd); return ""; }
    if (port == 80 || port == 8080) {
        std::string req = "HEAD / HTTP/1.1\r\nHost: " + ip + "\r\nConnection: close\r\n\r\n";
        send(fd, req.c_str(), req.size(), 0);
    }
    std::vector<char> buf(256, 0);
    ssize_t n = recv(fd, buf.data(), buf.size() - 1, 0);
    close(fd);
    if (n <= 0) return "";
    std::string s(buf.data(), n);
    s.erase(std::remove(s.begin(), s.end(), '\r'), s.end());
    auto nl = s.find('\n');
    if (nl != std::string::npos) s = s.substr(0, nl);
    if (s.size() > 55) s = s.substr(0, 55) + "...";
    return sanitize(s);
}
 
// ------------------------------------------------------------------
// UI helpers
// ------------------------------------------------------------------
void print_sep() {
    std::cout << CYAN << "  " << std::string(58, '=') << RESET << "\n";
}
 
void print_header(const std::string &title) {
    std::cout << "\n" << CYAN << BOLD
              << "  +" << std::string(58, '-') << "+\n"
              << "  |  " << WHITE << std::left << std::setw(56) << title << CYAN << "|\n"
              << "  +" << std::string(58, '-') << "+\n" << RESET;
}
 
void print_section(const std::string &title) {
    int pad = std::max(0, 46 - (int)title.size());
    std::cout << "\n" << CYAN << BOLD << "  -- " << WHITE << title
              << CYAN << " " << std::string(pad, '-') << RESET << "\n";
}
 
void print_row(const std::string &label, const std::string &val) {
    if (val.empty() || val == "null") return;
    std::cout << CYAN << "  [" << WHITE << std::left << std::setw(16) << label
              << CYAN << "] " << RESET << sanitize(val) << "\n";
}
 
std::string now_str() {
    time_t t = time(nullptr);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&t));
    return buf;
}
 
// ================================================================
//  1. PORT SCAN — top-1000 default, progress bar
// ================================================================
static const std::vector<int> TOP1000 = {
    1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,
    70,79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,
    135,139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,
    280,301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,
    464,465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,
    563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,
    705,711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,
    888,898,900,901,902,903,911,912,981,987,990,992,993,995,999,1000,1001,
    1002,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,1029,
    1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,
    1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,1055,1056,1057,
    1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,1068,1069,1070,1071,
    1072,1073,1074,1075,1076,1077,1078,1079,1080,1110,1234,1433,1434,1521,
    1720,1723,1755,1900,2000,2001,2049,2121,2181,2375,2376,3000,3128,3306,
    3389,3690,4444,4445,4899,5000,5432,5900,5901,6000,6001,6379,6443,7001,
    7443,8000,8008,8080,8081,8443,8888,9000,9090,9200,9300,10000,11211,
    27017,50070
};
 
void port_scan(const std::string &ip, int start, int end, int nthreads = 200) {
    print_header("PORT SCAN // " + ip);
 
    std::vector<int> ports;
    if (start == 0 && end == 0) {
        ports = TOP1000;
        std::cout << YELLOW << "  mode: top-1000 (default)\n" << RESET;
    } else {
        for (int p = start; p <= end; p++) ports.push_back(p);
        std::cout << YELLOW << "  scanning " << start << "-" << end
                  << "  threads=" << std::min(nthreads, (int)ports.size()) << "\n" << RESET;
    }
 
    std::vector<std::pair<int,int>> open;
    std::mutex mx;
    std::atomic<int> cur(0), done_count(0);
    int total = ports.size();
    int tc = std::min(nthreads, total);
 
    auto worker = [&]() {
        while (true) {
            int i = cur.fetch_add(1);
            if (i >= total) break;
            auto [ok, ms] = tcp_probe_ms(ip, ports[i], 400);
            if (ok) { std::lock_guard<std::mutex> lk(mx); open.push_back({ports[i], ms}); }
            done_count++;
            if (done_count % 50 == 0) {
                std::lock_guard<std::mutex> lk(g_print_mtx);
                draw_progress(done_count, total, std::to_string(open.size()) + " open");
            }
        }
    };
 
    std::vector<std::thread> pool;
    pool.reserve(tc);
    for (int i = 0; i < tc; i++) pool.emplace_back(worker);
    for (auto &t : pool) t.join();
 
    draw_progress(total, total, std::to_string(open.size()) + " open");
    std::cout << "\n";
 
    std::sort(open.begin(), open.end());
 
    std::cout << "\n" << BOLD << WHITE
              << "  PORT        SERVICE         LATENCY    RISK      BANNER\n"
              << "  " << std::string(78, '-') << "\n" << RESET;
 
    for (auto &[p, ms] : open) {
        std::string b = banner(ip, p);
        std::string s = svc(p);
        std::cout << GREEN << "  " << std::left << std::setw(12) << p
                  << WHITE << std::setw(16) << s
                  << CYAN  << std::setw(11) << (std::to_string(ms) + "ms")
                  << std::setw(10) << risk(p)
                  << GRAY  << b << RESET << "\n";
        g_result.open_ports.push_back({p, s});
    }
 
    if (open.empty())
        std::cout << YELLOW << "  no open ports\n" << RESET;
    else
        std::cout << CYAN << "\n  total: " << open.size() << " open\n" << RESET;
}
 
// ================================================================
//  2. NETWORK SCAN
// ================================================================
void net_scan(const std::string &subnet) {
    print_header("NETWORK SCAN // " + subnet + ".0/24");
    std::cout << YELLOW << "  scanning...\n\n" << RESET;
 
    std::atomic<int> cur(1), found(0);
 
    auto worker = [&]() {
        while (true) {
            int i = cur.fetch_add(1);
            if (i > 254) break;
            std::string ip = subnet + "." + std::to_string(i);
            auto out = safe_exec({"ping", "-c1", "-W1", ip}, 3);
            bool alive = !out.empty() && out.find("1 received") != std::string::npos;
            if (!alive)
                alive = tcp_probe(ip,80,250) || tcp_probe(ip,443,250)
                     || tcp_probe(ip,22,250) || tcp_probe(ip,445,250);
            if (!alive) continue;
            found++;
            char hbuf[NI_MAXHOST] = {};
            sockaddr_in sa{}; sa.sin_family = AF_INET;
            inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
            getnameinfo((sockaddr *)&sa, sizeof(sa), hbuf, sizeof(hbuf), nullptr, 0, 0);
            std::string os = "?";
            if      (tcp_probe(ip,3389,200) || tcp_probe(ip,445,200)) os = "Windows";
            else if (tcp_probe(ip,22,200))                             os = "Linux";
            std::lock_guard<std::mutex> lk(g_print_mtx);
            std::cout << GREEN << "  [+] " << std::left << std::setw(16) << ip
                      << CYAN  << std::setw(34) << sanitize(strlen(hbuf) ? hbuf : "no-hostname")
                      << YELLOW << os << RESET << "\n";
        }
    };
 
    std::vector<std::thread> pool;
    pool.reserve(50);
    for (int i = 0; i < 50; i++) pool.emplace_back(worker);
    for (auto &t : pool) t.join();
    std::cout << CYAN << "\n  alive: " << found << " hosts\n" << RESET;
}
 
// ================================================================
//  3. OS DETECTION
// ================================================================
void os_detect(const std::string &ip) {
    print_header("OS DETECTION // " + ip);
 
    struct Check { int port; const char *name; };
    std::vector<Check> checks = {
        {22,"SSH"},{80,"HTTP"},{443,"HTTPS"},{445,"SMB"},
        {3389,"RDP"},{3306,"MySQL"},{8080,"HTTP-ALT"},{161,"SNMP"},{23,"Telnet"}
    };
 
    std::map<int,bool> res;
    std::cout << "\n" << BOLD << WHITE << "  PORT FINGERPRINT:\n" << RESET;
    for (auto &c : checks) {
        bool ok = tcp_probe(ip, c.port, 600);
        res[c.port] = ok;
        std::cout << CYAN << "  [" << std::left << std::setw(5) << c.port
                  << " " << std::setw(12) << c.name << "] "
                  << (ok ? GREEN"OPEN  " : RED"closed") << RESET;
        if (ok) { auto b = banner(ip, c.port); if (!b.empty()) std::cout << GRAY << "  " << b; }
        std::cout << "\n";
    }
 
    auto ping_out = safe_exec({"ping", "-c3", "-W1", ip}, 5);
    int ttl = 0;
    auto tp = ping_out.find("ttl=");
    if (tp == std::string::npos) tp = ping_out.find("TTL=");
    if (tp != std::string::npos) try { ttl = std::stoi(ping_out.substr(tp + 4)); } catch (...) {}
 
    auto rtt_pos = ping_out.find("rtt min");
    std::string rtt_line;
    if (rtt_pos != std::string::npos) {
        auto el = ping_out.find('\n', rtt_pos);
        rtt_line = ping_out.substr(rtt_pos, el - rtt_pos);
    }
 
    std::cout << "\n" << BOLD << WHITE << "  TTL ANALYSIS:\n" << RESET;
    std::cout << CYAN << "  [ttl]     " << RESET << (ttl ? std::to_string(ttl) : "n/a") << "\n";
    if (!rtt_line.empty())
        std::cout << CYAN << "  [rtt]     " << RESET << rtt_line << "\n";
 
    std::string os, conf;
    if      (res[3389] || res[445])              { os = "Windows";           conf = "high (rdp/smb)"; }
    else if (ttl >= 120 && ttl <= 128)           { os = "Windows";           conf = "medium (ttl~128)"; }
    else if (ttl >= 60  && ttl <= 64 && res[22]) { os = "Linux/Unix";        conf = "high (ttl~64+ssh)"; }
    else if (ttl >= 60  && ttl <= 64)            { os = "Linux/Unix";        conf = "medium (ttl~64)"; }
    else if (ttl >= 250)                         { os = "Cisco/Network";     conf = "high (ttl~255)"; }
    else if (res[80] || res[443])                { os = "Linux (webserver)"; conf = "low"; }
    else                                         { os = "unknown";           conf = "n/a"; }
 
    std::cout << "\n" << CYAN << "  [os]      " << YELLOW << BOLD << os << RESET << "\n"
              << CYAN << "  [conf]    " << RESET << conf << "\n";
    g_result.os_guess = os;
}
 
// ================================================================
//  4. IP FULL INTELLIGENCE
// ================================================================
void ip_intel(const std::string &ip) {
    print_header("IP INTELLIGENCE // " + ip);
    g_result.target = ip;
    g_result.timestamp = now_str();
 
    print_section("GEOLOCATION");
    std::cout << YELLOW << "  fetching...\n" << RESET;
    std::string body = safe_curl(
        "http://ip-api.com/json/" + ip +
        "?fields=status,message,country,countryCode,regionName,"
        "city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query");
 
    if (!body.empty()) {
        auto g = [&](const std::string &k) { return json_val(body, k); };
        if (g("status") != "fail") {
            print_row("ip",       g("query").empty() ? ip : g("query"));
            print_row("country",  g("country") + " (" + g("countryCode") + ")");
            print_row("region",   g("regionName"));
            print_row("city",     g("city"));
            print_row("zip",      g("zip"));
            print_row("coords",   g("lat") + ", " + g("lon"));
            print_row("timezone", g("timezone"));
 
            print_section("NETWORK");
            print_row("isp",      g("isp"));
            print_row("org",      g("org"));
            print_row("as",       g("as"));
            print_row("as name",  g("asname"));
            print_row("hostname", g("reverse"));
 
            print_section("FLAGS");
            auto proxy   = g("proxy"),
                 hosting = g("hosting"),
                 mobile  = g("mobile");
            std::cout << CYAN << "  [proxy/vpn]    "
                      << (proxy == "true" ? RED"YES  detected" : GREEN"no") << RESET << "\n";
            std::cout << CYAN << "  [hosting/dc]   "
                      << (hosting == "true" ? YELLOW"yes - datacenter" : GREEN"no - residential") << RESET << "\n";
            std::cout << CYAN << "  [mobile]       " << RESET << (mobile == "true" ? "yes" : "no") << "\n";
 
            g_result.geo_country = g("country");
            g_result.geo_city    = g("city");
            g_result.geo_isp     = g("isp");
            g_result.geo_as      = g("as");
            g_result.proxy       = proxy == "true";
            g_result.hosting     = hosting == "true";
 
            auto lat = g("lat"), lon = g("lon");
            if (!lat.empty())
                std::cout << "\n" << YELLOW << "  map: https://maps.google.com/?q="
                          << lat << "," << lon << "\n" << RESET;
        }
    }
 
    print_section("REVERSE DNS");
    auto rdns = safe_exec({"host", ip}, 5);
    std::cout << (rdns.empty() ? std::string(GRAY) + "  none\n" + RESET : GREEN + rdns + RESET);
 
    print_section("ASN / BGP");
    auto bgp_raw = safe_exec({"whois", "-h", "whois.radb.net", ip}, 8);
    if (bgp_raw.empty()) {
        std::cout << GRAY << "  no bgp info\n" << RESET;
    } else {
        std::istringstream ss(bgp_raw); std::string line; int count = 0;
        while (std::getline(ss, line) && count < 6) {
            if (line.find("route:") != std::string::npos ||
                line.find("origin:") != std::string::npos ||
                line.find("descr:") != std::string::npos) {
                auto c = line.find(':');
                if (c != std::string::npos)
                    std::cout << CYAN << "  [" << std::left << std::setw(8) << line.substr(0,c)
                              << "] " << RESET << sanitize(line.substr(c+1)) << "\n";
                count++;
            }
        }
    }
 
    print_section("ABUSE CONTACTS");
    auto whois_raw = safe_exec({"whois", ip}, 10);
    if (!whois_raw.empty()) {
        std::istringstream ss(whois_raw); std::string line; int count = 0;
        std::vector<std::string> want = {"OrgAbuseEmail","abuse","OrgName","Phone"};
        while (std::getline(ss, line) && count < 8) {
            std::string ll = line;
            std::transform(ll.begin(), ll.end(), ll.begin(), ::tolower);
            for (auto &w : want) {
                std::string wl = w;
                std::transform(wl.begin(), wl.end(), wl.begin(), ::tolower);
                if (ll.find(wl) != std::string::npos) {
                    auto c = line.find(':');
                    if (c != std::string::npos)
                        std::cout << CYAN << "  [" << std::left << std::setw(16) << line.substr(0,c)
                                  << "] " << YELLOW << sanitize(line.substr(c+1)) << RESET << "\n";
                    count++; break;
                }
            }
        }
    }
 
    print_section("BLACKLIST CHECK");
    std::vector<std::string> lists = {
        "zen.spamhaus.org","bl.spamcop.net",
        "dnsbl.sorbs.net","b.barracudacentral.org"
    };
    std::string parts[4]; int pi = 0; std::string tmp;
    for (char ch : ip) { if (ch == '.') { parts[pi++] = tmp; tmp = ""; } else tmp += ch; }
    parts[pi] = tmp;
    std::string rev = parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0];
    for (auto &bl : lists) {
        std::string hit = resolve(rev + "." + bl);
        std::cout << CYAN << "  [" << std::left << std::setw(28) << bl << "] "
                  << (hit.empty() ? GREEN"clean" : RED"LISTED") << RESET << "\n";
    }
 
    print_section("OPEN PORTS (top 20)");
    std::vector<int> top = {21,22,23,25,53,80,110,143,443,445,993,995,
                             3306,3389,5432,5900,6379,8080,8443,27017};
    std::cout << BOLD << WHITE
              << "  PORT        SERVICE         RISK      BANNER\n"
              << "  " << std::string(65, '-') << "\n" << RESET;
    bool any = false;
    for (int p : top) {
        if (!tcp_probe(ip, p, 600)) continue;
        any = true;
        auto b = banner(ip, p);
        std::string s = svc(p);
        std::string bs = b.size() > 40 ? b.substr(0, 40) : b;
        std::cout << GREEN << "  " << std::left << std::setw(12) << p
                  << WHITE << std::setw(16) << s
                  << std::setw(10) << risk(p)
                  << GRAY  << bs << RESET << "\n";
        g_result.open_ports.push_back({p, s});
    }
    if (!any) std::cout << GRAY << "  top ports closed\n" << RESET;
 
    // ------------------------------------------------------------------
    // SSL cert without sh -c
    // old code did: sh -c "echo Q | openssl s_client | openssl x509"
    // now: safe_exec_with_input for s_client, extract PEM in-process,
    // then safe_exec_with_input again for x509 no shell involved at all
    // ------------------------------------------------------------------
    if (tcp_probe(ip, 443, 500)) {
        print_section("SSL CERTIFICATE");
        auto s_client_out = safe_exec_with_input(
            {"openssl", "s_client", "-connect", ip + ":443", "-servername", ip},
            "Q\n", 10);
 
        const std::string begin_marker = "-----BEGIN CERTIFICATE-----";
        const std::string end_marker   = "-----END CERTIFICATE-----";
        auto bpos = s_client_out.find(begin_marker);
        auto epos = s_client_out.find(end_marker);
 
        if (bpos != std::string::npos && epos != std::string::npos) {
            std::string pem = s_client_out.substr(bpos, epos - bpos + end_marker.size());
            auto cert_info = safe_exec_with_input(
                {"openssl", "x509", "-noout", "-subject", "-issuer", "-dates"},
                pem + "\n", 5);
            if (!cert_info.empty()) {
                std::istringstream ss(cert_info); std::string line;
                while (std::getline(ss, line))
                    std::cout << CYAN << "  " << sanitize(line) << RESET << "\n";
            } else {
                std::cout << GRAY << "  could not parse cert\n" << RESET;
            }
        } else {
            std::cout << GRAY << "  could not fetch cert\n" << RESET;
        }
    }
}
 
// ================================================================
//  5. DNS LOOKUP
// ================================================================
void dns_lookup(const std::string &domain) {
    print_header("DNS LOOKUP // " + domain);
 
    std::string ip = resolve(domain);
    if (!ip.empty()) {
        std::cout << GREEN << "  [A]    " << sanitize(domain) << " -> " << ip << "\n" << RESET;
        sockaddr_in sa{}; sa.sin_family = AF_INET;
        inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
        char hbuf[NI_MAXHOST] = {};
        if (getnameinfo((sockaddr *)&sa, sizeof(sa), hbuf, sizeof(hbuf), nullptr, 0, 0) == 0)
            std::cout << GREEN << "  [PTR]  " << ip << " -> " << sanitize(hbuf) << "\n" << RESET;
    }
 
    for (auto &type : {"A","AAAA","MX","NS","TXT","CNAME","SOA"}) {
        std::cout << "\n" << YELLOW << "  [" << type << "]:\n" << RESET;
        auto out = safe_exec({"dig", "+noall", "+answer", domain, type}, 6);
        if (out.empty()) std::cout << GRAY << "  none\n" << RESET;
        else std::cout << CYAN << sanitize(out) << RESET;
    }
 
    std::cout << "\n" << YELLOW << "  [zone transfer attempt]:\n" << RESET;
    auto ns_out = safe_exec({"dig", "+short", "NS", domain}, 5);
    if (!ns_out.empty()) {
        std::string ns = ns_out.substr(0, ns_out.find('\n'));
        while (!ns.empty() && (ns.back() == '.' || ns.back() == '\n')) ns.pop_back();
        if (!ns.empty()) {
            auto zt = safe_exec({"dig", "axfr", "@" + ns, domain}, 8);
            if (zt.empty() || zt.find("Transfer failed") != std::string::npos)
                std::cout << GREEN << "  refused (expected)\n" << RESET;
            else std::cout << RED << sanitize(zt) << RESET;
        }
    }
}
 
// ================================================================
//  6. WHOIS
// ================================================================
void whois_lookup(const std::string &target) {
    print_header("WHOIS // " + target);
    std::vector<std::string> keys = {
        "Domain","Registrar","Created","Updated","Expir","Name Server",
        "CIDR","NetRange","OrgName","Country","RegDate","NetName",
        "inetnum","netname","descr","origin","Email","Phone","Address"
    };
    auto raw = safe_exec({"whois", target}, 10);
    if (raw.empty()) { std::cout << RED << "  install: sudo apt install whois\n" << RESET; return; }
    std::istringstream ss(raw); std::string line;
    while (std::getline(ss, line)) {
        if (line.empty() || line[0] == '%' || line[0] == '#') continue;
        for (auto &k : keys) {
            std::string ll = line, kl = k;
            std::transform(ll.begin(), ll.end(), ll.begin(), ::tolower);
            std::transform(kl.begin(), kl.end(), kl.begin(), ::tolower);
            if (ll.find(kl) == std::string::npos) continue;
            auto c = line.find(':');
            if (c != std::string::npos)
                std::cout << CYAN << "  [" << std::left << std::setw(16) << line.substr(0,c)
                          << "] " << YELLOW << sanitize(line.substr(c+1)) << RESET << "\n";
            break;
        }
    }
}
 
// ================================================================
//  7. SITE -> IP
// ================================================================
void site_lookup(const std::string &raw) {
    print_header("SITE -> IP // " + raw);
    std::string s = raw;
    for (auto &prefix : {"https://","http://","www."})
        if (s.size() >= strlen(prefix) && s.substr(0, strlen(prefix)) == prefix)
            s = s.substr(strlen(prefix));
    for (char sep : {'/', '?', '#', ':'}) {
        auto p = s.find(sep); if (p != std::string::npos) s = s.substr(0, p);
    }
    while (!s.empty() && (s.back() == ' ' || s.back() == 10 || s.back() == 13)) s.pop_back();
    if (!valid_target(s)) { std::cout << RED << "  invalid input\n" << RESET; return; }
    std::cout << YELLOW << "  resolving " << s << "...\n" << RESET;
    std::string ip = resolve(s);
    if (ip.empty()) { std::cout << RED << "  could not resolve\n" << RESET; return; }
    std::cout << GREEN << "  " << s << " -> " << ip << "\n" << RESET;
    ip_intel(ip);
}
 
// ================================================================
//  8. OSINT USERNAME
// ================================================================
void osint_scan(const std::string &username) {
    print_header("OSINT // " + username);
 
    struct Site { std::string name, url, dead, cat; };
    std::vector<Site> sites = {
        // social
        {"Instagram",   "https://www.instagram.com/{}/",         "page isn't available",  "social"},
        {"TikTok",      "https://www.tiktok.com/@{}/",           "couldn't find",         "social"},
        {"Twitter/X",   "https://twitter.com/{}/",               "doesn't exist",         "social"},
        {"Reddit",      "https://www.reddit.com/user/{}/",       "page not found",        "social"},
        {"VK",          "https://vk.com/{}/",                    "not found",             "social"},
        {"Pinterest",   "https://www.pinterest.com/{}/",         "not found",             "social"},
        {"Tumblr",      "https://{}.tumblr.com/",                "not found",             "social"},
        {"Flickr",      "https://www.flickr.com/people/{}/",     "not found",             "social"},
        {"Ask.fm",      "https://ask.fm/{}/",                    "not found",             "social"},
        {"Taringa",     "https://www.taringa.net/{}/",           "not found",             "social"},
        // dev
        {"GitHub",      "https://github.com/{}/",                "not found",             "dev"},
        {"GitLab",      "https://gitlab.com/{}/",                "not found",             "dev"},
        {"Replit",      "https://replit.com/@{}/",               "not found",             "dev"},
        {"HackerOne",   "https://hackerone.com/{}/",             "not found",             "dev"},
        {"Pastebin",    "https://pastebin.com/u/{}/",            "not found",             "dev"},
        {"Bugcrowd",    "https://bugcrowd.com/{}/",              "not found",             "dev"},
        {"Codecademy",  "https://www.codecademy.com/profiles/{}","not found",             "dev"},
        {"SourceForge", "https://sourceforge.net/u/{}/profile/", "not found",             "dev"},
        {"HackerNews",  "https://news.ycombinator.com/user?id={}","no such user",         "dev"},
        // gaming
        {"Steam",       "https://steamcommunity.com/id/{}/",     "error",                 "gaming"},
        {"Twitch",      "https://www.twitch.tv/{}/",             "not found",             "gaming"},
        {"Minecraft",   "https://namemc.com/profile/{}/",        "not found",             "gaming"},
        {"Roblox",      "https://www.roblox.com/user.aspx?username={}", "not found",      "gaming"},
        {"Chess.com",   "https://www.chess.com/member/{}/",      "not found",             "gaming"},
        // messenger
        {"Telegram",    "https://t.me/{}/",                      "if you have telegram",  "msg"},
        {"Keybase",     "https://keybase.io/{}/",                "not found",             "msg"},
        // blog / content
        {"Medium",      "https://medium.com/@{}/",               "not found",             "blog"},
        {"Wordpress",   "https://{}.wordpress.com/",             "doesn't exist",         "blog"},
        {"Ghost",       "https://{}.ghost.io/",                  "not found",             "blog"},
        {"Substack",    "https://{}.substack.com/",              "not found",             "blog"},
        {"Dev.to",      "https://dev.to/{}/",                    "not found",             "blog"},
        {"Hashnode",    "https://hashnode.com/@{}/",             "not found",             "blog"},
        // music
        {"Spotify",     "https://open.spotify.com/user/{}/",     "not found",             "music"},
        {"SoundCloud",  "https://soundcloud.com/{}/",            "not found",             "music"},
        {"Bandcamp",    "https://{}.bandcamp.com/",              "not found",             "music"},
        {"Last.fm",     "https://www.last.fm/user/{}/",          "not found",             "music"},
        // other
        {"LinkedIn",    "https://www.linkedin.com/in/{}/",       "not found",             "other"},
        {"Gravatar",    "https://en.gravatar.com/{}/",           "not found",             "other"},
        {"About.me",    "https://about.me/{}/",                  "not found",             "other"},
        {"Letterboxd",  "https://letterboxd.com/{}/",            "not found",             "other"},
        {"Goodreads",   "https://www.goodreads.com/user/show/{}/","not found",            "other"},
        {"Strava",      "https://www.strava.com/athletes/{}/",   "not found",             "other"},
        {"Duolingo",    "https://www.duolingo.com/profile/{}/",  "not found",             "other"},
        {"Dribbble",    "https://dribbble.com/{}/",              "not found",             "other"},
        {"Behance",     "https://www.behance.net/{}/",           "not found",             "other"},
        {"ProductHunt", "https://www.producthunt.com/@{}/",      "not found",             "other"},
        {"Trakt",       "https://trakt.tv/users/{}/",            "not found",             "other"},
        {"Wattpad",     "https://www.wattpad.com/user/{}/",      "not found",             "other"},
        {"Foursquare",  "https://foursquare.com/{}/",            "not found",             "other"},
        {"Tripadvisor", "https://www.tripadvisor.com/members/{}/","not found",            "other"},
    };
 
    std::cout << YELLOW << "  checking " << sites.size() << " platforms...\n\n" << RESET;
 
    // ------------------------------------------------------------------
    //   ThreadPool 15 instead of spawning one thread per site
    //   lock ordering: always fm first, then g_print_mtx never reversed
    // ------------------------------------------------------------------
    std::vector<std::pair<std::string,std::string>> found;
    std::mutex fm;
    std::atomic<int> done_count(0);
    int total = (int)sites.size();
 
    auto worker = [&](const Site &s) {
        std::string url = s.url;
        auto pos = url.find("{}");
        if (pos != std::string::npos) url.replace(pos, 2, username);
        std::string body = safe_curl(url, 6);
        std::string bl   = body;
        std::transform(bl.begin(), bl.end(), bl.begin(), ::tolower);
        bool hit = !body.empty() && bl.find(s.dead) == std::string::npos;
 
        // update shared data first (under fm), then print (under g_print_mtx)
        // consistent ordering prevents potential lock inversion
        if (hit) {
            std::lock_guard<std::mutex> fl(fm);
            found.push_back({s.name, url});
            g_result.osint_hits.push_back(url);
        }
        done_count++;
        {
            std::lock_guard<std::mutex> lk(g_print_mtx);
            if (hit) {
                std::cout << "\r" << GREEN << "  [+] " << std::left << std::setw(14) << s.name
                          << GRAY << "[" << s.cat << "]  " << CYAN << url << "\n" << RESET;
            } else {
                std::cout << "\r" << RED << "  [-] " << std::left << std::setw(14) << s.name
                          << GRAY << "[" << s.cat << "]" << RESET << "\n";
            }
            draw_progress(done_count, total, std::to_string(found.size()) + " found");
        }
    };
 
    {
        ThreadPool pool(15);
        for (auto &s : sites)
            pool.push([&, s]() { worker(s); });
        pool.join_all();
    }
 
    std::cout << "\n" << CYAN << "\n  found " << found.size() << "/" << sites.size() << " accounts\n" << RESET;
 
    print_section("WEB MENTIONS");
    std::cout << YELLOW << "  searching...\n" << RESET;
    auto ddg = safe_curl("https://html.duckduckgo.com/html/?q=%22" + username + "%22", 10);
    if (!ddg.empty()) {
        std::string marker = "href=\"";
        size_t p = 0; int count = 0;
        while ((p = ddg.find(marker, p)) != std::string::npos && count < 8) {
            p += marker.size();
            auto end = ddg.find('"', p);
            if (end == std::string::npos) break;
            std::string url = ddg.substr(p, end - p);
            if (url.find("http") == 0 && url.find("duckduckgo") == std::string::npos) {
                std::cout << CYAN << "  " << sanitize(url) << "\n" << RESET;
                count++;
            }
            p = end;
        }
        if (count == 0) std::cout << GRAY << "  no public mentions\n" << RESET;
    }
}
 
// ================================================================
//  9. TRACEROUTE
// ================================================================
void traceroute(const std::string &ip) {
    print_header("TRACEROUTE // " + ip);
    std::cout << YELLOW << "  tracing (max 20 hops)...\n\n" << RESET
              << BOLD << WHITE << "  HOP    ADDRESS          RTT\n"
              << "  " << std::string(45, '-') << "\n" << RESET;
    auto out = safe_exec({"traceroute", "-m20", "-w2", "-n", ip}, 45);
    if (out.empty()) { std::cout << RED << "  sudo apt install traceroute\n" << RESET; return; }
    std::istringstream ss(out); std::string line; bool first = true;
    while (std::getline(ss, line)) {
        if (first) { first = false; continue; }
        std::cout << (line.find("* * *") != std::string::npos ? YELLOW : GREEN)
                  << "  " << sanitize(line) << RESET << "\n";
    }
}
 
// ================================================================
//  10. FULL RECON
// ================================================================
void full_recon(const std::string &ip) {
    std::cout << "\n" << MAGENTA << BOLD
              << "  +" << std::string(56, '=') << "+\n"
              << "  |  FULL RECON // " << std::left << std::setw(40) << ip << "|\n"
              << "  +" << std::string(56, '=') << "+\n" << RESET;
    ip_intel(ip);
    dns_lookup(ip);
    os_detect(ip);
    port_scan(ip, 0, 0);
}
 
// ================================================================
//  11. SUBDOMAIN SCAN
// ================================================================
void subdomain_scan(const std::string &domain) {
    print_header("SUBDOMAIN SCAN // " + domain);
 
    std::vector<std::string> wordlist = {
        "www","mail","ftp","admin","api","dev","test","staging","blog","shop",
        "cdn","static","vpn","remote","portal","app","m","mobile","secure",
        "login","dashboard","panel","cpanel","webmail","smtp","pop","imap",
        "git","gitlab","jenkins","jira","wiki","docs","support","beta","alpha",
        "old","new","prod","media","img","images","video","upload","backup",
        "db","redis","elastic","kibana","grafana","k8s","docker","internal",
        "intranet","corp","office","vpn2","mx","ns1","ns2","mx1","mx2",
        "autodiscover","lyncdiscover","sip","owa","exchange","sharepoint",
        "crm","erp","hr","finance","accounting","billing","pay","payment",
        "store","cart","checkout","status","monitor","nagios","zabbix",
        "grafana","prometheus","splunk","log","logs","logstash","elk",
        "proxy","firewall","gateway","router","switch","ap","wifi",
        "smtp2","mail2","webdisk","whm","plesk","directadmin","ispconfig",
        "download","downloads","files","file","assets","s3","storage",
        "api2","api-dev","api-staging","api-prod","v1","v2","sandbox"
    };
 
    std::cout << YELLOW << "  checking " << wordlist.size() << " subdomains...\n" << RESET;
 
    std::atomic<int> cur(0), found_count(0);
    std::vector<std::pair<std::string,std::string>> found;
    std::mutex fm;
    int total = (int)wordlist.size();
 
    // ------------------------------------------------------------------
    //   ThreadPool 20 instead of raw thread vector with captured lambda
    //   lock ordering fixed: fm first, then g_print_mtx  never both held
    //    at the same time (fm released before g_print_mtx acquired)
    // ------------------------------------------------------------------
    auto worker = [&](int i) {
        std::string sub = wordlist[i] + "." + domain;
        std::string ip  = resolve(sub);
        int current = cur.fetch_add(1) + 1;
 
        if (ip.empty()) {
            std::lock_guard<std::mutex> lk(g_print_mtx);
            draw_progress(current, total, std::to_string(found_count.load()) + " found");
            return;
        }
 
        bool http = tcp_probe(ip,80,300) || tcp_probe(ip,443,300);
 
        // update data structures under fm, don't hold it while printing
        {
            std::lock_guard<std::mutex> lk(fm);
            found.push_back({sub, ip});
            g_result.subdomains.push_back(sub);
            found_count++;
        }
 
        {
            std::lock_guard<std::mutex> lk(g_print_mtx);
            std::cout << "\r" << GREEN << "  [+] " << std::left << std::setw(38) << sub
                      << " -> " << std::setw(16) << ip
                      << (http ? CYAN"[http]" : "") << RESET << "\n";
            draw_progress(current, total, std::to_string(found_count.load()) + " found");
        }
    };
 
    {
        ThreadPool pool(20);
        for (int i = 0; i < total; i++)
            pool.push([&, i]() { worker(i); });
        pool.join_all();
    }
 
    draw_progress(total, total, std::to_string(found_count.load()) + " found");
    std::cout << "\n" << CYAN << "\n  found " << found.size() << " subdomains\n" << RESET;
}
 
// ================================================================
//  BANNER
// ================================================================
void print_banner() {
    write(STDOUT_FILENO, "\033[2J\033[H", 7);
 
    std::cout << "\n";
    std::cout << WHITE << BOLD;
    std::cout << "  ██████╗  █████╗ ██████╗ ██╗  ██╗    ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗\n";
    std::cout << "  ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝    ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝\n";
    std::cout << "  ██║  ██║███████║██████╔╝█████╔╝     ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗\n";
    std::cout << "  ██║  ██║██╔══██║██╔══██╗██╔═██╗     ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║\n";
    std::cout << "  ██████╔╝██║  ██║██║  ██║██║  ██╗    ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║\n";
    std::cout << GRAY;
    std::cout << "  ╫█╫══╝  ╚█╫  ╚╝╚█╫  ╚╝╚╝  ╚█╫    ╚╝  ╚═══╝╚══════╝╚╝  ╚═╝ ╚═════╝ ╚══════╝\n";
    std::cout << DIM;
    std::cout << "    |        |     ||            |\n";
    std::cout << "    .        .     ..            .\n";
    std::cout << RESET;
    std::cout << WHITE << BOLD << "  NETWORK INTELLIGENCE TOOL\n" << RESET;
    std::cout << CYAN  << "  " << std::string(80, '=') << "\n" << RESET;
    std::cout << MAGENTA << BOLD << "  by marshal" << RESET
              << "    " << GRAY << "t.me/fuckmarshal\n" << RESET;
    std::cout << "\n";
}
 
// ================================================================
//  MENU
// ================================================================
void print_menu() {
    auto sep = []() {
        std::cout << CYAN << "  +------+--------------------+----------------------------------+\n" << RESET;
    };
    std::cout << "\n";
    sep();
    std::cout << CYAN << "  | " << WHITE << BOLD << std::left
              << std::setw(4) << "NUM" << CYAN << " | "
              << std::setw(18) << "MODULE" << CYAN << " | "
              << std::setw(32) << "EXAMPLE" << CYAN << "   |\n" << RESET;
    sep();
 
    auto row = [&](const std::string &num, const std::string &mod, const std::string &ex) {
        std::cout << CYAN << "  | " << YELLOW << BOLD << std::left << std::setw(4) << num
                  << CYAN << " | " << GREEN  << std::setw(18) << mod
                  << CYAN << " | " << WHITE  << std::setw(34) << ex
                  << CYAN << " |\n" << RESET;
    };
 
    row(" [1]", "PORT SCAN",      "192.168.1.1   1-1000 (0 = top1000)");
    row(" [2]", "NETWORK SCAN",   "192.168.1.1");
    row(" [3]", "OS DETECTION",   "192.168.1.1");
    row(" [4]", "IP FULL INTEL",  "8.8.8.8");
    row(" [5]", "DNS LOOKUP",     "google.com");
    row(" [6]", "WHOIS LOOKUP",   "google.com / 8.8.8.8");
    row(" [7]", "SITE --> IP",    "https://google.com");
    row(" [8]", "OSINT USERNAME", "username");
    row(" [9]", "TRACEROUTE",     "8.8.8.8");
    row("[10]", "FULL IP RECON",  "8.8.8.8");
    row("[11]", "SUBDOMAIN SCAN", "google.com");
    row("[12]", "EXPORT JSON",    "save last scan result");
    row(" [0]", "EXIT",           "");
    sep();
 
    std::cout << GRAY << "  bugs / feedback -> t.me/fuckmarshal\n" << RESET;
    std::cout << "\n" << GREEN << BOLD << "  DARK NEXUS~# " << RESET;
}
 
// ================================================================
//  MAIN
// ================================================================
int main() {
    print_banner();
 
    while (true) {
        print_menu();
 
        std::string choice_s;
        std::cin >> choice_s;
        int choice = -1;
        try { choice = std::stoi(choice_s); } catch (...) {}
 
        if (choice == 0) break;
 
        if (choice == 12) {
            std::string fname = "dark_nexus_" + g_result.target + ".json";
            std::replace(fname.begin(), fname.end(), ':', '_');
            export_json(fname);
            print_sep();
            std::cout << "  press enter...";
            std::cin.ignore(); std::cin.get();
            print_banner();
            continue;
        }
 
        if (choice == 8) {
            std::string u;
            std::cout << GREEN << "\n  username: " << RESET; std::cin >> u;
            if (!valid_username(u)) { std::cout << RED << "  invalid username\n" << RESET; }
            else osint_scan(u);
        } else if (choice == 7) {
            std::string s;
            std::cout << GREEN << "\n  site: " << RESET; std::cin >> s;
            site_lookup(s);
        } else if (choice == 11) {
            std::string d;
            std::cout << GREEN << "\n  domain: " << RESET; std::cin >> d;
            if (!valid_target(d)) { std::cout << RED << "  invalid domain\n" << RESET; }
            else subdomain_scan(d);
        } else {
            std::string target;
            std::cout << GREEN << "\n  target: " << RESET; std::cin >> target;
 
            if (!valid_target(target)) {
                std::cout << RED << "  invalid - only ip/domain allowed\n" << RESET;
                continue;
            }
 
            std::string ip = resolve(target);
            if (ip.empty()) ip = target;
            else if (ip != target)
                std::cout << YELLOW << "  resolved: " << target << " -> " << ip << "\n" << RESET;
 
            switch (choice) {
                case 1: {
                    int s = 0, e = 0;
                    std::cout << GREEN << "  start port (0 = top1000): " << RESET; std::cin >> s;
                    if (s == 0) {
                        port_scan(ip, 0, 0);
                    } else {
                        std::cout << GREEN << "  end port: " << RESET; std::cin >> e;
                        if (!valid_port(s) || !valid_port(e) || s > e) {
                            std::cout << RED << "  invalid port range\n" << RESET; break;
                        }
                        port_scan(ip, s, e);
                    }
                    break;
                }
                case 2:  net_scan(ip.substr(0, ip.rfind('.'))); break;
                case 3:  os_detect(ip);    break;
                case 4:  ip_intel(ip);     break;
                case 5:  dns_lookup(ip);   break;
                case 6:  whois_lookup(ip); break;
                case 9:  traceroute(ip);   break;
                case 10: full_recon(ip);   break;
                default: std::cout << RED << "  invalid option\n" << RESET;
            }
        }
 
        print_sep();
        std::cout << "  press enter to continue...";
        std::cin.ignore(); std::cin.get();
        print_banner();
    }
 
    std::cout << "\n" << MAGENTA << BOLD << "  goodbye, marshal.\n\n" << RESET;
    return 0;
}
