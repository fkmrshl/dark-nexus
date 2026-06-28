#include "../include/dark_nexus.hpp"
#include "../include/security.hpp"

struct ProcResult {
    std::string out, err;
    int code = -1;
    bool timed_out = false;
};

static void append_capped(std::string& dst, const char* data, size_t n, size_t cap) {
    if (dst.size() >= cap) return;
    size_t room = cap - dst.size();
    dst.append(data, std::min(n, room));
}

static bool drain_fd(int& fd, std::string& dst, size_t cap) {
    if (fd < 0) return false;
    bool open = true;
    std::vector<char> buf(8192);
    for (;;) {
        ssize_t n = read(fd, buf.data(), buf.size());
        if (n > 0) {
            append_capped(dst, buf.data(), static_cast<size_t>(n), cap);
            continue;
        }
        if (n == 0) {
            close(fd);
            fd = -1;
            open = false;
            break;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        close(fd);
        fd = -1;
        open = false;
        break;
    }
    return open;
}

static std::string trim_value(std::string value) {
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) value.erase(value.begin());
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) value.pop_back();
    return value;
}

static std::vector<std::string> metadata_lines(const std::string& value) {
    std::vector<std::string> out;
    size_t pos = 0;
    while (pos <= value.size()) {
        size_t end = value.find('\n', pos);
        if (end == std::string::npos) {
            out.push_back(value.substr(pos));
            break;
        }
        out.push_back(value.substr(pos, end - pos));
        pos = end + 1;
    }
    return out;
}

static std::string read_capped_file(const std::string& path, size_t cap) {
    std::string out;
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return out;
    std::vector<char> buf(8192);
    while (out.size() < cap) {
        ssize_t n = read(fd, buf.data(), std::min(buf.size(), cap - out.size()));
        if (n > 0) {
            out.append(buf.data(), static_cast<size_t>(n));
            continue;
        }
        if (n == 0) break;
        if (errno == EINTR) continue;
        break;
    }
    close(fd);
    return out;
}

static ProcResult proc_run(const std::vector<std::string>& args,
                            int timeout_sec = 10,
                            const std::string& stdin_data = "",
                            size_t max_out = 4*1024*1024)
{
    ProcResult res;
    if (args.empty()) return res;

    std::vector<char*> argv;
    for (auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(nullptr);

    int pout[2], perr[2], pin[2];
    if (pipe(pout)<0 || pipe(perr)<0) return res;
    bool has_stdin = !stdin_data.empty();
    if (has_stdin && pipe(pin)<0) {
        close(pout[0]); close(pout[1]); close(perr[0]); close(perr[1]);
        return res;
    }

    pid_t pid = fork();
    if (pid == 0) {
        close(pout[0]); close(perr[0]);
        dup2(pout[1], STDOUT_FILENO); dup2(perr[1], STDERR_FILENO);
        close(pout[1]); close(perr[1]);
        if (has_stdin) { close(pin[1]); dup2(pin[0],STDIN_FILENO); close(pin[0]); }
        setpgid(0,0);
        execvp(argv[0], argv.data());
        _exit(127);
    }
    if (pid < 0) return res;

    close(pout[1]); close(perr[1]);
    if (has_stdin) {
        close(pin[0]);

        const char* data_ptr = stdin_data.data();
        size_t bytes_left = stdin_data.size();

        while (bytes_left > 0) {
            ssize_t written = write(pin[1], data_ptr, bytes_left);

            if (written < 0) {
                if (errno == EINTR) {
                    continue;
                }
                break;
            }
            data_ptr += written;
            bytes_left -= written;
        }
        close(pin[1]);
    }

    fcntl(pout[0], F_SETFL, O_NONBLOCK);
    fcntl(perr[0], F_SETFL, O_NONBLOCK);

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_sec);
    int ofd = pout[0], efd = perr[0];

    while (ofd >= 0 || efd >= 0) {
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) { kill(-pid, SIGKILL); res.timed_out = true; break; }
        auto us = std::chrono::duration_cast<std::chrono::microseconds>(deadline-now);
        int timeout_ms = std::max(1, (int)(us.count()/1000));
        struct pollfd pfds[2];
        int nfds = 0;
        int o_idx = -1, e_idx = -1;
        if (ofd>=0){pfds[nfds].fd=ofd; pfds[nfds].events=POLLIN | POLLHUP | POLLERR; o_idx=nfds++;}
        if (efd>=0){pfds[nfds].fd=efd; pfds[nfds].events=POLLIN | POLLHUP | POLLERR; e_idx=nfds++;}
        if (poll(pfds, nfds, timeout_ms) <= 0) continue;
        if (o_idx>=0 && (pfds[o_idx].revents & (POLLIN | POLLHUP | POLLERR))) {
            drain_fd(ofd, res.out, max_out);
        }
        if (e_idx>=0 && (pfds[e_idx].revents & (POLLIN | POLLHUP | POLLERR))) {
            drain_fd(efd, res.err, max_out);
        }
    }
    if (ofd>=0) close(ofd);
    if (efd>=0) close(efd);
    int status; waitpid(pid,&status,0);
    res.code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    return res;
}

std::string safe_exec(const std::vector<std::string>& args, int t) {
    return proc_run(args, t).out;
}

#include "../include/user_agents.hpp"

std::string safe_curl(const std::string& url, int t) {
    return safe_curl_detailed(url, t).body;
}

HttpFetchResult safe_curl_detailed(const std::string& url, int t) {
    HttpFetchResult result;
    if (!InputGuard::is_safe_url(url)) {
        result.blocked_or_error = true;
        return result;
    }

    char path_template[] = "/tmp/dark-nexus-curl-body-XXXXXX";
    int body_fd = mkstemp(path_template);
    if (body_fd < 0) {
        result.blocked_or_error = true;
        return result;
    }
    close(body_fd);
    std::string body_path = path_template;

    const std::string begin = "__DARK_NEXUS_CURL_META_BEGIN_7f4b2c91__";
    const std::string end = "__DARK_NEXUS_CURL_META_END_7f4b2c91__";
    std::string write_out = begin + "\n%{http_code}\n%{url_effective}\n" + end;
    ProcResult proc = proc_run({"curl","-sS","-L","--max-time",std::to_string(t),
        "-A",random_ua(),"-o",body_path,"-w",write_out,"--",url}, t+2);

    result.curl_exit_code = proc.code;
    result.timed_out = proc.timed_out;

    size_t begin_pos = proc.out.rfind(begin);
    if (begin_pos != std::string::npos) {
        size_t meta_start = begin_pos + begin.size();
        if (meta_start < proc.out.size() && proc.out[meta_start] == '\n') meta_start++;
        size_t end_pos = proc.out.find(end, meta_start);
        if (end_pos != std::string::npos) {
            std::string meta = proc.out.substr(meta_start, end_pos - meta_start);
            std::vector<std::string> lines = metadata_lines(meta);
            if (!lines.empty()) {
                try { result.http_status = std::stoi(trim_value(lines[0])); } catch (...) { result.http_status = 0; }
            }
            if (lines.size() > 1) result.final_url = trim_value(lines[1]);
        }
    }

    result.body = read_capped_file(body_path, 4*1024*1024);
    unlink(body_path.c_str());

    result.fetched = result.curl_exit_code == 0 && !result.timed_out && !result.body.empty();
    bool status_ok = result.http_status >= 200 && result.http_status < 300;
    bool blocked_status = result.http_status == 403 || result.http_status == 404 ||
                          result.http_status == 429 || result.http_status >= 500;
    result.success = result.fetched && status_ok;
    result.blocked_or_error = !result.success || blocked_status;
    return result;
}
