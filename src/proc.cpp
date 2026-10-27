#include "../include/dark_nexus.hpp"
#include "../include/security.hpp"
#include "process.hpp"

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

static ProcessResult proc_run(const std::vector<std::string>& args, int timeout_sec = 10) {
    return run_process(args, std::max(1, timeout_sec) * 1000, &g_cancel_token.cancelled);
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
    ProcessResult proc = proc_run({"curl","-sS","-L","--max-time",std::to_string(t),
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
