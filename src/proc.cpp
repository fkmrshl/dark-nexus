#include "../include/dark_nexus.hpp"
#include "../include/security.hpp"

struct ProcResult {
    std::string out, err;
    int code = -1;
    bool timed_out = false;
};

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
        if (ofd>=0){pfds[nfds].fd=ofd; pfds[nfds].events=POLLIN; o_idx=nfds++;}
        if (efd>=0){pfds[nfds].fd=efd; pfds[nfds].events=POLLIN; e_idx=nfds++;}
        if (poll(pfds, nfds, timeout_ms) <= 0) continue;
        std::vector<char> buf(8192);
        if (o_idx>=0 && (pfds[o_idx].revents & POLLIN)) {
            ssize_t n = read(ofd, buf.data(), buf.size());
            if (n > 0) res.out.append(buf.data(), static_cast<size_t>(n));
            else if (n == 0) { close(ofd); ofd = -1; }
        }
        if (e_idx>=0 && (pfds[e_idx].revents & POLLIN)) {
            ssize_t n = read(efd, buf.data(), buf.size());
            if (n <= 0) { close(efd); efd = -1; }
            else if (res.err.size() < max_out) res.err.append(buf.data(), static_cast<size_t>(n));
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
    if (!InputGuard::is_safe_url(url)) return "";
    return safe_exec({"curl","-s","--max-time",std::to_string(t),
        "-L","-A",random_ua(),"--",url}, t+2);
}
