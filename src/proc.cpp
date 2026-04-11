#include "../include/dark_nexus.hpp"

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
        write(pin[1], stdin_data.c_str(), stdin_data.size());
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
        timeval tv{us.count()/1000000, us.count()%1000000};
        fd_set rfds; FD_ZERO(&rfds);
        int maxfd = -1;
        if (ofd>=0){FD_SET(ofd,&rfds); maxfd=std::max(maxfd,ofd);}
        if (efd>=0){FD_SET(efd,&rfds); maxfd=std::max(maxfd,efd);}
        if (select(maxfd+1,&rfds,nullptr,nullptr,&tv) <= 0) continue;
        char buf[8192];
        if (ofd>=0 && FD_ISSET(ofd,&rfds)) {
            ssize_t n = read(ofd,buf,sizeof(buf));
            if (n<=0){close(ofd);ofd=-1;} else if(res.out.size()<max_out) res.out.append(buf,n);
        }
        if (efd>=0 && FD_ISSET(efd,&rfds)) {
            ssize_t n = read(efd,buf,sizeof(buf));
            if (n<=0){close(efd);efd=-1;} else if(res.err.size()<max_out) res.err.append(buf,n);
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

std::string safe_curl(const std::string& url, int t) {
    if (url.find('\'') != std::string::npos) return "";
    return safe_exec({"curl","-s","--max-time",std::to_string(t),
                      "-L","-A","Mozilla/5.0","--",url}, t+2);
}
