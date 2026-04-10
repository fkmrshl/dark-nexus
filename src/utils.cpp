#include "modules.hpp"

std::string sanitize(const std::string& s) {
    std::string o;
    for (size_t i = 0; i < s.size(); i++) {
        unsigned char c = s[i];
        if (c == 0x1b) { while (i < s.size() && s[i] != 'm') i++; continue; }
        if ((c >= 32 && c <= 126) || c == 10) o += c;
    }
    return o;
}

std::string safe_exec(const std::vector<std::string>& args, int t) {
    int pout[2];
    if (pipe(pout) < 0) return "";
    pid_t pid = fork();
    if (pid == 0) {
        close(pout[0]);
        dup2(pout[1], STDOUT_FILENO);
        std::vector<char*> argv;
        for (auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
        argv.push_back(nullptr);
        execvp(argv[0], argv.data());
        _exit(1);
    }
    close(pout[1]);
    std::string res;
    char buf[4096];
    ssize_t n;
    while ((n = read(pout[0], buf, sizeof(buf))) > 0) res.append(buf, n);
    close(pout[0]);
    waitpid(pid, nullptr, 0);
    return res;
}

std::string safe_curl(const std::string& url, int t) {
    return safe_exec({"curl", "-s", "--max-time", std::to_string(t), "-L", url}, t + 2);
}

void draw_progress(int done, int total, const std::string& label) {
    int w = 40;
    float pct = (float)done / total;
    int filled = w * pct;
    std::cout << "\r" << CYAN << "  [" << GREEN << std::string(filled, '=') << std::string(w - filled, ' ') << CYAN << "] " 
              << WHITE << (int)(pct * 100) << "% " << GRAY << label << RESET << std::flush;
}

void print_header(const std::string& title) {
    std::cout << "\n" << CYAN << BOLD << "  > " << WHITE << title << RESET << "\n";
}

void print_row(const std::string& label, const std::string& val) {
    if (val.empty()) return;
    std::cout << CYAN << "  [" << WHITE << std::left << std::setw(15) << label << CYAN << "] " << RESET << val << "\n";
}
