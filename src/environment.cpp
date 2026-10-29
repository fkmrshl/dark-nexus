#include "environment.hpp"

#include <cstdlib>
#include <filesystem>
#include <unistd.h>
#include <vector>

namespace environment {
namespace {
std::string join(const std::string& directory, const std::string& name) {
    return (std::filesystem::path(directory.empty() ? "." : directory) / name).string();
}

std::string default_path() {
    const auto size = confstr(_CS_PATH, nullptr, 0);
    if (!size) return "/bin:/usr/bin";
    std::vector<char> buffer(size);
    if (!confstr(_CS_PATH, buffer.data(), buffer.size())) return "/bin:/usr/bin";
    return buffer.data();
}
} // namespace

Context current() {
    const char* path = std::getenv("PATH");
    const char* home = std::getenv("HOME");
    std::error_code error;
    const auto executable = std::filesystem::read_symlink("/proc/self/exe", error);
    return {path ? std::optional<std::string>(path) : std::nullopt, home ? home : "",
            error ? "" : executable.string()};
}

bool executable_file(const std::string& path) {
    std::error_code error;
    return std::filesystem::is_regular_file(path, error) && access(path.c_str(), X_OK) == 0;
}

bool readable_wordlist(const std::string& path) {
    std::error_code error;
    if (!std::filesystem::is_regular_file(path, error) || access(path.c_str(), R_OK) != 0)
        return false;
    const auto size = std::filesystem::file_size(path, error);
    return !error && size > 0;
}

std::string find_in_path(const std::string& name, const Context& context) {
    if (name.find('/') != std::string::npos) return executable_file(name) ? name : "";
    const std::string path = context.path ? *context.path : default_path();
    std::size_t start = 0;
    do {
        const auto separator = path.find(':', start);
        const auto directory = path.substr(start, separator == std::string::npos ? separator : separator - start);
        const auto candidate = join(directory, name);
        if (executable_file(candidate)) return candidate;
        if (separator == std::string::npos) break;
        start = separator + 1;
    } while (start <= path.size());
    return "";
}

std::string find_wordlist(const Context& context) {
    std::vector<std::string> candidates = {"./best-dns-wordlist.txt"};
    if (!context.executable.empty()) {
        const auto prefix = std::filesystem::path(context.executable).parent_path().parent_path();
        candidates.push_back((prefix / "share/wordlists/dark-nexus/best-dns-wordlist.txt").string());
    }
    candidates.push_back("/usr/share/wordlists/dark-nexus/best-dns-wordlist.txt");
    if (!context.home.empty()) candidates.push_back(join(context.home, "best-dns-wordlist.txt"));
    const std::vector<std::string> system_candidates = {
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000000.txt",
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-500000.txt",
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
        "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-500000.txt",
        "/opt/SecLists/Discovery/DNS/subdomains-top1million-500000.txt",
        "/opt/wordlists/best-dns-wordlist.txt"
    };
    candidates.insert(candidates.end(), system_candidates.begin(), system_candidates.end());
    if (!context.home.empty()) candidates.push_back(join(context.home, "wordlists/subdomains-top1million-500000.txt"));
    for (const auto& candidate : candidates) {
        if (readable_wordlist(candidate)) return candidate;
    }
    return "";
}

} // namespace environment
