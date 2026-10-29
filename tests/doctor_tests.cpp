#include "doctor.hpp"
#include "environment.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

namespace {
int checks = 0;
int failures = 0;
void check(bool success, const std::string& label) {
    ++checks;
    if (!success) { ++failures; std::cerr << "FAIL: " << label << '\n'; }
}

void file(const std::filesystem::path& path, const std::string& content = "helper", bool executable = true) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream(path) << content;
    if (executable) chmod(path.c_str(), 0755);
}

const doctor::Check& find(const doctor::Report& report, const std::string& id) {
    for (const auto& value : report.checks) if (value.id == id) return value;
    throw std::runtime_error("missing check: " + id);
}
}

int main() {
    char pattern[] = "/tmp/dark-nexus-doctor-unit-XXXXXX";
    const char* directory = mkdtemp(pattern);
    if (!directory) return 1;
    const std::filesystem::path root(directory);
    const auto previous_directory = std::filesystem::current_path();
    try {
        std::filesystem::current_path(root);
        environment::Context context{(root / "bin").string(), (root / "home").string(), (root / "prefix/bin/dark-nexus").string()};
        check(environment::find_in_path("absent", context).empty(), "missing PATH tool");
        file(root / "bin/dig", "not executable", false);
        check(environment::find_in_path("dig", context).empty(), "non-executable is rejected");
        chmod((root / "bin/dig").c_str(), 0755);
        check(environment::find_in_path("dig", context) == (root / "bin/dig").string(), "executable PATH tool");
        std::filesystem::create_directory(root / "bin/directory");
        check(environment::find_in_path("directory", context).empty(), "directory is not executable helper");
        file(root / "working-tool");
        context.path = "";
        check(!environment::find_in_path("working-tool", context).empty(), "empty PATH means working directory");
        context.path = (root / "bin").string() + ':';
        check(!environment::find_in_path("working-tool", context).empty(), "trailing PATH entry means working directory");
        context.path = ':' + (root / "bin").string();
        check(!environment::find_in_path("working-tool", context).empty(), "leading PATH entry means working directory");
        context.path.reset();
        check(!environment::find_in_path("sh", context).empty(), "unset PATH uses default system path");
        context.path = (root / "bin").string();
        check(!environment::find_in_path((root / "working-tool").string(), context).empty(), "explicit executable path");
        file(root / "home/.local/bin/local-helper");
        check(environment::find_in_path("local-helper", context).empty(), "core helper follows PATH without implicit home fallback");
        file(root / "prefix/share/wordlists/dark-nexus/best-dns-wordlist.txt", "www\n", false);
        const auto detected = environment::find_wordlist(context);
        check(detected == (root / "prefix/share/wordlists/dark-nexus/best-dns-wordlist.txt").string(),
              "prefix-relative wordlist takes priority over system installations");
        file(root / "best-dns-wordlist.txt", "", false);
        check(environment::find_wordlist(context) == detected, "empty local wordlist ignored");
        std::filesystem::remove(root / "best-dns-wordlist.txt");
        mkfifo((root / "best-dns-wordlist.txt").c_str(), 0600);
        check(environment::find_wordlist(context) == detected, "FIFO wordlist ignored without opening");
        std::filesystem::remove(root / "best-dns-wordlist.txt");
        file(root / "best-dns-wordlist.txt", "mail\n", false);
        check(environment::find_wordlist(context) == "./best-dns-wordlist.txt", "working directory wordlist priority");

        for (const auto* name : {"whois", "host", "ping", "curl", "openssl", "getent"}) file(root / "bin" / name);
        auto report = doctor::inspect(context);
        check(report.checks.size() == 9, "all nine environment checks present");
        check(report.exit_code() == 0, "optional warnings do not fail readiness");
        for (const auto* name : {"dig", "whois", "host", "ping", "curl", "openssl", "getent"})
            check(find(report, std::string("core.") + name).status == "ok", "core executable detected");
        std::filesystem::remove(root / "bin/whois");
        report = doctor::inspect(context);
        check(find(report, "core.whois").status == "fail" && report.exit_code() == 1, "missing core helper fails readiness");
        check(find(report, "raw").detail.find("before privilege dropping") != std::string::npos, "capability limitation explained");
        std::ostringstream serialized;
        check(doctor::write_json(report, serialized), "JSON report writes successfully");
        const auto parsed = nlohmann::json::parse(serialized.str());
        check(parsed.at("schema_version") == 1 && parsed.at("status") == "fail", "stable report schema and aggregate status");
        check(parsed.at("checks").size() == 9 && serialized.str().find('\033') == std::string::npos, "JSON report contains all checks without ANSI");
        std::ostringstream text;
        check(doctor::write_text(report, text) && text.str().find("Affects:") != std::string::npos, "text report explains affected workflows");
        std::ostringstream failed;
        failed.setstate(std::ios::badbit);
        check(!doctor::write_json(report, failed), "JSON report rejects failed output stream");
        check(!doctor::write_text(report, failed), "text report rejects failed output stream");
    } catch (const std::exception& error) {
        ++failures;
        std::cerr << "FAIL: " << error.what() << '\n';
    }
    std::filesystem::current_path(previous_directory);
    std::filesystem::remove_all(root);
    std::cout << checks << " doctor checks, " << failures << " failures\n";
    return failures ? 1 : 0;
}
