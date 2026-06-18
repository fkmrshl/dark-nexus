#include "../include/osint.hpp"
#include <cerrno>
#include <sys/stat.h>

namespace osint {

static std::string join_path(const std::string& dir, const std::string& name) {
    if (dir.empty()) return name;
    return dir.back() == '/' ? dir + name : dir + "/" + name;
}

static std::string home_dir() {
    const char* home = std::getenv("HOME");
    return home && *home ? std::string(home) : "";
}

static bool is_executable(const std::string& path) {
    return !path.empty() && access(path.c_str(), X_OK) == 0;
}

static std::string search_path_tool(const std::string& name) {
    const char* path_env = std::getenv("PATH");
    if (!path_env || !*path_env) return "";

    std::stringstream ss(path_env);
    std::string dir;
    while (std::getline(ss, dir, ':')) {
        if (dir.empty()) dir = ".";
        std::string candidate = join_path(dir, name);
        if (is_executable(candidate)) return candidate;
    }
    return "";
}

static std::string local_bin_dir() {
    std::string home = home_dir();
    return home.empty() ? "" : join_path(home, ".local/bin");
}

static std::string local_venv_dir() {
    std::string home = home_dir();
    return home.empty() ? "" : join_path(home, ".local/share/dark-nexus/osint-venv");
}

static std::string resolve_tool_path(const std::string& name) {
    if (name.find('/') != std::string::npos) return is_executable(name) ? name : "";

    std::string from_path = search_path_tool(name);
    if (!from_path.empty()) return from_path;

    std::vector<std::string> dirs = {"/usr/local/bin", "/opt/dark-nexus-osint/bin"};
    std::string local_bin = local_bin_dir();
    std::string local_venv = local_venv_dir();
    if (!local_bin.empty()) dirs.push_back(local_bin);
    if (!local_venv.empty()) dirs.push_back(join_path(local_venv, "bin"));

    for (const auto& dir : dirs) {
        std::string candidate = join_path(dir, name);
        if (is_executable(candidate)) return candidate;
    }
    return "";
}

static bool tool_exists(const std::string& name) {
    return !resolve_tool_path(name).empty();
}

static int run_command_status(const std::vector<std::string>& args, int timeout_sec) {
    if (args.empty()) return -1;

    std::vector<char*> argv;
    for (const auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
    argv.push_back(nullptr);

    pid_t pid = fork();
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        setpgid(0, 0);
        execvp(argv[0], argv.data());
        _exit(127);
    }
    if (pid < 0) return -1;

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_sec);
    int status = 0;
    while (std::chrono::steady_clock::now() < deadline) {
        pid_t done = waitpid(pid, &status, WNOHANG);
        if (done == pid) {
            if (WIFEXITED(status)) return WEXITSTATUS(status);
            return -1;
        }
        if (done < 0) return -1;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    kill(-pid, SIGKILL);
    waitpid(pid, &status, 0);
    return -1;
}

static bool is_interactive() {
    return isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);
}

static bool path_is_symlink(const std::string& path) {
    struct stat st {};
    return lstat(path.c_str(), &st) == 0 && S_ISLNK(st.st_mode);
}

static bool ensure_dir(const std::string& path) {
    if (path.empty()) return false;
    if (access(path.c_str(), F_OK) == 0) return true;

    std::string current;
    size_t pos = 0;
    if (path[0] == '/') {
        current = "/";
        pos = 1;
    }

    while (pos <= path.size()) {
        size_t next = path.find('/', pos);
        std::string part = path.substr(pos, next == std::string::npos ? std::string::npos : next - pos);
        if (!part.empty()) {
            if (!current.empty() && current.back() != '/') current += "/";
            current += part;
            if (mkdir(current.c_str(), 0755) != 0 && errno != EEXIST) return false;
        }
        if (next == std::string::npos) break;
        pos = next + 1;
    }
    return access(path.c_str(), F_OK) == 0;
}

static void link_local_tool(const std::string& source, const std::string& binary) {
    std::string bin_dir = local_bin_dir();
    if (bin_dir.empty() || !is_executable(source) || !ensure_dir(bin_dir)) return;

    std::string target = join_path(bin_dir, binary);
    if (access(target.c_str(), F_OK) == 0 && !path_is_symlink(target)) return;

    unlink(target.c_str());
    if (symlink(source.c_str(), target.c_str()) != 0) {
        std::cout << BLOOD_RED << "  [warn] could not link " << WHITE << binary << BLOOD_RED << " into " << WHITE << bin_dir << "\n" << RESET;
    }
}

static void print_phoneinfoga_manual_install(const std::string& bin_dir) {
    std::string target = bin_dir.empty() ? "$HOME/.local/bin/phoneinfoga" : join_path(bin_dir, "phoneinfoga");
    std::cout << WHITE << "      manual install: download the latest PhoneInfoga release binary\n" << RESET;
    std::cout << WHITE << "      place it in " << target << "\n" << RESET;
    std::cout << WHITE << "      run: chmod +x \"" << target << "\"\n" << RESET;
}

static bool install_tool(const ToolSpec& spec) {
    if (!spec.python_package) {
        std::string bin_dir = local_bin_dir();
        if (bin_dir.empty()) {
            std::cout << BLOOD_RED << "  [-] " << WHITE << spec.binary << BLOOD_RED << " install skipped: HOME is not set\n" << RESET;
            return false;
        }
        if (!ensure_dir(bin_dir)) {
            std::cout << BLOOD_RED << "  [-] " << WHITE << spec.binary << BLOOD_RED << " install skipped: cannot create " << WHITE << bin_dir << "\n" << RESET;
            return false;
        }

        std::string go = resolve_tool_path("go");
        if (go.empty()) {
            std::cout << BLOOD_RED << "  [-] " << WHITE << "phoneinfoga" << BLOOD_RED << " install skipped: go not found\n" << RESET;
            print_phoneinfoga_manual_install(bin_dir);
            return false;
        }

        std::cout << BLOOD_RED << "  [*] installing " << WHITE << spec.binary << BLOOD_RED << " into " << WHITE << bin_dir << BLOOD_RED << "...\n" << RESET;
        int status = run_command_status({"/usr/bin/env", "GOBIN=" + bin_dir, go, "install", spec.package}, 300);
        std::string expected = join_path(bin_dir, spec.binary);

        if (status != 0) {
            std::cout << BLOOD_RED << "  [-] " << WHITE << spec.binary << BLOOD_RED << " go install failed; skipping optional phone helper\n" << RESET;
            print_phoneinfoga_manual_install(bin_dir);
            return false;
        }

        if (is_executable(expected)) {
            std::cout << BLOOD_RED << "  [+] " << WHITE << spec.binary << BLOOD_RED << " installed\n" << RESET;
            return true;
        }

        std::cout << BLOOD_RED << "  [-] " << WHITE << spec.binary << BLOOD_RED << " binary was not created; skipping optional phone helper\n" << RESET;
        print_phoneinfoga_manual_install(bin_dir);
        return false;
    }

    std::string venv = local_venv_dir();
    if (venv.empty()) {
        std::cout << BLOOD_RED << "  [-] " << WHITE << spec.binary << BLOOD_RED << " install skipped: HOME is not set\n" << RESET;
        return false;
    }

    std::string parent = join_path(home_dir(), ".local/share/dark-nexus");
    if (!ensure_dir(parent)) {
        std::cout << BLOOD_RED << "  [-] " << WHITE << spec.binary << BLOOD_RED << " install skipped: cannot create " << WHITE << parent << "\n" << RESET;
        return false;
    }

    std::string python = resolve_tool_path("python3");
    if (python.empty()) python = "python3";

    std::cout << BLOOD_RED << "  [*] installing " << WHITE << spec.binary << BLOOD_RED << " into " << WHITE << venv << BLOOD_RED << "...\n" << RESET;
    if (!is_executable(join_path(join_path(venv, "bin"), "python"))) {
        safe_exec({python, "-m", "venv", venv}, 120);
    }

    std::string venv_python = join_path(join_path(venv, "bin"), "python");
    if (!is_executable(venv_python)) {
        std::cout << BLOOD_RED << "  [-] " << WHITE << spec.binary << BLOOD_RED << " install failed: cannot create Python venv\n" << RESET;
        return false;
    }

    safe_exec({venv_python, "-m", "pip", "install", "-q", "--upgrade", "pip", "wheel"}, 180);
    safe_exec({venv_python, "-m", "pip", "install", "-q", spec.package}, 300);

    std::string venv_tool = join_path(join_path(venv, "bin"), spec.binary);
    link_local_tool(venv_tool, spec.binary);

    if (tool_exists(spec.binary)) {
        std::cout << BLOOD_RED << "  [+] " << WHITE << spec.binary << BLOOD_RED << " installed\n" << RESET;
        return true;
    }

    std::cout << BLOOD_RED << "  [-] " << WHITE << spec.binary << BLOOD_RED << " install failed. Run manually: " << WHITE << venv_python << " -m pip install " << spec.package << "\n" << RESET;
    return false;
}

static bool prepare_tools(const std::vector<ToolSpec>& specs, const std::string& label) {
    std::vector<ToolSpec> missing;
    for (const auto& spec : specs) {
        if (!tool_exists(spec.binary)) missing.push_back(spec);
    }

    if (missing.empty()) return true;

    std::cout << BLOOD_RED << "  [missing] " << WHITE << label << BLOOD_RED << " external tools:\n" << RESET;
    for (const auto& spec : missing) {
        std::cout << BLOOD_RED << "    - " << WHITE << spec.binary;
        if (!spec.package.empty()) std::cout << BLOOD_RED << " (" << WHITE << spec.package << BLOOD_RED << ")";
        std::cout << "\n" << RESET;
    }

    if (!is_interactive()) {
        std::cout << BLOOD_RED << "  [skip] non-interactive mode, missing tools skipped; running available tools\n" << RESET;
        return true;
    }

    std::cout << BLOOD_RED << "  Install missing OSINT tools? " << WHITE << "[y/N] " << RESET;
    std::string answer;
    if (!std::getline(std::cin, answer)) {
        std::cout << BLOOD_RED << "  [skip] missing tools skipped; running available tools\n" << RESET;
        return true;
    }
    answer = lower_copy(trim_copy(answer));
    if (answer != "y" && answer != "yes") {
        std::cout << BLOOD_RED << "  [skip] missing tools skipped; running available tools\n" << RESET;
        return true;
    }

    for (const auto& spec : missing) install_tool(spec);

    return true;
}

static std::string normalized_platform_name(std::string value) {
    value = lower_copy(trim_copy(value));
    std::string out;
    for (unsigned char c : value) {
        if (std::isalnum(c)) out += static_cast<char>(c);
    }
    return out;
}

static bool external_observation_structured(const ToolHit& hit) {
    return (!hit.url.empty() && InputGuard::is_safe_url(hit.url)) || !hit.platform.empty();
}

static double external_observation_confidence(const ToolHit& hit) {
    return external_observation_structured(hit) ? 0.72 : 0.55;
}

static HitConfidence external_observation_certainty(const ToolHit& hit) {
    return external_observation_structured(hit) ? HitConfidence::Probable : HitConfidence::Possible;
}

static std::string external_tool_detail(const ToolResult& tool, const ToolHit& hit) {
    std::string detail;
    if (!hit.platform.empty()) detail += "platform=" + hit.platform;
    if (!hit.url.empty()) {
        if (!detail.empty()) detail += "|";
        detail += "url=" + hit.url;
    }
    if (!hit.info.empty()) {
        if (!detail.empty()) detail += "|";
        detail += "info=" + hit.info;
    }
    if (detail.empty()) detail = tool.tool;
    return detail;
}

static std::string external_tool_finding_value(const ToolResult& tool, const ToolHit& hit) {
    return tool.tool + "|" + hit.platform + "|" + hit.url + "|" + hit.info;
}

static Evidence& add_external_tool_evidence(IdentityGraph& graph, const ToolResult& tool, const ToolHit& hit, EvidenceStatus status) {
    Evidence evidence;
    evidence.type = EvidenceType::ExternalTool;
    evidence.status = status;
    evidence.source = tool.tool;
    evidence.tool = tool.tool;
    evidence.url = hit.url;
    evidence.detail = external_tool_detail(tool, hit);
    evidence.confidence = external_observation_confidence(hit);
    evidence.certainty = external_observation_certainty(hit);
    return add_graph_evidence(graph, evidence);
}

static GraphNode& add_external_tool_finding_node(IdentityGraph& graph, const ToolResult& tool, const ToolHit& hit) {
    return add_graph_node(graph, GraphNodeType::ToolFinding, external_tool_finding_value(tool, hit), EvidenceStatus::Observed, external_observation_confidence(hit));
}

static void add_external_corroboration_graph_record(IdentityGraph& graph, const ToolResult& tool, const ToolHit& tool_hit, const Hit& flat_hit) {
    if (tool_hit.url.empty()) return;

    Evidence& evidence = add_external_tool_evidence(graph, tool, tool_hit, EvidenceStatus::Corroborated);
    std::string evidence_id = evidence.id;
    GraphNode& finding_node = add_external_tool_finding_node(graph, tool, tool_hit);
    std::string finding_id = finding_node.id;
    GraphNode& account_node = add_graph_node(graph, GraphNodeType::Account, tool_hit.url, EvidenceStatus::Observed, flat_hit.confidence);
    std::string account_id = account_node.id;

    add_graph_edge(graph, finding_id, account_id, GraphEdgeType::Corroborates, {evidence_id}, EvidenceStatus::Corroborated, flat_hit.confidence, flat_hit.certainty);
}

static void add_external_platform_observation_graph_record(IdentityGraph& graph, const ToolResult& tool, const ToolHit& tool_hit) {
    if (tool_hit.platform.empty()) return;

    Evidence& evidence = add_external_tool_evidence(graph, tool, tool_hit, EvidenceStatus::Observed);
    std::string evidence_id = evidence.id;
    GraphNode& finding_node = add_external_tool_finding_node(graph, tool, tool_hit);
    std::string finding_id = finding_node.id;
    GraphNode& platform_node = add_graph_node(graph, GraphNodeType::Platform, tool_hit.platform, EvidenceStatus::Observed, external_observation_confidence(tool_hit));
    std::string platform_id = platform_node.id;

    add_graph_edge(graph, finding_id, platform_id, GraphEdgeType::ExternalToolObserved, {evidence_id}, EvidenceStatus::Observed, external_observation_confidence(tool_hit), external_observation_certainty(tool_hit));
}

static void add_external_only_graph_record(IdentityGraph& graph, const ToolResult& tool, const ToolHit& tool_hit, const Hit& flat_hit) {
    Evidence& evidence = add_external_tool_evidence(graph, tool, tool_hit, EvidenceStatus::Observed);
    std::string evidence_id = evidence.id;
    GraphNode& finding_node = add_external_tool_finding_node(graph, tool, tool_hit);
    std::string finding_id = finding_node.id;
    std::string target_id;

    if (!tool_hit.url.empty()) {
        GraphNode& account_node = add_graph_node(graph, GraphNodeType::Account, tool_hit.url, EvidenceStatus::Observed, flat_hit.confidence);
        target_id = account_node.id;
    }
    if (!tool_hit.platform.empty()) {
        GraphNode& platform_node = add_graph_node(graph, GraphNodeType::Platform, tool_hit.platform, EvidenceStatus::Observed, flat_hit.confidence);
        if (target_id.empty()) target_id = platform_node.id;
    }
    if (target_id.empty()) return;

    add_graph_edge(graph, finding_id, target_id, GraphEdgeType::ExternalToolObserved, {evidence_id}, EvidenceStatus::Observed, flat_hit.confidence, flat_hit.certainty);
}

static ToolResult run_sherlock(const std::string& username) {
    ToolResult result;
    result.tool = "sherlock";
    std::string tool_path = resolve_tool_path("sherlock");
    result.available = !tool_path.empty();
    if (!result.available) return result;
    result.installed = true;

    std::cout << BLOOD_RED << "    running " << WHITE << "sherlock" << BLOOD_RED << "...\n" << RESET;
    std::string output = safe_exec({tool_path, "--print-found", "--timeout", "10", username}, 180);
    for (const auto& raw : split_lines(output)) {
        if (raw.find("[+]") == std::string::npos) continue;
        size_t url_pos = raw.find("http");
        if (url_pos == std::string::npos) continue;

        std::string url = trim_copy(raw.substr(url_pos));
        std::string platform;
        size_t mark = raw.find("[+]");
        if (mark != std::string::npos) {
            size_t colon = raw.find(':', mark);
            if (colon != std::string::npos && colon > mark + 3) platform = trim_copy(raw.substr(mark + 3, colon - mark - 3));
        }
        result.hits.push_back({platform, url, ""});
    }
    return result;
}

static ToolResult run_maigret(const std::string& username) {
    ToolResult result;
    result.tool = "maigret";
    std::string tool_path = resolve_tool_path("maigret");
    result.available = !tool_path.empty();
    if (!result.available) return result;
    result.installed = true;

    std::cout << BLOOD_RED << "    running " << WHITE << "maigret" << BLOOD_RED << "...\n" << RESET;
    std::string output = safe_exec({tool_path, "--no-color", "--timeout", "10", "-a", username}, 300);
    for (const auto& raw : split_lines(output)) {
        if (raw.find("[+]") == std::string::npos) continue;
        size_t url_pos = raw.find("http");
        if (url_pos == std::string::npos) continue;
        result.hits.push_back({"", trim_copy(raw.substr(url_pos)), ""});
    }
    return result;
}

static ToolResult run_holehe(const std::string& email) {
    ToolResult result;
    result.tool = "holehe";
    std::string tool_path = resolve_tool_path("holehe");
    result.available = !tool_path.empty();
    if (!result.available) return result;
    result.installed = true;

    std::cout << BLOOD_RED << "    running " << WHITE << "holehe" << BLOOD_RED << "...\n" << RESET;
    std::string output = safe_exec({tool_path, "--only-used", "--no-color", email}, 300);
    for (const auto& raw : split_lines(output)) {
        if (raw.find("[+]") == std::string::npos) continue;
        std::string platform = raw;
        size_t mark = platform.find("[+]");
        if (mark != std::string::npos) platform = platform.substr(mark + 3);
        platform = trim_copy(platform);
        if (!platform.empty()) result.hits.push_back({platform, "", ""});
    }
    return result;
}

static ToolResult run_theharvester(const std::string& domain) {
    ToolResult result;
    result.tool = "theHarvester";
    std::string tool_path = resolve_tool_path("theHarvester");
    result.available = !tool_path.empty();
    if (!result.available) return result;
    result.installed = true;

    std::cout << BLOOD_RED << "    running " << WHITE << "theHarvester" << BLOOD_RED << "...\n" << RESET;
    std::string output = safe_exec({tool_path, "-d", domain, "-b", "all", "-l", "200"}, 180);
    std::set<std::string> seen;
    for (const auto& raw : split_lines(output)) {
        std::string lowered = lower_copy(raw);
        if (lowered.find('@') == std::string::npos && lowered.find("http") == std::string::npos) continue;
        std::string clean = trim_copy(sanitize(raw));
        if (!clean.empty() && seen.insert(clean).second) result.hits.push_back({"", "", clean});
    }
    return result;
}

std::vector<ToolResult> run_username_tools(const std::string& username) {
    std::vector<ToolSpec> specs = {{"sherlock", "sherlock-project", true}, {"maigret", "maigret", true}};
    if (!prepare_tools(specs, "username")) return {};

    auto sherlock = std::async(std::launch::async, run_sherlock, username);
    auto maigret = std::async(std::launch::async, run_maigret, username);
    return {sherlock.get(), maigret.get()};
}

std::vector<ToolResult> run_email_tools(const std::string& email, const std::string& domain) {
    std::vector<ToolSpec> specs = {{"holehe", "holehe", true}, {"theHarvester", "theHarvester", true}};
    if (!prepare_tools(specs, "email")) return {};

    auto holehe = std::async(std::launch::async, run_holehe, email);
    auto harvester = std::async(std::launch::async, run_theharvester, domain);
    return {holehe.get(), harvester.get()};
}

ToolResult run_phoneinfoga(const std::string& e164) {
    ToolResult result;
    result.tool = "phoneinfoga";
    std::vector<ToolSpec> specs = {{"phoneinfoga", "github.com/sundowndev/phoneinfoga/v2@latest", false}};
    prepare_tools(specs, "phone");

    std::string tool_path = resolve_tool_path("phoneinfoga");
    result.available = !tool_path.empty();
    if (!result.available) {
        std::cout << BLOOD_RED << "  [-] phoneinfoga: not installed; skipping optional phone helper\n" << RESET;
        return result;
    }

    result.installed = true;
    std::cout << BLOOD_RED << "    running " << WHITE << "phoneinfoga" << BLOOD_RED << "...\n" << RESET;
    std::string output = safe_exec({tool_path, "scan", "-n", e164}, 120);
    std::set<std::string> seen;
    for (const auto& raw : split_lines(output)) {
        if (raw.empty() || raw[0] == '=' || raw[0] == '-') continue;
        std::string lowered = lower_copy(raw);
        if (lowered.find("error") != std::string::npos || lowered.find("time") != std::string::npos) continue;
        std::string clean = trim_copy(sanitize(raw));
        if (clean.size() > 5 && seen.insert(clean).second) result.hits.push_back({"", "", clean});
    }
    return result;
}

void cross_reference(IdentityGraph& graph, const std::vector<ToolResult>& tools) {
    std::set<std::string> tool_urls;
    std::set<std::string> tool_platforms;

    for (const auto& tool : tools) {
        for (const auto& hit : tool.hits) {
            if (!hit.url.empty()) tool_urls.insert(hit.url);
            std::string platform = normalized_platform_name(hit.platform);
            if (!platform.empty()) tool_platforms.insert(platform);
        }
    }

    for (auto& hit : graph.hits) {
        bool url_matched = !hit.url.empty() && tool_urls.count(hit.url) > 0;
        bool platform_matched = tool_platforms.count(normalized_platform_name(hit.name)) > 0;

        if (url_matched) {
            hit.certainty = HitConfidence::Confirmed;
            hit.confidence = std::min(0.99, hit.confidence + 0.25);
            hit.source = hit.source.empty() ? "external url" : hit.source + ", external-url";
            for (const auto& tool : tools) {
                for (const auto& tool_hit : tool.hits) {
                    if (tool_hit.url == hit.url) add_external_corroboration_graph_record(graph, tool, tool_hit, hit);
                }
            }
        } else if (platform_matched) {
            hit.confidence = std::min(0.85, hit.confidence + 0.12);
            if (hit.certainty != HitConfidence::Confirmed && hit.confidence >= 0.72) {
                hit.certainty = HitConfidence::Probable;
            }
            hit.source = hit.source.empty() ? "external platform" : hit.source + ", external-platform";
            for (const auto& tool : tools) {
                for (const auto& tool_hit : tool.hits) {
                    if (normalized_platform_name(tool_hit.platform) == normalized_platform_name(hit.name)) {
                        add_external_platform_observation_graph_record(graph, tool, tool_hit);
                    }
                }
            }
        } else if (hit.confidence >= 0.72) {
            hit.certainty = HitConfidence::Probable;
        }
    }

    for (const auto& tool : tools) {
        for (const auto& tool_hit : tool.hits) {
            if (tool_hit.url.empty() && tool_hit.platform.empty()) continue;

            bool exists = false;
            for (const auto& hit : graph.hits) {
                if (!tool_hit.url.empty() && hit.url == tool_hit.url) exists = true;
                if (!tool_hit.platform.empty()) {
                    std::string name = normalized_platform_name(hit.name);
                    std::string platform = normalized_platform_name(tool_hit.platform);
                    if (!name.empty() && name == platform) exists = true;
                }
            }
            if (exists) continue;

            Hit hit;
            hit.name = tool_hit.platform.empty() ? tool.tool : tool_hit.platform;
            hit.url = tool_hit.url;
            hit.category = "ext";
            hit.evidence = tool.tool;
            hit.source = tool.tool;
            bool structured = (!tool_hit.url.empty() && InputGuard::is_safe_url(tool_hit.url)) || !tool_hit.platform.empty();
            hit.confidence = structured ? 0.72 : 0.55;
            hit.certainty = structured ? HitConfidence::Probable : HitConfidence::Possible;
            add_external_only_graph_record(graph, tool, tool_hit, hit);
            add_graph_hit(graph, hit);
        }
    }

    {
        std::lock_guard<std::mutex> lock(g_result_mtx);
        for (auto& entry : g_result.osint) {
            for (const auto& hit : graph.hits) {
                bool same_url = !hit.url.empty() && entry.url == hit.url;
                bool same_name = hit.url.empty() && entry.url.empty() && lower_copy(entry.platform) == lower_copy(hit.name);
                if (!same_url && !same_name) continue;
                entry.certainty = certainty_text(hit.certainty);
                entry.confidence = hit.confidence;
                entry.evidence = hit.evidence;
                entry.source = hit.source;
            }
        }
    }

    dedupe_global_results();
}

}
