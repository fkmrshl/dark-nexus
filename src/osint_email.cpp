#include "../include/osint.hpp"

namespace osint {

static const std::set<std::string> DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "temp-mail.org", "throwam.com", "yopmail.com",
    "sharklasers.com", "guerrillamail.info", "guerrillamail.biz", "guerrillamail.de",
    "guerrillamail.net", "guerrillamail.org", "spam4.me", "trashmail.com", "trashmail.me",
    "trashmail.net", "dispostable.com", "mailnull.com", "mytemp.email", "tempmail.com",
    "fakeinbox.com", "maildrop.cc", "discard.email", "10minutemail.com", "getnada.com",
    "mailnesia.com", "mintemail.com", "tempr.email", "33mail.com", "spamgourmet.com"
};

static std::string domain_type(const std::string& domain, bool disposable) {
    static const std::map<std::string, std::string> types = {
        {"gmail.com", "personal Google"},
        {"yahoo.com", "personal Yahoo"},
        {"outlook.com", "personal Microsoft"},
        {"hotmail.com", "personal legacy Microsoft"},
        {"protonmail.com", "privacy-focused"},
        {"tutanota.com", "privacy-focused"},
        {"icloud.com", "Apple ecosystem"},
        {"yandex.ru", "Russian ecosystem Yandex"},
        {"mail.ru", "Russian ecosystem Mail.ru"},
        {"rambler.ru", "Russian ecosystem Rambler"},
        {"gmx.com", "European personal"},
        {"zoho.com", "business"}
    };

    auto it = types.find(domain);
    if (it != types.end()) return it->second;
    if (disposable) return "disposable or burner";
    return "corporate or custom domain";
}

static void print_domain_reputation(const std::string& domain) {
    print_section("DOMAIN REPUTATION");

    auto mx_future = std::async(std::launch::async, [&] {
        return safe_exec({"dig", "+short", "MX", domain}, 6);
    });
    auto txt_future = std::async(std::launch::async, [&] {
        return safe_exec({"dig", "+short", "TXT", domain}, 6);
    });
    auto dmarc_future = std::async(std::launch::async, [&] {
        return safe_exec({"dig", "+short", "TXT", "_dmarc." + domain}, 6);
    });
    auto a_future = std::async(std::launch::async, [&] {
        return safe_exec({"dig", "+short", "A", domain}, 6);
    });

    std::string mx = mx_future.get();
    std::string txt = txt_future.get();
    std::string dmarc = dmarc_future.get();
    std::string a_record = a_future.get();

    if (!mx.empty()) {
        std::cout << BLOOD_RED << "  [MX]     " << WHITE;
        for (const auto& line : split_lines(mx)) std::cout << sanitize(line) << "  ";
        std::cout << "\n" << RESET;
    } else {
        std::cout << BLOOD_RED << "  [MX]     no records found\n" << RESET;
    }

    bool spf_found = false;
    for (const auto& line : split_lines(txt)) {
        if (line.find("v=spf1") != std::string::npos) {
            std::cout << BLOOD_RED << "  [SPF]    " << WHITE << sanitize(line) << "\n" << RESET;
            spf_found = true;
        }
    }
    if (!spf_found) std::cout << BLOOD_RED << "  [SPF]    not found\n" << RESET;

    if (!dmarc.empty()) std::cout << BLOOD_RED << "  [DMARC]  " << WHITE << sanitize(dmarc) << "\n" << RESET;
    else std::cout << BLOOD_RED << "  [DMARC]  not found\n" << RESET;

    if (!a_record.empty()) std::cout << BLOOD_RED << "  [A]      " << WHITE << sanitize(a_record) << "\n" << RESET;
}

static void print_email_exposure_heuristic(const std::string& local, const std::string& domain, bool disposable) {
    print_section("EXPOSURE HEURISTIC");

    double score = 0.0;
    std::vector<std::string> factors;
    if (disposable) {
        score += 0.35;
        factors.push_back("disposable domain");
    }
    if (domain == "gmail.com") {
        score += 0.15;
        factors.push_back("common consumer mailbox provider");
    }
    if (domain == "yahoo.com") {
        score += 0.20;
        factors.push_back("provider with major historical breach exposure");
    }
    if (domain == "hotmail.com" || domain == "outlook.com") {
        score += 0.10;
        factors.push_back("large consumer mailbox ecosystem");
    }
    if (local.size() < 5) {
        score += 0.10;
        factors.push_back("short local part");
    }
    if (std::any_of(local.begin(), local.end(), [](unsigned char c) {
        return std::isdigit(c);
    })) {
        score += 0.05;
        factors.push_back("digits in local part");
    }

    score = std::min(score, 0.95);
    std::cout << BLOOD_RED << "  [risk] " << WHITE << std::fixed << std::setprecision(0) << (score * 100.0) << "%  " << confidence_bar(score) << "\n" << RESET;
    for (const auto& factor : factors) std::cout << BLOOD_RED << "  [!] " << WHITE << factor << "\n" << RESET;
    if (factors.empty()) std::cout << BLOOD_RED << "  [ok] no obvious mailbox heuristics\n" << RESET;

    std::cout << BLOOD_RED << "  [breach data] " << WHITE << "HIBP requires an API key and is skipped by default\n" << RESET;
}

void run_email(const std::string& email, IdentityGraph& graph) {
    if (!InputGuard::is_valid_email(email)) {
        std::cout << BLOOD_RED << "  [!] invalid email\n" << RESET;
        return;
    }

    size_t at = email.find('@');
    std::string local = email.substr(0, at);
    std::string domain = lower_copy(email.substr(at + 1));
    bool disposable = DISPOSABLE_DOMAINS.count(domain) > 0;

    graph.email_candidates.push_back(email);
    graph.profile.add("email", email);

    print_section("EMAIL PROFILE");
    std::cout << BLOOD_RED << "  [email]      " << WHITE << email << "\n" << RESET;
    std::cout << BLOOD_RED << "  [local]      " << WHITE << local << "\n" << RESET;
    std::cout << BLOOD_RED << "  [domain]     " << WHITE << domain << "\n" << RESET;
    std::cout << BLOOD_RED << "  [type]       " << WHITE << domain_type(domain, disposable) << "\n" << RESET;
    std::cout << BLOOD_RED << "  [disposable] " << WHITE << (disposable ? "YES" : "no") << "\n" << RESET;

    print_domain_reputation(domain);
    print_email_exposure_heuristic(local, domain, disposable);

    print_section("USERNAME CANDIDATES");
    graph.username_candidates = username_candidates_from_email_local(local);
    std::string email_seed_id = graph_node_id(GraphNodeType::Email, email);
    for (const auto& candidate : graph.username_candidates) {
        Evidence evidence;
        evidence.type = EvidenceType::Generated;
        evidence.status = EvidenceStatus::Hypothesis;
        evidence.source = "email_local_part";
        evidence.detail = "username_candidate:" + candidate;
        evidence.confidence = 0.25;
        evidence.certainty = HitConfidence::Possible;
        Evidence& added_evidence = add_graph_evidence(graph, evidence);

        GraphNode& candidate_node = add_graph_node(graph, GraphNodeType::Username, candidate, EvidenceStatus::Hypothesis, 0.25);
        add_graph_edge(graph, email_seed_id, candidate_node.id, GraphEdgeType::DerivedFromEmail, {added_evidence.id}, EvidenceStatus::Hypothesis, 0.25, HitConfidence::Possible);
    }
    for (const auto& candidate : graph.username_candidates) std::cout << BLOOD_RED << "  -> " << WHITE << candidate << "\n" << RESET;

    print_section("INTERNAL PLATFORM SCAN");
    run_platform_scan(local, graph);

    print_section("EXTERNAL TOOLS");
    auto tools = run_email_tools(email, domain);
    if (tools.empty()) {
        std::cout << BLOOD_RED << "  external email tools skipped\n" << RESET;
    } else {
        for (const auto& tool : tools) {
            if (tool.installed) {
                std::cout << BLOOD_RED << "  [+] " << WHITE << std::left << std::setw(16) << tool.tool
                          << BLOOD_RED << "found " << WHITE << tool.hits.size() << BLOOD_RED << " results\n" << RESET;
                for (const auto& hit : tool.hits) {
                    if (!hit.info.empty()) graph.profile.add(tool.tool, hit.info);
                    if (!hit.platform.empty()) graph.profile.add("account", tool.tool + ":" + hit.platform);
                }
            }
        }
        cross_reference(graph, tools);
    }

    print_section("RESULTS");
    print_hits(graph.hits);

    print_section("WEB MENTIONS");
    print_web_mentions(email, 8);

    print_profile(graph.profile, graph.hits, email);
    LOG_INFO("osint_email", "done email=" + email + " hits=" + std::to_string(graph.hits.size()));
}

}
