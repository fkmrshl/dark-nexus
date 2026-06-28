#include "../include/osint.hpp"

namespace osint {

void run_username(const std::string& username, IdentityGraph& graph) {
    if (!InputGuard::is_valid_username(username)) {
        std::cout << BLOOD_RED << "  [!] invalid username\n" << RESET;
        return;
    }

    graph.username_candidates.push_back(username);

    print_section("INTERNAL SCAN");
    run_platform_scan(username, graph);
    std::cout << "\n";

    print_section("EXTERNAL TOOLS");
    auto tools = run_username_tools(username);
    if (tools.empty()) {
        std::cout << BLOOD_RED << "  external username tools skipped\n" << RESET;
    } else {
        for (const auto& tool : tools) {
            if (tool.installed) {
                std::cout << BLOOD_RED << "  [+] " << WHITE << std::left << std::setw(16) << tool.tool
                          << BLOOD_RED << "found " << WHITE << tool.hits.size() << BLOOD_RED << " hits\n" << RESET;
            } else {
                std::cout << BLOOD_RED << "  [-] " << WHITE << std::left << std::setw(16) << tool.tool
                          << BLOOD_RED << "not installed\n" << RESET;
            }
        }
        cross_reference(graph, tools);
    }

    print_section("RESULTS");
    print_hits(graph.hits);

    print_section("USERNAME VARIANTS");
    auto patterns = username_patterns(username);
    graph.username_candidates = patterns;
    std::string username_seed_id = graph_node_id(GraphNodeType::Username, username);
    for (const auto& candidate : patterns) {
        if (graph_node_id(GraphNodeType::Username, candidate) == username_seed_id) continue;

        Evidence evidence;
        evidence.type = EvidenceType::Generated;
        evidence.status = EvidenceStatus::Hypothesis;
        evidence.source = "username_patterns";
        evidence.detail = "username_variant:" + candidate;
        evidence.confidence = 0.25;
        evidence.certainty = HitConfidence::Possible;
        Evidence& added_evidence = add_graph_evidence(graph, evidence);

        GraphNode& candidate_node = add_graph_node(graph, GraphNodeType::Username, candidate, EvidenceStatus::Hypothesis, 0.25);
        add_graph_edge(graph, username_seed_id, candidate_node.id, GraphEdgeType::GeneratedCandidate, {added_evidence.id}, EvidenceStatus::Hypothesis, 0.25, HitConfidence::Possible);
    }
    std::cout << BLOOD_RED << "  " << WHITE << patterns.size() << BLOOD_RED << " variants to check:\n" << RESET;
    for (size_t i = 0; i < std::min(patterns.size(), static_cast<size_t>(10)); ++i) std::cout << WHITE << "    " << patterns[i] << "\n" << RESET;
    if (patterns.size() > 10) std::cout << BLOOD_RED << "    ... +" << WHITE << patterns.size() - 10 << BLOOD_RED << " more\n" << RESET;

    print_section("EMAIL HYPOTHESES");
    static const std::vector<std::string> domains = {"gmail.com", "yahoo.com", "outlook.com", "protonmail.com", "icloud.com", "mail.ru", "yandex.ru"};
    for (const auto& domain : domains) {
        std::string email = username + "@" + domain;
        graph.email_candidates.push_back(email);
        Evidence evidence;
        evidence.type = EvidenceType::Generated;
        evidence.status = EvidenceStatus::Hypothesis;
        evidence.source = "email_hypotheses";
        evidence.detail = "email_hypothesis:" + email;
        evidence.confidence = 0.20;
        evidence.certainty = HitConfidence::Possible;
        Evidence& added_evidence = add_graph_evidence(graph, evidence);

        GraphNode& email_node = add_graph_node(graph, GraphNodeType::Email, email, EvidenceStatus::Hypothesis, 0.20);
        add_graph_edge(graph, username_seed_id, email_node.id, GraphEdgeType::GeneratedCandidate, {added_evidence.id}, EvidenceStatus::Hypothesis, 0.20, HitConfidence::Possible);
        std::cout << BLOOD_RED << "  -> " << WHITE << email << "\n" << RESET;
    }

    print_section("WEB MENTIONS");
    print_web_mentions(username, 8);

    print_profile(graph.profile, graph.hits, username);
    LOG_INFO("osint_username", "done user=" + username + " hits=" + std::to_string(graph.hits.size()));
}

}
