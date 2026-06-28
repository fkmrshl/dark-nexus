#include "../include/osint.hpp"

namespace osint {

InputType detect_input_type(const std::string& input) {
    if (InputGuard::is_valid_email(input)) return InputType::Email;

    std::string normalized;
    for (unsigned char c : input) {
        if (std::isdigit(c) || c == '+') normalized += static_cast<char>(c);
    }

    if (InputGuard::is_valid_phone(normalized)) {
        size_t digit_count = 0;
        for (unsigned char c : normalized) {
            if (std::isdigit(c)) digit_count++;
        }
        if (digit_count >= 7 && digit_count <= 16) return InputType::Phone;
    }

    if (InputGuard::is_valid_username(input)) return InputType::Username;
    return InputType::Unknown;
}

std::string input_type_name(InputType type) {
    switch (type) {
        case InputType::Username: return "USERNAME";
        case InputType::Email: return "EMAIL";
        case InputType::Phone: return "PHONE";
        default: return "UNKNOWN";
    }
}

void CorrelatedProfile::add(const std::string& key, const std::string& value) {
    std::string clean = trim_copy(value);
    if (clean.empty() || clean == "null") return;

    raw[key] = clean;
    std::string k = lower_copy(key);

    auto add_unique = [](std::vector<std::string>& values, const std::string& item) {
        if (std::find(values.begin(), values.end(), item) == values.end()) values.push_back(item);
    };

    if (k.find("name") != std::string::npos) add_unique(names, clean);
    else if (k.find("phone") != std::string::npos || k.find("tel") != std::string::npos) add_unique(phones, clean);
    else if (k.find("email") != std::string::npos || k.find("mail") != std::string::npos) add_unique(emails, clean);
    else if (k.find("city") != std::string::npos || k.find("location") != std::string::npos || k.find("region") != std::string::npos || k.find("country") != std::string::npos) add_unique(locations, clean);
    else if (k.find("url") != std::string::npos || k.find("account") != std::string::npos || k.find("profile") != std::string::npos) add_unique(accounts, clean);
}

std::string lower_copy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::string trim_copy(std::string value) {
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) value.erase(value.begin());
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) value.pop_back();
    return value;
}

std::string fill_template(const std::string& tmpl, const std::string& value) {
    std::string out = tmpl;
    size_t pos = out.find("{}");
    if (pos != std::string::npos) out.replace(pos, 2, value);
    return out;
}

std::string url_encode(const std::string& value) {
    std::string out;
    for (unsigned char c : value) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') out += static_cast<char>(c);
        else {
            char buf[4];
            snprintf(buf, sizeof(buf), "%%%02X", c);
            out += buf;
        }
    }
    return out;
}

std::vector<std::string> extract_links(const std::string& html, int max_count) {
    std::vector<std::string> links;
    size_t pos = 0;
    const std::string marker = "href=\"";
    while ((pos = html.find(marker, pos)) != std::string::npos && static_cast<int>(links.size()) < max_count) {
        pos += marker.size();
        size_t end = html.find('"', pos);
        if (end == std::string::npos) break;
        std::string url = html.substr(pos, end - pos);
        if (url.find("http://") == 0 || url.find("https://") == 0) links.push_back(url);
        pos = end;
    }
    return links;
}

std::string confidence_bar(double confidence) {
    int filled = std::max(0, std::min(10, static_cast<int>(confidence * 10.0)));
    std::string bar = "[";
    for (int i = 0; i < 10; ++i) bar += i < filled ? "#" : ".";
    bar += "]";
    return bar;
}

std::string certainty_text(HitConfidence certainty) {
    switch (certainty) {
        case HitConfidence::Confirmed: return "CONFIRMED";
        case HitConfidence::Probable: return "PROBABLE";
        default: return "POSSIBLE";
    }
}

std::string certainty_label(HitConfidence certainty) {
    return std::string(BLOOD_RED) + "[" + std::string(WHITE) + certainty_text(certainty) + std::string(BLOOD_RED) + "]" + std::string(RESET);
}

HitConfidence certainty_from_score(double confidence) {
    if (confidence >= 0.88) return HitConfidence::Confirmed;
    if (confidence >= 0.72) return HitConfidence::Probable;
    return HitConfidence::Possible;
}

double score_hit(bool fetched, bool missing_dead_marker, const std::vector<std::string>& markers, int weight) {
    if (!fetched) return 0.0;
    if (markers.empty()) return 0.0;

    bool dead_marker_present = !missing_dead_marker;
    if (dead_marker_present && markers.size() < 2) return 0.0;

    double confidence = 0.45;
    confidence += std::min(0.42, static_cast<double>(markers.size() - 1) * 0.14);
    if (missing_dead_marker) confidence += 0.08;
    confidence += std::min(0.10, static_cast<double>(std::max(0, weight - 1)) * 0.025);

    if (dead_marker_present) confidence = std::min(confidence, 0.70);
    return std::min(confidence, 0.99);
}

std::vector<std::string> username_patterns(const std::string& username) {
    std::vector<std::string> values = {username};

    std::string base = username;
    while (!base.empty() && std::isdigit(static_cast<unsigned char>(base.back()))) base.pop_back();
    if (!base.empty() && base != username) values.push_back(base);

    std::string compact = username;
    compact.erase(std::remove_if(compact.begin(), compact.end(), [](char c) {
        return c == '.' || c == '-' || c == '_';
    }), compact.end());
    if (!compact.empty() && compact != username) values.push_back(compact);

    static const std::vector<std::string> suffixes = {"1", "123", "x", "real", "pro", "dev", "me", "gg", "_", "official"};
    static const std::vector<std::string> prefixes = {"the", "its", "im", "real", "official", "i_am"};

    for (const auto& suffix : suffixes) values.push_back(username + suffix);
    for (const auto& prefix : prefixes) {
        values.push_back(prefix + username);
        values.push_back(prefix + "_" + username);
    }

    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
    return values;
}

std::vector<std::string> username_candidates_from_email_local(const std::string& local) {
    std::vector<std::string> candidates = {local};

    std::string base = local;
    while (!base.empty() && std::isdigit(static_cast<unsigned char>(base.back()))) base.pop_back();
    if (!base.empty() && base != local) candidates.push_back(base);

    std::string compact = local;
    compact.erase(std::remove_if(compact.begin(), compact.end(), [](char c) {
        return c == '.' || c == '-';
    }), compact.end());
    if (!compact.empty() && compact != local) candidates.push_back(compact);

    size_t dot = local.find('.');
    if (dot != std::string::npos && dot + 1 < local.size()) {
        candidates.push_back(local.substr(0, dot));
        candidates.push_back(local.substr(dot + 1));
        candidates.push_back(local.substr(0, 1) + local.substr(dot + 1));
        std::string underscore = local;
        std::replace(underscore.begin(), underscore.end(), '.', '_');
        candidates.push_back(underscore);
    }

    std::sort(candidates.begin(), candidates.end());
    candidates.erase(std::unique(candidates.begin(), candidates.end()), candidates.end());
    return candidates;
}

static std::string graph_node_type_key(GraphNodeType type) {
    switch (type) {
        case GraphNodeType::Seed: return "seed";
        case GraphNodeType::Username: return "username";
        case GraphNodeType::Email: return "email";
        case GraphNodeType::Phone: return "phone";
        case GraphNodeType::Account: return "account";
        case GraphNodeType::Platform: return "platform";
        case GraphNodeType::Domain: return "domain";
        case GraphNodeType::Location: return "location";
        case GraphNodeType::Name: return "name";
        case GraphNodeType::Carrier: return "carrier";
        case GraphNodeType::ToolFinding: return "tool_finding";
        case GraphNodeType::WebMention: return "web_mention";
    }
    return "unknown";
}

static std::string graph_edge_type_key(GraphEdgeType type) {
    switch (type) {
        case GraphEdgeType::SeedIs: return "seed_is";
        case GraphEdgeType::GeneratedCandidate: return "generated_candidate";
        case GraphEdgeType::DerivedFromEmail: return "derived_from_email";
        case GraphEdgeType::DerivedFromPhone: return "derived_from_phone";
        case GraphEdgeType::AccountOnPlatform: return "account_on_platform";
        case GraphEdgeType::ExternalToolObserved: return "external_tool_observed";
        case GraphEdgeType::ProfileAttribute: return "profile_attribute";
        case GraphEdgeType::Corroborates: return "corroborates";
        case GraphEdgeType::ConflictsWith: return "conflicts_with";
    }
    return "unknown";
}

static std::string evidence_type_key(EvidenceType type) {
    switch (type) {
        case EvidenceType::SeedInput: return "seed_input";
        case EvidenceType::Generated: return "generated";
        case EvidenceType::InternalHttp: return "internal_http";
        case EvidenceType::ExternalTool: return "external_tool";
        case EvidenceType::PhoneHeuristic: return "phone_heuristic";
        case EvidenceType::EmailHeuristic: return "email_heuristic";
        case EvidenceType::WebSearch: return "web_search";
    }
    return "unknown";
}

static std::string evidence_status_key(EvidenceStatus status) {
    switch (status) {
        case EvidenceStatus::Verified: return "verified";
        case EvidenceStatus::Hypothesis: return "hypothesis";
        case EvidenceStatus::Observed: return "observed";
        case EvidenceStatus::Corroborated: return "corroborated";
        case EvidenceStatus::Conflict: return "conflict";
        case EvidenceStatus::Rejected: return "rejected";
    }
    return "unknown";
}

static std::string certainty_key(HitConfidence certainty) {
    switch (certainty) {
        case HitConfidence::Confirmed: return "confirmed";
        case HitConfidence::Probable: return "probable";
        case HitConfidence::Possible: return "possible";
    }
    return "unknown";
}

static int evidence_status_rank(EvidenceStatus status) {
    switch (status) {
        case EvidenceStatus::Hypothesis: return 0;
        case EvidenceStatus::Observed: return 1;
        case EvidenceStatus::Corroborated: return 2;
        case EvidenceStatus::Verified: return 3;
        case EvidenceStatus::Conflict: return 4;
        case EvidenceStatus::Rejected: return 5;
    }
    return 0;
}

static std::string graph_normalize_value(const std::string& value) {
    return lower_copy(trim_copy(value));
}

static std::string join_graph_ids(const std::vector<std::string>& ids) {
    std::string out;
    for (const auto& id : ids) {
        if (!out.empty()) out += ",";
        out += id;
    }
    return out;
}

std::string graph_node_id(GraphNodeType type, const std::string& value) {
    return graph_node_type_key(type) + ":" + graph_normalize_value(value);
}

GraphNode* find_graph_node(IdentityGraph& graph, GraphNodeType type, const std::string& value) {
    std::string id = graph_node_id(type, value);
    auto it = std::find_if(graph.nodes.begin(), graph.nodes.end(), [&](const GraphNode& node) {
        return node.id == id;
    });
    if (it == graph.nodes.end()) return nullptr;
    return &*it;
}

const GraphNode* find_graph_node(const IdentityGraph& graph, GraphNodeType type, const std::string& value) {
    std::string id = graph_node_id(type, value);
    auto it = std::find_if(graph.nodes.begin(), graph.nodes.end(), [&](const GraphNode& node) {
        return node.id == id;
    });
    if (it == graph.nodes.end()) return nullptr;
    return &*it;
}

GraphNode& add_graph_node(IdentityGraph& graph, GraphNodeType type, const std::string& value, EvidenceStatus status, double confidence) {
    if (GraphNode* existing = find_graph_node(graph, type, value)) {
        existing->confidence = std::max(existing->confidence, confidence);
        if (evidence_status_rank(status) > evidence_status_rank(existing->status)) existing->status = status;
        return *existing;
    }

    GraphNode node;
    node.id = graph_node_id(type, value);
    node.type = type;
    node.value = trim_copy(value);
    node.status = status;
    node.confidence = confidence;
    graph.nodes.push_back(node);
    return graph.nodes.back();
}

Evidence& add_graph_evidence(IdentityGraph& graph, Evidence evidence) {
    if (evidence.id.empty()) {
        evidence.id = "evidence:" + evidence_type_key(evidence.type) + ":" +
            evidence_status_key(evidence.status) + ":" +
            graph_normalize_value(evidence.source) + ":" +
            graph_normalize_value(evidence.tool) + ":" +
            graph_normalize_value(evidence.url) + ":" +
            graph_normalize_value(evidence.detail) + ":" +
            std::to_string(evidence.confidence) + ":" +
            certainty_key(evidence.certainty);
    }

    auto it = std::find_if(graph.evidence.begin(), graph.evidence.end(), [&](const Evidence& item) {
        return item.id == evidence.id;
    });
    if (it != graph.evidence.end()) return *it;

    graph.evidence.push_back(evidence);
    return graph.evidence.back();
}

GraphEdge& add_graph_edge(IdentityGraph& graph, const std::string& from, const std::string& to, GraphEdgeType type, const std::vector<std::string>& evidence_ids, EvidenceStatus status, double confidence, HitConfidence certainty) {
    GraphEdge edge;
    edge.from = from;
    edge.to = to;
    edge.type = type;
    edge.status = status;
    edge.evidence_ids = evidence_ids;
    edge.confidence = confidence;
    edge.certainty = certainty;
    edge.id = "edge:" + graph_edge_type_key(type) + ":" + from + ":" + to + ":" + join_graph_ids(evidence_ids);

    auto it = std::find_if(graph.edges.begin(), graph.edges.end(), [&](const GraphEdge& item) {
        return item.id == edge.id;
    });
    if (it != graph.edges.end()) {
        it->confidence = std::max(it->confidence, confidence);
        if (evidence_status_rank(status) > evidence_status_rank(it->status)) it->status = status;
        if (static_cast<int>(certainty) < static_cast<int>(it->certainty)) it->certainty = certainty;
        return *it;
    }

    graph.edges.push_back(edge);
    return graph.edges.back();
}

static GraphNodeType seed_graph_node_type(InputType type) {
    switch (type) {
        case InputType::Username: return GraphNodeType::Username;
        case InputType::Email: return GraphNodeType::Email;
        case InputType::Phone: return GraphNodeType::Phone;
        default: return GraphNodeType::Username;
    }
}

static std::string normalize_phone_seed_value(const std::string& input) {
    std::string phone;
    for (unsigned char c : input) {
        if (std::isdigit(c) || c == '+') phone += static_cast<char>(c);
    }
    if (phone.empty()) return phone;
    return phone[0] == '+' ? phone : "+" + phone;
}

static std::string seed_graph_value(InputType type, const std::string& input) {
    if (type == InputType::Phone) return normalize_phone_seed_value(input);
    return input;
}

static GraphNode& add_seed_graph_data(IdentityGraph& graph, const std::string& input) {
    GraphNodeType node_type = seed_graph_node_type(graph.seed_type);
    std::string value = seed_graph_value(graph.seed_type, input);
    GraphNode& node = add_graph_node(graph, node_type, value, EvidenceStatus::Verified, 1.0);

    Evidence evidence;
    evidence.type = EvidenceType::SeedInput;
    evidence.status = EvidenceStatus::Verified;
    evidence.source = "seed";
    evidence.detail = value;
    evidence.confidence = 1.0;
    evidence.certainty = HitConfidence::Confirmed;
    add_graph_evidence(graph, evidence);

    return node;
}

void add_graph_hit(IdentityGraph& graph, const Hit& hit) {
    for (const auto& existing : graph.hits) {
        if (!hit.url.empty() && existing.url == hit.url) return;
        if (hit.url.empty() && existing.url.empty() && lower_copy(existing.name) == lower_copy(hit.name)) return;
    }

    graph.hits.push_back(hit);
    graph.category_counts[hit.category]++;
    if (!hit.url.empty()) graph.profile.add("account_url", hit.url);

    OsintEntry entry;
    entry.platform = hit.name;
    entry.url = hit.url;
    entry.category = hit.category;
    entry.certainty = certainty_text(hit.certainty);
    entry.confidence = hit.confidence;
    entry.evidence = hit.evidence;
    entry.source = hit.source;

    std::lock_guard<std::mutex> lock(g_result_mtx);
    g_result.osint.push_back(entry);
    if (!hit.url.empty()) g_result.osint_hits.push_back(hit.url);
}

void dedupe_global_results() {
    std::lock_guard<std::mutex> lock(g_result_mtx);
    std::vector<OsintEntry> clean;
    std::set<std::string> seen;

    for (const auto& item : g_result.osint) {
        std::string key = lower_copy(item.platform) + "|" + lower_copy(item.url) + "|" + lower_copy(item.category);
        if (seen.insert(key).second) clean.push_back(item);
    }
    g_result.osint = clean;

    std::vector<std::string> hits;
    std::set<std::string> seen_hits;
    for (const auto& url : g_result.osint_hits) {
        if (!url.empty() && seen_hits.insert(url).second) hits.push_back(url);
    }
    g_result.osint_hits = hits;
}

void print_hits(const std::vector<Hit>& hits) {
    if (hits.empty()) {
        std::cout << BLOOD_RED << "  nothing found\n" << RESET;
        return;
    }

    std::vector<Hit> sorted = hits;
    std::sort(sorted.begin(), sorted.end(), [](const Hit& a, const Hit& b) {
        if (a.certainty != b.certainty) return static_cast<int>(a.certainty) < static_cast<int>(b.certainty);
        return a.confidence > b.confidence;
    });

    std::map<std::string, std::vector<Hit>> by_category;
    for (const auto& hit : sorted) by_category[hit.category].push_back(hit);

    static const std::vector<std::string> order = {"social", "dev", "gaming", "msg", "music", "blog", "other", "ext"};
    for (const auto& category : order) {
        auto it = by_category.find(category);
        if (it == by_category.end()) continue;

        std::cout << "\n" << BLOOD_RED << BOLD << "  " << WHITE << category << BLOOD_RED << ":\n" << RESET;
        for (const auto& hit : it->second) {
            std::cout << "  " << certainty_label(hit.certainty) << "  " << WHITE << std::left << std::setw(16) << hit.name;
            if (!hit.url.empty()) std::cout << WHITE << hit.url << RESET;
            if (!hit.source.empty()) std::cout << BLOOD_RED << "  [" << WHITE << hit.source << BLOOD_RED << "]" << RESET;
            std::cout << BLOOD_RED << "  " << WHITE << std::fixed << std::setprecision(0) << (hit.confidence * 100.0) << "%\n" << RESET;
        }
    }

    long confirmed = std::count_if(hits.begin(), hits.end(), [](const Hit& hit) {
        return hit.certainty == HitConfidence::Confirmed;
    });
    long probable = std::count_if(hits.begin(), hits.end(), [](const Hit& hit) {
        return hit.certainty == HitConfidence::Probable;
    });
    long possible = std::count_if(hits.begin(), hits.end(), [](const Hit& hit) {
        return hit.certainty == HitConfidence::Possible;
    });

    std::cout << "\n" << BLOOD_RED << "  +" << std::string(48, '-') << "+\n" << RESET;
    std::cout << BLOOD_RED << "  | " << WHITE << "CONFIRMED " << std::left << std::setw(8) << confirmed
              << BLOOD_RED << " | " << WHITE << "PROBABLE " << std::left << std::setw(8) << probable
              << BLOOD_RED << " | " << WHITE << "POSSIBLE " << std::left << std::setw(8) << possible
              << BLOOD_RED << " |\n";
    std::cout << BLOOD_RED << "  +" << std::string(48, '-') << "+\n" << RESET;
}

void print_profile(const CorrelatedProfile& profile, const std::vector<Hit>& hits, const std::string& seed) {
    print_section("CORRELATED IDENTITY PROFILE");
    std::cout << BLOOD_RED << "  [seed]       " << WHITE << seed << "\n\n" << RESET;

    auto print_group = [](const std::string& title, const std::vector<std::string>& values) {
        if (values.empty()) return;
        std::cout << BLOOD_RED << BOLD << "  " << title << ":\n" << RESET;
        for (const auto& value : values) std::cout << BLOOD_RED << "  [+] " << WHITE << value << "\n" << RESET;
        std::cout << "\n";
    };

    print_group("NAMES FOUND", profile.names);
    print_group("PHONE NUMBERS", profile.phones);
    print_group("EMAIL ADDRESSES", profile.emails);
    print_group("LOCATIONS", profile.locations);
    print_group("LINKED ACCOUNTS", profile.accounts);

    long confirmed = std::count_if(hits.begin(), hits.end(), [](const Hit& hit) {
        return hit.certainty == HitConfidence::Confirmed;
    });
    long probable = std::count_if(hits.begin(), hits.end(), [](const Hit& hit) {
        return hit.certainty == HitConfidence::Probable;
    });

    double completeness = 0.0;
    if (!profile.names.empty()) completeness += 0.30;
    if (!profile.phones.empty()) completeness += 0.20;
    if (!profile.emails.empty()) completeness += 0.20;
    if (!profile.locations.empty()) completeness += 0.15;
    if (confirmed > 0) completeness += 0.15;

    std::cout << BLOOD_RED << "  [completeness] " << WHITE << std::fixed << std::setprecision(0) << (completeness * 100.0) << "%  " << confidence_bar(completeness) << "\n" << RESET;
    std::cout << BLOOD_RED << "  [confirmed]    " << WHITE << confirmed << BLOOD_RED << " accounts\n" << RESET;
    std::cout << BLOOD_RED << "  [probable]     " << WHITE << probable << BLOOD_RED << " accounts\n" << RESET;
    std::cout << BLOOD_RED << "  [data_points]  " << WHITE << profile.raw.size() << "\n" << RESET;
}

struct GraphSummaryRow {
    std::string platform;
    std::string url;
    std::string source;
    double confidence = 0.0;
    HitConfidence certainty = HitConfidence::Possible;
};

struct ExternalSummaryRow {
    std::string target;
    std::string tool;
    std::string kind;
    double confidence = 0.0;
    HitConfidence certainty = HitConfidence::Possible;
};

static const GraphNode* graph_node_by_id(const IdentityGraph& graph, const std::string& id) {
    auto it = std::find_if(graph.nodes.begin(), graph.nodes.end(), [&](const GraphNode& node) {
        return node.id == id;
    });
    if (it == graph.nodes.end()) return nullptr;
    return &*it;
}

static const Evidence* graph_evidence_by_id(const IdentityGraph& graph, const std::string& id) {
    auto it = std::find_if(graph.evidence.begin(), graph.evidence.end(), [&](const Evidence& evidence) {
        return evidence.id == id;
    });
    if (it == graph.evidence.end()) return nullptr;
    return &*it;
}

static const Evidence* first_edge_evidence(const IdentityGraph& graph, const GraphEdge& edge) {
    if (edge.evidence_ids.empty()) return nullptr;
    return graph_evidence_by_id(graph, edge.evidence_ids.front());
}

static const Hit* matching_flat_hit_for_url(const IdentityGraph& graph, const std::string& url) {
    if (url.empty()) return nullptr;
    auto it = std::find_if(graph.hits.begin(), graph.hits.end(), [&](const Hit& hit) {
        return hit.url == url;
    });
    if (it == graph.hits.end()) return nullptr;
    return &*it;
}

static int graph_certainty_rank(HitConfidence certainty) {
    switch (certainty) {
        case HitConfidence::Confirmed: return 3;
        case HitConfidence::Probable: return 2;
        case HitConfidence::Possible: return 1;
    }
    return 0;
}

static HitConfidence external_display_certainty(HitConfidence certainty) {
    if (certainty == HitConfidence::Confirmed) return HitConfidence::Probable;
    return certainty;
}

static std::string trim_display(std::string value, size_t limit = 96) {
    value = sanitize(value);
    if (value.size() <= limit) return value;
    if (limit <= 3) return value.substr(0, limit);
    return value.substr(0, limit - 3) + "...";
}

static std::string evidence_source_label(const Evidence* evidence, const std::string& fallback) {
    if (!evidence) return fallback;
    if (!evidence->tool.empty()) return evidence->tool;
    if (!evidence->source.empty()) return evidence->source;
    return fallback;
}

static void sort_graph_summary_rows(std::vector<GraphSummaryRow>& rows) {
    std::sort(rows.begin(), rows.end(), [](const GraphSummaryRow& a, const GraphSummaryRow& b) {
        if (a.certainty != b.certainty) return graph_certainty_rank(a.certainty) > graph_certainty_rank(b.certainty);
        if (a.confidence != b.confidence) return a.confidence > b.confidence;
        if (a.platform != b.platform) return a.platform < b.platform;
        return a.url < b.url;
    });
}

static std::vector<GraphSummaryRow> collect_graph_account_rows(const IdentityGraph& graph) {
    std::vector<GraphSummaryRow> rows;
    std::set<std::string> seen;

    for (const auto& edge : graph.edges) {
        if (edge.type != GraphEdgeType::AccountOnPlatform) continue;
        const GraphNode* account = graph_node_by_id(graph, edge.from);
        const GraphNode* platform = graph_node_by_id(graph, edge.to);
        if (!account || account->type != GraphNodeType::Account || account->value.empty()) continue;
        if (!seen.insert(account->value).second) continue;

        const Evidence* evidence = first_edge_evidence(graph, edge);
        const Hit* flat = matching_flat_hit_for_url(graph, account->value);
        GraphSummaryRow row;
        row.platform = platform && platform->type == GraphNodeType::Platform ? platform->value : (flat ? flat->name : "");
        row.url = account->value;
        row.confidence = flat ? flat->confidence : edge.confidence;
        row.certainty = flat ? flat->certainty : edge.certainty;
        row.source = flat ? flat->source : evidence_source_label(evidence, "internal");
        rows.push_back(row);
    }

    for (const auto& edge : graph.edges) {
        if (edge.type != GraphEdgeType::ExternalToolObserved) continue;
        const GraphNode* target = graph_node_by_id(graph, edge.to);
        if (!target || target->type != GraphNodeType::Account || target->value.empty()) continue;
        if (!seen.insert(target->value).second) continue;

        const Evidence* evidence = first_edge_evidence(graph, edge);
        const Hit* flat = matching_flat_hit_for_url(graph, target->value);
        GraphSummaryRow row;
        row.platform = flat ? flat->name : evidence_source_label(evidence, "external");
        row.url = target->value;
        row.confidence = flat ? flat->confidence : edge.confidence;
        row.certainty = external_display_certainty(flat ? flat->certainty : edge.certainty);
        row.source = flat ? flat->source : evidence_source_label(evidence, "external");
        rows.push_back(row);
    }

    sort_graph_summary_rows(rows);
    return rows;
}

static std::vector<ExternalSummaryRow> collect_graph_corroboration_rows(const IdentityGraph& graph) {
    std::vector<ExternalSummaryRow> rows;
    std::set<std::string> seen;

    for (const auto& edge : graph.edges) {
        if (edge.type != GraphEdgeType::Corroborates) continue;
        const GraphNode* account = graph_node_by_id(graph, edge.to);
        if (!account || account->type != GraphNodeType::Account || account->value.empty()) continue;
        const Evidence* evidence = first_edge_evidence(graph, edge);
        std::string tool = evidence_source_label(evidence, "external");
        std::string key = account->value + "|" + tool;
        if (!seen.insert(key).second) continue;

        ExternalSummaryRow row;
        row.target = account->value;
        row.tool = tool;
        row.kind = "exact URL corroboration";
        row.confidence = edge.confidence;
        row.certainty = edge.certainty;
        rows.push_back(row);
    }

    std::sort(rows.begin(), rows.end(), [](const ExternalSummaryRow& a, const ExternalSummaryRow& b) {
        if (a.confidence != b.confidence) return a.confidence > b.confidence;
        return a.target < b.target;
    });
    return rows;
}

static std::vector<ExternalSummaryRow> collect_graph_external_rows(const IdentityGraph& graph) {
    std::vector<ExternalSummaryRow> rows;
    std::set<std::string> seen;

    for (const auto& edge : graph.edges) {
        if (edge.type != GraphEdgeType::ExternalToolObserved) continue;
        const GraphNode* target = graph_node_by_id(graph, edge.to);
        if (!target || target->type == GraphNodeType::ToolFinding || target->value.empty()) continue;
        const Evidence* evidence = first_edge_evidence(graph, edge);
        std::string tool = evidence_source_label(evidence, "external");
        std::string kind = target->type == GraphNodeType::Account ? "external account observation" : "platform observation";
        std::string key = target->value + "|" + tool + "|" + kind;
        if (!seen.insert(key).second) continue;

        ExternalSummaryRow row;
        row.target = target->value;
        row.tool = tool;
        row.kind = kind;
        row.confidence = edge.confidence;
        row.certainty = external_display_certainty(edge.certainty);
        rows.push_back(row);
    }

    std::sort(rows.begin(), rows.end(), [](const ExternalSummaryRow& a, const ExternalSummaryRow& b) {
        if (a.certainty != b.certainty) return graph_certainty_rank(a.certainty) > graph_certainty_rank(b.certainty);
        if (a.confidence != b.confidence) return a.confidence > b.confidence;
        return a.target < b.target;
    });
    return rows;
}

static void add_hypothesis_value(std::vector<std::string>& values, std::set<std::string>& seen, const GraphNode* node) {
    if (!node || node->status != EvidenceStatus::Hypothesis || node->value.empty()) return;
    std::string key = graph_normalize_value(node->value);
    if (seen.insert(key).second) values.push_back(node->value);
}

static void collect_graph_hypothesis_values(const IdentityGraph& graph, std::vector<std::string>& usernames, std::vector<std::string>& emails, std::vector<std::string>& phones) {
    std::set<std::string> seen_usernames;
    std::set<std::string> seen_emails;
    std::set<std::string> seen_phones;

    for (const auto& edge : graph.edges) {
        if (edge.type != GraphEdgeType::GeneratedCandidate && edge.type != GraphEdgeType::DerivedFromEmail && edge.type != GraphEdgeType::DerivedFromPhone) continue;
        const GraphNode* node = graph_node_by_id(graph, edge.to);
        if (!node) continue;
        if (node->type == GraphNodeType::Username) add_hypothesis_value(usernames, seen_usernames, node);
        else if (node->type == GraphNodeType::Email) add_hypothesis_value(emails, seen_emails, node);
        else if (node->type == GraphNodeType::Phone) add_hypothesis_value(phones, seen_phones, node);
    }

    std::sort(usernames.begin(), usernames.end());
    std::sort(emails.begin(), emails.end());
    std::sort(phones.begin(), phones.end());
}

static bool graph_has_conflicts(const IdentityGraph& graph) {
    for (const auto& evidence : graph.evidence) {
        if (evidence.status == EvidenceStatus::Conflict || evidence.status == EvidenceStatus::Rejected) return true;
    }
    for (const auto& edge : graph.edges) {
        if (edge.status == EvidenceStatus::Conflict || edge.status == EvidenceStatus::Rejected) return true;
    }
    return false;
}

static void print_limited_values(const std::string& label, const std::vector<std::string>& values, size_t cap) {
    if (values.empty()) return;
    std::cout << BLOOD_RED << "  [" << label << "] " << WHITE << values.size() << BLOOD_RED << " hypotheses\n" << RESET;
    size_t shown = std::min(values.size(), cap);
    for (size_t i = 0; i < shown; ++i) {
        std::cout << BLOOD_RED << "    -> " << WHITE << trim_display(values[i]) << "\n" << RESET;
    }
    if (values.size() > shown) {
        std::cout << BLOOD_RED << "    ... +" << WHITE << values.size() - shown << BLOOD_RED << " more\n" << RESET;
    }
}

static void print_account_rows(const std::vector<GraphSummaryRow>& rows) {
    std::cout << BLOOD_RED << BOLD << "  ACCOUNT FINDINGS\n" << RESET;
    if (rows.empty()) {
        std::cout << BLOOD_RED << "  none\n" << RESET;
        return;
    }

    size_t shown = std::min(rows.size(), static_cast<size_t>(8));
    for (size_t i = 0; i < shown; ++i) {
        const auto& row = rows[i];
        std::cout << "  " << certainty_label(row.certainty) << "  " << WHITE;
        if (!row.platform.empty()) std::cout << std::left << std::setw(16) << trim_display(row.platform, 16);
        std::cout << trim_display(row.url) << BLOOD_RED << "  " << WHITE
                  << std::fixed << std::setprecision(0) << (row.confidence * 100.0) << "%"
                  << BLOOD_RED << "  [" << WHITE << trim_display(row.source, 32) << BLOOD_RED << "]\n" << RESET;
    }
    if (rows.size() > shown) std::cout << BLOOD_RED << "  ... +" << WHITE << rows.size() - shown << BLOOD_RED << " more account rows\n" << RESET;
}

static void print_external_rows(const std::string& title, const std::vector<ExternalSummaryRow>& rows, size_t cap) {
    std::cout << BLOOD_RED << BOLD << "  " << title << "\n" << RESET;
    if (rows.empty()) {
        std::cout << BLOOD_RED << "  none\n" << RESET;
        return;
    }

    size_t shown = std::min(rows.size(), cap);
    for (size_t i = 0; i < shown; ++i) {
        const auto& row = rows[i];
        std::cout << "  " << certainty_label(row.certainty) << "  " << WHITE << trim_display(row.target)
                  << BLOOD_RED << "  [" << WHITE << trim_display(row.tool, 24)
                  << BLOOD_RED << ": " << WHITE << row.kind << BLOOD_RED << "]\n" << RESET;
    }
    if (rows.size() > shown) std::cout << BLOOD_RED << "  ... +" << WHITE << rows.size() - shown << BLOOD_RED << " more\n" << RESET;
}

static void print_graph_identity_summary(const IdentityGraph& graph, const std::string& input, const std::string& type_name) {
    print_section("IDENTITY GRAPH SUMMARY");
    std::string seed_value = graph.seed.empty() ? input : graph.seed;
    if (graph.seed_type != InputType::Unknown) {
        const GraphNode* seed_node = find_graph_node(graph, seed_graph_node_type(graph.seed_type), seed_graph_value(graph.seed_type, seed_value));
        if (seed_node && seed_node->status == EvidenceStatus::Verified && !seed_node->value.empty()) seed_value = seed_node->value;
    }

    std::cout << BLOOD_RED << BOLD << "  SEED\n" << RESET;
    std::cout << BLOOD_RED << "  [value]  " << WHITE << trim_display(seed_value) << "\n" << RESET;
    std::cout << BLOOD_RED << "  [type]   " << WHITE << type_name << "\n" << RESET;
    std::cout << BLOOD_RED << "  [status] " << WHITE << "verified\n\n" << RESET;

    auto account_rows = collect_graph_account_rows(graph);
    auto corroboration_rows = collect_graph_corroboration_rows(graph);
    auto external_rows = collect_graph_external_rows(graph);
    std::vector<std::string> usernames;
    std::vector<std::string> emails;
    std::vector<std::string> phones;
    collect_graph_hypothesis_values(graph, usernames, emails, phones);

    print_account_rows(account_rows);
    std::cout << "\n";
    print_external_rows("EXTERNAL CORROBORATION", corroboration_rows, 6);
    std::cout << "\n";
    print_external_rows("EXTERNAL OBSERVATIONS", external_rows, 6);
    std::cout << "\n";

    std::cout << BLOOD_RED << BOLD << "  GENERATED HYPOTHESES\n" << RESET;
    if (usernames.empty() && emails.empty() && phones.empty()) {
        std::cout << BLOOD_RED << "  none\n" << RESET;
    } else {
        print_limited_values("usernames", usernames, 8);
        print_limited_values("emails", emails, 6);
        print_limited_values("phones", phones, 6);
    }

    std::cout << "\n" << BLOOD_RED << BOLD << "  CONFLICTS\n" << RESET;
    std::cout << BLOOD_RED << "  " << WHITE << (graph_has_conflicts(graph) ? "present" : "none") << "\n" << RESET;
}

void print_web_mentions(const std::string& query, int max_count) {
    std::string url = "https://html.duckduckgo.com/html/?q=%22" + url_encode(query) + "%22";
    if (!InputGuard::is_safe_url(url)) return;

    auto body = safe_curl(url, 10);
    int shown = 0;
    for (const auto& link : extract_links(body, max_count)) {
        if (link.find("duckduckgo") != std::string::npos) continue;
        std::cout << WHITE << "  " << sanitize(link) << RESET << "\n";
        shown++;
    }
    if (!shown) std::cout << BLOOD_RED << "  no public mentions\n" << RESET;
}

}

void osint_scan(const std::string& input) {
    osint::InputType type = osint::detect_input_type(input);
    std::string type_name = osint::input_type_name(type);

    print_header("OSINT // " + type_name + " // " + input);
    std::cout << BLOOD_RED << "  [auto-detected] " << WHITE << type_name << "\n" << RESET;

    osint::IdentityGraph graph;
    graph.seed = input;
    graph.seed_type = type;
    if (type != osint::InputType::Unknown) osint::add_seed_graph_data(graph, input);

    switch (type) {
        case osint::InputType::Username:
            osint::run_username(input, graph);
            break;
        case osint::InputType::Email:
            osint::run_email(input, graph);
            break;
        case osint::InputType::Phone:
            osint::run_phone(input, graph);
            break;
        default:
            std::cout << BLOOD_RED << "  [!] cannot determine input type\n" << RESET;
            return;
    }

    osint::dedupe_global_results();

    if (!graph.hits.empty() || !graph.username_candidates.empty() || !graph.email_candidates.empty() || !graph.phone_candidates.empty() || !graph.nodes.empty() || !graph.edges.empty() || !graph.evidence.empty()) {
        osint::print_graph_identity_summary(graph, input, type_name);
    }

    LOG_INFO("osint", "done input=" + input + " type=" + type_name + " hits=" + std::to_string(graph.hits.size()));
}
