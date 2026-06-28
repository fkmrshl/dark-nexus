#pragma once

#include "dark_nexus.hpp"
#include "security.hpp"

namespace osint {

enum class InputType { Username, Email, Phone, Unknown };
enum class HitConfidence { Confirmed, Probable, Possible };
enum class GraphNodeType { Seed, Username, Email, Phone, Account, Platform, Domain, Location, Name, Carrier, ToolFinding, WebMention };
enum class GraphEdgeType { SeedIs, GeneratedCandidate, DerivedFromEmail, DerivedFromPhone, AccountOnPlatform, ExternalToolObserved, ProfileAttribute, Corroborates, ConflictsWith };
enum class EvidenceType { SeedInput, Generated, InternalHttp, ExternalTool, PhoneHeuristic, EmailHeuristic, WebSearch };
enum class EvidenceStatus { Verified, Hypothesis, Observed, Corroborated, Conflict, Rejected };

struct Evidence {
    std::string id;
    EvidenceType type = EvidenceType::Generated;
    EvidenceStatus status = EvidenceStatus::Observed;
    std::string source;
    std::string tool;
    std::string url;
    std::string detail;
    double confidence = 0.0;
    HitConfidence certainty = HitConfidence::Possible;
};

struct GraphNode {
    std::string id;
    GraphNodeType type = GraphNodeType::Seed;
    std::string value;
    EvidenceStatus status = EvidenceStatus::Observed;
    double confidence = 0.0;
};

struct GraphEdge {
    std::string id;
    std::string from;
    std::string to;
    GraphEdgeType type = GraphEdgeType::GeneratedCandidate;
    EvidenceStatus status = EvidenceStatus::Observed;
    std::vector<std::string> evidence_ids;
    double confidence = 0.0;
    HitConfidence certainty = HitConfidence::Possible;
};

struct Site {
    std::string name;
    std::string url;
    std::string dead;
    std::string category;
    int weight = 1;
    std::vector<std::string> positive_markers;
};

struct Hit {
    std::string name;
    std::string url;
    std::string category;
    std::string evidence;
    std::string source;
    double confidence = 0.0;
    HitConfidence certainty = HitConfidence::Possible;
};

struct ToolHit {
    std::string platform;
    std::string url;
    std::string info;
};

struct ToolResult {
    std::string tool;
    bool available = false;
    bool installed = false;
    bool skipped = false;
    std::vector<ToolHit> hits;
};

struct ToolSpec {
    std::string binary;
    std::string package;
    bool python_package = true;
};

struct CorrelatedProfile {
    std::vector<std::string> names;
    std::vector<std::string> phones;
    std::vector<std::string> emails;
    std::vector<std::string> locations;
    std::vector<std::string> accounts;
    std::map<std::string, std::string> raw;

    void add(const std::string& key, const std::string& value);
};

struct IdentityGraph {
    std::string seed;
    InputType seed_type = InputType::Unknown;
    std::vector<std::string> username_candidates;
    std::vector<std::string> email_candidates;
    std::vector<std::string> phone_candidates;
    std::vector<Hit> hits;
    std::map<std::string, int> category_counts;
    CorrelatedProfile profile;
    std::vector<GraphNode> nodes;
    std::vector<GraphEdge> edges;
    std::vector<Evidence> evidence;
};

InputType detect_input_type(const std::string& input);
std::string input_type_name(InputType type);
std::string lower_copy(std::string value);
std::string trim_copy(std::string value);
std::string fill_template(const std::string& tmpl, const std::string& value);
std::string url_encode(const std::string& value);
std::vector<std::string> extract_links(const std::string& html, int max_count = 10);
std::string confidence_bar(double confidence);
std::string certainty_text(HitConfidence certainty);
std::string certainty_label(HitConfidence certainty);
HitConfidence certainty_from_score(double confidence);
double score_hit(bool fetched, bool missing_dead_marker, const std::vector<std::string>& markers, int weight);
std::vector<std::string> username_patterns(const std::string& username);
std::vector<std::string> username_candidates_from_email_local(const std::string& local);
std::string graph_node_id(GraphNodeType type, const std::string& value);
GraphNode* find_graph_node(IdentityGraph& graph, GraphNodeType type, const std::string& value);
const GraphNode* find_graph_node(const IdentityGraph& graph, GraphNodeType type, const std::string& value);
GraphNode& add_graph_node(IdentityGraph& graph, GraphNodeType type, const std::string& value, EvidenceStatus status = EvidenceStatus::Observed, double confidence = 0.0);
Evidence& add_graph_evidence(IdentityGraph& graph, Evidence evidence);
GraphEdge& add_graph_edge(IdentityGraph& graph, const std::string& from, const std::string& to, GraphEdgeType type, const std::vector<std::string>& evidence_ids = {}, EvidenceStatus status = EvidenceStatus::Observed, double confidence = 0.0, HitConfidence certainty = HitConfidence::Possible);
void add_graph_hit(IdentityGraph& graph, const Hit& hit);
void dedupe_global_results();
void print_hits(const std::vector<Hit>& hits);
void print_profile(const CorrelatedProfile& profile, const std::vector<Hit>& hits, const std::string& seed);
void print_web_mentions(const std::string& query, int max_count = 8);

void run_platform_scan(const std::string& username, IdentityGraph& graph);

std::vector<ToolResult> run_username_tools(const std::string& username);
std::vector<ToolResult> run_email_tools(const std::string& email, const std::string& domain);
ToolResult run_phoneinfoga(const std::string& e164);
void cross_reference(IdentityGraph& graph, const std::vector<ToolResult>& tools);

void run_username(const std::string& username, IdentityGraph& graph);
void run_email(const std::string& email, IdentityGraph& graph);
void run_phone(const std::string& phone, IdentityGraph& graph);

}
