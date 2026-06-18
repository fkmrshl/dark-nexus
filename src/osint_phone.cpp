#include "../include/osint.hpp"

namespace osint {

struct OperatorInfo {
    std::string name;
    std::string region;
};

struct CountryInfo {
    std::string code;
    std::string country;
    std::string region;
    std::string language;
    std::vector<std::string> carriers;
    std::vector<std::string> platforms;
    std::string messenger_note;
};

static const std::map<std::string, OperatorInfo> RU_OPERATORS = {
    {"900", {"MTS", "Russia"}}, {"901", {"MTS", "Russia"}}, {"902", {"MTS", "Russia"}},
    {"903", {"MTS", "Russia"}}, {"904", {"MTS", "Russia"}}, {"905", {"MTS", "Russia"}},
    {"906", {"MTS", "Russia"}}, {"908", {"MTS", "Russia"}}, {"909", {"MTS", "Russia"}},
    {"910", {"MegaFon", "Central Russia"}}, {"911", {"MegaFon", "North-West"}},
    {"912", {"MegaFon", "Ural"}}, {"913", {"MegaFon", "Siberia"}},
    {"914", {"MegaFon", "Far East"}}, {"915", {"MTS", "Central Russia"}},
    {"916", {"MTS", "Moscow"}}, {"917", {"MTS", "Volga"}}, {"918", {"MTS", "South Russia"}},
    {"919", {"MTS", "North-West"}}, {"920", {"Beeline", "Volga"}},
    {"921", {"Beeline", "North-West"}}, {"922", {"Beeline", "Ural"}},
    {"923", {"Beeline", "Siberia"}}, {"924", {"Beeline", "Far East"}},
    {"925", {"MTS", "Moscow"}}, {"926", {"MTS", "Moscow"}}, {"927", {"MTS", "Volga"}},
    {"928", {"MTS", "South Russia"}}, {"929", {"MTS", "Central Russia"}},
    {"930", {"Tele2", "Russia"}}, {"931", {"Tele2", "North-West"}},
    {"932", {"Tele2", "Ural"}}, {"933", {"Tele2", "Siberia"}},
    {"934", {"Tele2", "Far East"}}, {"936", {"Tele2", "Central Russia"}},
    {"937", {"Tele2", "Volga"}}, {"938", {"Tele2", "South Russia"}},
    {"939", {"Tele2", "Russia"}}, {"941", {"Tele2", "Russia"}},
    {"950", {"Beeline", "Russia"}}, {"951", {"Beeline", "Russia"}},
    {"952", {"Beeline", "Russia"}}, {"953", {"Beeline", "Russia"}},
    {"958", {"Rostelecom", "Russia"}}, {"959", {"Rostelecom", "Russia"}},
    {"960", {"Beeline", "Russia"}}, {"961", {"Beeline", "Russia"}},
    {"962", {"Beeline", "Russia"}}, {"963", {"Beeline", "Russia"}},
    {"964", {"Beeline", "Russia"}}, {"965", {"MTS", "Russia"}},
    {"966", {"MTS", "Russia"}}, {"967", {"MTS", "Russia"}},
    {"968", {"MTS", "Russia"}}, {"969", {"MTS", "Russia"}},
    {"970", {"Tele2", "Crimea"}}, {"971", {"Tele2", "Crimea"}},
    {"977", {"Beeline", "Moscow"}}, {"978", {"MTS", "Crimea"}},
    {"979", {"MTS", "Crimea"}}, {"980", {"MTS", "Russia"}},
    {"981", {"MegaFon", "North-West"}}, {"982", {"MegaFon", "Ural"}},
    {"983", {"MegaFon", "Siberia"}}, {"984", {"MegaFon", "Far East"}},
    {"985", {"MTS", "Moscow"}}, {"986", {"MTS", "Russia"}},
    {"987", {"MTS", "Russia"}}, {"988", {"MTS", "South Russia"}},
    {"989", {"MegaFon", "South Russia"}}, {"991", {"Tele2", "Russia"}},
    {"992", {"Tele2", "Russia"}}, {"993", {"Tele2", "Russia"}},
    {"994", {"Tele2", "Russia"}}, {"995", {"MegaFon", "Russia"}},
    {"996", {"MegaFon", "Russia"}}, {"997", {"MegaFon", "Russia"}},
    {"999", {"MegaFon", "Moscow"}}
};

static const std::vector<CountryInfo> COUNTRY_DB = {
    {"+1", "USA/Canada", "North America", "en", {"AT&T", "Verizon", "T-Mobile"}, {"Twitter", "Instagram", "Facebook", "LinkedIn", "GitHub", "Reddit"}, "iMessage, WhatsApp, and carrier identity services are common"},
    {"+7", "Russia/KZ", "CIS", "ru", {"MTS", "MegaFon", "Beeline", "Tele2"}, {"VK", "Telegram", "OK.ru", "Instagram", "TikTok"}, "Telegram is common, but phone lookup requires consent or authenticated services"},
    {"+44", "UK", "Europe", "en", {"EE", "O2", "Vodafone", "Three"}, {"Twitter", "Instagram", "LinkedIn", "GitHub", "Reddit"}, "WhatsApp is common"},
    {"+49", "Germany", "Europe", "de", {"Telekom", "Vodafone", "O2"}, {"Instagram", "Twitter", "XING", "GitHub"}, "WhatsApp is common"},
    {"+33", "France", "Europe", "fr", {"Orange", "SFR", "Bouygues", "Free"}, {"Twitter", "Instagram", "LinkedIn"}, "WhatsApp is common"},
    {"+39", "Italy", "Europe", "it", {"TIM", "Vodafone", "Wind Tre", "Iliad"}, {"Instagram", "Twitter", "Facebook"}, "WhatsApp is common"},
    {"+34", "Spain", "Europe", "es", {"Movistar", "Vodafone", "Orange", "Yoigo"}, {"Instagram", "Twitter", "Facebook"}, "WhatsApp is common"},
    {"+380", "Ukraine", "CIS", "uk", {"Kyivstar", "Vodafone UA", "lifecell"}, {"Telegram", "Instagram", "VK", "Twitter"}, "Telegram is common"},
    {"+375", "Belarus", "CIS", "ru", {"A1", "MTS BY", "life:)"}, {"Telegram", "VK", "Instagram"}, "Telegram is common"},
    {"+998", "Uzbekistan", "CIS", "uz", {"Ucell", "Beeline UZ", "MTS UZ"}, {"Telegram", "Instagram", "VK"}, "Telegram is common"},
    {"+81", "Japan", "Asia", "ja", {"NTT Docomo", "SoftBank", "au"}, {"Twitter", "Instagram", "LINE"}, "LINE is common"},
    {"+82", "South Korea", "Asia", "ko", {"SKT", "KT", "LG U+"}, {"KakaoTalk", "Naver", "Instagram", "Twitter"}, "KakaoTalk is common"},
    {"+91", "India", "Asia", "hi", {"Jio", "Airtel", "Vi", "BSNL"}, {"Instagram", "Twitter", "LinkedIn", "WhatsApp"}, "WhatsApp is common"},
    {"+55", "Brazil", "South America", "pt", {"Claro", "TIM", "Vivo", "Oi"}, {"Instagram", "Twitter", "WhatsApp", "TikTok", "Facebook"}, "WhatsApp is common"},
    {"+52", "Mexico", "North America", "es", {"Telcel", "AT&T MX", "Movistar"}, {"Instagram", "Twitter", "Facebook", "TikTok"}, "WhatsApp is common"},
    {"+61", "Australia", "Oceania", "en", {"Telstra", "Optus", "Vodafone"}, {"Instagram", "Twitter", "LinkedIn", "Reddit", "GitHub"}, "iMessage and WhatsApp are common"},
    {"+27", "South Africa", "Africa", "en", {"Vodacom", "MTN", "Cell C"}, {"WhatsApp", "Instagram", "Twitter", "Facebook"}, "WhatsApp is common"},
    {"+234", "Nigeria", "Africa", "en", {"MTN NG", "Airtel NG", "Glo"}, {"WhatsApp", "Instagram", "Twitter", "Facebook"}, "WhatsApp is common"}
};

static const CountryInfo* find_country(const std::string& e164) {
    const CountryInfo* best = nullptr;
    for (const auto& country : COUNTRY_DB) {
        if (e164.find(country.code) == 0 && (!best || country.code.size() > best->code.size())) best = &country;
    }
    return best;
}

static void print_phone_formats(const CountryInfo* country, const std::string& e164, const std::string& raw_digits, IdentityGraph& graph) {
    print_section("PHONE FORMATS");

    std::vector<std::string> formats = {e164, raw_digits};
    if (country && country->code == "+7" && raw_digits.size() == 11) {
        formats.push_back("8" + raw_digits.substr(1));
        formats.push_back("(" + raw_digits.substr(1, 3) + ") " + raw_digits.substr(4, 3) + "-" + raw_digits.substr(7, 2) + "-" + raw_digits.substr(9));
        formats.push_back("+7 (" + raw_digits.substr(1, 3) + ") " + raw_digits.substr(4, 3) + "-" + raw_digits.substr(7, 2) + "-" + raw_digits.substr(9));
    }

    std::sort(formats.begin(), formats.end());
    formats.erase(std::unique(formats.begin(), formats.end()), formats.end());
    graph.phone_candidates = formats;

    std::string phone_seed_id = graph_node_id(GraphNodeType::Phone, e164);
    for (const auto& format : formats) {
        if (graph_node_id(GraphNodeType::Phone, format) == phone_seed_id) continue;

        Evidence evidence;
        evidence.type = EvidenceType::Generated;
        evidence.status = EvidenceStatus::Hypothesis;
        evidence.source = "phone_formats";
        evidence.detail = "phone_format:" + format;
        evidence.confidence = 0.20;
        evidence.certainty = HitConfidence::Possible;
        Evidence& added_evidence = add_graph_evidence(graph, evidence);

        GraphNode& format_node = add_graph_node(graph, GraphNodeType::Phone, format, EvidenceStatus::Hypothesis, 0.20);
        add_graph_edge(graph, phone_seed_id, format_node.id, GraphEdgeType::DerivedFromPhone, {added_evidence.id}, EvidenceStatus::Hypothesis, 0.20, HitConfidence::Possible);
    }

    for (const auto& format : formats) std::cout << WHITE << "  " << format << "\n" << RESET;
}

static void print_phone_risk(const CountryInfo* country, const std::string& raw_digits) {
    print_section("FRAUD & SPAM HEURISTICS");

    double score = 0.0;
    std::vector<std::string> flags;
    if (!country) {
        score += 0.40;
        flags.push_back("unknown country code");
    }

    std::string tail = raw_digits.size() >= 4 ? raw_digits.substr(raw_digits.size() - 4) : "";
    static const std::set<std::string> suspicious_tails = {"0000", "1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888", "9999", "1234", "4321"};
    if (suspicious_tails.count(tail)) {
        score += 0.20;
        flags.push_back("suspicious tail: " + tail);
    }

    if (raw_digits.size() > 4 && std::all_of(raw_digits.begin(), raw_digits.end(), [&](char c) {
        return c == raw_digits[0];
    })) {
        score += 0.50;
        flags.push_back("all digits are identical");
    }

    if (country && country->code == "+7" && raw_digits.size() == 11 && !RU_OPERATORS.count(raw_digits.substr(1, 3))) {
        score += 0.15;
        flags.push_back("unknown RU operator prefix: " + raw_digits.substr(1, 3));
    }

    score = std::min(score, 0.95);
    std::cout << BLOOD_RED << "  [fraud_score] " << WHITE << std::fixed << std::setprecision(0) << (score * 100.0) << "%  " << confidence_bar(score) << "\n" << RESET;
    for (const auto& flag : flags) std::cout << BLOOD_RED << "  [!] " << WHITE << flag << "\n" << RESET;
    if (flags.empty()) std::cout << BLOOD_RED << "  [ok] no suspicious digit patterns\n" << RESET;
}

void run_phone(const std::string& phone_raw, IdentityGraph& graph) {
    std::string phone;
    for (unsigned char c : phone_raw) {
        if (std::isdigit(c) || c == '+') phone += static_cast<char>(c);
    }

    if (!InputGuard::is_valid_phone(phone)) {
        std::cout << BLOOD_RED << "  [!] invalid phone\n" << RESET;
        return;
    }

    std::string e164 = phone[0] == '+' ? phone : "+" + phone;
    std::string raw_digits;
    for (unsigned char c : phone) {
        if (std::isdigit(c)) raw_digits += static_cast<char>(c);
    }

    const CountryInfo* country = find_country(e164);

    print_section("PHONE PROFILE");
    std::cout << BLOOD_RED << "  [number]   " << WHITE << e164 << "\n" << RESET;
    graph.profile.add("phone", e164);

    if (country) {
        std::cout << BLOOD_RED << "  [country]  " << WHITE << country->country << "\n" << RESET;
        std::cout << BLOOD_RED << "  [region]   " << WHITE << country->region << "\n" << RESET;
        std::cout << BLOOD_RED << "  [language] " << WHITE << country->language << "\n" << RESET;
        std::cout << BLOOD_RED << "  [code]     " << WHITE << country->code << "\n" << RESET;
        std::cout << BLOOD_RED << "  [carriers] " << WHITE;
        for (size_t i = 0; i < country->carriers.size(); ++i) {
            std::cout << country->carriers[i];
            if (i + 1 < country->carriers.size()) std::cout << BLOOD_RED << ", " << WHITE;
        }
        std::cout << "\n" << RESET;
        graph.profile.add("country", country->country);
        graph.profile.add("region_country", country->region);

        if (country->code == "+7" && raw_digits.size() == 11) {
            std::string prefix = raw_digits.substr(1, 3);
            auto op = RU_OPERATORS.find(prefix);
            if (op != RU_OPERATORS.end()) {
                std::cout << BLOOD_RED << "  [operator] " << WHITE << op->second.name << BLOOD_RED << " (prefix " << WHITE << prefix << BLOOD_RED << ")\n" << RESET;
                std::cout << BLOOD_RED << "  [reg_area] " << WHITE << op->second.region << "\n" << RESET;
                graph.profile.add("operator", op->second.name);
                graph.profile.add("registration_region", op->second.region);
            } else {
                std::cout << BLOOD_RED << "  [operator] " << WHITE << "unknown prefix " << prefix << "\n" << RESET;
            }
        }
    } else {
        std::cout << BLOOD_RED << "  [country]  " << WHITE << "unknown country code\n" << RESET;
    }

    print_section("PUBLIC LOOKUP POLICY");
    std::cout << BLOOD_RED << "  [safe] " << WHITE << "GetContact, Truecaller, VK, OK.ru, WhatsApp, Signal, and Viber phone lookups require auth, consent, or private APIs and are skipped\n" << RESET;
    std::cout << BLOOD_RED << "  [hint] " << WHITE << "Use provider consoles or authorized APIs when you have permission\n" << RESET;

    print_section("BEHAVIORAL PROFILE");
    if (country) {
        std::cout << BLOOD_RED << "  [messenger_note] " << WHITE << country->messenger_note << "\n\n" << RESET;
        std::cout << BLOOD_RED << "  common platforms in " << WHITE << country->country << BLOOD_RED << ":\n" << RESET;
        for (const auto& platform : country->platforms) std::cout << BLOOD_RED << "    -> " << WHITE << platform << "\n" << RESET;
    }

    print_section("EXTERNAL TOOLS");
    ToolResult phoneinfoga = run_phoneinfoga(e164);
    if (phoneinfoga.installed) {
        std::cout << BLOOD_RED << "  [+] " << WHITE << "phoneinfoga: found " << phoneinfoga.hits.size() << " results\n" << RESET;
        for (const auto& hit : phoneinfoga.hits) {
            if (!hit.info.empty()) {
                std::cout << WHITE << "  " << hit.info << RESET << "\n";
                graph.profile.add("phoneinfoga", hit.info);
            }
        }
    }

    print_phone_risk(country, raw_digits);
    print_phone_formats(country, e164, raw_digits, graph);

    print_section("PUBLIC WEB MENTIONS");
    print_web_mentions(raw_digits, 8);

    print_profile(graph.profile, graph.hits, e164);
    LOG_INFO("osint_phone", "done phone=" + phone);
}

}
