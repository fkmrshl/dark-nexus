#include "../include/dark_nexus.hpp"

enum class OsintInputType { USERNAME, EMAIL, PHONE, UNKNOWN };
enum class HitConfidence  { CONFIRMED, PROBABLE, POSSIBLE };

struct OsintSite {
    std::string name, url, dead, cat;
    int weight = 1;
    std::vector<std::string> pos;
};

struct OsintHit {
    std::string   name, url, cat, evidence;
    double        conf      = 0.0;
    HitConfidence certainty = HitConfidence::POSSIBLE;
};

struct ToolHit {
    std::string platform, url, info;
};

struct ToolResult {
    std::string           tool;
    bool                  available  = false;
    bool                  installed  = false;
    std::vector<ToolHit>  hits;
};

struct IdentityGraph {
    std::string              seed;
    OsintInputType           seed_type;
    std::vector<std::string> username_candidates;
    std::vector<std::string> email_candidates;
    std::vector<std::string> phone_candidates;
    std::vector<OsintHit>    hits;
    std::map<std::string,int> category_counts;
};

static const std::vector<OsintSite> SITES = {
    {"Instagram",   "https://www.instagram.com/{}/",                "page isn't available", "social",5,{"og:title","instagram.com/{}"}},
    {"TikTok",      "https://www.tiktok.com/@{}/",                  "couldn't find",        "social",5,{"@{}","tiktok.com"}},
    {"Twitter/X",   "https://twitter.com/{}/",                      "doesn't exist",        "social",5,{"twitter.com/{}"}},
    {"Reddit",      "https://www.reddit.com/user/{}/",              "page not found",       "social",4,{"u/{}"}},
    {"VK",          "https://vk.com/{}/",                           "not found",            "social",3,{"vk.com/{}"}},
    {"Facebook",    "https://www.facebook.com/{}/",                 "isn't available",      "social",4,{"facebook.com/{}"}},
    {"Pinterest",   "https://www.pinterest.com/{}/",                "not found",            "social",3,{"pinterest.com/{}"}},
    {"Tumblr",      "https://{}.tumblr.com/",                       "not found",            "social",2,{"tumblr.com"}},
    {"Flickr",      "https://www.flickr.com/people/{}/",            "not found",            "social",2,{"flickr.com"}},
    {"GitHub",      "https://github.com/{}/",                       "not found",            "dev",  5,{"github.com/{}","repositories"}},
    {"GitLab",      "https://gitlab.com/{}/",                       "not found",            "dev",  4,{"gitlab.com/{}"}},
    {"HackerOne",   "https://hackerone.com/{}/",                    "not found",            "dev",  3,{"hackerone.com"}},
    {"Bugcrowd",    "https://bugcrowd.com/{}/",                     "not found",            "dev",  3,{"bugcrowd.com"}},
    {"Pastebin",    "https://pastebin.com/u/{}/",                   "not found",            "dev",  2,{"pastebin.com/u/{}"}},
    {"HackerNews",  "https://news.ycombinator.com/user?id={}",      "no such user",         "dev",  3,{"user?id={}"}},
    {"Bitbucket",   "https://bitbucket.org/{}/",                    "not found",            "dev",  3,{"bitbucket.org/{}"}},
    {"npm",         "https://www.npmjs.com/~{}/",                   "not found",            "dev",  3,{"npmjs.com"}},
    {"PyPI",        "https://pypi.org/user/{}/",                    "not found",            "dev",  3,{"pypi.org/user/{}"}},
    {"DockerHub",   "https://hub.docker.com/u/{}/",                 "not found",            "dev",  3,{"hub.docker.com/u/{}"}},
    {"Steam",       "https://steamcommunity.com/id/{}/",            "error",                "gaming",4,{"steamcommunity.com/id/{}"}},
    {"Twitch",      "https://www.twitch.tv/{}/",                    "not found",            "gaming",4,{"twitch.tv/{}"}},
    {"Chess.com",   "https://www.chess.com/member/{}/",             "not found",            "gaming",3,{"chess.com/member/{}"}},
    {"Lichess",     "https://lichess.org/@{}/",                     "not found",            "gaming",3,{"lichess.org"}},
    {"Faceit",      "https://www.faceit.com/en/players/{}/",        "not found",            "gaming",3,{"faceit.com"}},
    {"Telegram",    "https://t.me/{}/",                             "if you have telegram", "msg",  5,{"t.me/{}","telegram"}},
    {"Keybase",     "https://keybase.io/{}/",                       "not found",            "msg",  3,{"keybase.io/{}"}},
    {"Medium",      "https://medium.com/@{}/",                      "not found",            "blog", 4,{"medium.com/@{}"}},
    {"Dev.to",      "https://dev.to/{}/",                           "not found",            "blog", 3,{"dev.to/{}"}},
    {"Substack",    "https://{}.substack.com/",                     "not found",            "blog", 3,{"substack.com"}},
    {"Spotify",     "https://open.spotify.com/user/{}/",            "not found",            "music",3,{"spotify.com"}},
    {"SoundCloud",  "https://soundcloud.com/{}/",                   "not found",            "music",4,{"soundcloud.com/{}"}},
    {"Last.fm",     "https://www.last.fm/user/{}/",                 "not found",            "music",3,{"last.fm/user/{}"}},
    {"LinkedIn",    "https://www.linkedin.com/in/{}/",              "not found",            "other",5,{"linkedin.com/in/{}"}},
    {"Gravatar",    "https://en.gravatar.com/{}/",                  "not found",            "other",2,{"gravatar.com"}},
    {"Letterboxd",  "https://letterboxd.com/{}/",                   "not found",            "other",3,{"letterboxd.com/{}"}},
    {"Strava",      "https://www.strava.com/athletes/{}/",          "not found",            "other",3,{"strava.com"}},
    {"Dribbble",    "https://dribbble.com/{}/",                     "not found",            "other",3,{"dribbble.com/{}"}},
    {"Linktree",    "https://linktr.ee/{}/",                        "sorry",                "other",3,{"linktr.ee/{}"}},
    {"Patreon",     "https://www.patreon.com/{}/",                  "not found",            "other",3,{"patreon.com/{}"}},
};

static const std::set<std::string> DISPOSABLE_DOMAINS = {
    "mailinator.com","guerrillamail.com","temp-mail.org","throwam.com","yopmail.com",
    "sharklasers.com","guerrillamail.info","guerrillamail.biz","guerrillamail.de",
    "guerrillamail.net","guerrillamail.org","spam4.me","trashmail.com","trashmail.me",
    "trashmail.net","dispostable.com","mailnull.com","mytemp.email","tempmail.com",
    "fakeinbox.com","maildrop.cc","discard.email","10minutemail.com","getnada.com",
    "mailnesia.com","mintemail.com","tempr.email","33mail.com","spamgourmet.com",
};

static const std::map<std::string,std::string> RU_OPERATORS = {
    {"900","MTS"},{"901","MTS"},{"902","MTS"},{"903","MTS"},{"904","MTS"},{"905","MTS"},
    {"906","MTS"},{"908","MTS"},{"909","MTS"},{"910","MegaFon"},{"911","MegaFon"},
    {"912","MegaFon"},{"913","MegaFon"},{"914","MegaFon"},{"915","MTS"},{"916","MTS"},
    {"917","MTS"},{"918","MTS"},{"919","MTS"},{"920","Beeline"},{"921","Beeline"},
    {"922","Beeline"},{"923","Beeline"},{"924","Beeline"},{"925","MTS"},{"926","MTS"},
    {"927","MTS"},{"928","MTS"},{"929","MTS"},{"930","Tele2"},{"931","Tele2"},
    {"932","Tele2"},{"933","Tele2"},{"934","Tele2"},{"936","Tele2"},{"937","Tele2"},
    {"938","Tele2"},{"939","Tele2"},{"950","Beeline"},{"951","Beeline"},{"952","Beeline"},
    {"953","Beeline"},{"960","Beeline"},{"961","Beeline"},{"962","Beeline"},{"963","Beeline"},
    {"964","Beeline"},{"965","MTS"},{"966","MTS"},{"967","MTS"},{"968","MTS"},{"969","MTS"},
    {"977","Beeline"},{"978","MTS"},{"980","MTS"},{"981","MegaFon"},{"982","MegaFon"},
    {"983","MegaFon"},{"984","MegaFon"},{"985","MTS"},{"986","MTS"},{"987","MTS"},
    {"988","MTS"},{"989","MegaFon"},{"991","Tele2"},{"992","Tele2"},{"993","Tele2"},
    {"994","Tele2"},{"995","MegaFon"},{"996","MegaFon"},{"997","MegaFon"},{"999","MegaFon"},
};

struct CountryInfo {
    std::string code, country, region, lang;
    std::vector<std::string> carriers, platforms;
    std::string messenger_note;
};

static const std::vector<CountryInfo> COUNTRY_DB = {
    {"+1",   "USA/Canada",  "North America","en", {"AT&T","Verizon","T-Mobile"},           {"Twitter","Instagram","Facebook","LinkedIn","GitHub","Reddit"},  "iMessage + iCloud dominant"},
    {"+7",   "Russia/KZ",   "CIS",          "ru", {"MTS","MegaFon","Beeline","Tele2"},     {"VK","Telegram","OK.ru","Instagram","TikTok"},                   "Telegram dominant over WhatsApp"},
    {"+44",  "UK",          "Europe",       "en", {"EE","O2","Vodafone","Three"},           {"Twitter","Instagram","LinkedIn","GitHub","Reddit"},             "WhatsApp most used"},
    {"+49",  "Germany",     "Europe",       "de", {"Telekom","Vodafone","O2"},              {"Instagram","Twitter","XING","GitHub"},                         "WhatsApp dominant"},
    {"+33",  "France",      "Europe",       "fr", {"Orange","SFR","Bouygues","Free"},       {"Twitter","Instagram","LinkedIn"},                              "WhatsApp common"},
    {"+39",  "Italy",       "Europe",       "it", {"TIM","Vodafone","Wind Tre","Iliad"},    {"Instagram","Twitter","Facebook"},                              "WhatsApp very dominant"},
    {"+34",  "Spain",       "Europe",       "es", {"Movistar","Vodafone","Orange","Yoigo"}, {"Instagram","Twitter","Facebook"},                              "WhatsApp very dominant"},
    {"+380", "Ukraine",     "CIS",          "uk", {"Kyivstar","Vodafone UA","lifecell"},    {"Telegram","Instagram","VK","Twitter"},                         "Telegram dominant"},
    {"+375", "Belarus",     "CIS",          "ru", {"A1","MTS BY","life:)"},                {"Telegram","VK","Instagram"},                                   "Telegram dominant"},
    {"+372", "Estonia",     "Europe",       "et", {"Tele2","Elisa","Telia"},               {"GitHub","LinkedIn","Twitter"},                                 "WhatsApp common"},
    {"+370", "Lithuania",   "Europe",       "lt", {"Tele2","Bite","Telia"},                {"Facebook","Instagram","Twitter"},                              "Messenger popular"},
    {"+371", "Latvia",      "Europe",       "lv", {"LMT","Tele2","Bite"},                  {"Draugiem.lv","Instagram","Twitter"},                           "WhatsApp common"},
    {"+995", "Georgia",     "CIS",          "ka", {"Magti","Geocell","Beeline GE"},         {"Facebook","Instagram","Telegram"},                             "Telegram growing"},
    {"+374", "Armenia",     "CIS",          "hy", {"Beeline AM","Ucom","VivaCell"},         {"Facebook","Instagram","Telegram"},                             "Telegram dominant"},
    {"+998", "Uzbekistan",  "CIS",          "uz", {"Ucell","Beeline UZ","MTS UZ"},          {"Telegram","Instagram","VK"},                                   "Telegram dominant"},
    {"+86",  "China",       "Asia",         "zh", {"China Mobile","Unicom","Telecom"},       {"WeChat","Weibo","Bilibili","Douyin"},                          "WeChat/QQ only, VPN needed for others"},
    {"+81",  "Japan",       "Asia",         "ja", {"NTT Docomo","SoftBank","au"},            {"Twitter","Instagram","LINE","Niconico"},                       "LINE dominant"},
    {"+82",  "South Korea", "Asia",         "ko", {"SKT","KT","LG U+"},                     {"KakaoTalk","Naver","Instagram","Twitter"},                      "KakaoTalk dominant"},
    {"+91",  "India",       "Asia",         "hi", {"Jio","Airtel","Vi","BSNL"},              {"Instagram","Twitter","LinkedIn","ShareChat","WhatsApp"},        "WhatsApp #1"},
    {"+90",  "Turkey",      "Asia/EU",      "tr", {"Turkcell","Vodafone TR","Telekom"},      {"Twitter","Instagram","Facebook","YouTube"},                     "WhatsApp + Instagram"},
    {"+972", "Israel",      "Middle East",  "he", {"Partner","Cellcom","HOT Mobile"},        {"GitHub","LinkedIn","Instagram","Twitter"},                      "WhatsApp dominant"},
    {"+971", "UAE",         "Middle East",  "ar", {"Etisalat","du"},                         {"Instagram","Twitter","LinkedIn"},                              "WhatsApp dominant"},
    {"+966", "Saudi Arabia","Middle East",  "ar", {"STC","Mobily","Zain"},                   {"Instagram","Twitter","Snapchat"},                              "Snapchat popular"},
    {"+55",  "Brazil",      "S.America",    "pt", {"Claro","TIM","Vivo","Oi"},               {"Instagram","Twitter","WhatsApp","TikTok","Facebook"},           "WhatsApp #1 messenger"},
    {"+52",  "Mexico",      "N.America",    "es", {"Telcel","AT&T MX","Movistar"},           {"Instagram","Twitter","Facebook","TikTok"},                     "WhatsApp dominant"},
    {"+54",  "Argentina",   "S.America",    "es", {"Claro AR","Personal","Movistar AR"},     {"Instagram","Twitter","WhatsApp","Facebook"},                   "WhatsApp dominant"},
    {"+61",  "Australia",   "Oceania",      "en", {"Telstra","Optus","Vodafone"},            {"Instagram","Twitter","LinkedIn","Reddit","GitHub"},             "iMessage + WhatsApp"},
    {"+64",  "New Zealand", "Oceania",      "en", {"Spark","One NZ","2degrees"},             {"Instagram","Twitter","GitHub"},                               "WhatsApp growing"},
    {"+20",  "Egypt",       "Africa",       "ar", {"Vodafone EG","Orange EG","Etisalat EG"}, {"Facebook","Instagram","Twitter"},                             "WhatsApp dominant"},
    {"+27",  "S.Africa",    "Africa",       "en", {"Vodacom","MTN","Cell C"},                {"WhatsApp","Instagram","Twitter","Facebook"},                   "WhatsApp #1"},
    {"+234", "Nigeria",     "Africa",       "en", {"MTN NG","Airtel NG","Glo"},              {"WhatsApp","Instagram","Twitter","Facebook"},                   "WhatsApp #1"},
};

static OsintInputType detect_input_type(const std::string& input) {
    if (input.find('@') != std::string::npos) return OsintInputType::EMAIL;
    std::string norm;
    for (char c : input) if (std::isdigit(c) || c == '+') norm += c;
    if (norm.size() >= 7 && norm.size() <= 16 &&
        (input[0] == '+' || std::all_of(input.begin(), input.end(),
            [](char c){ return std::isdigit(c); })))
        return OsintInputType::PHONE;
    return OsintInputType::USERNAME;
}

static std::string fill(const std::string& tmpl, const std::string& val) {
    std::string u = tmpl;
    auto p = u.find("{}");
    if (p != std::string::npos) u.replace(p, 2, val);
    return u;
}

static std::string url_encode(const std::string& s) {
    std::string out;
    for (unsigned char c : s) {
        if (std::isalnum(c) || c=='-' || c=='_' || c=='.' || c=='~') out += c;
        else { char buf[4]; snprintf(buf, sizeof(buf), "%%%02X", c); out += buf; }
    }
    return out;
}

static std::vector<std::string> extract_links(const std::string& html, int max = 10) {
    std::vector<std::string> links;
    size_t p = 0;
    std::string marker = "href=\"";
    while ((p = html.find(marker, p)) != std::string::npos && (int)links.size() < max) {
        p += marker.size();
        auto end = html.find('"', p);
        if (end == std::string::npos) break;
        std::string u = html.substr(p, end - p);
        if (u.find("http") == 0) links.push_back(u);
        p = end;
    }
    return links;
}

static std::string conf_bar(double c) {
    int n = (int)(c * 10);
    std::string b = "[";
    for (int i = 0; i < 10; i++) b += (i < n ? "\xe2\x96\x88" : "\xe2\x96\x91");
    return b + "]";
}

static std::string certainty_str(HitConfidence c) {
    switch (c) {
        case HitConfidence::CONFIRMED: return std::string(GREEN)  + "[CONFIRMED]" + RESET;
        case HitConfidence::PROBABLE:  return std::string(YELLOW) + "[PROBABLE] " + RESET;
        default:                       return std::string(GRAY)   + "[POSSIBLE] " + RESET;
    }
}

static double bayes_score(bool ok, bool dead_absent,
                           const std::vector<std::string>& hints, int w) {
    if (!ok) return 0.0;
    double p = 0.30;
    for (size_t i = 0; i < hints.size(); i++) p = p + (1.0 - p) * 0.25;
    if (dead_absent) p = p + (1.0 - p) * 0.20;
    p = 1.0 - std::pow(1.0 - p, w);
    return std::min(p, 0.99);
}

static std::vector<std::string> gen_patterns(const std::string& u) {
    std::vector<std::string> r = {u};
    std::string base = u;
    while (!base.empty() && std::isdigit(base.back())) base.pop_back();
    if (base != u && !base.empty()) r.push_back(base);
    std::string nd = u;
    nd.erase(std::remove_if(nd.begin(), nd.end(), [](char c){ return c=='.'||c=='-'||c=='_'; }), nd.end());
    if (nd != u && !nd.empty()) r.push_back(nd);
    static const std::vector<std::string> sfx = {"1","123","x","real","pro","dev","me","gg","_","official"};
    for (auto& s : sfx) r.push_back(u + s);
    static const std::vector<std::string> pfx = {"the","its","im","real","official","i_am"};
    for (auto& p : pfx) { r.push_back(p+u); r.push_back(p+"_"+u); }
    std::sort(r.begin(), r.end());
    r.erase(std::unique(r.begin(), r.end()), r.end());
    return r;
}

static bool tool_exists(const std::string& name) {
    return !safe_exec({"which", name}, 3).empty();
}

static void ensure_tool(const std::string& name, const std::string& pip_pkg) {
    if (tool_exists(name)) return;
    std::cout << YELLOW << "  [*] installing " << name << "...\n" << RESET;
    std::string out = safe_exec({"pip3", "install", "--break-system-packages", "-q", pip_pkg}, 120);
    if (tool_exists(name))
        std::cout << GREEN << "  [+] " << name << " installed\n" << RESET;
    else
        std::cout << RED << "  [-] " << name << " install failed -- run: pip3 install " << pip_pkg << "\n" << RESET;
}

static void ensure_tools_username() {
    ensure_tool("sherlock",  "sherlock-project");
    ensure_tool("maigret",   "maigret");
}

static void ensure_tools_email() {
    ensure_tool("holehe",       "holehe");
    ensure_tool("theHarvester", "theHarvester");
}

static void ensure_tools_phone() {
    if (!tool_exists("phoneinfoga")) {
        std::cout << YELLOW << "  [*] phoneinfoga: install manually:\n" << RESET;
        std::cout << GRAY  << "    go install github.com/sundowndev/phoneinfoga/v2/cmd/phoneinfoga@latest\n" << RESET;
        std::cout << GRAY  << "    or: https://github.com/sundowndev/phoneinfoga/releases\n" << RESET;
    }
}

static ToolResult run_sherlock(const std::string& username) {
    ToolResult r; r.tool = "sherlock"; r.available = tool_exists("sherlock");
    if (!r.available) return r;
    r.installed = true;
    std::cout << GRAY << "    running sherlock...\n" << RESET;
    auto out = safe_exec({"sherlock", "--print-found", "--timeout", "10", username}, 180);
    for (auto& line : split_lines(out)) {
        if (line.find("[+]") == std::string::npos) continue;
        auto url_pos = line.find("http");
        if (url_pos == std::string::npos) continue;
        std::string url = line.substr(url_pos);
        while (!url.empty() && std::isspace(url.back())) url.pop_back();
        std::string platform;
        auto b = line.find("[+]");
        if (b != std::string::npos) {
            auto c = line.find(':', b);
            if (c != std::string::npos) platform = line.substr(b+4, c-b-4);
            while (!platform.empty() && std::isspace(platform.back())) platform.pop_back();
        }
        r.hits.push_back({platform, url, ""});
    }
    return r;
}

static ToolResult run_maigret(const std::string& username) {
    ToolResult r; r.tool = "maigret"; r.available = tool_exists("maigret");
    if (!r.available) return r;
    r.installed = true;
    std::cout << GRAY << "    running maigret...\n" << RESET;
    auto out = safe_exec({"maigret", "--no-color", "--timeout", "10", "-a", username}, 300);
    for (auto& line : split_lines(out)) {
        if (line.find("[+]") == std::string::npos) continue;
        auto url_pos = line.find("http");
        if (url_pos == std::string::npos) continue;
        std::string url = line.substr(url_pos);
        while (!url.empty() && std::isspace(url.back())) url.pop_back();
        r.hits.push_back({"", url, ""});
    }
    return r;
}

static ToolResult run_holehe(const std::string& email) {
    ToolResult r; r.tool = "holehe"; r.available = tool_exists("holehe");
    if (!r.available) return r;
    r.installed = true;
    std::cout << GRAY << "    running holehe...\n" << RESET;
    auto out = safe_exec({"holehe", "--only-used", "--no-color", email}, 300);
    for (auto& line : split_lines(out)) {
        if (line.find("[+]") == std::string::npos) continue;
        std::string platform = line;
        auto b = platform.find("[+]");
        if (b != std::string::npos) platform = platform.substr(b+4);
        while (!platform.empty() && std::isspace(platform.front())) platform.erase(platform.begin());
        while (!platform.empty() && std::isspace(platform.back())) platform.pop_back();
        if (!platform.empty()) r.hits.push_back({platform, "", ""});
    }
    return r;
}

static ToolResult run_theharvester(const std::string& domain) {
    ToolResult r; r.tool = "theHarvester"; r.available = tool_exists("theHarvester");
    if (!r.available) return r;
    r.installed = true;
    std::cout << GRAY << "    running theHarvester...\n" << RESET;
    auto out = safe_exec({"theHarvester", "-d", domain, "-b", "all", "-l", "200"}, 180);
    std::set<std::string> seen;
    for (auto& line : split_lines(out)) {
        std::string ll = line;
        std::transform(ll.begin(), ll.end(), ll.begin(), ::tolower);
        if (ll.find('@') != std::string::npos || ll.find("http") != std::string::npos) {
            std::string clean = sanitize(line);
            while (!clean.empty() && std::isspace(clean.front())) clean.erase(clean.begin());
            while (!clean.empty() && std::isspace(clean.back())) clean.pop_back();
            if (!clean.empty() && !seen.count(clean)) {
                seen.insert(clean);
                r.hits.push_back({"", "", clean});
            }
        }
    }
    return r;
}

static ToolResult run_phoneinfoga(const std::string& e164) {
    ToolResult r; r.tool = "phoneinfoga"; r.available = tool_exists("phoneinfoga");
    if (!r.available) return r;
    r.installed = true;
    std::cout << GRAY << "    running phoneinfoga...\n" << RESET;
    auto out = safe_exec({"phoneinfoga", "scan", "-n", e164}, 120);
    std::set<std::string> seen;
    for (auto& line : split_lines(out)) {
        if (line.empty() || line[0] == '=' || line[0] == '-') continue;
        std::string ll = line;
        std::transform(ll.begin(), ll.end(), ll.begin(), ::tolower);
        if (ll.find("error") != std::string::npos || ll.find("time") != std::string::npos) continue;
        std::string clean = sanitize(line);
        while (!clean.empty() && std::isspace(clean.front())) clean.erase(clean.begin());
        while (!clean.empty() && std::isspace(clean.back())) clean.pop_back();
        if (clean.size() > 5 && !seen.count(clean)) {
            seen.insert(clean);
            r.hits.push_back({"", "", clean});
        }
    }
    return r;
}

static void cross_reference(std::vector<OsintHit>& hits,
                              const std::vector<ToolResult>& tools)
{
    std::set<std::string> tool_urls;
    std::map<std::string,std::string> tool_names;
    for (auto& tr : tools) {
        for (auto& h : tr.hits) {
            if (!h.url.empty()) tool_urls.insert(h.url);
            if (!h.platform.empty()) tool_names[h.platform] = h.url;
        }
    }

    for (auto& h : hits) {
        bool by_url  = tool_urls.count(h.url) > 0;
        bool by_name = false;
        for (auto& tr : tools) {
            for (auto& th : tr.hits) {
                if (th.platform.empty()) continue;
                std::string hl = h.name, pl = th.platform;
                std::transform(hl.begin(), hl.end(), hl.begin(), ::tolower);
                std::transform(pl.begin(), pl.end(), pl.begin(), ::tolower);
                if (hl == pl || hl.find(pl) != std::string::npos || pl.find(hl) != std::string::npos)
                    by_name = true;
            }
        }
        if (by_url || by_name) {
            h.certainty = HitConfidence::CONFIRMED;
            h.conf      = std::min(h.conf + 0.25, 0.99);
        } else if (h.conf >= 0.70) {
            h.certainty = HitConfidence::PROBABLE;
        }
    }

    for (auto& tr : tools) {
        for (auto& th : tr.hits) {
            if (th.url.empty() && th.platform.empty()) continue;
            bool exists = false;
            for (auto& h : hits) {
                if ((!th.url.empty() && h.url == th.url)) { exists = true; break; }
                if (!th.platform.empty()) {
                    std::string hl = h.name, pl = th.platform;
                    std::transform(hl.begin(), hl.end(), hl.begin(), ::tolower);
                    std::transform(pl.begin(), pl.end(), pl.begin(), ::tolower);
                    if (hl.find(pl) != std::string::npos || pl.find(hl) != std::string::npos)
                        { exists = true; break; }
                }
            }
            if (!exists) {
                OsintHit h;
                h.name      = th.platform.empty() ? tr.tool : th.platform;
                h.url       = th.url;
                h.cat       = "ext";
                h.conf      = 0.85;
                h.certainty = HitConfidence::CONFIRMED;
                h.evidence  = tr.tool;
                hits.push_back(h);
            }
        }
    }
}

static void run_platform_scan(const std::string& username,
                               std::vector<OsintHit>& hits,
                               std::mutex& hits_mtx)
{
    std::atomic<int> done_c(0);
    int total = (int)SITES.size();
    std::cout << YELLOW << "  scanning " << total << " platforms" << RESET;
    std::cout.flush();

    ThreadPool pool(std::min(total, 40));
    std::vector<std::future<void>> futs;
    futs.reserve(total);

    for (auto& s : SITES) {
        futs.push_back(pool.submit([&, s] {
            std::string url  = fill(s.url, username);
            std::string body = safe_curl(url, 7);
            std::string bl   = body;
            std::transform(bl.begin(), bl.end(), bl.begin(), ::tolower);

            bool ok          = !body.empty();
            bool dead_absent = ok && bl.find(s.dead) == std::string::npos;

            std::vector<std::string> found_hints;
            std::string evidence;
            for (auto& h : s.pos) {
                std::string hl = fill(h, username);
                std::transform(hl.begin(), hl.end(), hl.begin(), ::tolower);
                if (!bl.empty() && bl.find(hl) != std::string::npos) {
                    found_hints.push_back(h);
                    if (evidence.empty()) evidence = h;
                }
            }

            double conf = bayes_score(ok, dead_absent, found_hints, s.weight);
            int cur = ++done_c;

            if (conf >= 0.45) {
                std::lock_guard<std::mutex> lk(hits_mtx);
                hits.push_back({s.name, url, s.cat, evidence, conf, HitConfidence::POSSIBLE});
                g_result.osint_hits.push_back(url);
            }
            if (cur % 10 == 0) {
                std::lock_guard<std::mutex> lk(g_print_mtx);
                std::cout << "." << std::flush;
            }
        }));
    }
    for (auto& f : futs) f.get();
    std::cout << " done\n";
}

static void print_results(const std::vector<OsintHit>& hits) {
    if (hits.empty()) {
        std::cout << GRAY << "  nothing found\n" << RESET;
        return;
    }

    auto sorted = hits;
    std::sort(sorted.begin(), sorted.end(), [](const OsintHit& a, const OsintHit& b) {
        if (a.certainty != b.certainty) return (int)a.certainty < (int)b.certainty;
        return a.conf > b.conf;
    });

    std::map<std::string, std::vector<const OsintHit*>> by_cat;
    for (auto& h : sorted) by_cat[h.cat].push_back(&h);

    static const std::vector<std::string> order = {
        "social","dev","gaming","msg","music","blog","other","ext"
    };

    for (auto& cat : order) {
        if (!by_cat.count(cat)) continue;
        std::cout << "\n" << BOLD << WHITE << "  " << cat << ":\n" << RESET;
        for (auto* h : by_cat[cat]) {
            std::cout << "  " << certainty_str(h->certainty)
                      << "  " << std::left << std::setw(16) << h->name;
            if (!h->url.empty()) std::cout << CYAN << h->url << RESET;
            if (!h->evidence.empty() && h->cat == "ext")
                std::cout << GRAY << "  [via " << h->evidence << "]" << RESET;
            std::cout << "\n";
        }
    }

    long confirmed = std::count_if(hits.begin(), hits.end(),
        [](const OsintHit& h){ return h.certainty == HitConfidence::CONFIRMED; });
    long probable  = std::count_if(hits.begin(), hits.end(),
        [](const OsintHit& h){ return h.certainty == HitConfidence::PROBABLE; });
    long possible  = std::count_if(hits.begin(), hits.end(),
        [](const OsintHit& h){ return h.certainty == HitConfidence::POSSIBLE; });

    std::cout << "\n" << CYAN << "  +" << std::string(46,'-') << "+\n" << RESET;
    std::cout << CYAN << "  | " << GREEN  << "CONFIRMED " << WHITE << confirmed
              << CYAN << "  | " << YELLOW << "PROBABLE  " << WHITE << probable
              << CYAN << "  | " << GRAY   << "POSSIBLE  " << WHITE << possible
              << CYAN << "  |\n  +" << std::string(46,'-') << "+\n" << RESET;
}

static void run_username(const std::string& username, IdentityGraph& graph) {
    print_section("TOOL SETUP");
    ensure_tools_username();

    print_section("INTERNAL SCAN");
    std::mutex hits_mtx;
    run_platform_scan(username, graph.hits, hits_mtx);
    std::cout << "\n";

    print_section("EXTERNAL TOOLS");
    auto f_sherlock = std::async(std::launch::async, run_sherlock, username);
    auto f_maigret  = std::async(std::launch::async, run_maigret,  username);
    auto sr = f_sherlock.get();
    auto mr = f_maigret.get();

    auto print_tool_stat = [](const ToolResult& t) {
        if (t.installed)
            std::cout << GREEN << "  [+] " << RESET << std::left << std::setw(16) << t.tool
                      << "found " << t.hits.size() << " hits\n";
        else
            std::cout << YELLOW << "  [-] " << std::left << std::setw(16) << t.tool
                      << "not installed\n" << RESET;
    };
    print_tool_stat(sr);
    print_tool_stat(mr);

    std::vector<ToolResult> tools = {sr, mr};

    print_section("CROSS-REFERENCE & VERIFICATION");
    cross_reference(graph.hits, tools);

    print_section("RESULTS");
    print_results(graph.hits);

    print_section("USERNAME VARIANTS");
    auto patterns = gen_patterns(username);
    std::cout << YELLOW << "  " << patterns.size() << " variants to check:\n" << RESET;
    for (size_t i = 0; i < std::min(patterns.size(), (size_t)10); i++)
        std::cout << GRAY << "    " << patterns[i] << "\n" << RESET;
    if (patterns.size() > 10)
        std::cout << GRAY << "    ... +" << patterns.size()-10 << " more\n" << RESET;

    print_section("EMAIL HYPOTHESES");
    static const std::vector<std::string> doms = {
        "gmail.com","yahoo.com","outlook.com","protonmail.com","icloud.com","mail.ru","yandex.ru"
    };
    for (auto& d : doms) {
        std::string addr = username + "@" + d;
        graph.email_candidates.push_back(addr);
        std::cout << CYAN << "  -> " << RESET << addr << "\n";
    }

    print_section("WEB MENTIONS");
    auto ddg = safe_curl("https://html.duckduckgo.com/html/?q=%22" + url_encode(username) + "%22", 10);
    if (!ddg.empty()) {
        int shown = 0;
        for (auto& l : extract_links(ddg, 8))
            if (l.find("duckduckgo") == std::string::npos)
                { std::cout << CYAN << "  " << sanitize(l) << RESET << "\n"; shown++; }
        if (!shown) std::cout << GRAY << "  no public mentions\n" << RESET;
    }

    for (auto& h : graph.hits) graph.category_counts[h.cat]++;
    LOG_INFO("osint_username", "done user="+username+" hits="+std::to_string(graph.hits.size()));
}

static void run_email(const std::string& email, IdentityGraph& graph) {
    static const std::regex email_re(R"(^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$)");
    if (!std::regex_match(email, email_re)) {
        std::cout << RED << "  [!] invalid email\n" << RESET; return;
    }

    auto at            = email.find('@');
    std::string local  = email.substr(0, at);
    std::string domain = email.substr(at + 1);
    bool        disp   = DISPOSABLE_DOMAINS.count(domain) > 0;

    static const std::map<std::string,std::string> dom_types = {
        {"gmail.com","personal (Google)"},{"yahoo.com","personal (Yahoo)"},
        {"outlook.com","personal (Microsoft)"},{"hotmail.com","personal legacy (Microsoft)"},
        {"protonmail.com","privacy-focused"},{"tutanota.com","privacy-focused"},
        {"icloud.com","Apple ecosystem"},{"yandex.ru","Russian ecosystem (Yandex)"},
        {"mail.ru","Russian ecosystem (Mail.ru)"},{"rambler.ru","Russian ecosystem (Rambler)"},
        {"gmx.com","European personal"},{"zoho.com","business"},
    };

    print_section("TOOL SETUP");
    ensure_tools_email();

    print_section("EMAIL PROFILE");
    std::cout << GREEN << "  " << email << "\n\n" << RESET;
    std::cout << CYAN << "  [local]      " << RESET << local  << "\n";
    std::cout << CYAN << "  [domain]     " << RESET << domain << "\n";
    auto dt = dom_types.find(domain);
    if (dt != dom_types.end())
        std::cout << CYAN << "  [type]       " << RESET << dt->second << "\n";
    else if (disp)
        std::cout << CYAN << "  [type]       " << RED << "DISPOSABLE/BURNER\n" << RESET;
    else
        std::cout << CYAN << "  [type]       " << RESET << "corporate/custom domain\n";
    std::cout << CYAN << "  [disposable] " << RESET
              << (disp ? std::string(RED)+"YES -- temp/spam domain"+RESET
                       : std::string(GREEN)+"no"+RESET) << "\n";

    print_section("DOMAIN REPUTATION");
    auto fut_mx    = std::async(std::launch::async, [&]{ return safe_exec({"dig","+short","MX", domain},6); });
    auto fut_spf   = std::async(std::launch::async, [&]{ return safe_exec({"dig","+short","TXT",domain},6); });
    auto fut_dmarc = std::async(std::launch::async, [&]{ return safe_exec({"dig","+short","TXT","_dmarc."+domain},6); });
    auto fut_a     = std::async(std::launch::async, [&]{ return safe_exec({"dig","+short","A",  domain},6); });

    auto mx    = fut_mx.get();
    auto spf   = fut_spf.get();
    auto dmarc = fut_dmarc.get();
    auto a_rec = fut_a.get();

    if (!mx.empty()) {
        std::cout << GREEN << "  [MX]     " << RESET;
        for (auto& l : split_lines(mx)) std::cout << sanitize(l) << "  ";
        std::cout << "\n";
    } else {
        std::cout << RED << "  [MX]     no records -- domain may not accept email\n" << RESET;
    }

    bool spf_found = false;
    for (auto& l : split_lines(spf))
        if (l.find("v=spf1") != std::string::npos)
            { std::cout << GREEN << "  [SPF]    " << RESET << sanitize(l) << "\n"; spf_found = true; }
    if (!spf_found) std::cout << YELLOW << "  [SPF]    not found\n" << RESET;

    if (!dmarc.empty()) std::cout << GREEN << "  [DMARC]  " << RESET << sanitize(dmarc) << "\n";
    else                std::cout << YELLOW << "  [DMARC]  not found\n" << RESET;

    if (!a_rec.empty()) std::cout << CYAN << "  [A]      " << RESET << sanitize(a_rec) << "\n";

    print_section("BREACH INTELLIGENCE");
    double breach_risk = 0.0;
    std::vector<std::string> risk_factors;
    if (disp)                { breach_risk += 0.35; risk_factors.push_back("disposable domain"); }
    if (domain=="gmail.com") { breach_risk += 0.15; risk_factors.push_back("very common domain, high breach DB presence"); }
    if (domain=="yahoo.com") { breach_risk += 0.20; risk_factors.push_back("Yahoo 2013 breach (3B accounts)"); }
    if (domain=="hotmail.com"||domain=="outlook.com") { breach_risk += 0.10; risk_factors.push_back("Microsoft ecosystem breach history"); }
    if (local.size() < 5)   { breach_risk += 0.10; risk_factors.push_back("short local part -- common in old accounts"); }
    if (std::any_of(local.begin(),local.end(),[](char c){ return std::isdigit(c); }))
                             { breach_risk += 0.05; risk_factors.push_back("digits in local -- typical in mass registrations"); }
    breach_risk = std::min(breach_risk, 0.95);

    std::cout << CYAN << "  [breach_risk]  " << RESET
              << std::fixed << std::setprecision(0) << (breach_risk*100) << "%  "
              << conf_bar(breach_risk) << "\n";
    for (auto& f : risk_factors) std::cout << YELLOW << "  [!] " << RESET << f << "\n";

    auto hibp = safe_curl("https://haveibeenpwned.com/api/v3/breachedaccount/" +
                           url_encode(local) + "%40" + url_encode(domain), 12);
    if (!hibp.empty() && hibp.find("Name") != std::string::npos) {
        std::cout << RED << "\n  [!!!] FOUND IN BREACH DATABASES:\n" << RESET;
        size_t p = 0; std::string mk = "\"Name\":\""; int cnt = 0;
        while ((p = hibp.find(mk, p)) != std::string::npos && cnt < 30) {
            p += mk.size(); auto end = hibp.find('"', p);
            if (end == std::string::npos) break;
            std::cout << RED << "    [breach] " << RESET << hibp.substr(p,end-p) << "\n";
            p = end; cnt++;
        }
    } else {
        std::cout << GREEN << "  [ok] HIBP: not found (or API key required)\n" << RESET;
    }

    print_section("GRAVATAR / PROFILE DATA");
    auto grav = safe_curl("https://en.gravatar.com/" + url_encode(local) + ".json", 8);
    if (!grav.empty() && grav.find("entry") != std::string::npos) {
        std::cout << GREEN << "  [+] Gravatar profile found:\n" << RESET;
        for (auto& k : {"displayName","aboutMe","currentLocation","profileUrl","phoneNumbers"}) {
            auto v = json_val(grav, k);
            if (!v.empty())
                std::cout << CYAN << "  [" << std::left << std::setw(16) << k << "] "
                          << RESET << sanitize(v) << "\n";
        }
    } else {
        std::cout << GRAY << "  no Gravatar profile\n" << RESET;
    }

    print_section("EXTERNAL TOOLS");
    auto f_holehe    = std::async(std::launch::async, run_holehe,       email);
    auto f_harvester = std::async(std::launch::async, run_theharvester, domain);
    auto hr = f_holehe.get();
    auto tr = f_harvester.get();

    if (hr.installed)  std::cout << GREEN << "  [+] " << RESET << std::left << std::setw(16) << "holehe"       << "found " << hr.hits.size() << " services\n";
    else               std::cout << YELLOW<< "  [-] " << std::left << std::setw(16) << "holehe"       << "not installed\n" << RESET;
    if (tr.installed)  std::cout << GREEN << "  [+] " << RESET << std::left << std::setw(16) << "theHarvester" << "found " << tr.hits.size() << " items\n";
    else               std::cout << YELLOW<< "  [-] " << std::left << std::setw(16) << "theHarvester" << "not installed\n" << RESET;

    if (hr.installed && !hr.hits.empty()) {
        std::cout << "\n" << BOLD << WHITE << "  holehe -- registered services:\n" << RESET;
        for (auto& h : hr.hits)
            std::cout << GREEN << "  [+] " << RESET << h.platform << "\n";
    }

    if (tr.installed && !tr.hits.empty()) {
        std::cout << "\n" << BOLD << WHITE << "  theHarvester -- domain intel:\n" << RESET;
        for (size_t i = 0; i < std::min(tr.hits.size(), (size_t)20); i++)
            std::cout << CYAN << "  " << tr.hits[i].info << RESET << "\n";
        if (tr.hits.size() > 20)
            std::cout << GRAY << "  ... +" << tr.hits.size()-20 << " more\n" << RESET;
    }

    print_section("USERNAME CANDIDATES");
    std::vector<std::string> candidates = {local};
    std::string base = local;
    while (!base.empty() && std::isdigit(base.back())) base.pop_back();
    if (base!=local && !base.empty()) candidates.push_back(base);
    std::string nd = local;
    nd.erase(std::remove_if(nd.begin(),nd.end(),[](char c){ return c=='.'||c=='-'; }), nd.end());
    if (nd != local) candidates.push_back(nd);
    auto dot = local.find('.');
    if (dot != std::string::npos) {
        candidates.push_back(local.substr(0, dot));
        candidates.push_back(local.substr(dot+1));
        candidates.push_back(local.substr(0,1) + local.substr(dot+1));
        std::string us = local; std::replace(us.begin(),us.end(),'.','_');
        candidates.push_back(us);
    }
    std::sort(candidates.begin(),candidates.end());
    candidates.erase(std::unique(candidates.begin(),candidates.end()),candidates.end());
    for (auto& c : candidates) std::cout << CYAN << "  -> " << RESET << c << "\n";
    graph.username_candidates = candidates;

    print_section("PLATFORM SCAN (primary username)");
    std::mutex hm;
    run_platform_scan(local, graph.hits, hm);

    std::vector<ToolResult> tools = {hr, tr};
    cross_reference(graph.hits, tools);

    print_section("RESULTS");
    print_results(graph.hits);

    print_section("WEB MENTIONS");
    auto ddg = safe_curl("https://html.duckduckgo.com/html/?q=%22" +
                          url_encode(local) + "%40" + url_encode(domain) + "%22", 10);
    if (!ddg.empty()) {
        int shown = 0;
        for (auto& l : extract_links(ddg, 8))
            if (l.find("duckduckgo")==std::string::npos)
                { std::cout << CYAN << "  " << sanitize(l) << RESET << "\n"; shown++; }
        if (!shown) std::cout << GRAY << "  no public mentions\n" << RESET;
    }
    LOG_INFO("osint_email","done email="+email+" hits="+std::to_string(graph.hits.size()));
}

static void run_phone(const std::string& phone_raw, IdentityGraph& graph) {
    std::string phone;
    for (char c : phone_raw) if (std::isdigit(c) || c=='+') phone += c;
    if (phone.size() < 7 || phone.size() > 16) {
        std::cout << RED << "  [!] invalid phone\n" << RESET; return;
    }
    std::string e164 = (phone[0] != '+') ? "+" + phone : phone;

    std::string raw_digits;
    for (char c : phone) if (std::isdigit(c)) raw_digits += c;

    print_section("TOOL SETUP");
    ensure_tools_phone();

    print_section("PHONE PROFILE");
    std::cout << GREEN << "  " << e164 << "\n\n" << RESET;

    const CountryInfo* cc = nullptr;
    for (auto& c : COUNTRY_DB) if (e164.find(c.code)==0) { cc=&c; break; }

    if (cc) {
        std::cout << CYAN << "  [country]    " << RESET << cc->country << "\n";
        std::cout << CYAN << "  [region]     " << RESET << cc->region  << "\n";
        std::cout << CYAN << "  [language]   " << RESET << cc->lang    << "\n";
        std::cout << CYAN << "  [code]       " << RESET << cc->code    << "\n";

        std::cout << CYAN << "  [carriers]   " << RESET;
        for (size_t i = 0; i < cc->carriers.size(); i++) {
            std::cout << cc->carriers[i];
            if (i+1 < cc->carriers.size()) std::cout << ", ";
        }
        std::cout << "\n";

        if (cc->code == "+7") {
            std::string ln = e164.substr(1);
            if (ln.size() == 11) {
                auto it = RU_OPERATORS.find(ln.substr(1,3));
                if (it != RU_OPERATORS.end())
                    std::cout << GREEN << "  [operator]   " << RESET << it->second
                              << GRAY << " (prefix " << ln.substr(1,3) << ")\n" << RESET;
                else
                    std::cout << YELLOW << "  [operator]   unknown prefix " << ln.substr(1,3) << "\n" << RESET;

                std::string region_prefix = ln.substr(1,3);
                static const std::map<std::string,std::string> ru_regions = {
                    {"495","Moscow"},{"499","Moscow"},{"812","Saint Petersburg"},
                    {"343","Yekaterinburg"},{"383","Novosibirsk"},{"846","Samara"},
                    {"831","Nizhny Novgorod"},{"863","Rostov-on-Don"},{"347","Ufa"},
                    {"843","Kazan"},{"351","Chelyabinsk"},{"391","Krasnoyarsk"},
                };
                auto ri = ru_regions.find(region_prefix);
                if (ri != ru_regions.end())
                    std::cout << CYAN << "  [city_hint]  " << RESET << ri->second << "\n";
            }
        }
    } else {
        std::cout << RED << "  [country]    unknown code\n" << RESET;
    }

    print_section("LINE TYPE & CARRIER LOOKUP");
    auto nl = safe_curl("https://api.numlookupapi.com/v1/info/" + url_encode(e164), 8);
    if (!nl.empty() && nl != "{}" && nl.find("error") == std::string::npos) {
        for (auto& k : {"valid","country_code","location","carrier","line_type","number_type"}) {
            auto v = json_val(nl, k);
            if (!v.empty() && v != "null")
                std::cout << CYAN << "  [" << std::left << std::setw(14) << k << "] "
                          << RESET << sanitize(v) << "\n";
        }
    } else {
        std::cout << GRAY << "  NumLookup API: no key or unavailable\n" << RESET;

        auto tw = safe_curl("https://www.twilio.com/lookup/v1/PhoneNumbers/" + url_encode(e164) +
                             "?Type=carrier&Type=caller-name", 8);
        if (!tw.empty() && tw.find("carrier") != std::string::npos) {
            auto carrier = json_val(tw, "name");
            auto type    = json_val(tw, "type");
            if (!carrier.empty()) std::cout << CYAN << "  [carrier]   " << RESET << sanitize(carrier) << "\n";
            if (!type.empty())    std::cout << CYAN << "  [line_type] " << RESET << sanitize(type) << "\n";
        }
    }

    print_section("BEHAVIORAL PROFILE");
    if (cc) {
        std::cout << CYAN << "  [messenger_note] " << RESET << cc->messenger_note << "\n\n";
        std::cout << YELLOW << "  dominant platforms in " << cc->country << ":\n" << RESET;
        for (auto& p : cc->platforms)
            std::cout << CYAN << "    -> " << RESET << p << "\n";
    }

    print_section("MESSAGING PLATFORM CHECK");
    auto tg = safe_curl("https://t.me/" + e164, 8);
    if (!tg.empty() && tg.find("tgme_page") != std::string::npos &&
        tg.find("not found") == std::string::npos)
        std::cout << GREEN << "  [CONFIRMED] Telegram: t.me/" << e164 << "\n" << RESET;
    else
        std::cout << GRAY << "  [-] Telegram: no direct hit\n" << RESET;

    std::cout << GRAY << "  [-] WhatsApp  -- no public API\n" << RESET;
    std::cout << GRAY << "  [-] Signal    -- no public API\n" << RESET;
    std::cout << GRAY << "  [-] Viber     -- no public API\n" << RESET;

    print_section("EXTERNAL TOOLS");
    ToolResult pif = run_phoneinfoga(e164);
    if (pif.installed) {
        std::cout << GREEN << "  [+] " << RESET << "phoneinfoga: found " << pif.hits.size() << " results\n";
        if (!pif.hits.empty()) {
            std::cout << "\n" << BOLD << WHITE << "  phoneinfoga output:\n" << RESET;
            for (auto& h : pif.hits)
                if (!h.info.empty())
                    std::cout << CYAN << "  " << h.info << RESET << "\n";
        }
    } else {
        std::cout << YELLOW << "  [-] phoneinfoga: not installed\n"
                  << GRAY   << "      install: go install github.com/sundowndev/phoneinfoga/v2/cmd/phoneinfoga@latest\n"
                  << RESET;
    }

    print_section("FRAUD & SPAM HEURISTICS");
    double fraud = 0.0;
    std::vector<std::string> flags;
    if (!cc) { fraud += 0.4; flags.push_back("unknown country code"); }

    std::string tail4 = raw_digits.size()>=4 ? raw_digits.substr(raw_digits.size()-4) : "";
    static const std::set<std::string> sus_tails = {"0000","1111","2222","3333","4444","5555",
                                                     "6666","7777","8888","9999","1234","4321"};
    if (sus_tails.count(tail4)) { fraud += 0.2; flags.push_back("suspicious tail: "+tail4); }

    if (raw_digits.size()>4 &&
        std::all_of(raw_digits.begin(),raw_digits.end(),[&](char c){ return c==raw_digits[0]; }))
        { fraud += 0.5; flags.push_back("all identical digits -- likely fake"); }

    if (cc && cc->code=="+7" && raw_digits.size()==11) {
        std::string pfx = raw_digits.substr(1,3);
        bool known_op = RU_OPERATORS.count(pfx) > 0;
        if (!known_op) { fraud += 0.15; flags.push_back("unknown RU operator prefix: "+pfx); }
    }

    fraud = std::min(fraud, 0.95);
    std::cout << CYAN << "  [fraud_score] " << RESET
              << std::fixed << std::setprecision(0) << (fraud*100) << "%  " << conf_bar(fraud) << "\n";
    for (auto& f : flags) std::cout << YELLOW << "  [!] " << RESET << f << "\n";
    if (flags.empty()) std::cout << GREEN << "  [ok] no suspicious patterns detected\n" << RESET;

    print_section("PHONE FORMATS (for manual search)");
    std::vector<std::string> fmts = {e164, raw_digits};
    if (cc && cc->code=="+7" && raw_digits.size()==11) {
        fmts.push_back("8" + raw_digits.substr(1));
        fmts.push_back("(" + raw_digits.substr(1,3) + ") " +
                        raw_digits.substr(4,3) + "-" +
                        raw_digits.substr(7,2) + "-" + raw_digits.substr(9));
        fmts.push_back("+7 (" + raw_digits.substr(1,3) + ") " +
                        raw_digits.substr(4,3) + "-" +
                        raw_digits.substr(7,2) + "-" + raw_digits.substr(9));
    }
    for (auto& f : fmts) std::cout << GRAY << "  " << f << "\n" << RESET;
    graph.phone_candidates = fmts;

    print_section("WEB MENTIONS");
    auto ddg = safe_curl("https://html.duckduckgo.com/html/?q=%22" + url_encode(raw_digits) + "%22", 10);
    if (!ddg.empty()) {
        int shown = 0;
        for (auto& l : extract_links(ddg, 8))
            if (l.find("duckduckgo")==std::string::npos)
                { std::cout << CYAN << "  " << sanitize(l) << RESET << "\n"; shown++; }
        if (!shown) std::cout << GRAY << "  no public mentions\n" << RESET;
    }
    LOG_INFO("osint_phone","done phone="+phone);
}

void osint_scan(const std::string& input) {
    OsintInputType type = detect_input_type(input);
    std::string type_str;
    switch (type) {
        case OsintInputType::USERNAME: type_str = "USERNAME"; break;
        case OsintInputType::EMAIL:    type_str = "EMAIL";    break;
        case OsintInputType::PHONE:    type_str = "PHONE";    break;
        default:                       type_str = "UNKNOWN";  break;
    }

    print_header("OSINT // " + type_str + " // " + input);
    std::cout << CYAN << "  [auto-detected] " << RESET << type_str << "\n";

    IdentityGraph graph;
    graph.seed      = input;
    graph.seed_type = type;

    switch (type) {
        case OsintInputType::USERNAME: run_username(input, graph); break;
        case OsintInputType::EMAIL:    run_email(input, graph);    break;
        case OsintInputType::PHONE:    run_phone(input, graph);    break;
        default:
            std::cout << RED << "  [!] cannot determine input type\n" << RESET; return;
    }

    if (!graph.hits.empty() || !graph.username_candidates.empty()) {
        print_section("IDENTITY GRAPH SUMMARY");
        std::cout << CYAN << "  [seed]    " << RESET << input << GRAY << "  [" << type_str << "]\n" << RESET;
        if (!graph.username_candidates.empty()) {
            std::cout << CYAN << "  [usernames] " << RESET;
            for (auto& u : graph.username_candidates) std::cout << u << "  ";
            std::cout << "\n";
        }
        if (!graph.email_candidates.empty()) {
            std::cout << CYAN << "  [emails]    " << RESET;
            for (size_t i = 0; i < std::min(graph.email_candidates.size(),(size_t)4); i++)
                std::cout << graph.email_candidates[i] << "  ";
            std::cout << "\n";
        }
        if (!graph.phone_candidates.empty()) {
            std::cout << CYAN << "  [phones]    " << RESET;
            for (auto& p : graph.phone_candidates) std::cout << p << "  ";
            std::cout << "\n";
        }
    }

    LOG_INFO("osint","done input="+input+" type="+type_str+" hits="+std::to_string(graph.hits.size()));
}
