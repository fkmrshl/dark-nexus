#include "../include/dark_nexus.hpp"
#include "../include/security.hpp"

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

struct CorrelatedProfile {
    std::vector<std::string> names;
    std::vector<std::string> phones;
    std::vector<std::string> emails;
    std::vector<std::string> locations;
    std::vector<std::string> accounts;
    std::map<std::string,std::string> raw;
    void add(const std::string& key, const std::string& val) {
        if (val.empty() || val == "null") return;
        raw[key] = val;
        std::string kl = key;
        std::transform(kl.begin(), kl.end(), kl.begin(), ::tolower);
        if (kl.find("name") != std::string::npos)
        { if(std::find(names.begin(),names.end(),val)==names.end()) names.push_back(val); }
        else if (kl.find("phone") != std::string::npos || kl.find("tel") != std::string::npos)
        { if(std::find(phones.begin(),phones.end(),val)==phones.end()) phones.push_back(val); }
        else if (kl.find("email") != std::string::npos || kl.find("mail") != std::string::npos)
        { if(std::find(emails.begin(),emails.end(),val)==emails.end()) emails.push_back(val); }
        else if (kl.find("city") != std::string::npos || kl.find("location") != std::string::npos ||
            kl.find("region") != std::string::npos || kl.find("country") != std::string::npos)
        { if(std::find(locations.begin(),locations.end(),val)==locations.end()) locations.push_back(val); }
        else if (kl.find("url") != std::string::npos || kl.find("account") != std::string::npos ||
            kl.find("profile") != std::string::npos)
        { if(std::find(accounts.begin(),accounts.end(),val)==accounts.end()) accounts.push_back(val); }
    }
};

struct IdentityGraph {
    std::string              seed;
    OsintInputType           seed_type;
    std::vector<std::string> username_candidates;
    std::vector<std::string> email_candidates;
    std::vector<std::string> phone_candidates;
    std::vector<OsintHit>    hits;
    std::map<std::string,int> category_counts;
    CorrelatedProfile        profile;
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

struct RuOperatorInfo {
    std::string op;
    std::string region;
};

static const std::map<std::string, RuOperatorInfo> RU_OPERATORS = {
    {"900",{"MTS","Russia"}},{"901",{"MTS","Russia"}},{"902",{"MTS","Russia"}},
    {"903",{"MTS","Russia"}},{"904",{"MTS","Russia"}},{"905",{"MTS","Russia"}},
    {"906",{"MTS","Russia"}},{"908",{"MTS","Russia"}},{"909",{"MTS","Russia"}},
    {"910",{"MegaFon","Central Russia"}},{"911",{"MegaFon","North-West"}},
    {"912",{"MegaFon","Ural"}},{"913",{"MegaFon","Siberia"}},
    {"914",{"MegaFon","Far East"}},{"915",{"MTS","Central Russia"}},
    {"916",{"MTS","Moscow"}},{"917",{"MTS","Volga"}},
    {"918",{"MTS","South Russia"}},{"919",{"MTS","North-West"}},
    {"920",{"Beeline","Volga"}},{"921",{"Beeline","North-West"}},
    {"922",{"Beeline","Ural"}},{"923",{"Beeline","Siberia"}},
    {"924",{"Beeline","Far East"}},{"925",{"MTS","Moscow"}},
    {"926",{"MTS","Moscow"}},{"927",{"MTS","Volga"}},
    {"928",{"MTS","South Russia"}},{"929",{"MTS","Central Russia"}},
    {"930",{"Tele2","Russia"}},{"931",{"Tele2","North-West"}},
    {"932",{"Tele2","Ural"}},{"933",{"Tele2","Siberia"}},
    {"934",{"Tele2","Far East"}},{"936",{"Tele2","Central Russia"}},
    {"937",{"Tele2","Volga"}},{"938",{"Tele2","South Russia"}},
    {"939",{"Tele2","Russia"}},
    {"941",{"Tele2","Russia"}},
    {"950",{"Beeline","Russia"}},{"951",{"Beeline","Russia"}},
    {"952",{"Beeline","Russia"}},{"953",{"Beeline","Russia"}},
    {"958",{"Rostelecom","Russia"}},{"959",{"Rostelecom","Russia"}},
    {"960",{"Beeline","Russia"}},{"961",{"Beeline","Russia"}},
    {"962",{"Beeline","Russia"}},{"963",{"Beeline","Russia"}},
    {"964",{"Beeline","Russia"}},{"965",{"MTS","Russia"}},
    {"966",{"MTS","Russia"}},{"967",{"MTS","Russia"}},
    {"968",{"MTS","Russia"}},{"969",{"MTS","Russia"}},
    {"970",{"Tele2","Crimea"}},{"971",{"Tele2","Crimea"}},
    {"977",{"Beeline","Moscow"}},{"978",{"MTS","Crimea"}},
    {"979",{"MTS","Crimea"}},
    {"980",{"MTS","Russia"}},{"981",{"MegaFon","North-West"}},
    {"982",{"MegaFon","Ural"}},{"983",{"MegaFon","Siberia"}},
    {"984",{"MegaFon","Far East"}},{"985",{"MTS","Moscow"}},
    {"986",{"MTS","Russia"}},{"987",{"MTS","Russia"}},
    {"988",{"MTS","South Russia"}},{"989",{"MegaFon","South Russia"}},
    {"991",{"Tele2","Russia"}},{"992",{"Tele2","Russia"}},
    {"993",{"Tele2","Russia"}},{"994",{"Tele2","Russia"}},
    {"995",{"MegaFon","Russia"}},{"996",{"MegaFon","Russia"}},
    {"997",{"MegaFon","Russia"}},{"999",{"MegaFon","Moscow"}},
};

static const std::map<std::string,std::string> RU_CITY_CODES = {
    {"495","Moscow"},{"499","Moscow"},{"812","Saint Petersburg"},
    {"343","Yekaterinburg"},{"383","Novosibirsk"},{"846","Samara"},
    {"831","Nizhny Novgorod"},{"863","Rostov-on-Don"},{"347","Ufa"},
    {"843","Kazan"},{"351","Chelyabinsk"},{"391","Krasnoyarsk"},
    {"423","Vladivostok"},{"342","Perm"},{"861","Krasnodar"},
    {"473","Voronezh"},{"8152","Murmansk"},{"4722","Belgorod"},
    {"482","Tver"},{"8442","Volgograd"},{"8332","Kirov"},
    {"3952","Irkutsk"},{"8552","Naberezhnye Chelny"},{"8202","Vologda"},
    {"4112","Yakutsk"},{"3412","Izhevsk"},{"862","Sochi"},
    {"8452","Saratov"},{"3532","Orenburg"},{"4212","Khabarovsk"},
    {"3812","Omsk"},{"3852","Barnaul"},{"4922","Vladimir"},
    {"8313","Nizhny Novgorod"},{"3842","Kemerovo"},
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
    std::string b = std::string(BLOOD_RED) + "[";
    for (int i = 0; i < 10; i++) b += (i < n ? std::string(WHITE) + "\xe2\x96\x88" : std::string(BLOOD_RED) + "\xe2\x96\x91");
    return b + std::string(BLOOD_RED) + "]";
}

static std::string certainty_str(HitConfidence c) {
    switch (c) {
        case HitConfidence::CONFIRMED: return std::string(BLOOD_RED) + "[" + std::string(WHITE) + "CONFIRMED" + std::string(BLOOD_RED) + "]" + std::string(RESET);
        case HitConfidence::PROBABLE:  return std::string(BLOOD_RED) + "[" + std::string(WHITE) + "PROBABLE" + std::string(BLOOD_RED) + "] " + std::string(RESET);
        default:                       return std::string(BLOOD_RED) + "[" + std::string(WHITE) + "POSSIBLE" + std::string(BLOOD_RED) + "] " + std::string(RESET);
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
                              std::cout << BLOOD_RED << "  [*] installing " << WHITE << name << BLOOD_RED << "...\n" << RESET;
                              std::string out = safe_exec({"pip3", "install", "--break-system-packages", "-q", pip_pkg}, 120);
                              if (tool_exists(name))
                                  std::cout << BLOOD_RED << "  [+] " << WHITE << name << BLOOD_RED << " installed\n" << RESET;
                              else
                                  std::cout << BLOOD_RED << "  [-] " << WHITE << name << BLOOD_RED << " install failed -- run: pip3 install " << WHITE << pip_pkg << "\n" << RESET;
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
                                  std::cout << BLOOD_RED << "  [*] phoneinfoga: install manually:\n" << RESET;
                                  std::cout << WHITE << "    go install github.com/sundowndev/phoneinfoga/v2/cmd/phoneinfoga@latest\n" << RESET;
                                  std::cout << WHITE << "    or: https://github.com/sundowndev/phoneinfoga/releases\n" << RESET;
                              }
                          }

                          static ToolResult run_sherlock(const std::string& username) {
                              ToolResult r; r.tool = "sherlock"; r.available = tool_exists("sherlock");
                              if (!r.available) return r;
                              r.installed = true;
                              std::cout << BLOOD_RED << "    running " << WHITE << "sherlock" << BLOOD_RED << "...\n" << RESET;
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
                              std::cout << BLOOD_RED << "    running " << WHITE << "maigret" << BLOOD_RED << "...\n" << RESET;
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
                              std::cout << BLOOD_RED << "    running " << WHITE << "holehe" << BLOOD_RED << "...\n" << RESET;
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
                              std::cout << BLOOD_RED << "    running " << WHITE << "theHarvester" << BLOOD_RED << "...\n" << RESET;
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
                              std::cout << BLOOD_RED << "    running " << WHITE << "phoneinfoga" << BLOOD_RED << "...\n" << RESET;
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

                              {
                                  std::lock_guard<std::mutex> rlk(g_result_mtx);
                                  for (auto& o : g_result.osint) {
                                      for (auto& h : hits) {
                                          if (o.url == h.url) {
                                              o.certainty = (h.certainty == HitConfidence::CONFIRMED) ? "CONFIRMED" :
                                                            (h.certainty == HitConfidence::PROBABLE) ? "PROBABLE" : "POSSIBLE";
                                              break;
                                          }
                                      }
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
                                          OsintEntry oe;
                                          oe.platform = h.name;
                                          oe.url = h.url;
                                          oe.category = h.cat;
                                          oe.certainty = "CONFIRMED";
                                          std::lock_guard<std::mutex> rlk(g_result_mtx);
                                          g_result.osint.push_back(oe);
                                          g_result.osint_hits.push_back(h.url);
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
                              std::cout << BLOOD_RED << "  scanning " << WHITE << total << BLOOD_RED << " platforms" << RESET;
                              std::cout.flush();

                              ThreadPool pool(std::min(total, 40));
                              std::vector<std::future<void>> futs;
                              futs.reserve(total);

                              for (auto& s : SITES) {
                                  if (g_cancel_token.cancelled) break;
                                  futs.push_back(pool.submit([&, s] {
                                      if (g_cancel_token.cancelled) { ++done_c; return; }
                                      std::string url  = fill(s.url, username);
                                      if (!InputGuard::is_safe_url(url)) { ++done_c; return; }
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
                                          OsintEntry oe;
                                          oe.platform = s.name;
                                          oe.url = url;
                                          oe.category = s.cat;
                                          oe.certainty = "POSSIBLE";
                                          std::lock_guard<std::mutex> rlk(g_result_mtx);
                                          g_result.osint.push_back(oe);
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
                                  std::cout << BLOOD_RED << "  nothing found\n" << RESET;
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
                                  std::cout << "\n" << BLOOD_RED << BOLD << "  " << WHITE << cat << BLOOD_RED << ":\n" << RESET;
                                  for (auto* h : by_cat[cat]) {
                                      std::cout << "  " << certainty_str(h->certainty)
                                      << "  " << WHITE << std::left << std::setw(16) << h->name;
                                      if (!h->url.empty()) std::cout << WHITE << h->url << RESET;
                                      if (!h->evidence.empty() && h->cat == "ext")
                                          std::cout << BLOOD_RED << "  [via " << WHITE << h->evidence << BLOOD_RED << "]" << RESET;
                                      std::cout << "\n";
                                  }
                              }

                              long confirmed = std::count_if(hits.begin(), hits.end(),
                                                             [](const OsintHit& h){ return h.certainty == HitConfidence::CONFIRMED; });
                              long probable  = std::count_if(hits.begin(), hits.end(),
                                                             [](const OsintHit& h){ return h.certainty == HitConfidence::PROBABLE; });
                              long possible  = std::count_if(hits.begin(), hits.end(),
                                                             [](const OsintHit& h){ return h.certainty == HitConfidence::POSSIBLE; });

                              std::cout << "\n" << BLOOD_RED << "  +" << std::string(46,'-') << "+\n" << RESET;
                              std::cout << BLOOD_RED << "  | " << WHITE << "CONFIRMED " << WHITE << std::left << std::setw(10) << confirmed
                              << BLOOD_RED << "  | " << WHITE << "PROBABLE  " << WHITE << std::left << std::setw(10) << probable
                              << BLOOD_RED << "  | " << WHITE << "POSSIBLE  " << WHITE << std::left << std::setw(10) << possible
                              << BLOOD_RED << "  |\n  +" << std::string(46,'-') << "+\n" << RESET;
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
                                      std::cout << BLOOD_RED << "  [+] " << WHITE << std::left << std::setw(16) << t.tool
                                      << BLOOD_RED << "found " << WHITE << t.hits.size() << BLOOD_RED << " hits\n" << RESET;
                                  else
                                      std::cout << BLOOD_RED << "  [-] " << WHITE << std::left << std::setw(16) << t.tool
                                      << BLOOD_RED << "not installed\n" << RESET;
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
                              std::cout << BLOOD_RED << "  " << WHITE << patterns.size() << BLOOD_RED << " variants to check:\n" << RESET;
                              for (size_t i = 0; i < std::min(patterns.size(), (size_t)10); i++)
                                  std::cout << WHITE << "    " << patterns[i] << "\n" << RESET;
                              if (patterns.size() > 10)
                                  std::cout << BLOOD_RED << "    ... +" << WHITE << patterns.size()-10 << BLOOD_RED << " more\n" << RESET;

                              print_section("EMAIL HYPOTHESES");
                              static const std::vector<std::string> doms = {
                                  "gmail.com","yahoo.com","outlook.com","protonmail.com","icloud.com","mail.ru","yandex.ru"
                              };
                              for (auto& d : doms) {
                                  std::string addr = username + "@" + d;
                                  graph.email_candidates.push_back(addr);
                                  std::cout << BLOOD_RED << "  -> " << WHITE << addr << "\n" << RESET;
                              }

                              print_section("WEB MENTIONS");
                              {
                                  std::string ddg_url = "https://html.duckduckgo.com/html/?q=%22" + url_encode(username) + "%22";
                                  if (InputGuard::is_safe_url(ddg_url)) {
                                      auto ddg = safe_curl(ddg_url, 10);
                                      if (!ddg.empty()) {
                                          int shown = 0;
                                          for (auto& l : extract_links(ddg, 8)) {
                                              if (l.find("duckduckgo") == std::string::npos) {
                                                  std::cout << WHITE << "  " << sanitize(l) << RESET << "\n";
                                                  shown++;
                                              }
                                          }
                                          if (!shown) std::cout << BLOOD_RED << "  no public mentions\n" << RESET;
                                      }
                                  }
                              }

                              for (auto& h : graph.hits) graph.category_counts[h.cat]++;
                              LOG_INFO("osint_username", "done user="+username+" hits="+std::to_string(graph.hits.size()));
                          }

                          static void extract_phone_from_email_sources(const std::string& email, const std::string& local, CorrelatedProfile& prof);
                          static void correlate_and_print(CorrelatedProfile& prof, const std::vector<OsintHit>& hits, const std::string& seed);

                          static void run_email(const std::string& email, IdentityGraph& graph) {
                              if (!InputGuard::is_valid_email(email)) {
                                  std::cout << BLOOD_RED << "  [!] invalid email\n" << RESET; return;
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
                              std::cout << BLOOD_RED << "  " << WHITE << email << "\n\n" << RESET;
                              std::cout << BLOOD_RED << "  [local]      " << WHITE << local  << "\n" << RESET;
                              std::cout << BLOOD_RED << "  [domain]     " << WHITE << domain << "\n" << RESET;
                              auto dt = dom_types.find(domain);
                              if (dt != dom_types.end())
                                  std::cout << BLOOD_RED << "  [type]       " << WHITE << dt->second << "\n" << RESET;
                              else if (disp)
                                  std::cout << BLOOD_RED << "  [type]       " << WHITE << "DISPOSABLE/BURNER\n" << RESET;
                              else
                                  std::cout << BLOOD_RED << "  [type]       " << WHITE << "corporate/custom domain\n" << RESET;
                              std::cout << BLOOD_RED << "  [disposable] " << WHITE
                              << (disp ? "YES -- temp/spam domain" : "no") << "\n" << RESET;

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
                                  std::cout << BLOOD_RED << "  [MX]     " << WHITE;
                                  for (auto& l : split_lines(mx)) std::cout << sanitize(l) << "  ";
                                  std::cout << "\n" << RESET;
                              } else {
                                  std::cout << BLOOD_RED << "  [MX]     no records -- domain may not accept email\n" << RESET;
                              }

                              bool spf_found = false;
                              for (auto& l : split_lines(spf)) {
                                  if (l.find("v=spf1") != std::string::npos)
                                  { std::cout << BLOOD_RED << "  [SPF]    " << WHITE << sanitize(l) << "\n" << RESET; spf_found = true; }
                              }
                              if (!spf_found) std::cout << BLOOD_RED << "  [SPF]    not found\n" << RESET;

                              if (!dmarc.empty()) std::cout << BLOOD_RED << "  [DMARC]  " << WHITE << sanitize(dmarc) << "\n" << RESET;
                              else                std::cout << BLOOD_RED << "  [DMARC]  not found\n" << RESET;

                              if (!a_rec.empty()) std::cout << BLOOD_RED << "  [A]      " << WHITE << sanitize(a_rec) << "\n" << RESET;

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

                              std::cout << BLOOD_RED << "  [breach_risk]  " << WHITE
                              << std::fixed << std::setprecision(0) << (breach_risk*100) << "%  "
                              << conf_bar(breach_risk) << "\n" << RESET;
                              for (auto& f : risk_factors) std::cout << BLOOD_RED << "  [!] " << WHITE << f << "\n" << RESET;

                              {
                                  std::string hibp_url = "https://haveibeenpwned.com/api/v3/breachedaccount/" +
                                  url_encode(local) + "%40" + url_encode(domain);
                                  if (InputGuard::is_safe_url(hibp_url)) {
                                      auto hibp = safe_curl(hibp_url, 12);
                                      if (!hibp.empty() && hibp.find("Name") != std::string::npos) {
                                          std::cout << BLOOD_RED << "\n  [!!!] FOUND IN BREACH DATABASES:\n" << RESET;
                                          size_t p = 0; std::string mk = "\"Name\":\""; int cnt = 0;
                                          while ((p = hibp.find(mk, p)) != std::string::npos && cnt < 30) {
                                              p += mk.size(); auto end = hibp.find('"', p);
                                              if (end == std::string::npos) break;
                                              std::cout << BLOOD_RED << "    [breach] " << WHITE << hibp.substr(p,end-p) << "\n" << RESET;
                                              p = end; cnt++;
                                          }
                                      } else {
                                          std::cout << BLOOD_RED << "  [ok] HIBP: not found (or API key required)\n" << RESET;
                                      }
                                  }
                              }

                              print_section("GRAVATAR / PROFILE DATA");
                              {
                                  std::string grav_url = "https://en.gravatar.com/" + url_encode(local) + ".json";
                                  if (InputGuard::is_safe_url(grav_url)) {
                                      auto grav = safe_curl(grav_url, 8);
                                      if (!grav.empty() && grav.find("entry") != std::string::npos) {
                                          std::cout << BLOOD_RED << "  [+] Gravatar profile found:\n" << RESET;
                                          for (auto& k : {"displayName","aboutMe","currentLocation","profileUrl","phoneNumbers"}) {
                                              auto v = json_val(grav, k);
                                              if (!v.empty())
                                                  std::cout << BLOOD_RED << "  [" << WHITE << std::left << std::setw(16) << k << BLOOD_RED << "] "
                                                  << WHITE << sanitize(v) << "\n" << RESET;
                                          }
                                      } else {
                                          std::cout << BLOOD_RED << "  no Gravatar profile\n" << RESET;
                                      }
                                  }
                              }

                              print_section("EXTERNAL TOOLS");
                              auto f_holehe    = std::async(std::launch::async, run_holehe,       email);
                              auto f_harvester = std::async(std::launch::async, run_theharvester, domain);
                              auto hr = f_holehe.get();
                              auto tr = f_harvester.get();

                              if (hr.installed)  std::cout << BLOOD_RED << "  [+] " << WHITE << std::left << std::setw(16) << "holehe"       << BLOOD_RED << "found " << WHITE << hr.hits.size() << BLOOD_RED << " services\n" << RESET;
                              else               std::cout << BLOOD_RED << "  [-] " << WHITE << std::left << std::setw(16) << "holehe"       << BLOOD_RED << "not installed\n" << RESET;
                              if (tr.installed)  std::cout << BLOOD_RED << "  [+] " << WHITE << std::left << std::setw(16) << "theHarvester" << BLOOD_RED << "found " << WHITE << tr.hits.size() << BLOOD_RED << " items\n" << RESET;
                              else               std::cout << BLOOD_RED << "  [-] " << WHITE << std::left << std::setw(16) << "theHarvester" << BLOOD_RED << "not installed\n" << RESET;

                              if (hr.installed && !hr.hits.empty()) {
                                  std::cout << "\n" << BLOOD_RED << BOLD << "  holehe -- registered services:\n" << RESET;
                                  for (auto& h : hr.hits)
                                      std::cout << BLOOD_RED << "  [+] " << WHITE << h.platform << "\n" << RESET;
                              }

                              if (tr.installed && !tr.hits.empty()) {
                                  std::cout << "\n" << BLOOD_RED << BOLD << "  theHarvester -- domain intel:\n" << RESET;
                                  for (size_t i = 0; i < std::min(tr.hits.size(), (size_t)20); i++)
                                      std::cout << WHITE << "  " << tr.hits[i].info << RESET << "\n";
                                  if (tr.hits.size() > 20)
                                      std::cout << BLOOD_RED << "  ... +" << WHITE << tr.hits.size()-20 << BLOOD_RED << " more\n" << RESET;
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
                              for (auto& c : candidates) std::cout << BLOOD_RED << "  -> " << WHITE << c << "\n" << RESET;
                              graph.username_candidates = candidates;

                              extract_phone_from_email_sources(email, local, graph.profile);

                              print_section("PLATFORM SCAN (primary username)");
                              std::mutex hm;
                              run_platform_scan(local, graph.hits, hm);

                              std::vector<ToolResult> tools = {hr, tr};
                              cross_reference(graph.hits, tools);

                              print_section("RESULTS");
                              print_results(graph.hits);

                              print_section("WEB MENTIONS");
                              {
                                  std::string ddg_url = "https://html.duckduckgo.com/html/?q=%22" + url_encode(local) + "%40" + url_encode(domain) + "%22";
                                  if (InputGuard::is_safe_url(ddg_url)) {
                                      auto ddg = safe_curl(ddg_url, 10);
                                      if (!ddg.empty()) {
                                          int shown = 0;
                                          for (auto& l : extract_links(ddg, 8)) {
                                              if (l.find("duckduckgo") == std::string::npos) {
                                                  std::cout << WHITE << "  " << sanitize(l) << RESET << "\n";
                                                  shown++;
                                              }
                                          }
                                          if (!shown) std::cout << BLOOD_RED << "  no public mentions\n" << RESET;
                                      }
                                  }
                              }

                              correlate_and_print(graph.profile, graph.hits, email);
                              LOG_INFO("osint_email","done email="+email+" hits="+std::to_string(graph.hits.size()));
                          }

                          static void lookup_getcontact(const std::string& e164, CorrelatedProfile& prof) {
                              print_section("GETCONTACT LOOKUP");
                              {
                                  std::string url1 = "https://api.getcontact.com/v1/search?phone=" + url_encode(e164);
                                  std::string resp;
                                  if (InputGuard::is_safe_url(url1)) resp = safe_curl(url1, 8);
                                  if (resp.empty()) {
                                      std::string url2 = "https://pbgc.ru/phone/" + url_encode(e164.substr(e164[0]=='+'?1:0));
                                      if (InputGuard::is_safe_url(url2)) {
                                          auto resp2 = safe_curl(url2, 8);
                                          if (!resp2.empty() && resp2.size() > 100) {
                                              std::string rl = resp2;
                                              std::transform(rl.begin(), rl.end(), rl.begin(), ::tolower);
                                              static const std::vector<std::string> name_markers = {
                                                  "name\":\"","title\":\"","fullname\":\"","displayname\":\"","contact_name\":\""
                                              };
                                              for (auto& mk : name_markers) {
                                                  auto p = rl.find(mk);
                                                  if (p != std::string::npos) {
                                                      p += mk.size();
                                                      auto end = resp2.find('"', p);
                                                      if (end != std::string::npos) {
                                                          std::string name = sanitize(resp2.substr(p, end-p));
                                                          if (!name.empty() && name.size() > 1) {
                                                              std::cout << BLOOD_RED << "  [+] name: " << WHITE << name << "\n" << RESET;
                                                              prof.add("getcontact_name", name);
                                                          }
                                                      }
                                                  }
                                              }
                                          }
                                      }
                                  } else {
                                      for (auto& k : {"name","displayName","tag","firstName","lastName"}) {
                                          auto v = json_val(resp, k);
                                          if (!v.empty() && v != "null") {
                                              std::cout << BLOOD_RED << "  [+] " << WHITE << std::left << std::setw(14) << k
                                              << BLOOD_RED << " " << WHITE << sanitize(v) << "\n" << RESET;
                                              prof.add(k, sanitize(v));
                                          }
                                      }
                                  }
                              }

                              {
                                  std::string purl = "https://www.getcontact.com/ru/search/" +
                                  url_encode(e164.substr(e164[0]=='+'?1:0));
                                  if (InputGuard::is_safe_url(purl)) {
                                      auto pbody = safe_curl(purl, 8);
                                      if (!pbody.empty()) {
                                          std::string bl = pbody;
                                          std::transform(bl.begin(), bl.end(), bl.begin(), ::tolower);
                                          static const std::vector<std::string> patterns = {
                                              "data-name=\"","og:title\" content=\"","class=\"name\">","<title>"
                                          };
                                          for (auto& pat : patterns) {
                                              auto pos = bl.find(pat);
                                              if (pos != std::string::npos) {
                                                  pos += pat.size();
                                                  auto end = pbody.find_first_of("\"<\n", pos);
                                                  if (end != std::string::npos && end > pos) {
                                                      std::string val = sanitize(pbody.substr(pos, end-pos));
                                                      if (!val.empty() && val.size() > 2 && val.find("GetContact") == std::string::npos) {
                                                          std::cout << BLOOD_RED << "  [+] contact name: " << WHITE << val << "\n" << RESET;
                                                          prof.add("getcontact_tag", val);
                                                          break;
                                                      }
                                                  }
                                              }
                                          }
                                      }
                                  }
                              }

                              if (prof.names.empty()) std::cout << BLOOD_RED << "  no public data (API requires auth)\n" << RESET;
                              std::cout << BLOOD_RED << "  tip: getcontact.com/ru/search/" << WHITE << e164.substr(e164[0]=='+'?1:0) << "\n" << RESET;
                          }

                          static void lookup_truecaller(const std::string& e164, CorrelatedProfile& prof) {
                              print_section("TRUECALLER LOOKUP");
                              std::string cc = e164.size() > 2 ? e164.substr(1,2) : "RU";
                              {
                                  std::string tc_url = "https://search5-noneu.truecaller.com/v2/search?q=" +
                                  url_encode(e164) + "&countryCode=" + url_encode(cc) +
                                  "&type=4&locAddr=&encoding=json";
                                  if (InputGuard::is_safe_url(tc_url)) {
                                      auto resp = safe_curl(tc_url, 8);
                                      if (!resp.empty() && resp.find("data") != std::string::npos) {
                                          for (auto& k : {"name","firstName","lastName","cityName","countryCode","carrier","phoneType"}) {
                                              auto v = json_val(resp, k);
                                              if (!v.empty() && v != "null") {
                                                  std::cout << BLOOD_RED << "  [+] " << WHITE << std::left << std::setw(14) << k
                                                  << BLOOD_RED << " " << WHITE << sanitize(v) << "\n" << RESET;
                                                  prof.add(k, sanitize(v));
                                              }
                                          }
                                          auto img = json_val(resp, "image");
                                          if (!img.empty()) {
                                              std::cout << BLOOD_RED << "  [avatar]       " << WHITE << sanitize(img) << "\n" << RESET;
                                              prof.add("avatar", img);
                                          }
                                          std::cout << BLOOD_RED << "  tip: truecaller.com/search/ru/" << WHITE << e164.substr(e164[0]=='+'?1:0) << "\n" << RESET;
                                          return;
                                      }
                                  }
                              }
                              {
                                  std::string web_url = "https://www.truecaller.com/search/ru/" +
                                  url_encode(e164.substr(e164[0]=='+'?1:0));
                                  if (InputGuard::is_safe_url(web_url)) {
                                      auto web = safe_curl(web_url, 8);
                                      if (!web.empty()) {
                                          std::string wl = web;
                                          std::transform(wl.begin(), wl.end(), wl.begin(), ::tolower);
                                          auto pos = wl.find("\"name\":\"");
                                          if (pos != std::string::npos) {
                                              pos += 8;
                                              auto end = web.find('"', pos);
                                              if (end != std::string::npos) {
                                                  std::string name = sanitize(web.substr(pos, end-pos));
                                                  if (!name.empty()) {
                                                      std::cout << BLOOD_RED << "  [+] name: " << WHITE << name << "\n" << RESET;
                                                      prof.add("truecaller_name", name);
                                                  }
                                              }
                                          }
                                      }
                                  }
                              }
                              if (prof.names.empty())
                                  std::cout << BLOOD_RED << "  no data (Truecaller API requires bearer token)\n" << RESET;
                              std::cout << BLOOD_RED << "  tip: truecaller.com/search/ru/" << WHITE << e164.substr(e164[0]=='+'?1:0) << "\n" << RESET;
                          }

                          static void lookup_vk_by_phone(const std::string& e164, CorrelatedProfile& prof) {
                              print_section("VK SEARCH BY PHONE");
                              {
                                  std::string vk_url = "https://api.vk.com/method/users.search?q=" +
                                  url_encode(e164) + "&count=5&fields=city,country,photo_200,bdate,domain&v=5.199";
                                  if (InputGuard::is_safe_url(vk_url)) {
                                      auto resp = safe_curl(vk_url, 8);
                                      if (!resp.empty() && resp.find("\"id\"") != std::string::npos) {
                                          std::cout << BLOOD_RED << "  [+] VK profile(s) found:\n" << RESET;
                                          size_t p = 0;
                                          std::string mk = "\"id\":";
                                          int cnt = 0;
                                          while ((p = resp.find(mk, p)) != std::string::npos && cnt < 3) {
                                              p += mk.size();
                                              auto end = resp.find(',', p);
                                              if (end == std::string::npos) break;
                                              std::string uid = resp.substr(p, end-p);
                                              while (!uid.empty() && !std::isdigit(uid[0])) uid.erase(uid.begin());
                                              while (!uid.empty() && !std::isdigit(uid.back())) uid.pop_back();
                                              if (!uid.empty()) {
                                                  std::string profile_url = "https://vk.com/id" + uid;
                                                  std::cout << BLOOD_RED << "    -> " << WHITE << profile_url << "\n" << RESET;
                                                  prof.add("vk_profile", profile_url);
                                                  cnt++;
                                              }
                                          }
                                          for (auto& k : {"first_name","last_name","domain","city","country","bdate"}) {
                                              auto v = json_val(resp, k);
                                              if (!v.empty() && v != "null") {
                                                  std::cout << BLOOD_RED << "  [" << WHITE << std::left << std::setw(12) << k << BLOOD_RED << "] "
                                                  << WHITE << sanitize(v) << "\n" << RESET;
                                                  prof.add(k, sanitize(v));
                                              }
                                          }
                                      } else {
                                          std::cout << BLOOD_RED << "  not found via public API\n" << RESET;
                                          std::cout << BLOOD_RED << "  tip (with token): vk.com/dev/users.search\n" << RESET;
                                      }
                                  }
                              }
                              {
                                  std::string web_url = "https://vk.com/search?c[section]=people&c[phone]=" + url_encode(e164);
                                  if (InputGuard::is_safe_url(web_url)) {
                                      auto web = safe_curl(web_url, 8);
                                      if (!web.empty() && web.find("profile_link") != std::string::npos) {
                                          auto pos = web.find("profile_link");
                                          if (pos != std::string::npos) {
                                              auto href = web.find("href=\"", pos);
                                              if (href != std::string::npos) {
                                                  href += 6;
                                                  auto end = web.find('"', href);
                                                  if (end != std::string::npos) {
                                                      std::string url = sanitize(web.substr(href, end-href));
                                                      if (!url.empty()) {
                                                          std::cout << BLOOD_RED << "  [+] VK web search: " << WHITE << url << "\n" << RESET;
                                                          prof.add("vk_web", url);
                                                      }
                                                  }
                                              }
                                          }
                                      }
                                  }
                              }
                          }

                          static void lookup_ok_by_phone(const std::string& e164, CorrelatedProfile& prof) {
                              print_section("OK.RU SEARCH BY PHONE");
                              std::string ok_url = "https://api.ok.ru/fb.do?method=users.search&query=" +
                              url_encode(e164) + "&count=5&fields=name,location,pic_full&application_key=CBAJLNABABABABABA&v=2.1";
                              if (!InputGuard::is_safe_url(ok_url)) return;
                              auto resp = safe_curl(ok_url, 8);
                              if (!resp.empty() && resp.find("\"uid\"") != std::string::npos) {
                                  for (auto& k : {"name","location","uid"}) {
                                      auto v = json_val(resp, k);
                                      if (!v.empty() && v != "null") {
                                          std::cout << BLOOD_RED << "  [+] " << WHITE << std::left << std::setw(10) << k
                                          << BLOOD_RED << " " << WHITE << sanitize(v) << "\n" << RESET;
                                          prof.add("ok_" + std::string(k), sanitize(v));
                                      }
                                  }
                              } else {
                                  std::cout << BLOOD_RED << "  not found (OK.ru requires app token)\n" << RESET;
                              }
                          }

                          static void lookup_telegram_extended(const std::string& e164, CorrelatedProfile& prof) {
                              print_section("TELEGRAM EXTENDED CHECK");
                              std::string without_plus = e164.substr(e164[0]=='+'?1:0);
                              {
                                  std::string tg_url = "https://t.me/" + url_encode(e164);
                                  if (InputGuard::is_safe_url(tg_url)) {
                                      auto tg1 = safe_curl(tg_url, 8);
                                      if (!tg1.empty() && tg1.find("tgme_page") != std::string::npos &&
                                          tg1.find("not found") == std::string::npos) {
                                          std::cout << BLOOD_RED << "  [CONFIRMED] " << WHITE << "t.me/" << e164 << "\n" << RESET;
                                      prof.add("telegram_phone", "t.me/" + e164);

                                      for (auto& mk : {"tgme_page_title\">","og:title\" content=\"","<title>"}) {
                                          auto pos = tg1.find(mk);
                                          if (pos != std::string::npos) {
                                              pos += strlen(mk);
                                              auto end = tg1.find_first_of("<\"", pos);
                                              if (end != std::string::npos) {
                                                  std::string name = sanitize(tg1.substr(pos, end-pos));
                                                  if (!name.empty() && name.find("Telegram") == std::string::npos) {
                                                      std::cout << BLOOD_RED << "  [+] display name: " << WHITE << name << "\n" << RESET;
                                                      prof.add("telegram_name", name);
                                                      break;
                                                  }
                                              }
                                          }
                                      }
                                      auto img = tg1.find("tgme_page_photo_image");
                                      if (img != std::string::npos) {
                                          auto src = tg1.find("src=\"", img);
                                          if (src != std::string::npos) {
                                              src += 5;
                                              auto end = tg1.find('"', src);
                                              if (end != std::string::npos) {
                                                  std::string photo_url = sanitize(tg1.substr(src, end-src));
                                                  if (!photo_url.empty()) {
                                                      std::cout << BLOOD_RED << "  [+] profile photo: " << WHITE << photo_url << "\n" << RESET;
                                                      prof.add("telegram_photo", photo_url);
                                                  }
                                              }
                                          }
                                      }
                                          } else {
                                              std::cout << BLOOD_RED << "  [-] no Telegram profile at t.me/" << WHITE << e164 << "\n" << RESET;
                                          }
                                  }
                              }
                              {
                                  std::string tg2_url = "https://t.me/+" + url_encode(without_plus);
                                  if (InputGuard::is_safe_url(tg2_url)) {
                                      auto tg2 = safe_curl(tg2_url, 8);
                                      if (!tg2.empty() && tg2.find("tgme_page") != std::string::npos &&
                                          tg2.find("not found") == std::string::npos) {
                                          std::cout << BLOOD_RED << "  [CONFIRMED] " << WHITE << "t.me/+" << without_plus << "\n" << RESET;
                                      prof.add("telegram_plus", "t.me/+" + without_plus);
                                          }
                                  }
                              }
                              std::cout << BLOOD_RED << "  [-] WhatsApp / Signal / Viber: no public lookup API\n" << RESET;
                          }

                          static void lookup_public_phonebooks(const std::string& /*e164*/,
                                                               const std::string& raw_digits,
                                                               CorrelatedProfile& prof) {
                              print_section("PUBLIC PHONEBOOK SEARCH");

                              const std::vector<std::pair<std::string,std::string>> books = {
                                  {"nomer.org",             "https://nomer.org/"                          + raw_digits},
                                  {"phonenumbers",          "https://www.phonenumbers.ru/"                 + raw_digits},
                                  {"telefonnaya-spravka",   "https://www.telfin.ru/spravka/number/"       + raw_digits},
                              };

                              for (auto& [name, url] : books) {
                                  if (!InputGuard::is_safe_url(url)) continue;
                                  auto body = safe_curl(url, 8);
                                  if (body.empty()) continue;
                                  std::string bl = body;
                                  std::transform(bl.begin(), bl.end(), bl.begin(), ::tolower);

                                  static const std::vector<std::string> markers = {
                                      "itemprop=\"name\">","class=\"owner\">","class=\"name\">",
                                      "\"name\":\"","<h1>","owner_name"
                                  };
                                  for (auto& mk : markers) {
                                      auto pos = bl.find(mk);
                                      if (pos != std::string::npos) {
                                          pos += mk.size();
                                          auto end = body.find_first_of("<\"", pos);
                                          if (end != std::string::npos && end > pos) {
                                              std::string val = sanitize(body.substr(pos, end-pos));
                                              if (!val.empty() && val.size() > 2) {
                                                  std::cout << BLOOD_RED << "  [+] " << WHITE << name << BLOOD_RED << ": " << WHITE << val << "\n" << RESET;
                                                  prof.add("phonebook_" + name, val);
                                                  break;
                                              }
                                          }
                                      }
                                  }
                              }

                              {
                                  std::string ddg_url = "https://html.duckduckgo.com/html/?q=%22" + url_encode(raw_digits) + "%22";
                                  if (InputGuard::is_safe_url(ddg_url)) {
                                      auto ddg = safe_curl(ddg_url, 10);
                                      if (!ddg.empty()) {
                                          int shown = 0;
                                          for (auto& l : extract_links(ddg, 8)) {
                                              if (l.find("duckduckgo") == std::string::npos) {
                                                  std::cout << WHITE << "  " << sanitize(l) << RESET << "\n";
                                                  shown++;
                                              }
                                          }
                                          if (!shown) std::cout << BLOOD_RED << "  no public web mentions\n" << RESET;
                                      }
                                  }
                              }
                                                               }

                                                               static void extract_phone_from_email_sources(const std::string& email,
                                                                                                            const std::string& local,
                                                                                                            CorrelatedProfile& prof) {
                                                                   print_section("LINKED PHONE EXTRACTION");
                                                                   {
                                                                       std::string grav_url = "https://en.gravatar.com/" + url_encode(local) + ".json";
                                                                       if (InputGuard::is_safe_url(grav_url)) {
                                                                           auto grav = safe_curl(grav_url, 8);
                                                                           if (!grav.empty() && grav.find("phoneNumbers") != std::string::npos) {
                                                                               auto pos = grav.find("phoneNumbers");
                                                                               if (pos != std::string::npos) {
                                                                                   auto val_pos = grav.find("value\":\"", pos);
                                                                                   if (val_pos != std::string::npos) {
                                                                                       val_pos += 8;
                                                                                       auto end = grav.find('"', val_pos);
                                                                                       if (end != std::string::npos) {
                                                                                           std::string phone = sanitize(grav.substr(val_pos, end-val_pos));
                                                                                           if (!phone.empty()) {
                                                                                               std::cout << BLOOD_RED << "  [+] Gravatar phone: " << WHITE << phone << "\n" << RESET;
                                                                                               prof.add("gravatar_phone", phone);
                                                                                           }
                                                                                       }
                                                                                   }
                                                                               }
                                                                           } else {
                                                                               std::cout << BLOOD_RED << "  Gravatar: no phone in public profile\n" << RESET;
                                                                           }
                                                                       }
                                                                   }
                                                                   {
                                                                       std::string vk_url = "https://api.vk.com/method/users.search?q=" + url_encode(email) +
                                                                       "&fields=contacts,city,country&count=5&v=5.199";
                                                                       if (InputGuard::is_safe_url(vk_url)) {
                                                                           auto vk = safe_curl(vk_url, 8);
                                                                           if (!vk.empty() && vk.find("\"id\"") != std::string::npos) {
                                                                               std::cout << BLOOD_RED << "  [+] VK: email found in profile\n" << RESET;
                                                                               for (auto& k : {"first_name","last_name","mobile_phone","home_phone","domain"}) {
                                                                                   auto v = json_val(vk, k);
                                                                                   if (!v.empty() && v != "null") {
                                                                                       std::cout << BLOOD_RED << "  [" << WHITE << std::left << std::setw(14) << k << BLOOD_RED << "] "
                                                                                       << WHITE << sanitize(v) << "\n" << RESET;
                                                                                       prof.add("vk_" + std::string(k), sanitize(v));
                                                                                   }
                                                                               }
                                                                           } else {
                                                                               std::cout << BLOOD_RED << "  VK: email not found in public profiles\n" << RESET;
                                                                           }
                                                                       }
                                                                   }
                                                                   {
                                                                       std::string gh_url = "https://api.github.com/search/users?q=" +
                                                                       url_encode(email) + "+in:email&per_page=3";
                                                                       if (InputGuard::is_safe_url(gh_url)) {
                                                                           auto hub = safe_curl(gh_url, 8);
                                                                           if (!hub.empty() && hub.find("\"login\"") != std::string::npos) {
                                                                               std::cout << BLOOD_RED << "  [+] GitHub: profile linked to this email\n" << RESET;
                                                                               size_t p = 0; int cnt = 0;
                                                                               while ((p = hub.find("\"login\":\"", p)) != std::string::npos && cnt < 3) {
                                                                                   p += 9;
                                                                                   auto end = hub.find('"', p);
                                                                                   if (end != std::string::npos) {
                                                                                       std::string login = sanitize(hub.substr(p, end-p));
                                                                                       std::cout << BLOOD_RED << "  [github] " << WHITE << "github.com/" << login << "\n" << RESET;
                                                                                       prof.add("github_account", "github.com/" + login);
                                                                                       cnt++;
                                                                                   }
                                                                               }
                                                                           }
                                                                       }
                                                                   }
                                                                   {
                                                                       std::string li_url = "https://www.linkedin.com/pub/dir/?first=&last=&search=Search&emailAddress=" +
                                                                       url_encode(email);
                                                                       if (InputGuard::is_safe_url(li_url)) {
                                                                           auto li = safe_curl(li_url, 10);
                                                                           if (!li.empty() && li.find("profile-name") != std::string::npos) {
                                                                               auto pos = li.find("profile-name");
                                                                               if (pos != std::string::npos) {
                                                                                   auto end = li.find("</", pos);
                                                                                   if (end != std::string::npos) {
                                                                                       std::string chunk = sanitize(li.substr(pos, end-pos));
                                                                                       if (!chunk.empty())
                                                                                           std::cout << BLOOD_RED << "  [+] LinkedIn match found\n" << RESET;
                                                                                   }
                                                                               }
                                                                           }
                                                                       }
                                                                   }
                                                                                                            }

                                                                                                            static void correlate_and_print(CorrelatedProfile& prof,
                                                                                                                                            const std::vector<OsintHit>& hits,
                                                                                                                                            const std::string& seed) {
                                                                                                                print_section("CORRELATED IDENTITY PROFILE");

                                                                                                                std::cout << BLOOD_RED << "  [seed]       " << WHITE << seed << "\n\n" << RESET;

                                                                                                                if (!prof.names.empty()) {
                                                                                                                    std::cout << BLOOD_RED << BOLD << "  NAMES FOUND:\n" << RESET;
                                                                                                                    for (auto& n : prof.names)
                                                                                                                        std::cout << BLOOD_RED << "  [+] " << WHITE << n << "\n" << RESET;
                                                                                                                    std::cout << "\n";
                                                                                                                }

                                                                                                                if (!prof.phones.empty()) {
                                                                                                                    std::cout << BLOOD_RED << BOLD << "  PHONE NUMBERS:\n" << RESET;
                                                                                                                    for (auto& p : prof.phones)
                                                                                                                        std::cout << BLOOD_RED << "  [+] " << WHITE << p << "\n" << RESET;
                                                                                                                    std::cout << "\n";
                                                                                                                }

                                                                                                                if (!prof.emails.empty()) {
                                                                                                                    std::cout << BLOOD_RED << BOLD << "  EMAIL ADDRESSES:\n" << RESET;
                                                                                                                    for (auto& e : prof.emails)
                                                                                                                        std::cout << BLOOD_RED << "  [+] " << WHITE << e << "\n" << RESET;
                                                                                                                    std::cout << "\n";
                                                                                                                }

                                                                                                                if (!prof.locations.empty()) {
                                                                                                                    std::cout << BLOOD_RED << BOLD << "  LOCATIONS:\n" << RESET;
                                                                                                                    for (auto& l : prof.locations)
                                                                                                                        std::cout << BLOOD_RED << "  [+] " << WHITE << l << "\n" << RESET;
                                                                                                                    std::cout << "\n";
                                                                                                                }

                                                                                                                if (!prof.accounts.empty()) {
                                                                                                                    std::cout << BLOOD_RED << BOLD << "  LINKED ACCOUNTS:\n" << RESET;
                                                                                                                    for (auto& a : prof.accounts)
                                                                                                                        std::cout << BLOOD_RED << "  [+] " << WHITE << a << "\n" << RESET;
                                                                                                                    std::cout << "\n";
                                                                                                                }

                                                                                                                long confirmed = std::count_if(hits.begin(), hits.end(),
                                                                                                                                               [](const OsintHit& h){ return h.certainty == HitConfidence::CONFIRMED; });
                                                                                                                long probable  = std::count_if(hits.begin(), hits.end(),
                                                                                                                                               [](const OsintHit& h){ return h.certainty == HitConfidence::PROBABLE; });

                                                                                                                double completeness = 0.0;
                                                                                                                if (!prof.names.empty())     completeness += 0.30;
                                                                                                                if (!prof.phones.empty())    completeness += 0.20;
                                                                                                                if (!prof.emails.empty())    completeness += 0.20;
                                                                                                                if (!prof.locations.empty()) completeness += 0.15;
                                                                                                                if (confirmed > 0)           completeness += 0.15;

                                                                                                                std::cout << BLOOD_RED << "  [completeness] " << WHITE
                                                                                                                << std::fixed << std::setprecision(0) << (completeness*100) << "%  "
                                                                                                                << conf_bar(completeness) << "\n" << RESET;
                                                                                                                std::cout << BLOOD_RED << "  [confirmed]    " << WHITE << confirmed << BLOOD_RED << " accounts\n" << RESET;
                                                                                                                std::cout << BLOOD_RED << "  [probable]     " << WHITE << probable  << BLOOD_RED << " accounts\n" << RESET;
                                                                                                                std::cout << BLOOD_RED << "  [data_points]  " << WHITE << prof.raw.size() << "\n" << RESET;

                                                                                                                if (!prof.names.empty() && !prof.locations.empty())
                                                                                                                    std::cout << BLOOD_RED << "\n  [IDENTITY] " << WHITE
                                                                                                                    << prof.names[0] << BLOOD_RED << " -- " << WHITE << prof.locations[0] << "\n" << RESET;
                                                                                                                else if (!prof.names.empty())
                                                                                                                    std::cout << BLOOD_RED << "\n  [IDENTITY] " << WHITE << prof.names[0] << "\n" << RESET;
                                                                                                                                            }

                                                                                                                                            static void run_phone(const std::string& phone_raw, IdentityGraph& graph) {
                                                                                                                                                std::string phone;
                                                                                                                                                for (char c : phone_raw) if (std::isdigit(c) || c=='+') phone += c;
                                                                                                                                                if (!InputGuard::is_valid_phone(phone)) {
                                                                                                                                                    std::cout << BLOOD_RED << "  [!] invalid phone\n" << RESET; return;
                                                                                                                                                }
                                                                                                                                                std::string e164 = (phone[0] != '+') ? "+" + phone : phone;
                                                                                                                                                std::string raw_digits;
                                                                                                                                                for (char c : phone) if (std::isdigit(c)) raw_digits += c;

                                                                                                                                                print_section("TOOL SETUP");
                                                                                                                                                ensure_tools_phone();

                                                                                                                                                print_section("PHONE PROFILE");
                                                                                                                                                std::cout << BLOOD_RED << "  " << WHITE << e164 << "\n\n" << RESET;

                                                                                                                                                const CountryInfo* cc = nullptr;
                                                                                                                                                for (auto& c : COUNTRY_DB) if (e164.find(c.code)==0) { cc=&c; break; }

                                                                                                                                                if (cc) {
                                                                                                                                                    std::cout << BLOOD_RED << "  [country]    " << WHITE << cc->country << "\n" << RESET;
                                                                                                                                                    std::cout << BLOOD_RED << "  [region]     " << WHITE << cc->region  << "\n" << RESET;
                                                                                                                                                    std::cout << BLOOD_RED << "  [language]   " << WHITE << cc->lang    << "\n" << RESET;
                                                                                                                                                    std::cout << BLOOD_RED << "  [code]       " << WHITE << cc->code    << "\n" << RESET;
                                                                                                                                                    std::cout << BLOOD_RED << "  [carriers]   " << WHITE;
                                                                                                                                                    for (size_t i = 0; i < cc->carriers.size(); i++) {
                                                                                                                                                        std::cout << cc->carriers[i];
                                                                                                                                                        if (i+1 < cc->carriers.size()) std::cout << BLOOD_RED << ", " << WHITE;
                                                                                                                                                    }
                                                                                                                                                    std::cout << "\n" << RESET;
                                                                                                                                                    graph.profile.add("country", cc->country);
                                                                                                                                                    graph.profile.add("region_country", cc->region);

                                                                                                                                                    if (cc->code == "+7") {
                                                                                                                                                        std::string ln = e164.substr(1);
                                                                                                                                                        if (ln.size() == 11) {
                                                                                                                                                            std::string prefix = ln.substr(1,3);
                                                                                                                                                            auto it = RU_OPERATORS.find(prefix);
                                                                                                                                                            if (it != RU_OPERATORS.end()) {
                                                                                                                                                                std::cout << BLOOD_RED << "  [operator]   " << WHITE << it->second.op
                                                                                                                                                                << BLOOD_RED << " (prefix " << WHITE << prefix << BLOOD_RED << ")\n" << RESET;
                                                                                                                                                                std::cout << BLOOD_RED << "  [reg_region] " << WHITE << it->second.region << "\n" << RESET;
                                                                                                                                                                graph.profile.add("operator", it->second.op);
                                                                                                                                                                graph.profile.add("registration_region", it->second.region);
                                                                                                                                                            } else {
                                                                                                                                                                std::cout << BLOOD_RED << "  [operator]   " << WHITE << "unknown prefix " << prefix << "\n" << RESET;
                                                                                                                                                            }

                                                                                                                                                            auto ci = RU_CITY_CODES.find(prefix);
                                                                                                                                                            if (ci != RU_CITY_CODES.end()) {
                                                                                                                                                                std::cout << BLOOD_RED << "  [city_hint]  " << WHITE << ci->second << "\n" << RESET;
                                                                                                                                                                graph.profile.add("city_hint", ci->second);
                                                                                                                                                            }
                                                                                                                                                            for (int len : {4, 3}) {
                                                                                                                                                                std::string long_pfx = ln.substr(1, len);
                                                                                                                                                                auto lci = RU_CITY_CODES.find(long_pfx);
                                                                                                                                                                if (lci != RU_CITY_CODES.end()) {
                                                                                                                                                                    std::cout << BLOOD_RED << "  [city_exact] " << WHITE << lci->second << "\n" << RESET;
                                                                                                                                                                    graph.profile.add("city_exact", lci->second);
                                                                                                                                                                    break;
                                                                                                                                                                }
                                                                                                                                                            }
                                                                                                                                                        }
                                                                                                                                                    }
                                                                                                                                                } else {
                                                                                                                                                    std::cout << BLOOD_RED << "  [country]    unknown code\n" << RESET;
                                                                                                                                                }

                                                                                                                                                print_section("LINE TYPE & CARRIER LOOKUP");
                                                                                                                                                {
                                                                                                                                                    std::string nl_url = "https://api.numlookupapi.com/v1/info/" + url_encode(e164);
                                                                                                                                                    if (InputGuard::is_safe_url(nl_url)) {
                                                                                                                                                        auto nl = safe_curl(nl_url, 8);
                                                                                                                                                        if (!nl.empty() && nl != "{}" && nl.find("error") == std::string::npos) {
                                                                                                                                                            for (auto& k : {"valid","country_code","location","carrier","line_type","number_type"}) {
                                                                                                                                                                auto v = json_val(nl, k);
                                                                                                                                                                if (!v.empty() && v != "null") {
                                                                                                                                                                    std::cout << BLOOD_RED << "  [" << WHITE << std::left << std::setw(14) << k << BLOOD_RED << "] "
                                                                                                                                                                    << WHITE << sanitize(v) << "\n" << RESET;
                                                                                                                                                                    graph.profile.add(k, sanitize(v));
                                                                                                                                                                }
                                                                                                                                                            }
                                                                                                                                                        } else {
                                                                                                                                                            std::string tw_url = "https://www.twilio.com/lookup/v1/PhoneNumbers/" +
                                                                                                                                                            url_encode(e164) + "?Type=carrier&Type=caller-name";
                                                                                                                                                            if (InputGuard::is_safe_url(tw_url)) {
                                                                                                                                                                auto tw = safe_curl(tw_url, 8);
                                                                                                                                                                if (!tw.empty() && tw.find("carrier") != std::string::npos) {
                                                                                                                                                                    auto carrier = json_val(tw, "name");
                                                                                                                                                                    auto type    = json_val(tw, "type");
                                                                                                                                                                    if (!carrier.empty()) {
                                                                                                                                                                        std::cout << BLOOD_RED << "  [carrier]    " << WHITE << sanitize(carrier) << "\n" << RESET;
                                                                                                                                                                        graph.profile.add("carrier", sanitize(carrier));
                                                                                                                                                                    }
                                                                                                                                                                    if (!type.empty()) {
                                                                                                                                                                        std::cout << BLOOD_RED << "  [line_type]  " << WHITE << sanitize(type) << "\n" << RESET;
                                                                                                                                                                        graph.profile.add("line_type", sanitize(type));
                                                                                                                                                                    }
                                                                                                                                                                } else {
                                                                                                                                                                    std::cout << BLOOD_RED << "  carrier API unavailable (no key)\n" << RESET;
                                                                                                                                                                }
                                                                                                                                                            }
                                                                                                                                                        }
                                                                                                                                                    }
                                                                                                                                                }

                                                                                                                                                lookup_getcontact(e164, graph.profile);
                                                                                                                                                lookup_truecaller(e164, graph.profile);
                                                                                                                                                lookup_vk_by_phone(e164, graph.profile);
                                                                                                                                                lookup_ok_by_phone(e164, graph.profile);
                                                                                                                                                lookup_telegram_extended(e164, graph.profile);

                                                                                                                                                print_section("BEHAVIORAL PROFILE");
                                                                                                                                                if (cc) {
                                                                                                                                                    std::cout << BLOOD_RED << "  [messenger_note] " << WHITE << cc->messenger_note << "\n\n" << RESET;
                                                                                                                                                    std::cout << BLOOD_RED << "  dominant platforms in " << WHITE << cc->country << BLOOD_RED << ":\n" << RESET;
                                                                                                                                                    for (auto& p : cc->platforms)
                                                                                                                                                        std::cout << BLOOD_RED << "    -> " << WHITE << p << "\n" << RESET;
                                                                                                                                                }

                                                                                                                                                print_section("EXTERNAL TOOLS");
                                                                                                                                                ToolResult pif = run_phoneinfoga(e164);
                                                                                                                                                if (pif.installed) {
                                                                                                                                                    std::cout << BLOOD_RED << "  [+] " << WHITE << "phoneinfoga: found " << pif.hits.size() << " results\n" << RESET;
                                                                                                                                                    for (auto& h : pif.hits)
                                                                                                                                                        if (!h.info.empty()) {
                                                                                                                                                            std::cout << WHITE << "  " << h.info << RESET << "\n";
                                                                                                                                                            graph.profile.add("phoneinfoga", h.info);
                                                                                                                                                        }
                                                                                                                                                } else {
                                                                                                                                                    std::cout << BLOOD_RED << "  [-] phoneinfoga: not installed\n"
                                                                                                                                                    << WHITE   << "      install: go install github.com/sundowndev/phoneinfoga/v2/cmd/phoneinfoga@latest\n"
                                                                                                                                                    << RESET;
                                                                                                                                                }

                                                                                                                                                print_section("FRAUD & SPAM HEURISTICS");
                                                                                                                                                double fraud = 0.0;
                                                                                                                                                std::vector<std::string> flags;
                                                                                                                                                if (!cc) { fraud += 0.4; flags.push_back("unknown country code"); }
                                                                                                                                                std::string tail4 = raw_digits.size()>=4 ? raw_digits.substr(raw_digits.size()-4) : "";
                                                                                                                                                static const std::set<std::string> sus_tails = {
                                                                                                                                                    "0000","1111","2222","3333","4444","5555","6666","7777","8888","9999","1234","4321"
                                                                                                                                                };
                                                                                                                                                if (sus_tails.count(tail4)) { fraud += 0.2; flags.push_back("suspicious tail: "+tail4); }
                                                                                                                                                if (raw_digits.size()>4 &&
                                                                                                                                                    std::all_of(raw_digits.begin(),raw_digits.end(),[&](char c){ return c==raw_digits[0]; }))
                                                                                                                                                { fraud += 0.5; flags.push_back("all identical digits -- likely fake"); }
                                                                                                                                                if (cc && cc->code=="+7" && raw_digits.size()==11) {
                                                                                                                                                    if (!RU_OPERATORS.count(raw_digits.substr(1,3)))
                                                                                                                                                    { fraud += 0.15; flags.push_back("unknown RU operator prefix: "+raw_digits.substr(1,3)); }
                                                                                                                                                }
                                                                                                                                                fraud = std::min(fraud, 0.95);
                                                                                                                                                std::cout << BLOOD_RED << "  [fraud_score] " << WHITE
                                                                                                                                                << std::fixed << std::setprecision(0) << (fraud*100) << "%  " << conf_bar(fraud) << "\n" << RESET;
                                                                                                                                                for (auto& f : flags) std::cout << BLOOD_RED << "  [!] " << WHITE << f << "\n" << RESET;
                                                                                                                                                if (flags.empty()) std::cout << BLOOD_RED << "  [ok] no suspicious patterns\n" << RESET;

                                                                                                                                                print_section("PHONE FORMATS");
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
                                                                                                                                                for (auto& f : fmts) std::cout << WHITE << "  " << f << "\n" << RESET;
                                                                                                                                                graph.phone_candidates = fmts;

                                                                                                                                                lookup_public_phonebooks(e164, raw_digits, graph.profile);
                                                                                                                                                correlate_and_print(graph.profile, graph.hits, e164);

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
                                                                                                                                                std::cout << BLOOD_RED << "  [auto-detected] " << WHITE << type_str << "\n" << RESET;

                                                                                                                                                IdentityGraph graph;
                                                                                                                                                graph.seed      = input;
                                                                                                                                                graph.seed_type = type;

                                                                                                                                                switch (type) {
                                                                                                                                                    case OsintInputType::USERNAME: run_username(input, graph); break;
                                                                                                                                                    case OsintInputType::EMAIL:    run_email(input, graph);    break;
                                                                                                                                                    case OsintInputType::PHONE:    run_phone(input, graph);    break;
                                                                                                                                                    default:
                                                                                                                                                        std::cout << BLOOD_RED << "  [!] cannot determine input type\n" << RESET; return;
                                                                                                                                                }

                                                                                                                                                if (!graph.hits.empty() || !graph.username_candidates.empty()) {
                                                                                                                                                    print_section("IDENTITY GRAPH SUMMARY");
                                                                                                                                                    std::cout << BLOOD_RED << "  [seed]    " << WHITE << input << BLOOD_RED << "  [" << WHITE << type_str << BLOOD_RED << "]\n" << RESET;
                                                                                                                                                    if (!graph.username_candidates.empty()) {
                                                                                                                                                        std::cout << BLOOD_RED << "  [usernames] " << WHITE;
                                                                                                                                                        for (auto& u : graph.username_candidates) std::cout << u << "  ";
                                                                                                                                                        std::cout << "\n" << RESET;
                                                                                                                                                    }
                                                                                                                                                    if (!graph.email_candidates.empty()) {
                                                                                                                                                        std::cout << BLOOD_RED << "  [emails]    " << WHITE;
                                                                                                                                                        for (size_t i = 0; i < std::min(graph.email_candidates.size(),(size_t)4); i++)
                                                                                                                                                            std::cout << graph.email_candidates[i] << "  ";
                                                                                                                                                        std::cout << "\n" << RESET;
                                                                                                                                                    }
                                                                                                                                                    if (!graph.phone_candidates.empty()) {
                                                                                                                                                        std::cout << BLOOD_RED << "  [phones]    " << WHITE;
                                                                                                                                                        for (auto& p : graph.phone_candidates) std::cout << p << "  ";
                                                                                                                                                        std::cout << "\n" << RESET;
                                                                                                                                                    }
                                                                                                                                                }

                                                                                                                                                LOG_INFO("osint","done input="+input+" type="+type_str+" hits="+std::to_string(graph.hits.size()));
                                                                                                                                            }
