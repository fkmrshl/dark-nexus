#include "../include/dark_nexus.hpp"

void osint_scan(const std::string& username) {
    print_header("OSINT // " + username);

    struct Site { std::string name, url, dead, cat; };
    static const std::vector<Site> sites = {
        {"Instagram",   "https://www.instagram.com/{}/",          "page isn't available",  "social"},
        {"TikTok",      "https://www.tiktok.com/@{}/",            "couldn't find",         "social"},
        {"Twitter/X",   "https://twitter.com/{}/",                "doesn't exist",         "social"},
        {"Reddit",      "https://www.reddit.com/user/{}/",        "page not found",        "social"},
        {"VK",          "https://vk.com/{}/",                     "not found",             "social"},
        {"Pinterest",   "https://www.pinterest.com/{}/",          "not found",             "social"},
        {"Tumblr",      "https://{}.tumblr.com/",                 "not found",             "social"},
        {"Flickr",      "https://www.flickr.com/people/{}/",      "not found",             "social"},
        {"GitHub",      "https://github.com/{}/",                 "not found",             "dev"},
        {"GitLab",      "https://gitlab.com/{}/",                 "not found",             "dev"},
        {"Replit",      "https://replit.com/@{}/",                "not found",             "dev"},
        {"HackerOne",   "https://hackerone.com/{}/",              "not found",             "dev"},
        {"Pastebin",    "https://pastebin.com/u/{}/",             "not found",             "dev"},
        {"Bugcrowd",    "https://bugcrowd.com/{}/",               "not found",             "dev"},
        {"HackerNews",  "https://news.ycombinator.com/user?id={}", "no such user",         "dev"},
        {"Steam",       "https://steamcommunity.com/id/{}/",      "error",                 "gaming"},
        {"Twitch",      "https://www.twitch.tv/{}/",              "not found",             "gaming"},
        {"Minecraft",   "https://namemc.com/profile/{}/",         "not found",             "gaming"},
        {"Roblox",      "https://www.roblox.com/user.aspx?username={}", "not found",       "gaming"},
        {"Chess.com",   "https://www.chess.com/member/{}/",       "not found",             "gaming"},
        {"Telegram",    "https://t.me/{}/",                       "if you have telegram",  "msg"},
        {"Keybase",     "https://keybase.io/{}/",                 "not found",             "msg"},
        {"Medium",      "https://medium.com/@{}/",                "not found",             "blog"},
        {"Dev.to",      "https://dev.to/{}/",                     "not found",             "blog"},
        {"Hashnode",    "https://hashnode.com/@{}/",              "not found",             "blog"},
        {"Substack",    "https://{}.substack.com/",               "not found",             "blog"},
        {"Spotify",     "https://open.spotify.com/user/{}/",      "not found",             "music"},
        {"SoundCloud",  "https://soundcloud.com/{}/",             "not found",             "music"},
        {"Bandcamp",    "https://{}.bandcamp.com/",               "not found",             "music"},
        {"Last.fm",     "https://www.last.fm/user/{}/",           "not found",             "music"},
        {"LinkedIn",    "https://www.linkedin.com/in/{}/",        "not found",             "other"},
        {"Gravatar",    "https://en.gravatar.com/{}/",            "not found",             "other"},
        {"Letterboxd",  "https://letterboxd.com/{}/",             "not found",             "other"},
        {"Goodreads",   "https://www.goodreads.com/user/show/{}/","not found",             "other"},
        {"Strava",      "https://www.strava.com/athletes/{}/",    "not found",             "other"},
        {"Dribbble",    "https://dribbble.com/{}/",               "not found",             "other"},
        {"Behance",     "https://www.behance.net/{}/",            "not found",             "other"},
        {"ProductHunt", "https://www.producthunt.com/@{}/",       "not found",             "other"},
        {"Trakt",       "https://trakt.tv/users/{}/",             "not found",             "other"},
        {"Wattpad",     "https://www.wattpad.com/user/{}/",       "not found",             "other"},
    };

    std::cout<<YELLOW<<"  checking "<<sites.size()<<" platforms...\n\n"<<RESET;
    std::vector<std::pair<std::string,std::string>> found;
    std::mutex fm;
    std::atomic<int> done_c(0);
    int total=sites.size();

    ThreadPool pool(sites.size());
    std::vector<std::future<void>> futs; futs.reserve(total);

    for(auto& s:sites){
        futs.push_back(pool.submit([&,s]{
            std::string url=s.url;
            auto pos=url.find("{}"); if(pos!=std::string::npos) url.replace(pos,2,username);
            std::string body=safe_curl(url,6);
            std::string bl=body;
            std::transform(bl.begin(),bl.end(),bl.begin(),::tolower);
            bool hit=!body.empty()&&bl.find(s.dead)==std::string::npos;
            done_c++;
            std::lock_guard<std::mutex> lk(g_print_mtx);
            if(hit){
                std::cout<<"\r"<<GREEN<<"  [+] "<<std::left<<std::setw(14)<<s.name<<GRAY<<"["<<s.cat<<"]  "<<CYAN<<url<<"\n"<<RESET;
                std::lock_guard<std::mutex> fl(fm);
                found.push_back({s.name,url});
                g_result.osint_hits.push_back(url);
            } else {
                std::cout<<"\r"<<RED<<"  [-] "<<std::left<<std::setw(14)<<s.name<<GRAY<<"["<<s.cat<<"]"<<RESET<<"\n";
            }
            draw_progress(done_c,total,std::to_string(found.size())+" found");
        }));
    }
    for(auto& f:futs) f.get();

    std::cout<<"\n"<<CYAN<<"\n  found "<<found.size()<<"/"<<sites.size()<<" accounts\n"<<RESET;

    print_section("WEB MENTIONS");
    std::cout<<YELLOW<<"  searching...\n"<<RESET;
    auto ddg=safe_curl("https://html.duckduckgo.com/html/?q=%22"+username+"%22",10);
    if(!ddg.empty()){
        std::string marker="href=\""; size_t p=0; int cnt=0;
        while((p=ddg.find(marker,p))!=std::string::npos&&cnt<8){
            p+=marker.size(); auto end=ddg.find('"',p); if(end==std::string::npos) break;
            std::string url=ddg.substr(p,end-p);
            if(url.find("http")==0&&url.find("duckduckgo")==std::string::npos){
                std::cout<<CYAN<<"  "<<sanitize(url)<<"\n"<<RESET; cnt++;
            }
            p=end;
        }
        if(cnt==0) std::cout<<GRAY<<"  no public mentions\n"<<RESET;
    }
    LOG_INFO("osint","done username="+username+" found="+std::to_string(found.size()));
}
