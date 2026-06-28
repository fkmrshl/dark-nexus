#include "../include/osint.hpp"

namespace osint {

static const std::vector<Site> SITES = {
    {"Instagram", "https://www.instagram.com/{}/", "page isn't available", "social", 5, {"og:title", "instagram.com/{}"}},
    {"TikTok", "https://www.tiktok.com/@{}/", "couldn't find", "social", 5, {"@{}", "tiktok.com"}},
    {"Twitter/X", "https://twitter.com/{}/", "doesn't exist", "social", 5, {"twitter.com/{}"}},
    {"Reddit", "https://www.reddit.com/user/{}/", "page not found", "social", 4, {"u/{}"}},
    {"VK", "https://vk.com/{}/", "not found", "social", 3, {"vk.com/{}"}},
    {"Facebook", "https://www.facebook.com/{}/", "isn't available", "social", 4, {"facebook.com/{}"}},
    {"Pinterest", "https://www.pinterest.com/{}/", "not found", "social", 3, {"pinterest.com/{}"}},
    {"Tumblr", "https://{}.tumblr.com/", "not found", "social", 2, {"tumblr.com"}},
    {"Flickr", "https://www.flickr.com/people/{}/", "not found", "social", 2, {"flickr.com"}},
    {"GitHub", "https://github.com/{}/", "not found", "dev", 5, {"github.com/{}", "repositories"}},
    {"GitLab", "https://gitlab.com/{}/", "not found", "dev", 4, {"gitlab.com/{}"}},
    {"HackerOne", "https://hackerone.com/{}/", "not found", "dev", 3, {"hackerone.com"}},
    {"Bugcrowd", "https://bugcrowd.com/{}/", "not found", "dev", 3, {"bugcrowd.com"}},
    {"Pastebin", "https://pastebin.com/u/{}/", "not found", "dev", 2, {"pastebin.com/u/{}"}},
    {"HackerNews", "https://news.ycombinator.com/user?id={}", "no such user", "dev", 3, {"user?id={}"}},
    {"Bitbucket", "https://bitbucket.org/{}/", "not found", "dev", 3, {"bitbucket.org/{}"}},
    {"npm", "https://www.npmjs.com/~{}/", "not found", "dev", 3, {"npmjs.com"}},
    {"PyPI", "https://pypi.org/user/{}/", "not found", "dev", 3, {"pypi.org/user/{}"}},
    {"DockerHub", "https://hub.docker.com/u/{}/", "not found", "dev", 3, {"hub.docker.com/u/{}"}},
    {"Steam", "https://steamcommunity.com/id/{}/", "error", "gaming", 4, {"steamcommunity.com/id/{}"}},
    {"Twitch", "https://www.twitch.tv/{}/", "not found", "gaming", 4, {"twitch.tv/{}"}},
    {"Chess.com", "https://www.chess.com/member/{}/", "not found", "gaming", 3, {"chess.com/member/{}"}},
    {"Lichess", "https://lichess.org/@{}/", "not found", "gaming", 3, {"lichess.org"}},
    {"Faceit", "https://www.faceit.com/en/players/{}/", "not found", "gaming", 3, {"faceit.com"}},
    {"Telegram", "https://t.me/{}/", "if you have telegram", "msg", 5, {"t.me/{}", "telegram"}},
    {"Keybase", "https://keybase.io/{}/", "not found", "msg", 3, {"keybase.io/{}"}},
    {"Medium", "https://medium.com/@{}/", "not found", "blog", 4, {"medium.com/@{}"}},
    {"Dev.to", "https://dev.to/{}/", "not found", "blog", 3, {"dev.to/{}"}},
    {"Substack", "https://{}.substack.com/", "not found", "blog", 3, {"substack.com"}},
    {"Spotify", "https://open.spotify.com/user/{}/", "not found", "music", 3, {"spotify.com"}},
    {"SoundCloud", "https://soundcloud.com/{}/", "not found", "music", 4, {"soundcloud.com/{}"}},
    {"Last.fm", "https://www.last.fm/user/{}/", "not found", "music", 3, {"last.fm/user/{}"}},
    {"LinkedIn", "https://www.linkedin.com/in/{}/", "not found", "other", 5, {"linkedin.com/in/{}"}},
    {"Gravatar", "https://en.gravatar.com/{}/", "not found", "other", 2, {"gravatar.com"}},
    {"Letterboxd", "https://letterboxd.com/{}/", "not found", "other", 3, {"letterboxd.com/{}"}},
    {"Strava", "https://www.strava.com/athletes/{}/", "not found", "other", 3, {"strava.com"}},
    {"Dribbble", "https://dribbble.com/{}/", "not found", "other", 3, {"dribbble.com/{}"}},
    {"Linktree", "https://linktr.ee/{}/", "sorry", "other", 3, {"linktr.ee/{}"}},
    {"Patreon", "https://www.patreon.com/{}/", "not found", "other", 3, {"patreon.com/{}"}}
};

static void add_internal_platform_graph_record(IdentityGraph& graph, const Hit& hit) {
    if (hit.url.empty()) return;

    GraphNode& platform_node = add_graph_node(graph, GraphNodeType::Platform, hit.name, EvidenceStatus::Observed, hit.confidence);
    std::string platform_id = platform_node.id;
    GraphNode& account_node = add_graph_node(graph, GraphNodeType::Account, hit.url, EvidenceStatus::Observed, hit.confidence);
    std::string account_id = account_node.id;

    Evidence evidence;
    evidence.type = EvidenceType::InternalHttp;
    evidence.status = EvidenceStatus::Observed;
    evidence.source = "internal";
    evidence.url = hit.url;
    evidence.detail = hit.evidence.empty() ? hit.name : hit.evidence;
    evidence.confidence = hit.confidence;
    evidence.certainty = hit.certainty;
    Evidence& added_evidence = add_graph_evidence(graph, evidence);

    add_graph_edge(graph, account_id, platform_id, GraphEdgeType::AccountOnPlatform, {added_evidence.id}, EvidenceStatus::Observed, hit.confidence, hit.certainty);
}

void run_platform_scan(const std::string& username, IdentityGraph& graph) {
    if (!InputGuard::is_valid_username(username)) {
        std::cout << BLOOD_RED << "  [!] invalid username for platform scan\n" << RESET;
        return;
    }

    std::atomic<int> done(0);
    int total = static_cast<int>(SITES.size());
    std::mutex graph_mutex;

    std::cout << BLOOD_RED << "  scanning " << WHITE << total << BLOOD_RED << " platforms" << RESET;
    std::cout.flush();

    ThreadPool pool(std::min(total, 40));
    std::vector<std::future<void>> futures;
    futures.reserve(total);

    for (const auto& site : SITES) {
        if (g_cancel_token.cancelled) break;

        futures.push_back(pool.submit([&, site] {
            if (g_cancel_token.cancelled) {
                ++done;
                return;
            }

            std::string url = fill_template(site.url, username);
            if (!InputGuard::is_safe_url(url)) {
                ++done;
                return;
            }

            HttpFetchResult fetch = safe_curl_detailed(url, 7);
            std::string body = fetch.body;
            std::string lowered = lower_copy(body);
            std::string dead = lower_copy(site.dead);
            bool fetched = fetch.success && !fetch.blocked_or_error;
            bool missing_dead_marker = fetched && lowered.find(dead) == std::string::npos;

            std::vector<std::string> markers;
            std::string evidence;
            for (const auto& marker : site.positive_markers) {
                std::string expected = lower_copy(fill_template(marker, username));
                if (!lowered.empty() && lowered.find(expected) != std::string::npos) {
                    markers.push_back(marker);
                    if (evidence.empty()) evidence = marker;
                }
            }

            double confidence = score_hit(fetched, missing_dead_marker, markers, site.weight);
            if (confidence >= 0.60) {
                Hit hit;
                hit.name = site.name;
                hit.url = url;
                hit.category = site.category;
                hit.evidence = evidence.empty() ? "http response heuristic" : evidence;
                hit.source = "internal";
                hit.confidence = confidence;
                hit.certainty = certainty_from_score(confidence);

                std::lock_guard<std::mutex> lock(graph_mutex);
                add_internal_platform_graph_record(graph, hit);
                add_graph_hit(graph, hit);
            }

            int current = ++done;
            if (current % 10 == 0) {
                std::lock_guard<std::mutex> lock(g_print_mtx);
                std::cout << "." << std::flush;
            }
        }));
    }

    for (auto& future : futures) future.get();
    std::cout << " done\n";
}

}
