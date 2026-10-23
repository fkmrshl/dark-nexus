#include "port_scan_engine.hpp"
#include "port_probe.hpp"
#include "port_enrich.hpp"
#include "port_vuln.hpp"
#include "os_fingerprint.hpp"
#include <sys/resource.h>

// Exercise the real scanner and worker pools with deterministic network stubs.
// No DNS lookups, sockets or external services are used by this executable.
ScanResult g_result;
std::mutex g_print_mtx, g_result_mtx;
CancellationToken g_cancel_token;
static std::atomic<int> calibrations{0}, syns{0}, connects{0}, banners{0}, http{0}, tls{0}, combined{0};
static std::atomic<int> timeout_seen{0}, retries_seen{0}, banner_timeout_seen{0}, active{0}, peak{0};
static int calibration_timeout_seen = 0;
static std::vector<int> calibration_ports_seen;
static bool delay_connect = false;
static void work() {
    const int count = ++active;
    int previous = peak.load();
    while (previous < count && !peak.compare_exchange_weak(previous, count)) {}
    std::this_thread::sleep_for(std::chrono::milliseconds(3));
    --active;
}
std::string resolve_for_scan(const std::string& target, ScanAddrFamily) { return target; }
bool port_scan_is_v6(const std::string&) { return false; }
AdaptiveConfig calibrate_port_target(const std::string&, const std::vector<int>& ports, int timeout) {
    ++calibrations;
    calibration_ports_seen = ports;
    calibration_timeout_seen = timeout;
    return {1000, 2000, 2, 100, 10};
}
std::pair<int,bool> port_probe_connect(const std::string&, int, int timeout, int retries) {
    ++connects; timeout_seen = timeout; retries_seen = retries;
    if (delay_connect) work();
    return {1,false};
}
std::pair<int,bool> port_probe_syn(const std::string&, int, int timeout, int retries) {
    ++syns; timeout_seen = timeout; retries_seen = retries; return {1,false};
}
std::pair<int,bool> port_probe_udp_smart(const std::string&, int, int) { return {1,false}; }
std::string smart_banner(const std::string&, int, int timeout, bool) {
    ++banners; banner_timeout_seen = timeout; work(); return "service banner";
}
bool port_is_tls_http_port(int p) { return p == 443; }
bool port_is_http_candidate(int p) { return p == 80 || p == 443; }
bool port_is_tls_candidate(int p) { return p == 443; }
int port_service_priority(int) { return 1; }
std::string port_extract_version(const std::string&, int) { return {}; }
bool port_banner_usable(const std::string& s) { return !s.empty(); }
std::string port_resolve_sni_host(const std::string&) { return {}; }
std::string ptr_lookup(const std::string&) { return {}; }
std::string svc(int) { return "test"; }
std::string risk_label(int) { return "LOW"; }
std::string sanitize(const std::string& s) { return s; }
void print_section(const std::string&) {}
void print_header(const std::string&) {}
void draw_progress(int,int,const std::string&) {}
TLSInfo port_inspect_tls(const std::string&,int,int timeout,const std::string&) {
    ++tls; banner_timeout_seen = timeout; return {};
}
TlsHttpResult port_probe_tls_http(const std::string&,int,int timeout,const std::string&,int) {
    ++combined; banner_timeout_seen = timeout; return {};
}
HttpInfo port_probe_http(const std::string&,int,int timeout,bool,const std::string&) {
    ++http; banner_timeout_seen = timeout; return {};
}
std::string port_probe_redis_ping(const std::string&,int,int) { return {}; }
std::string port_probe_mongo_ping(const std::string&,int,int) { return {}; }
std::string port_probe_ssh_banner(const std::string&,int,int) { return {}; }
std::string port_probe_ftp_banner(const std::string&,int,int) { return {}; }
std::string port_probe_smtp_banner(const std::string&,int,int) { return {}; }
std::string port_probe_mysql_banner(const std::string&,int,int) { return {}; }
std::string port_probe_postgres_banner(const std::string&,int,int) { return {}; }
void print_port_http_enrichment(const HttpInfo&) {}
void print_port_powered_by_line(const HttpInfo&) {}
void print_port_stack_disclosures(const ScanResults&) {}
void print_port_tls_enrichment(const TLSInfo&) {}
bool port_vuln_is_significant(const std::string&) { return false; }
std::vector<VulnHint> check_port_vulns(int,const std::string&,const std::string&,const TLSInfo*,const HttpInfo*) { return {}; }
std::vector<VulnHint> dedupe_port_vulns(std::vector<VulnHint> values) { return values; }
OsPortSignal make_os_port_signal(int,const std::string&,const std::string&,bool) { return {}; }
OsFingerprintResult fingerprint_os(const OsFingerprintInput&) { return {}; }
static void reset() {
    syns=0; connects=0; banners=0; http=0; tls=0; combined=0; timeout_seen=0;
    retries_seen=0; banner_timeout_seen=0; active=0; peak=0;
    calibration_timeout_seen=0; calibration_ports_seen.clear();
    g_result=ScanResult{};
}
int main() {
    int checks=0, failures=0;
    auto check = [&](bool condition,const char* name) {
        ++checks; if (!condition) { ++failures; std::cerr << "FAIL: " << name << '\n'; }
    };
    terminal::configure(terminal::ColorMode::Never);
    std::ostringstream output;
    auto* previous = std::cout.rdbuf(output.rdbuf());
    PortScanOverrides overrides;
    overrides.threads=1; overrides.timeout_ms=77; overrides.banner_timeout_ms=88;
    overrides.retries=0; overrides.connect=true; overrides.tls=false; overrides.http=false;
    port_scan("127.0.0.1",0,0,false,5,{},ScanAddrFamily::Auto,{22,23,80,443,8000},overrides);
    check(connects==5 && syns==0,"connect override selects connect probes");
    check(timeout_seen==77 && retries_seen==0,"explicit timeout/retries override T5 calibration");
    check(banner_timeout_seen==88,"explicit banner timeout overrides T5 calibration");
    check(http==0 && banners==2,"no-http suppresses HTTP and HTTP smart-banner path");
    check(tls==0 && combined==0,"no-tls suppresses standalone and combined TLS");
    check(peak==1,"one worker also limits deep analysis");
    check(calibration_ports_seen==std::vector<int>({22,23,80,443,8000}),
          "calibration is restricted to the explicitly selected ports");
    check(calibration_timeout_seen==77,"explicit timeout also applies to calibration");
    reset();
    overrides=PortScanOverrides{};
    port_scan("127.0.0.1",0,0,false,3,{},ScanAddrFamily::Auto,{80,443},overrides);
    check(syns==2 && connects==0,"default keeps SYN discovery");
    check(http==1 && banners==1 && combined==1,"default preserves HTTP and TLS enrichment");
    check(calibration_timeout_seen==800,"default calibration timeout is 800 ms");
    reset();
    overrides.threads=16; overrides.http=false;
    port_scan("127.0.0.1",0,0,false,4,{},ScanAddrFamily::Auto,{443},overrides);
    check(tls==1 && combined==0 && http==0,"no-http preserves independent TLS inspection");
    const int calibration_count = calibrations;
    std::set<int> exclude;
    for(int port=1;port<=65535;++port) exclude.insert(port);
    try {
        port_scan("127.0.0.1",0,0,false,3,exclude,ScanAddrFamily::Auto,{},{});
        check(false,"empty preset selection rejected");
    } catch(const std::invalid_argument&) {
        check(calibrations==calibration_count,"empty preset selection rejects before calibration");
    }
    reset();
    overrides=PortScanOverrides{}; overrides.http=false; overrides.tls=false;
    port_scan("127.0.0.1",0,0,false,3,{23,80},ScanAddrFamily::Auto,{22,23,80,443,8000},overrides);
    check(calibration_ports_seen==std::vector<int>({22,443,8000}),
          "excluded ports are removed before calibration");
    reset();
    const int before_udp = calibrations;
    port_scan("127.0.0.1",0,0,true,3,{},ScanAddrFamily::Auto,{53},overrides);
    check(calibrations==before_udp && syns==0 && connects==0,
          "UDP scanning never performs TCP calibration or TCP discovery");
    reset();
    // Lower only this test process's soft limit and restore it after the check.
    struct rlimit original{};
    if (getrlimit(RLIMIT_NOFILE,&original)==0 && original.rlim_cur>=53) {
        struct rlimit limited=original;
        limited.rlim_cur=53;
        if (setrlimit(RLIMIT_NOFILE,&limited)==0) {
            overrides=PortScanOverrides{}; overrides.threads=512; overrides.connect=true;
            overrides.http=false; overrides.tls=false; delay_connect=true;
            port_scan("127.0.0.1",0,0,false,5,{},ScanAddrFamily::Auto,{22,23,24,26},overrides);
            delay_connect=false;
            setrlimit(RLIMIT_NOFILE,&original);
            check(peak==1,"descriptor cap applies after explicit worker override, minimum one");
        }
    }
    std::cout.rdbuf(previous);
    std::cout << checks << " port flag integration checks, " << failures << " failures\n";
    return failures?1:0;
}
