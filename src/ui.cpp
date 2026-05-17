#include "../include/dark_nexus.hpp"
#include "../include/security.hpp"

std::string now_str() {
    time_t t=time(nullptr); char buf[32];
    strftime(buf,sizeof(buf),"%Y-%m-%d %H:%M:%S",localtime(&t));
    return buf;
}

void export_json(const std::string& fname) {
    if (fname.find('/') != std::string::npos || fname.find("..") != std::string::npos) {
        std::cout << RED << "  invalid filename\n" << RESET;
        return;
    }

    std::ofstream f(fname);
    if (!f.is_open()) {
        std::cout << RED << "  [!] failed to open file for writing: " << fname << "\n" << RESET;
        LOG_ERR("export", "failed to open file: " + fname);
        return;
    }

    f << "{\n  \"target\":\"" << SafeJson::escape(g_result.target) << "\",\n";
    f << "  \"timestamp\":\"" << SafeJson::escape(g_result.timestamp) << "\",\n";

    f << "  \"geo\":{\"country\":\"" << SafeJson::escape(g_result.geo_country)
    << "\",\"city\":\"" << SafeJson::escape(g_result.geo_city)
    << "\",\"isp\":\"" << SafeJson::escape(g_result.geo_isp)
    << "\",\"as\":\"" << SafeJson::escape(g_result.geo_as)
    << "\",\"proxy\":" << (g_result.proxy ? "true" : "false")
    << ",\"hosting\":" << (g_result.hosting ? "true" : "false") << "},\n";

    f << "  \"os\":\"" << SafeJson::escape(g_result.os_guess) << "\",\n";

    f << "  \"open_ports\":[\n";
    for (size_t i = 0; i < g_result.open_ports.size(); i++) {
        f << "    {\"port\":" << g_result.open_ports[i].first
        << ",\"service\":\"" << SafeJson::escape(g_result.open_ports[i].second) << "\"}";
        if (i + 1 < g_result.open_ports.size()) f << ",";
        f << "\n";
    }

    f << "  ],\n  \"subdomains\":[";
    for (size_t i = 0; i < g_result.subdomains.size(); i++) {
        f << "\"" << SafeJson::escape(g_result.subdomains[i]) << "\"";
        if (i + 1 < g_result.subdomains.size()) f << ",";
    }

    f << "],\n  \"osint\":[";
    for (size_t i = 0; i < g_result.osint_hits.size(); i++) {
        f << "\"" << SafeJson::escape(g_result.osint_hits[i]) << "\"";
        if (i + 1 < g_result.osint_hits.size()) f << ",";
    }

    f << "]\n}\n";

    std::cout << RED << "  saved: " << fname << "\n" << RESET;
    LOG_INFO("export", "json saved: " + fname);
}

std::string json_val(const std::string& json, const std::string& key) {
    auto pos=json.find("\""+key+"\"");
    if(pos==std::string::npos) return "";
    pos=json.find(':',pos); if(pos==std::string::npos) return "";
    while(++pos<json.size()&&(json[pos]==' '||json[pos]=='\t'));
    if(pos>=json.size()) return "";
    if(json[pos]=='"'){
        pos++;
        auto end=json.find('"',pos);
        return end==std::string::npos?"":json.substr(pos,end-pos);
    }
    auto end=json.find_first_of(",}\n",pos);
    std::string v=json.substr(pos,(end==std::string::npos?json.size():end)-pos);
    while(!v.empty()&&(v.back()==' '||v.back()=='\r'||v.back()=='\n')) v.pop_back();
    return v;
}

int term_width() {
    struct winsize w;
    if (ioctl(STDOUT_FILENO,TIOCGWINSZ,&w)==0&&w.ws_col>0) return w.ws_col;
    return 80;
}

void draw_progress(int done, int total, const std::string& label) {
    if (total<=0) return;
    int w=std::min(term_width()-20,50);
    int filled=(int)((double)done/total*w);
    std::string bar(filled,'=');
    if(filled<w) bar+='>';
    bar+=std::string(std::max(0,w-filled-1),' ');
    int pct=(int)((double)done/total*100);
    std::cout<<"\r"<<RED<<"  ["<<RED<<bar<<RED<<"] "<<WHITE<<std::setw(3)<<pct<<"% "<<WHITE<<label<<RESET<<std::flush;
}

void print_sep() {
    std::cout<<RED<<"  "<<std::string(58,'=')<<RESET<<"\n";
}

void print_header(const std::string& title) {
    std::cout<<"\n"<<RED<<BOLD<<"  +"<<std::string(58,'-')<<"+\n"
             <<"  |  "<<WHITE<<std::left<<std::setw(56)<<title<<RED<<"|\n"
             <<"  +"<<std::string(58,'-')<<"+\n"<<RESET;
}

void print_section(const std::string& title) {
    int pad=std::max(0,46-(int)title.size());
    std::cout<<"\n"<<RED<<BOLD<<"  -- "<<WHITE<<title<<RED<<" "<<std::string(pad,'-')<<RESET<<"\n";
}

void print_row(const std::string& label, const std::string& val) {
    if(val.empty()||val=="null") return;
    std::cout<<RED<<"  ["<<WHITE<<std::left<<std::setw(16)<<label<<RED<<"] "<<RESET<<sanitize(val)<<"\n";
}

std::vector<std::string> split_lines(const std::string& s) {
    std::vector<std::string> v;
    std::istringstream ss(s);
    std::string l;
    while(std::getline(ss,l)) if(!l.empty()) v.push_back(l);
    return v;
}

std::string dig_short(const std::string& domain, const std::string& type, int t) {
    return safe_exec({"dig","+short","+time=4","+tries=2",domain,type}, t);
}

std::string dig_full(const std::string& domain, const std::string& type, int t) {
    return safe_exec({"dig","+noall","+answer","+time=4","+tries=2",domain,type}, t);
}
