#include "../include/dark_nexus.hpp"
#include "../include/security.hpp"
#include "../include/output.hpp"

std::string now_str() {
    time_t t=time(nullptr); char buf[32];
    strftime(buf,sizeof(buf),"%Y-%m-%d %H:%M:%S",localtime(&t));
    return buf;
}

void export_json(const std::string& fname) {
    if (!InputGuard::is_safe_path(fname) && fname.find('/') != 0) {
        std::cout << BLOOD_RED << "  invalid filename\n" << RESET;
        return;
    }
    OutputWriter::write_json(g_result, fname);
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
    if (total <= 0 || !terminal::interactive()) return;
    int pct = std::clamp(static_cast<int>(100.0 * done / total), 0, 100);
    std::cout << "\r\033[2K  " << CYAN << std::setw(3) << pct << "%"
              << RESET << "  " << label << std::flush;
}

void print_sep() {
    std::cout << '\n';
}

void print_header(const std::string& title) {
    std::cout << '\n' << CYAN << BOLD << title << RESET << '\n';
}

void print_section(const std::string& title) {
    std::cout << '\n' << BOLD << title << RESET << '\n';
}

void print_row(const std::string& label, const std::string& val) {
    if(val.empty()||val=="null") return;
    std::cout << "  " << std::left << std::setw(18) << label << sanitize(val) << '\n';
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
