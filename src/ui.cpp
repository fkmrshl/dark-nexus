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
    if (total<=0) return;
    int w=std::min(term_width()-20,50);
    int filled=(int)((double)done/total*w);
    std::string bar(filled,'=');
    if(filled<w) bar+='>';
    bar+=std::string(std::max(0,w-filled-1),' ');
    int pct=(int)((double)done/total*100);
    std::cout<<"\r"<<BLOOD_RED<<"  ["<<BLOOD_RED<<bar<<BLOOD_RED<<"] "<<WHITE<<std::setw(3)<<pct<<"% "<<WHITE<<label<<RESET<<std::flush;
}

void print_sep() {
    std::cout<<BLOOD_RED<<"  "<<std::string(58,'=')<<RESET<<"\n";
}

void print_header(const std::string& title) {
    std::cout<<"\n"<<BLOOD_RED<<BOLD<<"  +"<<std::string(58,'-')<<"+\n"
             <<"  |  "<<WHITE<<std::left<<std::setw(56)<<title<<BLOOD_RED<<"|\n"
             <<"  +"<<std::string(58,'-')<<"+\n"<<RESET;
}

void print_section(const std::string& title) {
    int pad=std::max(0,46-(int)title.size());
    std::cout<<"\n"<<BLOOD_RED<<BOLD<<"  -- "<<WHITE<<title<<BLOOD_RED<<" "<<std::string(pad,'-')<<RESET<<"\n";
}

void print_row(const std::string& label, const std::string& val) {
    if(val.empty()||val=="null") return;
    std::cout<<BLOOD_RED<<"  ["<<WHITE<<std::left<<std::setw(16)<<label<<BLOOD_RED<<"] "<<RESET<<sanitize(val)<<"\n";
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
