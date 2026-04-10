include "modules.hpp"

std::string resolve(const std::string& host) {
    addrinfo hints{}, *res;
    hints.ai_family = AF_INET;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0) return "";
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &((sockaddr_in*)res->ai_addr)->sin_addr, buf, sizeof(buf));
    freeaddrinfo(res);
    return buf;
}

bool tcp_probe(const std::string& ip, int port, int ms = 500) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;
    timeval tv{ms / 1000, (ms % 1000) * 1000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
    fcntl(fd, F_SETFL, O_NONBLOCK);
    connect(fd, (sockaddr*)&sa, sizeof(sa));
    fd_set fds; FD_ZERO(&fds); FD_SET(fd, &fds);
    int r = select(fd + 1, nullptr, &fds, nullptr, &tv);
    close(fd);
    return r > 0;
}
