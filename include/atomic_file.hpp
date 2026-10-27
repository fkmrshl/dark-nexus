#pragma once

#include <cerrno>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <string>
#include <unistd.h>
#include <vector>

inline bool write_atomic_file(const std::string& filename, const std::string& content,
                              std::string& error) {
    if (filename.empty() || filename.find('\0') != std::string::npos) {
        error = "invalid output filename";
        return false;
    }
    std::string pattern = filename + ".tmp.XXXXXX";
    std::vector<char> temporary(pattern.begin(), pattern.end());
    temporary.push_back('\0');
    const int descriptor = mkstemp(temporary.data());
    if (descriptor < 0) {
        error = "cannot create output for " + filename + ": " + std::strerror(errno);
        return false;
    }
    bool success = fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0;
    int failure = success ? 0 : errno;
    std::size_t position = 0;
    while (success && position < content.size()) {
        const auto written = write(descriptor, content.data() + position, content.size() - position);
        if (written > 0) position += static_cast<std::size_t>(written);
        else if (written < 0 && errno == EINTR) continue;
        else { success = false; failure = written == 0 ? EIO : errno; }
    }
    if (success && fsync(descriptor) != 0) { success = false; failure = errno; }
    if (close(descriptor) != 0 && success) { success = false; failure = errno; }
    if (success && rename(temporary.data(), filename.c_str()) != 0) { success = false; failure = errno; }
    if (!success) {
        unlink(temporary.data());
        error = "cannot write " + filename + ": " + std::strerror(failure);
    }
    return success;
}
