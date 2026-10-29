#pragma once

#include <optional>
#include <string>

namespace environment {

struct Context {
    std::optional<std::string> path;
    std::string home;
    std::string executable;
};

Context current();
bool executable_file(const std::string& path);
bool readable_wordlist(const std::string& path);
std::string find_in_path(const std::string& name, const Context& context);
// Known locations only: never invokes locate or another subprocess.
std::string find_wordlist(const Context& context);

} // namespace environment
