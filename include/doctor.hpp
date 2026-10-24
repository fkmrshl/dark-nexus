#pragma once

#include "environment.hpp"
#include <iosfwd>
#include <string>
#include <vector>

namespace doctor {

struct Check {
    std::string id, status, detail, remedy;
    std::vector<std::string> workflows;
};

struct Report {
    std::vector<Check> checks;
    std::string status() const;
    int exit_code() const;
};

Report inspect(const environment::Context& context);
bool write_text(const Report& report, std::ostream& output);
bool write_json(const Report& report, std::ostream& output);

} // namespace doctor
