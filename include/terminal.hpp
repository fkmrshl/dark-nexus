#pragma once

#include <iosfwd>

namespace terminal {

enum class ColorMode { Auto, Always, Never };
enum class Style { Reset, Accent, Success, Warning, Strong, Muted, Text, Value };

// Configure before writing output or starting worker threads. Auto respects
// NO_COLOR, TERM=dumb and whether stdout is connected to a terminal.
void configure(ColorMode mode = ColorMode::Auto);
bool interactive();
bool color_enabled();
const char* style(Style value);
// Machine reports bypass terminal filtering, preserving embedded CR/LF in CSV.
std::streambuf* stdout_buffer();

} // namespace terminal
