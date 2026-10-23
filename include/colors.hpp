#pragma once

#include "terminal.hpp"

// Keep the existing module API while applying one restrained terminal palette.
#define RESET     terminal::style(terminal::Style::Reset)
#define RED       terminal::style(terminal::Style::Accent)
#define BLOOD_RED terminal::style(terminal::Style::Accent)
#define GREEN     terminal::style(terminal::Style::Success)
#define YELLOW    terminal::style(terminal::Style::Warning)
#define MAGENTA   terminal::style(terminal::Style::Accent)
#define CYAN      terminal::style(terminal::Style::Accent)
#define WHITE     terminal::style(terminal::Style::Text)
#define BOLD      terminal::style(terminal::Style::Strong)
#define DIM       terminal::style(terminal::Style::Muted)
#define GRAY      terminal::style(terminal::Style::Muted)
