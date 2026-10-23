#include "../include/terminal.hpp"

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <mutex>
#include <streambuf>
#include <unistd.h>

namespace terminal {
namespace {
std::atomic<bool> use_color{false};
std::atomic<bool> use_progress{false};
std::streambuf* raw_stdout = nullptr;

// Modules also contain literal cursor-control sequences. Filter those at the
// stream boundary so redirected output remains plain text. Only SGR is allowed
// when color is explicitly enabled on a pipe; cursor movement is never useful
// there. The parser keeps state between writes, including split ESC sequences.
class OutputBuffer final : public std::streambuf {
public:
    explicit OutputBuffer(std::streambuf* destination) : destination_(destination) {}

    void configure(bool color, bool controls) {
        std::lock_guard<std::mutex> lock(mutex_);
        color_ = color;
        controls_ = controls;
        state_ = State::Text;
        sequence_.clear();
    }

protected:
    int_type overflow(int_type value) override {
        if (traits_type::eq_int_type(value, traits_type::eof()))
            return traits_type::not_eof(value);
        std::lock_guard<std::mutex> lock(mutex_);
        return consume(traits_type::to_char_type(value)) ? value : traits_type::eof();
    }

    std::streamsize xsputn(const char* data, std::streamsize size) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (std::streamsize i = 0; i < size; ++i)
            if (!consume(data[i])) return i;
        return size;
    }

    int sync() override {
        std::lock_guard<std::mutex> lock(mutex_);
        return destination_->pubsync();
    }

private:
    enum class State { Text, Escape, Csi, String, StringEscape };

    bool emit(char value) {
        if (traits_type::eq_int_type(destination_->sputc(value), traits_type::eof()))
            return false;
        line_has_text_ = value != '\n';
        return true;
    }

    bool consume(char value) {
        const unsigned char byte = static_cast<unsigned char>(value);
        switch (state_) {
            case State::Escape:
                if (value == '[') { sequence_ += value; state_ = State::Csi; }
                else if (value == ']' || value == 'P' || value == '_' || value == '^')
                    state_ = State::String;
                else { state_ = State::Text; sequence_.clear(); }
                return true;
            case State::Csi:
                // Bound memory for malformed or untrusted terminal sequences.
                if (sequence_.size() < 128) sequence_ += value;
                if (byte >= 0x40 && byte <= 0x7e) {
                    bool success = true;
                    if (color_ && value == 'm')
                        success = destination_->sputn(sequence_.data(), sequence_.size())
                            == static_cast<std::streamsize>(sequence_.size());
                    else if (controls_)
                        success = destination_->sputn(sequence_.data(), sequence_.size())
                            == static_cast<std::streamsize>(sequence_.size());
                    state_ = State::Text;
                    sequence_.clear();
                    return success;
                }
                return true;
            case State::String:
                if (byte == 7) state_ = State::Text;
                else if (byte == 27) state_ = State::StringEscape;
                return true;
            case State::StringEscape:
                state_ = value == '\\' ? State::Text : State::String;
                return true;
            case State::Text:
                break;
        }
        if (byte == 27) { sequence_ = "\033"; state_ = State::Escape; return true; }
        if (value == '\r' && !controls_) {
            // A completed result may start with CR to clear a progress line.
            // Preserve its text, separating any preceding partial status line.
            if (!line_has_text_) return true;
            const bool success = emit('\n');
            emitted_cr_newline_ = true;
            return success;
        }
        if (!controls_ && emitted_cr_newline_) {
            emitted_cr_newline_ = false;
            if (value == '\n') return true;
        }
        return emit(value);
    }

    std::streambuf* destination_;
    std::mutex mutex_;
    State state_ = State::Text;
    std::string sequence_;
    bool color_ = false;
    bool controls_ = false;
    bool line_has_text_ = false;
    bool emitted_cr_newline_ = false;
};

struct OutputSession {
    std::streambuf* original_out = std::cout.rdbuf();
    std::streambuf* original_err = std::cerr.rdbuf();
    OutputBuffer out{original_out};
    OutputBuffer err{original_err};

    OutputSession() {
        raw_stdout = original_out;
        std::cout.rdbuf(&out);
        std::cerr.rdbuf(&err);
    }
    ~OutputSession() {
        // Quiet mode may have replaced the buffer. Avoid dereferencing it here.
        out.pubsync();
        err.pubsync();
        std::cout.rdbuf(original_out);
        std::cerr.rdbuf(original_err);
    }
};
} // namespace

void configure(ColorMode mode) {
    static OutputSession session;
    const char* term = std::getenv("TERM");
    const bool capable = !term || std::strcmp(term, "dumb") != 0;
    const bool tty = isatty(STDOUT_FILENO) != 0 && capable;
    const bool color = mode == ColorMode::Always ||
        (mode == ColorMode::Auto && tty && std::getenv("NO_COLOR") == nullptr);
    use_color.store(color, std::memory_order_relaxed);
    use_progress.store(tty && color, std::memory_order_relaxed);
    session.out.configure(color, tty && color);
    session.err.configure(color, isatty(STDERR_FILENO) != 0 && capable && color);
}

bool interactive() { return use_progress.load(std::memory_order_relaxed); }
bool color_enabled() { return use_color.load(std::memory_order_relaxed); }
std::streambuf* stdout_buffer() { return raw_stdout ? raw_stdout : std::cout.rdbuf(); }

const char* style(Style value) {
    if (!color_enabled()) return "";
    switch (value) {
        case Style::Reset: return "\033[0m";
        case Style::Accent: return "\033[36m";
        case Style::Success: return "\033[36m";
        case Style::Warning: return "\033[33m";
        case Style::Strong: return "\033[1m";
        case Style::Muted: return "\033[2m";
        case Style::Text: return "\033[0m";
    }
    return "";
}
} // namespace terminal
