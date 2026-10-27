#include "process.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

extern char** environ;

namespace {
class Descriptor {
public:
    int fd = -1;
    ~Descriptor() { reset(); }
    void reset() { if (fd >= 0) close(fd); fd = -1; }
};

bool make_pipe(Descriptor& input, Descriptor& output) {
    int descriptors[2];
    if (pipe2(descriptors, O_CLOEXEC) != 0) return false;
    input.fd = descriptors[0]; output.fd = descriptors[1];
    // Spawn file actions must never accidentally close a redirected stdio fd.
    for (auto* descriptor : {&input, &output}) {
        if (descriptor->fd < 3) {
            const int moved = fcntl(descriptor->fd, F_DUPFD_CLOEXEC, 3);
            if (moved < 0) return false;
            descriptor->reset();
            descriptor->fd = moved;
        }
    }
    const int flags = fcntl(input.fd, F_GETFL);
    return flags >= 0 && fcntl(input.fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

void drain(Descriptor& stream, std::string& destination, ProcessResult& result,
           std::size_t cap) {
    char buffer[8192];
    // Bound work per iteration, including for helpers that continuously write.
    for (int attempt = 0; attempt < 8 && stream.fd >= 0; ++attempt) {
        const ssize_t count = read(stream.fd, buffer, sizeof(buffer));
        if (count > 0) {
            const auto available = cap - std::min(cap, destination.size());
            const auto copied = std::min(available, static_cast<std::size_t>(count));
            destination.append(buffer, copied);
            if (copied < static_cast<std::size_t>(count)) result.truncated = true;
        } else if (count == 0) stream.reset();
        else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) stream.reset();
        else if (errno != EINTR) break;
    }
}

class SpawnActions {
public:
    posix_spawn_file_actions_t actions{};
    posix_spawnattr_t attributes{};
    bool actions_ready = false, attributes_ready = false;
    ~SpawnActions() {
        if (actions_ready) posix_spawn_file_actions_destroy(&actions);
        if (attributes_ready) posix_spawnattr_destroy(&attributes);
    }
};
} // namespace

ProcessResult run_process(const std::vector<std::string>& args, int timeout_ms,
                          const std::atomic<bool>* cancel, std::size_t max_output) {
    ProcessResult result;
    if (cancel && cancel->load(std::memory_order_relaxed)) {
        result.cancelled = true;
        return result;
    }
    if (args.empty() || args.front().empty() || timeout_ms <= 0 ||
        std::any_of(args.begin(), args.end(), [](const std::string& value) {
            return value.find('\0') != std::string::npos;
        })) {
        result.err = "Invalid process arguments or deadline";
        return result;
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    Descriptor output, output_writer, errors, error_writer;
    if (!make_pipe(output, output_writer) || !make_pipe(errors, error_writer)) {
        result.err = std::string("Cannot create process pipes: ") + std::strerror(errno);
        return result;
    }
    SpawnActions spawn;
    int error = posix_spawn_file_actions_init(&spawn.actions);
    if (error == 0) spawn.actions_ready = true;
    if (error == 0) {
        error = posix_spawnattr_init(&spawn.attributes);
        if (error == 0) spawn.attributes_ready = true;
    }
    auto action = [&](int code) { if (!error) error = code; };
    if (!error) {
        action(posix_spawn_file_actions_addopen(&spawn.actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0));
        action(posix_spawn_file_actions_adddup2(&spawn.actions, output_writer.fd, STDOUT_FILENO));
        action(posix_spawn_file_actions_adddup2(&spawn.actions, error_writer.fd, STDERR_FILENO));
        for (const int fd : {output.fd, output_writer.fd, errors.fd, error_writer.fd})
            action(posix_spawn_file_actions_addclose(&spawn.actions, fd));
        sigset_t defaults, mask;
        sigemptyset(&defaults); sigemptyset(&mask);
        sigaddset(&defaults, SIGINT); sigaddset(&defaults, SIGTERM); sigaddset(&defaults, SIGPIPE);
        action(posix_spawnattr_setsigdefault(&spawn.attributes, &defaults));
        action(posix_spawnattr_setsigmask(&spawn.attributes, &mask));
        action(posix_spawnattr_setpgroup(&spawn.attributes, 0));
        action(posix_spawnattr_setflags(&spawn.attributes,
            POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK));
    }
    if (error) {
        result.err = std::string("Cannot prepare process: ") + std::strerror(error);
        return result;
    }
    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (const auto& argument : args) argv.push_back(const_cast<char*>(argument.c_str()));
    argv.push_back(nullptr);
    pid_t pid = -1;
    error = posix_spawnp(&pid, argv.front(), &spawn.actions, &spawn.attributes, argv.data(), environ);
    output_writer.reset(); error_writer.reset();
    if (error) {
        result.code = error == ENOENT ? 127 : 126;
        result.err = std::string("Cannot execute ") + args.front() + ": " + std::strerror(error);
        return result;
    }

    bool exited = false;
    while (!exited || output.fd >= 0 || errors.fd >= 0) {
        if (cancel && cancel->load(std::memory_order_relaxed)) result.cancelled = true;
        if (!result.cancelled && std::chrono::steady_clock::now() >= deadline) result.timed_out = true;
        if (result.cancelled || result.timed_out) {
            kill(-pid, SIGKILL);
            if (!exited) kill(pid, SIGKILL);
            drain(output, result.out, result, max_output);
            drain(errors, result.err, result, max_output);
            break;
        }
        if (!exited) {
            // Keep the exited leader waitable until cleanup, reserving its PID
            // while checking/killing any descendants that retained the pipes.
            siginfo_t information{};
            if (waitid(P_PID, static_cast<id_t>(pid), &information, WEXITED | WNOHANG | WNOWAIT) == 0)
                exited = information.si_pid == pid;
            else if (errno != EINTR) {
                result.err += "Cannot observe helper exit: " + std::string(std::strerror(errno));
                kill(-pid, SIGKILL);
                break;
            }
        }
        if (exited && output.fd < 0 && errors.fd < 0) break;
        pollfd streams[2]{};
        nfds_t count = 0;
        if (output.fd >= 0) streams[count++] = {output.fd, POLLIN | POLLHUP | POLLERR, 0};
        if (errors.fd >= 0) streams[count++] = {errors.fd, POLLIN | POLLHUP | POLLERR, 0};
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        const int wait_ms = static_cast<int>(std::clamp<long long>(remaining, 1, 50));
        if (poll(streams, count, wait_ms) < 0 && errno != EINTR) {
            result.err += "Cannot poll helper output: " + std::string(std::strerror(errno));
            kill(-pid, SIGKILL);
            break;
        }
        drain(output, result.out, result, max_output);
        drain(errors, result.err, result, max_output);
    }
    // Helpers cannot leave background workers behind, even after a normal exit.
    kill(-pid, SIGKILL);
    output.reset(); errors.reset();
    int status = 0;
    pid_t reaped;
    do { reaped = waitpid(pid, &status, 0); } while (reaped < 0 && errno == EINTR);
    if (reaped == pid) {
        if (WIFEXITED(status)) result.code = WEXITSTATUS(status);
        else if (WIFSIGNALED(status)) result.code = 128 + WTERMSIG(status);
    }
    return result;
}
