import Foundation

/// Runs the bundled read-only snapshot command. Stderr is deliberately
/// discarded: draining two pipes sequentially deadlocks if the child fills
/// stderr before it starts writing to stdout.
///
/// The transport is a bounded state machine rather than a blocking read
/// followed by an unbounded wait for exit: stdout is non-blocking and polled
/// against a monotonic deadline, and the direct child is reaped here with
/// `waitpid`. Because the child stays unreaped until this code collects it,
/// its PID cannot be recycled while TERM/KILL are being delivered. Only the
/// direct child is signalled; descendants that inherited stdout are never
/// targeted, the transport merely stops waiting for their EOF.
enum SnapshotProcessResult {
    case success(Data)
    case launchFailed
    case executionFailed
    case outputTooLarge
    case timedOut
}

enum SnapshotProcessTransport {
    static let maximumOutputBytes = 16 * 1024 * 1024
    static let readChunkBytes = 65_536

    /// Worst-case return time is `timeoutSeconds + 2 * terminationGraceSeconds`
    /// plus scheduling latency, even if the child ignores SIGTERM, a
    /// descendant keeps stdout open, or the child writes forever.
    static func run(
        executable: URL,
        arguments: [String],
        timeoutSeconds: TimeInterval = 20,
        terminationGraceSeconds: TimeInterval = 1
    ) -> SnapshotProcessResult {
        let deadline = monotonicNow() + nanoseconds(timeoutSeconds)

        var fds: [Int32] = [-1, -1]
        guard pipe(&fds) == 0 else { return .launchFailed }
        let readFD = fds[0], writeFD = fds[1]
        // Keep both ends out of unrelated concurrent spawns. A narrow window
        // between pipe() and fcntl() remains; a leaked writer can only delay
        // EOF, which the deadline below still bounds.
        _ = fcntl(readFD, F_SETFD, FD_CLOEXEC)
        _ = fcntl(writeFD, F_SETFD, FD_CLOEXEC)

        guard let pid = spawn(executable: executable, arguments: arguments, stdoutFD: writeFD) else {
            close(readFD)
            close(writeFD)
            return .launchFailed
        }
        close(writeFD)
        defer { close(readFD) }
        let flags = fcntl(readFD, F_GETFL)
        guard flags >= 0, fcntl(readFD, F_SETFL, flags | O_NONBLOCK) == 0 else {
            stop(pid, grace: terminationGraceSeconds)
            return .executionFailed
        }

        var data = Data()
        var buffer = [UInt8](repeating: 0, count: readChunkBytes)
        readLoop: while true {
            let now = monotonicNow()
            guard now < deadline else {
                stop(pid, grace: terminationGraceSeconds)
                return .timedOut
            }
            var pfd = pollfd(fd: readFD, events: Int16(POLLIN), revents: 0)
            let waitMs = Int32(clamping: (deadline - now + 999_999) / 1_000_000)
            let ready = poll(&pfd, 1, max(1, waitMs))
            if ready < 0 {
                if errno == EINTR { continue }
                stop(pid, grace: terminationGraceSeconds)
                return .executionFailed
            }
            if ready == 0 { continue }
            // Drain what is available; POLLHUP still requires reading to EOF.
            while true {
                let count = buffer.withUnsafeMutableBytes { read(readFD, $0.baseAddress, readChunkBytes) }
                if count > 0 {
                    if count > maximumOutputBytes - data.count {
                        // Stop the capture at once instead of consuming an
                        // unbounded stream until EOF.
                        data.removeAll(keepingCapacity: false)
                        stop(pid, grace: terminationGraceSeconds)
                        return .outputTooLarge
                    }
                    data.append(contentsOf: buffer[0..<count])
                    continue
                }
                if count == 0 { break readLoop }
                if errno == EINTR { continue }
                if errno == EAGAIN || errno == EWOULDBLOCK { continue readLoop }
                stop(pid, grace: terminationGraceSeconds)
                return .executionFailed
            }
        }

        // EOF observed; the exit must also be collected before the deadline.
        switch reap(pid, until: deadline) {
        case .running:
            stop(pid, grace: terminationGraceSeconds)
            return .timedOut
        case .gone:
            return .executionFailed
        case .exited(let status):
            // Exit status 0 only: signalled or non-zero exits are failures.
            return status == 0 ? .success(data) : .executionFailed
        }
    }

    // MARK: - Child lifecycle

    private enum ReapState {
        case running
        /// Collected elsewhere (for example SIGCHLD set to SIG_IGN); status unknown.
        case gone
        /// Raw wait status as returned by waitpid.
        case exited(Int32)
    }

    private static func spawn(executable: URL, arguments: [String], stdoutFD: Int32) -> pid_t? {
        var actions: posix_spawn_file_actions_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else { return nil }
        defer { posix_spawn_file_actions_destroy(&actions) }
        var attributes: posix_spawnattr_t?
        guard posix_spawnattr_init(&attributes) == 0 else { return nil }
        defer { posix_spawnattr_destroy(&attributes) }

        guard posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0) == 0,
              posix_spawn_file_actions_adddup2(&actions, stdoutFD, 1) == 0,
              // Stderr is not exposed to the UI and can contain private data.
              posix_spawn_file_actions_addopen(&actions, 2, "/dev/null", O_WRONLY, 0) == 0
        else { return nil }

        // Only fds 0-2 above are inherited; dispositions and mask are reset so
        // an ignored signal in this process does not leak into the child.
        var defaults = sigset_t()
        sigemptyset(&defaults)
        for signal in 1..<NSIG where signal != SIGKILL && signal != SIGSTOP {
            sigaddset(&defaults, signal)
        }
        var mask = sigset_t()
        sigemptyset(&mask)
        let spawnFlags = Int16(POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK)
        guard posix_spawnattr_setsigdefault(&attributes, &defaults) == 0,
              posix_spawnattr_setsigmask(&attributes, &mask) == 0,
              posix_spawnattr_setflags(&attributes, spawnFlags) == 0
        else { return nil }

        let path = executable.path
        var argv: [UnsafeMutablePointer<CChar>?] = ([path] + arguments).map { strdup($0) }
        argv.append(nil)
        defer { argv.forEach { free($0) } }
        var pid: pid_t = 0
        let status = posix_spawn(&pid, path, &actions, &attributes, argv, environ)
        return status == 0 && pid > 0 ? pid : nil
    }

    private static func reap(_ pid: pid_t, until deadline: UInt64) -> ReapState {
        var status: Int32 = 0
        while true {
            let result = waitpid(pid, &status, WNOHANG)
            if result == pid { return .exited(status) }
            if result == -1 {
                if errno == EINTR { continue }
                return .gone
            }
            if monotonicNow() >= deadline { return .running }
            usleep(5_000)
        }
    }

    /// Signals only the direct, still-unreaped child. A PID is never signalled
    /// after `waitpid` reported it as collected or gone.
    private static func stop(_ pid: pid_t, grace: TimeInterval) {
        guard case .running = reap(pid, until: 0) else { return }
        kill(pid, SIGTERM)
        guard case .running = reap(pid, until: monotonicNow() + nanoseconds(grace)) else { return }
        kill(pid, SIGKILL)
        guard case .running = reap(pid, until: monotonicNow() + nanoseconds(grace)) else { return }
        // Still not collectable (for example blocked in the kernel). Return to
        // the caller now and collect the zombie in the background.
        Thread.detachNewThread {
            var status: Int32 = 0
            while waitpid(pid, &status, 0) == -1 && errno == EINTR {}
        }
    }

    private static func monotonicNow() -> UInt64 { DispatchTime.now().uptimeNanoseconds }

    private static func nanoseconds(_ seconds: TimeInterval) -> UInt64 {
        guard seconds > 0 else { return 0 }
        return UInt64(min(seconds, 86_400) * 1_000_000_000)
    }
}
