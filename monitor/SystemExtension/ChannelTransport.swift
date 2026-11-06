import Foundation
import Darwin

/// All root I/O stays relative to an opened, no-follow directory descriptor.
/// Receipts are root-owned, read-only to the user, inside their 0700 directory.
final class ExtensionStateDirectory {
    let fd: Int32
    let uid: uid_t
    let home: String
    init(home: String, uid: uid_t) throws {
        guard uid > 0, home.hasPrefix("/"), !home.split(separator: "/").contains(".."),
              let account = getpwuid(uid), String(cString: account.pointee.pw_dir) == home else {
            throw Self.error("Invalid control user")
        }
        self.uid = uid
        self.home = home
        var current = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard current >= 0 else { throw Self.error("Cannot open root") }
        do {
            for component in (home + "/Library/Application Support/ClaudeWatch/state").split(separator: "/") {
                let next = openat(current, String(component), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard next >= 0 else { throw Self.error("Control directory unavailable") }
                Darwin.close(current)
                current = next
            }
            var info = stat()
            guard fstat(current, &info) == 0, info.st_uid == uid, info.st_mode & 0o077 == 0 else {
                throw Self.error("Control directory must belong to the configured user and be private")
            }
            fd = current
        } catch {
            Darwin.close(current)
            throw error
        }
    }
    deinit { Darwin.close(fd) }
    static func error(_ message: String) -> Error {
        NSError(domain: "WatchChannel.Transport", code: Int(errno), userInfo: [NSLocalizedDescriptionKey: message])
    }
    // This file is only a locator/wakeup hint. Never apply its command fields.
    func gatewayLocation() throws -> String {
        let file = openat(fd, "system-extension-command.json", O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard file >= 0 else { throw Self.error("Command unavailable") }
        defer { Darwin.close(file) }
        var info = stat()
        guard fstat(file, &info) == 0, info.st_uid == uid, info.st_mode & S_IFMT == S_IFREG,
              info.st_mode & 0o077 == 0, info.st_nlink == 1, info.st_size <= 65536 else {
            throw Self.error("Untrusted command file")
        }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = Darwin.read(file, &buffer, buffer.count)
            if count == 0 { break }
            if count < 0 { if errno == EINTR { continue }; throw Self.error("Command read failed") }
            data.append(contentsOf: buffer.prefix(count))
            if data.count > 65536 { throw Self.error("Oversized command") }
        }
        guard let hint = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let path = hint["gateway_socket"] as? String, path.hasPrefix("/tmp/cw-channel-") else {
            throw Self.error("Invalid gateway locator")
        }
        return path
    }
    func writeObservation(_ object: Any, name: String) throws {
        guard ["system-extension-heartbeat.json", "system-extension-receipt.json"].contains(name) else {
            throw Self.error("Invalid observation name")
        }
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        let temporary = ".extension-\(UUID().uuidString)"
        let file = openat(fd, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard file >= 0 else { throw Self.error("Observation create failed") }
        defer { Darwin.close(file); unlinkat(fd, temporary, 0) }
        try data.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let count = Darwin.write(file, raw.baseAddress!.advanced(by: offset), raw.count - offset)
                if count < 0 { if errno == EINTR { continue }; throw Self.error("Observation write failed") }
                guard count > 0 else { throw Self.error("Short observation write") }
                offset += count
            }
        }
        // The containing directory is private to the configured user. The user
        // can read this root-authored file but cannot forge its root ownership.
        guard fchmod(file, 0o644) == 0, fsync(file) == 0,
              renameat(fd, temporary, fd, name) == 0 else { throw Self.error("Observation publish failed") }
        _ = fsync(fd)
        CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
            CFNotificationName("io.local.claudewatch.extension-observation" as CFString), nil, nil, true)
    }
}

/// Native Unix stream forwarding; shutdown affects every in-flight dup before
/// the descriptor is closed. Completion is based on the actual shutdown result.
final class GatewayConnection {
    enum State { case connected, cancelled, failed }
    private let lock = NSLock()
    private var descriptor: Int32
    private var currentState: State = .connected
    private let reads = DispatchQueue(label: "watch.gateway.read", qos: .userInitiated)
    private let writes = DispatchQueue(label: "watch.gateway.write", qos: .userInitiated)
    var state: State { lock.lock(); defer { lock.unlock() }; return currentState }
    init(path: String, expectedUID: uid_t) throws {
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8) + [0]
        guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path), path.hasPrefix("/tmp/cw-channel-") else {
            throw ExtensionStateDirectory.error("Invalid gateway socket")
        }
        withUnsafeMutableBytes(of: &address.sun_path) { raw in raw.copyBytes(from: bytes) }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw ExtensionStateDirectory.error("Socket creation failed") }
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
            Darwin.close(descriptor); descriptor = -1
            throw ExtensionStateDirectory.error("Socket deadline setup failed")
        }
        var noSignal: Int32 = 1
        setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
        var connected = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        if connected != 0 && errno == EINPROGRESS {
            var pending = pollfd(fd: descriptor, events: Int16(POLLOUT), revents: 0)
            var socketError: Int32 = 0
            var errorSize = socklen_t(MemoryLayout<Int32>.size)
            if poll(&pending, 1, 1000) > 0 && getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &socketError, &errorSize) == 0 && socketError == 0 {
                connected = 0
            }
        }
        var uid: uid_t = 0
        var gid: gid_t = 0
        guard connected == 0, fcntl(descriptor, F_SETFL, flags) == 0,
              getpeereid(descriptor, &uid, &gid) == 0, uid == expectedUID,
              ChannelCodeIdentity.authenticatedGateway(fd: descriptor, uid: expectedUID) else {
            Darwin.close(descriptor)
            descriptor = -1
            throw ExtensionStateDirectory.error("Gateway peer unavailable or wrong user")
        }
    }
    deinit { _ = cancel() }
    #if CHANNEL_TRANSPORT_TESTS
    // Transport-only fixtures never compile into the provider target.
    init(testSocket: Int32) { descriptor = testSocket }
    #endif
    /// One bounded RPC over the same authenticated socket used by forwarding.
    /// The peer returns its in-memory commands, never a user-writable file.
    static func controlSnapshot(path: String, uid: uid_t, home: String) throws -> Data {
        let connection = try GatewayConnection(path: path, expectedUID: uid)
        defer { connection.cancel() }
        let nonce = UUID().uuidString
        let request = Data("WATCH-CONTROL \(nonce) HTTP/1.1\r\n\r\n".utf8)
        let deadline = ProcessInfo.processInfo.systemUptime + 1.0
        let fd = connection.descriptor
        func ready(_ events: Int16) throws {
            let remaining = deadline - ProcessInfo.processInfo.systemUptime
            var descriptor = pollfd(fd: fd, events: events, revents: 0)
            guard remaining > 0, poll(&descriptor, 1, Int32(remaining * 1000)) > 0,
                  descriptor.revents & events != 0 else { throw ExtensionStateDirectory.error("Control deadline exceeded") }
        }
        try request.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                try ready(Int16(POLLOUT))
                let n = Darwin.send(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset, MSG_DONTWAIT)
                if n < 0 && [EINTR, EAGAIN].contains(errno) { continue }
                guard n > 0 else { throw ExtensionStateDirectory.error("Control request failed") }
                offset += n
            }
        }
        func readExact(_ count: Int) throws -> Data {
            var result = Data()
            while result.count < count {
                try ready(Int16(POLLIN))
                var bytes = [UInt8](repeating: 0, count: min(4096, count - result.count))
                let n = Darwin.recv(fd, &bytes, bytes.count, MSG_DONTWAIT)
                if n < 0 && [EINTR, EAGAIN].contains(errno) { continue }
                guard n > 0 else { throw ExtensionStateDirectory.error("Control response truncated") }
                result.append(contentsOf: bytes.prefix(n))
            }
            return result
        }
        let count = try readExact(4).withUnsafeBytes { Int(UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self))) }
        guard count > 0, count <= 1_048_576 else { throw ExtensionStateDirectory.error("Control response too large") }
        return try decodeControlResponse(readExact(count), nonce: nonce, path: path, home: home)
    }
    static func decodeControlResponse(_ data: Data, nonce: String, path: String, home: String) throws -> Data {
        guard let value = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              value["nonce"] as? String == nonce, let envelope = value["envelope"] as? [String: Any],
              envelope["gateway_socket"] as? String == path, envelope["control_home"] as? String == home else {
            throw ExtensionStateDirectory.error("Control response does not match this connection")
        }
        return try JSONSerialization.data(withJSONObject: envelope, options: [.sortedKeys])
    }
    private func duplicate() -> Int32 {
        lock.lock(); defer { lock.unlock() }
        return currentState == .connected ? dup(descriptor) : -1
    }
    @discardableResult func cancel() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if descriptor < 0 { return currentState == .cancelled }
        let stopped = shutdown(descriptor, SHUT_RDWR) == 0 || errno == ENOTCONN
        let closed = Darwin.close(descriptor) == 0
        descriptor = -1
        currentState = stopped && closed ? .cancelled : .failed
        return currentState == .cancelled
    }
    func write(_ data: Data, completionHandler: @escaping (Error?) -> Void) {
        writes.async { [self] in
            let fd = duplicate()
            guard fd >= 0 else { completionHandler(ExtensionStateDirectory.error("Gateway closed")); return }
            defer { Darwin.close(fd) }
            do {
                try data.withUnsafeBytes { raw in
                    var offset = 0
                    while offset < raw.count {
                        let sent = Darwin.write(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset)
                        if sent < 0 && errno == EINTR { continue }
                        guard sent > 0 else { throw ExtensionStateDirectory.error("Gateway write failed") }
                        offset += sent
                    }
                }
                completionHandler(nil)
            } catch { completionHandler(error) }
        }
    }
    func readMinimumLength(_ minimum: Int, maximumLength: Int, completionHandler: @escaping (Data?, Error?) -> Void) {
        reads.async { [self] in
            let fd = duplicate()
            guard fd >= 0 else { completionHandler(nil, ExtensionStateDirectory.error("Gateway closed")); return }
            defer { Darwin.close(fd) }
            var bytes = [UInt8](repeating: 0, count: maximumLength)
            var count: Int
            repeat { count = Darwin.read(fd, &bytes, bytes.count) } while count < 0 && errno == EINTR
            if count < 0 { completionHandler(nil, ExtensionStateDirectory.error("Gateway read failed")) }
            else { completionHandler(Data(bytes.prefix(count)), nil) }
        }
    }
}
