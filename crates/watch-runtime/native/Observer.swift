import Darwin
import Dispatch
import Foundation
import SystemConfiguration

// OS observations only. This program cannot launch, terminate, switch accounts or change settings.
private struct ObservationFailure: Error { let code: String }
private struct Identity: Codable, Equatable {
    let pid: Int32
    let parent: Int32
    let uid: UInt32
    let executable: String
    let start_seconds: UInt64
    let start_microseconds: UInt64
    let start_stamp: String
    func sameProcess(_ other: Self) -> Bool {
        pid == other.pid && uid == other.uid && executable == other.executable
            && start_seconds == other.start_seconds && start_microseconds == other.start_microseconds
    }
}
private struct Request: Decodable { let schema: Int; let round_id: String; let targets: [Identity] }
#if OBSERVER_TESTING
// Test-only hooks target processes created and owned by the test harness.
private var observerIdentityMisses: [Int32: Int] = [:]
private var observerAfterInventoryScan: (() -> Void)?
private var observerBeforeSocketRecheck: ((Int32) -> Void)?
#endif
private func currentIdentity(_ pid: Int32) -> Identity? {
    #if OBSERVER_TESTING
    if let count = observerIdentityMisses[pid], count > 0 {
        observerIdentityMisses[pid] = count - 1
        return nil
    }
    #endif
    guard pid > 1 else { return nil }
    var info = proc_bsdinfo()
    let size = Int32(MemoryLayout<proc_bsdinfo>.size)
    guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size, info.pbi_status != SZOMB else { return nil }
    var path = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
    guard proc_pidpath(pid, &path, UInt32(path.count)) > 0 else { return nil }
    let formatter = DateFormatter(); formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.dateFormat = "EEE MMM d HH:mm:ss yyyy"
    return Identity(pid: pid, parent: Int32(info.pbi_ppid), uid: info.pbi_uid,
        executable: String(cString: path), start_seconds: info.pbi_start_tvsec, start_microseconds: info.pbi_start_tvusec,
        start_stamp: formatter.string(from: Date(timeIntervalSince1970: Double(info.pbi_start_tvsec))))
}
private func encoded(_ value: Identity) throws -> [String: Any] {
    try JSONSerialization.jsonObject(with: JSONEncoder().encode(value)) as! [String: Any]
}
private func exited(_ pid: Int32) -> Bool {
    if Darwin.kill(pid, 0) != 0 && errno == ESRCH { return true }
    var info = proc_bsdinfo(); let size = Int32(MemoryLayout<proc_bsdinfo>.size)
    if proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size && info.pbi_status == SZOMB { return true }
    // A zombie can still answer kill(pid, 0) while libproc reports ESRCH.
    // Confirm its current kernel status; missing paths or denied reads alone
    // must never be promoted to an exited process.
    var process = kinfo_proc()
    var length = MemoryLayout<kinfo_proc>.size
    var mib = [Int32(CTL_KERN), Int32(KERN_PROC), Int32(KERN_PROC_PID), pid]
    return sysctl(&mib, UInt32(mib.count), &process, &length, nil, 0) == 0
        && length == MemoryLayout<kinfo_proc>.size
        && process.kp_eproc.e_ucred.cr_uid == getuid()
        && Int32(process.kp_proc.p_stat) == SZOMB
}
private func pidList() throws -> ([Int32], Bool) {
    let expected = proc_listpids(UInt32(PROC_UID_ONLY), getuid(), nil, 0)
    guard expected > 0 else { throw ObservationFailure(code: "pid_inventory_unavailable") }
    let capacity = min(65536, max(1024, Int(expected) / MemoryLayout<Int32>.stride + 256))
    var pids = [Int32](repeating: 0, count: capacity)
    let bytes = pids.withUnsafeMutableBytes { buffer in
        proc_listpids(UInt32(PROC_UID_ONLY), getuid(), buffer.baseAddress, Int32(buffer.count))
    }
    guard bytes > 0, bytes % Int32(MemoryLayout<Int32>.stride) == 0 else { throw ObservationFailure(code: "pid_inventory_unavailable") }
    return (Array(Set(pids.prefix(Int(bytes) / MemoryLayout<Int32>.stride).filter { $0 > 1 })).sorted(), Int(bytes) >= capacity * MemoryLayout<Int32>.stride)
}
private func inventory() throws -> [String: Any] {
    let (pids, truncated) = try pidList()
    // A logged-in user routinely has a thousand-odd PIDs and every lookup is a
    // sysctl plus, for app processes, a bundle read. Three seconds regularly
    // expired mid-scan, which reported the whole round as incomplete even
    // though nothing was wrong. The guard rescans every round, so a longer
    // deadline only costs time on a genuinely hung system.
    let deadline = DispatchTime.now().uptimeNanoseconds + 10_000_000_000
    var values = [[String: Any]](), unavailable = [[String: Any]](), ended = [Int32](), pending = [Int32]()
    func appendIdentity(_ identity: Identity) throws {
        var value = try encoded(identity)
        if let range = identity.executable.range(of: ".app/Contents/") {
            let bundle = String(identity.executable[..<range.lowerBound]) + ".app"
            value["bundle_path"] = bundle
            value["bundle_id"] = Bundle(path: bundle)?.bundleIdentifier ?? ""
        }
        values.append(value)
    }
    for pid in pids {
        if DispatchTime.now().uptimeNanoseconds > deadline {
            unavailable.append(["pid": pid, "code": "inventory_deadline"]); break
        }
        guard let identity = currentIdentity(pid), identity.uid == getuid() else {
            if exited(pid) { ended.append(pid) } else { pending.append(pid) }
            continue
        }
        try appendIdentity(identity)
    }
    #if OBSERVER_TESTING
    observerAfterInventoryScan?()
    #endif
    // Recheck unresolved PIDs after the rest of the scan. A process which is
    // still unreadable stays unknown; only a confirmed exit can be excluded.
    for pid in pending {
        if DispatchTime.now().uptimeNanoseconds > deadline {
            unavailable.append(["pid": pid, "code": "inventory_deadline"]); break
        }
        if let identity = currentIdentity(pid), identity.uid == getuid() { try appendIdentity(identity) }
        else if exited(pid) { ended.append(pid) }
        else { unavailable.append(["pid": pid, "code": "identity_unavailable"]) }
    }
    // Unresolved identities remain in unavailable and are treated as an
    // incomplete inventory by the Rust decoder; this state does not hide them.
    let fatal = truncated || unavailable.contains { ($0["code"] as? String) == "inventory_deadline" }
    return ["processes": values, "unavailable": unavailable, "exited": ended, "truncated": truncated,
        "state": fatal ? "partial" : "ok", "requested_count": pids.count]
}
private func request() throws -> Request {
    var data = Data()
    while let chunk = try FileHandle.standardInput.read(upToCount: 8192), !chunk.isEmpty {
        guard data.count + chunk.count <= 1_048_576 else { throw ObservationFailure(code: "request_oversize") }
        data.append(chunk)
    }
    let value = try JSONDecoder().decode(Request.self, from: data)
    guard value.schema == 1, !value.round_id.isEmpty, value.round_id.utf8.count <= 128, value.targets.count <= 2048,
        Set(value.targets.map(\.pid)).count == value.targets.count,
        value.targets.allSatisfy({ $0.pid > 1 && $0.uid == getuid() && $0.start_seconds > 0 && $0.start_microseconds < 1_000_000 && $0.executable.hasPrefix("/") })
    else { throw ObservationFailure(code: "invalid_observation_request") }
    return value
}
private func currentDirectory(_ pid: Int32) -> String? {
    var info = proc_vnodepathinfo()
    let size = Int32(MemoryLayout<proc_vnodepathinfo>.size)
    guard proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &info, size) == size else { return nil }
    return withUnsafePointer(to: &info.pvi_cdir.vip_path) { pointer in
        pointer.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) { String(cString: $0) }
    }
}
private func argumentPrefix(_ pid: Int32) throws -> ([String], Bool) {
    var mib = [Int32(CTL_KERN), Int32(KERN_PROCARGS2), pid]
    var size = 0
    guard sysctl(&mib, UInt32(mib.count), nil, &size, nil, 0) == 0, size >= 4, size <= 1_048_576 else {
        throw ObservationFailure(code: "arguments_unavailable")
    }
    var bytes = [UInt8](repeating: 0, count: size)
    let result = bytes.withUnsafeMutableBytes { pointer in sysctl(&mib, UInt32(mib.count), pointer.baseAddress, &size, nil, 0) }
    guard result == 0, size >= 4 else { throw ObservationFailure(code: "arguments_unavailable") }
    let argc = bytes.withUnsafeBytes { $0.loadUnaligned(as: Int32.self) }
    guard argc >= 0, argc <= 131072 else { throw ObservationFailure(code: "arguments_invalid") }
    var offset = 4
    // KERN_PROCARGS2 has argc, executable path, NUL padding, then exactly argc argv strings.
    while offset < size && bytes[offset] != 0 { offset += 1 }
    while offset < size && bytes[offset] == 0 { offset += 1 }
    var args = [String](), total = 0
    for _ in 0..<min(Int(argc), 256) {
        guard offset < size else { throw ObservationFailure(code: "arguments_invalid") }
        let start = offset
        while offset < size && bytes[offset] != 0 { offset += 1 }
        guard offset < size, offset - start <= 16384 else { throw ObservationFailure(code: "argument_oversize") }
        total += offset - start
        guard total <= 65536, let text = String(bytes: bytes[start..<offset], encoding: .utf8) else {
            throw ObservationFailure(code: "argument_prefix_limit")
        }
        args.append(text); offset += 1
    }
    return (args, Int(argc) > args.count)
}
private func arguments(_ input: Request) throws -> [String: Any] {
    let deadline = DispatchTime.now().uptimeNanoseconds + 3_000_000_000
    var rows = [[String: Any]]()
    for target in input.targets {
        if DispatchTime.now().uptimeNanoseconds > deadline { rows.append(["pid": target.pid, "state": "unknown", "code": "arguments_deadline"]); break }
        guard let before = currentIdentity(target.pid), before.sameProcess(target) else {
            rows.append(["pid": target.pid, "state": "unknown", "code": exited(target.pid) ? "process_exited" : "identity_changed"]); continue
        }
        do {
            let (args, truncated) = try argumentPrefix(target.pid)
            let cwd = currentDirectory(target.pid) ?? ""
            guard let after = currentIdentity(target.pid), before.sameProcess(after) else { throw ObservationFailure(code: "identity_changed") }
            rows.append(["pid": target.pid, "identity": try encoded(after), "arguments": args,
                "truncated": truncated, "cwd": cwd, "state": "ok"])
        } catch {
            rows.append(["pid": target.pid, "state": "unknown", "code": (error as? ObservationFailure)?.code ?? "arguments_unavailable"])
        }
    }
    return ["round_id": input.round_id, "argument_prefixes": rows]
}
private func identities(_ input: Request) throws -> [String: Any] {
    var rows = [[String: Any]]()
    for target in input.targets {
        if let identity = currentIdentity(target.pid), identity.sameProcess(target) {
            rows.append(["pid": target.pid, "state": "ok", "identity": try encoded(identity)])
        } else { rows.append(["pid": target.pid, "state": "unknown", "code": exited(target.pid) ? "process_exited" : "identity_changed"]) }
    }
    return ["round_id": input.round_id, "identities": rows]
}
private func address4(_ raw: in_addr) -> String? {
    var value = raw, text = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
    return withUnsafePointer(to: &value) { ptr in inet_ntop(AF_INET, ptr, &text, socklen_t(text.count)) == nil ? nil : String(cString: text) }
}
private func address6(_ raw: in6_addr) -> String? {
    var value = raw, text = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
    return withUnsafePointer(to: &value) { ptr in inet_ntop(AF_INET6, ptr, &text, socklen_t(text.count)) == nil ? nil : String(cString: text) }
}
private func socketValue(_ raw: socket_fdinfo, pid: Int32, fd: Int32) -> [String: Any]? {
    let socket = raw.psi
    guard socket.soi_family == AF_INET || socket.soi_family == AF_INET6 else { return nil }
    let tcp = socket.soi_kind == SOCKINFO_TCP && socket.soi_protocol == IPPROTO_TCP
    let udp = socket.soi_kind == SOCKINFO_IN && socket.soi_protocol == IPPROTO_UDP
    guard tcp || udp else { return nil }
    let info = tcp ? socket.soi_proto.pri_tcp.tcpsi_ini : socket.soi_proto.pri_in
    let localPort = UInt16(bigEndian: UInt16(truncatingIfNeeded: info.insi_lport))
    let peerPort = UInt16(bigEndian: UInt16(truncatingIfNeeded: info.insi_fport))
    guard localPort > 0 && peerPort > 0 else { return nil }
    let ipv4 = socket.soi_family == AF_INET || info.insi_vflag == INI_IPV4
    let local = ipv4 ? address4(info.insi_laddr.ina_46.i46a_addr4) : address6(info.insi_laddr.ina_6)
    let peer = ipv4 ? address4(info.insi_faddr.ina_46.i46a_addr4) : address6(info.insi_faddr.ina_6)
    guard let local, let peer, peer != "0.0.0.0", peer != "::" else { return nil }
    return ["pid": pid, "fd": fd, "protocol": tcp ? "tcp" : "udp", "local": [local, Int(localPort)],
        "peer": [peer, Int(peerPort)], "socket_state": tcp ? socket.soi_proto.pri_tcp.tcpsi_state : Int32(socket.soi_state)]
}
private func environment() throws -> [String: Any] {
    let preferences = UserDefaults.standard.persistentDomain(forName: UserDefaults.globalDomain) ?? [:]
    let app = UserDefaults.standard.persistentDomain(forName: "com.anthropic.claudefordesktop") ?? [:]
    let languages = (app["AppleLanguages"] as? [String]).flatMap { $0.isEmpty ? nil : $0 }
        ?? (preferences["AppleLanguages"] as? [String]) ?? []
    let sample = Date(timeIntervalSince1970: 1792713600)
    let styles: [(String, DateFormatter.Style)] = [("short", .short), ("medium", .medium), ("long", .long)]
    func patterns(_ locale: Locale?) -> [String: String] {
        var values = [String: String]()
        for (name, style) in styles { let f = DateFormatter(); if let locale { f.locale = locale }; f.dateStyle = style; f.timeStyle = .none; values[name] = f.dateFormat ?? "" }
        return values
    }
    var references = [String: [String: String]](), samples = [String: String]()
    for locale in ["en_US", "ja_JP", "zh_CN", "zh_TW", "zh_HK", "en_SG", "en_GB", "de_DE", "fr_FR", "ko_KR", "en_AU", "en_CA"] {
        references[locale] = patterns(Locale(identifier: locale)); let f = DateFormatter(); f.locale = Locale(identifier: locale); f.dateStyle = .short; f.timeStyle = .none; samples[locale] = f.string(from: sample)
    }
    let current = DateFormatter(); current.dateStyle = .short; current.timeStyle = .none
    let regional: [String: Any] = ["state": "available", "configured_locale": preferences["AppleLocale"] as? String ?? "", "effective_locale": Locale.current.identifier,
        "patterns": patterns(nil), "short_sample": current.string(from: sample), "reference_patterns": references, "reference_samples": samples, "has_custom_formats": preferences["AppleICUDateFormatStrings"] != nil]
    var network = [String: Any](), ipv6 = "unknown", ipv6Method: String? = nil, proxy = [String: Any]()
    if let store = SCDynamicStoreCreate(nil, "ClaudeWatch.ReadOnly" as CFString, nil, nil) {
        let global = SCDynamicStoreCopyValue(store, "State:/Network/Global/IPv4" as CFString) as? [String: Any] ?? [:]
        let serviceID = global["PrimaryService"] as? String ?? ""
        if !serviceID.isEmpty {
            let setup = SCDynamicStoreCopyValue(store, "Setup:/Network/Service/\(serviceID)" as CFString) as? [String: Any] ?? [:]
            let device = SCDynamicStoreCopyValue(store, "Setup:/Network/Service/\(serviceID)/Interface" as CFString) as? [String: Any] ?? [:]
            network = ["service": setup["UserDefinedName"] as? String ?? "", "interface": device["DeviceName"] as? String ?? global["PrimaryInterface"] as? String ?? "", "service_id": serviceID]
            let settings = SCDynamicStoreCopyValue(store, "Setup:/Network/Service/\(serviceID)/IPv6" as CFString) as? [String: Any] ?? [:]
            let live = SCDynamicStoreCopyValue(store, "State:/Network/Service/\(serviceID)/IPv6" as CFString) as? [String: Any] ?? [:]
            if let method = settings["ConfigMethod"] as? String {
                ipv6 = method.caseInsensitiveCompare("Off") == .orderedSame ? "ok" : "fail"
                ipv6Method = method.lowercased()
            } else if !live.isEmpty {
                // 该服务仍有活动 IPv6 状态实体，说明未关闭，只是系统未给出 ConfigMethod。
                ipv6 = "fail"
            } else if !setup.isEmpty {
                // macOS 在 IPv6 关闭时会整体移除该服务的 IPv6 实体：Setup 与 State 都不存在。
                // 这与 `networksetup -getinfo <服务>` 输出 “IPv6: Off” 是同一事实，
                // 只有服务本身已确认存在时才据此判定，避免把读取失败当成“已关闭”。
                ipv6 = "ok"
                ipv6Method = "off"
            }
        }
        if let raw = SCDynamicStoreCopyProxies(store) as? [String: Any] {
            for key in ["HTTPEnable", "HTTPProxy", "HTTPPort", "HTTPSEnable", "HTTPSProxy", "HTTPSPort", "SOCKSEnable", "SOCKSProxy", "SOCKSPort", "ProxyAutoConfigEnable"] { if let value = raw[key] { proxy[key] = value } }
        }
    }
    let claude = Bundle(path: "/Applications/Claude.app")
    return ["timezone": TimeZone.current.identifier, "locale": preferences["AppleLocale"] as? String ?? "", "language": "(" + languages.map { "\"" + $0 + "\"" }.joined(separator: ",") + ")",
        "app_language": (app["AppleLanguages"] as? [String]) as Any? ?? NSNull(), "date_format": regional, "network": network, "ipv6": ipv6, "ipv6_method": ipv6Method as Any? ?? NSNull(), "system_proxy": proxy,
        "claude_app": ["path": "/Applications/Claude.app", "bundle_id": claude?.bundleIdentifier ?? "", "version": claude?.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? ""]]
}
private func sockets(_ input: Request) throws -> [String: Any] {
    let deadline = DispatchTime.now().uptimeNanoseconds + 3_000_000_000
    var rows = [[String: Any]]()
    for target in input.targets {
        if DispatchTime.now().uptimeNanoseconds > deadline { rows.append(["pid": target.pid, "state": "unknown", "code": "socket_deadline"]); break }
        guard let before = currentIdentity(target.pid) else {
            rows.append(["pid": target.pid, "state": "unknown", "code": exited(target.pid) ? "process_exited" : "identity_unavailable"]); continue
        }
        guard before.sameProcess(target) else {
            rows.append(["pid": target.pid, "state": "unknown", "code": "identity_changed"]); continue
        }
        let width = MemoryLayout<proc_fdinfo>.stride
        errno = 0
        let expected = proc_pidinfo(target.pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard expected >= 0 && (expected > 0 || errno == 0) && expected <= 32768 * width else {
            rows.append(["pid": target.pid, "state": "unknown", "code": exited(target.pid) ? "process_exited" : "fd_inventory_unavailable"]); continue
        }
        let count = max(32, Int(expected) / width + 32)
        var descriptors = [proc_fdinfo](repeating: proc_fdinfo(), count: count)
        errno = 0
        let bytes = descriptors.withUnsafeMutableBytes { pointer in proc_pidinfo(target.pid, PROC_PIDLISTFDS, 0, pointer.baseAddress, Int32(pointer.count)) }
        guard bytes >= 0, (bytes > 0 || errno == 0), Int(bytes) % width == 0 else { rows.append(["pid": target.pid, "state": "unknown", "code": exited(target.pid) ? "process_exited" : "fd_inventory_unavailable"]); continue }
        var values = [[String: Any]](), dropped = [String: Int](), inspected = 0
        if Int(bytes) >= count * width { dropped["fd_list_truncated"] = 1 }
        for descriptor in descriptors.prefix(Int(bytes) / width) where descriptor.proc_fdtype == PROX_FDTYPE_SOCKET {
            if DispatchTime.now().uptimeNanoseconds > deadline { dropped["socket_deadline", default: 0] += 1; break }
            var info = socket_fdinfo(); let size = Int32(MemoryLayout<socket_fdinfo>.size)
            guard proc_pidfdinfo(target.pid, descriptor.proc_fd, PROC_PIDFDSOCKETINFO, &info, size) == size else {
                dropped[errno == EBADF || errno == ENOENT ? "fd_closed_during_sample" : "socket_info_unavailable", default: 0] += 1; continue
            }
            inspected += 1
            if let value = socketValue(info, pid: target.pid, fd: descriptor.proc_fd) { values.append(value) }
        }
        #if OBSERVER_TESTING
        observerBeforeSocketRecheck?(target.pid)
        #endif
        guard let after = currentIdentity(target.pid) else {
            rows.append(["pid": target.pid, "state": "unknown", "code": exited(target.pid) ? "process_exited" : "identity_unavailable"]); continue
        }
        guard before.sameProcess(after) else {
            rows.append(["pid": target.pid, "state": "unknown", "code": "identity_changed"]); continue
        }
        rows.append(["pid": target.pid, "identity": try encoded(after), "state": dropped.isEmpty ? "ok" : "partial", "sockets": values,
            "dropped": dropped, "inspected_socket_count": inspected])
    }
    return ["round_id": input.round_id, "socket_samples": rows]
}
#if !OBSERVER_TESTING
@main
private struct Observer {
    static func main() {
        do {
            guard getuid() != 0, CommandLine.arguments.count == 2 else { throw ObservationFailure(code: "invalid_observer_invocation") }
            let started = Date().timeIntervalSince1970
            var value: [String: Any]
            switch CommandLine.arguments[1] {
            case "inventory": value = try inventory()
            case "arguments": value = try arguments(request())
            case "identities": value = try identities(request())
            case "sockets": value = try sockets(request())
            case "environment": value = try environment()
            default: throw ObservationFailure(code: "invalid_observer_action")
            }
            value["schema"] = 1; value["status"] = "ok"; value["uid"] = getuid()
            value["started_at"] = started; value["finished_at"] = Date().timeIntervalSince1970
            let data = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
            guard data.count <= 8 * 1024 * 1024 else { throw ObservationFailure(code: "observer_output_oversize") }
            FileHandle.standardOutput.write(data); FileHandle.standardOutput.write(Data([10]))
        } catch {
            let code = (error as? ObservationFailure)?.code ?? "native_observation_failed"
            let value: [String: Any] = ["schema": 1, "status": "error", "code": code]
            if let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) { FileHandle.standardOutput.write(data); FileHandle.standardOutput.write(Data([10])) }
            exit(4)
        }
    }
}
#endif
