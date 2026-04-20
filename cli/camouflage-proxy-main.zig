const std = @import("std");
const ayllu_camouflage = @import("ayllu-camouflage");
const ayllu_proxy = @import("ayllu-proxy");

const default_listen_host = "0.0.0.0";
const default_listen_port: u16 = 443;

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(gpa);

    var listen_host: []const u8 = default_listen_host;
    var listen_port: u16 = default_listen_port;
    var listen_addr: ?std.Io.net.IpAddress = null;
    var reality_listen_host: ?[]const u8 = null;
    var reality_listen_port: u16 = 0;
    var reality_listen_addr: ?std.Io.net.IpAddress = null;
    var target: ?ayllu_camouflage.reality.Target = null;
    var private_key: ?[ayllu_camouflage.reality.key_length]u8 = null;
    var min_client_version: ?std.SemanticVersion = null;
    var max_client_version: ?std.SemanticVersion = null;
    var max_time_diff_ms: u64 = 5_000;
    var token_policy: ayllu_camouflage.tokens.Policy = .{};
    var proxy_config: ayllu_proxy.daemon.Config = .{};
    var server_names = std.ArrayList([]const u8).empty;
    var short_ids = std.ArrayList(ayllu_camouflage.reality.ShortId).empty;
    var cover_target: ?ayllu_camouflage.reverse_proxy.CoverTarget = null;
    var pool_entries = std.ArrayList(ayllu_camouflage.cover_pool.WeightedCover).empty;
    var rate_limit_cfg: ayllu_camouflage.rate_limit.Config = .{};
    var metrics_listen: ?std.Io.net.IpAddress = null;
    var inner_protocol: ayllu_camouflage.reality.InnerProtocol = .socks5;
    var vless_uuid: ?[16]u8 = null;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--listen")) {
            i += 1;
            if (i >= args.len) return error.MissingListenValue;
            const parsed_host, const parsed_port, const parsed_addr = try parseListenSpec(args[i]);
            listen_host = parsed_host;
            listen_port = parsed_port;
            listen_addr = parsed_addr;
        } else if (std.mem.eql(u8, args[i], "--reality-listen")) {
            i += 1;
            if (i >= args.len) return error.MissingRealityListenValue;
            const parsed_host, const parsed_port, const parsed_addr = try parseListenSpec(args[i]);
            reality_listen_host = parsed_host;
            reality_listen_port = parsed_port;
            reality_listen_addr = parsed_addr;
        } else if (std.mem.eql(u8, args[i], "--inner-protocol")) {
            i += 1;
            if (i >= args.len) return error.MissingInnerProtocolValue;
            if (std.mem.eql(u8, args[i], "socks5")) {
                inner_protocol = .socks5;
            } else if (std.mem.eql(u8, args[i], "vless")) {
                inner_protocol = .vless;
            } else {
                return error.UnknownInnerProtocol;
            }
        } else if (std.mem.eql(u8, args[i], "--vless-uuid")) {
            i += 1;
            if (i >= args.len) return error.MissingVlessUuidValue;
            vless_uuid = ayllu_camouflage.reality.parseVlessUuid(args[i]) catch return error.BadVlessUuidValue;
        } else if (std.mem.eql(u8, args[i], "--target")) {
            i += 1;
            if (i >= args.len) return error.MissingTargetValue;
            target = try ayllu_camouflage.reality.parseTarget(args[i]);
        } else if (std.mem.eql(u8, args[i], "--server-name")) {
            i += 1;
            if (i >= args.len) return error.MissingServerNameValue;
            try server_names.append(gpa, args[i]);
        } else if (std.mem.eql(u8, args[i], "--private-key")) {
            i += 1;
            if (i >= args.len) return error.MissingPrivateKeyValue;
            private_key = try ayllu_camouflage.reality.decodeKey(args[i]);
        } else if (std.mem.eql(u8, args[i], "--short-id")) {
            i += 1;
            if (i >= args.len) return error.MissingShortIdValue;
            try short_ids.append(gpa, try ayllu_camouflage.reality.parseShortId(args[i]));
        } else if (std.mem.eql(u8, args[i], "--auth-file")) {
            i += 1;
            if (i >= args.len) return error.MissingAuthFileValue;
            proxy_config.auth = try ayllu_proxy.auth.loadFromFile(io, gpa, args[i]);
        } else if (std.mem.eql(u8, args[i], "--max-time-diff-ms")) {
            i += 1;
            if (i >= args.len) return error.MissingMaxTimeDiffValue;
            max_time_diff_ms = std.fmt.parseInt(u64, args[i], 10) catch return error.BadMaxTimeDiffValue;
        } else if (std.mem.eql(u8, args[i], "--token-slot-ms")) {
            i += 1;
            if (i >= args.len) return error.MissingTokenSlotValue;
            token_policy.slot_ms = std.fmt.parseInt(u64, args[i], 10) catch return error.BadTokenSlotValue;
        } else if (std.mem.eql(u8, args[i], "--token-max-age-slots")) {
            i += 1;
            if (i >= args.len) return error.MissingTokenMaxAgeValue;
            token_policy.max_age_slots = std.fmt.parseInt(u8, args[i], 10) catch return error.BadTokenMaxAgeValue;
        } else if (std.mem.eql(u8, args[i], "--token-max-future-slots")) {
            i += 1;
            if (i >= args.len) return error.MissingTokenMaxFutureValue;
            token_policy.max_future_slots = std.fmt.parseInt(u8, args[i], 10) catch return error.BadTokenMaxFutureValue;
        } else if (std.mem.eql(u8, args[i], "--min-client-ver")) {
            i += 1;
            if (i >= args.len) return error.MissingMinClientVerValue;
            min_client_version = std.SemanticVersion.parse(args[i]) catch return error.BadMinClientVerValue;
        } else if (std.mem.eql(u8, args[i], "--max-client-ver")) {
            i += 1;
            if (i >= args.len) return error.MissingMaxClientVerValue;
            max_client_version = std.SemanticVersion.parse(args[i]) catch return error.BadMaxClientVerValue;
        } else if (std.mem.eql(u8, args[i], "--cover-target")) {
            i += 1;
            if (i >= args.len) return error.MissingCoverTargetValue;
            cover_target = try parseCoverTarget(args[i]);
        } else if (std.mem.eql(u8, args[i], "--cover-site")) {
            i += 1;
            if (i >= args.len) return error.MissingCoverSiteValue;
            try pool_entries.append(gpa, try parseCoverSite(args[i]));
        } else if (std.mem.eql(u8, args[i], "--admission-fail-threshold")) {
            i += 1;
            if (i >= args.len) return error.MissingAdmissionFailThresholdValue;
            rate_limit_cfg.failures_per_window = std.fmt.parseInt(u32, args[i], 10) catch return error.BadAdmissionFailThresholdValue;
        } else if (std.mem.eql(u8, args[i], "--admission-window-ms")) {
            i += 1;
            if (i >= args.len) return error.MissingAdmissionWindowValue;
            rate_limit_cfg.window_ms = std.fmt.parseInt(i64, args[i], 10) catch return error.BadAdmissionWindowValue;
        } else if (std.mem.eql(u8, args[i], "--admission-silent-ms")) {
            i += 1;
            if (i >= args.len) return error.MissingAdmissionSilentValue;
            rate_limit_cfg.silent_duration_ms = std.fmt.parseInt(i64, args[i], 10) catch return error.BadAdmissionSilentValue;
        } else if (std.mem.eql(u8, args[i], "--metrics-listen")) {
            i += 1;
            if (i >= args.len) return error.MissingMetricsListenValue;
            _, _, metrics_listen = try parseListenSpec(args[i]);
        } else if (std.mem.eql(u8, args[i], "--help") or std.mem.eql(u8, args[i], "-h")) {
            try printUsage(io);
            return;
        } else {
            try printUsage(io);
            return error.UnknownArg;
        }
    }

    const reality_config: ayllu_camouflage.reality.Config = .{
        .target = target orelse return error.MissingTargetValue,
        .server_names = server_names.items,
        .private_key = private_key orelse return error.MissingPrivateKeyValue,
        .min_client_version = min_client_version,
        .max_client_version = max_client_version,
        .max_time_diff_ms = max_time_diff_ms,
        .short_ids = short_ids.items,
        .inner_protocol = inner_protocol,
        .vless_uuid = vless_uuid,
    };
    try reality_config.validate();

    var registry: ayllu_camouflage.metrics.Registry = .{};

    // Generate a fresh Ed25519 self-signed stub cert per process start.
    // REALITY normally proxies the cover host's real cert — C6's harvest
    // pipeline replaces this stub with captured bytes.
    const now_unix_s: i64 = @intCast(@divFloor(std.Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
    var cert_stub = try ayllu_camouflage.tls.cert_stub.CertStub.generate(
        gpa,
        io,
        reality_config.server_names[0],
        now_unix_s,
    );
    defer cert_stub.deinit();

    var state: ayllu_camouflage.server.State = .{
        .config = .{
            .pivot = .{
                .reality = reality_config,
                .token_policy = token_policy,
            },
            .proxy = proxy_config,
            .cover_target = cover_target,
            .cover_pool = ayllu_camouflage.cover_pool.Pool.init(pool_entries.items),
            .rate_limit = rate_limit_cfg,
        },
        .metrics = &registry,
        .allocator = gpa,
    };
    state.initLimiter(gpa);
    defer state.deinitLimiter();

    // Optional Prometheus-style metrics endpoint on a separate listener.
    var metrics_server_storage: ?std.Io.net.Server = null;
    if (metrics_listen) |m_addr| {
        metrics_server_storage = try m_addr.listen(io, .{ .reuse_address = true });
        _ = io.async(ayllu_camouflage.metrics.serve, .{ io, &metrics_server_storage.?, @as(*const ayllu_camouflage.metrics.Registry, &registry) });
    }
    defer if (metrics_server_storage) |*s| s.deinit(io);

    const addr = listen_addr orelse try std.Io.net.IpAddress.parse(listen_host, listen_port);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);

    // Optional second listener for REALITY-speaking clients. Shares
    // the same `state` so metrics and rate-limit buckets are unified.
    var reality_server_storage: ?std.Io.net.Server = null;
    if (reality_listen_addr) |r_addr| {
        reality_server_storage = try r_addr.listen(io, .{ .reuse_address = true });
        _ = io.async(realityAcceptLoop, .{ io, &reality_server_storage.?, &state, &cert_stub });
    }
    defer if (reality_server_storage) |*s| s.deinit(io);

    var stdout_buffer: [512]u8 = undefined;
    var stdout_writer: std.Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    try stdout_writer.interface.print(
        "ayllu-camouflage-proxy listening on {s}:{d} -> camouflage target {s}:{d}\n",
        .{ listen_host, listen_port, reality_config.target.host, reality_config.target.port },
    );
    if (reality_listen_host) |rh| {
        try stdout_writer.interface.print(
            "  reality listener on {s}:{d}\n",
            .{ rh, reality_listen_port },
        );
    }
    try stdout_writer.interface.flush();

    while (true) {
        const client_stream = server.accept(io) catch |err| {
            std.log.warn("accept failed: {t}", .{err});
            continue;
        };
        _ = io.async(sessionWrapper, .{ io, client_stream.socket, &state });
    }
}

fn realityAcceptLoop(
    io: std.Io,
    server: *std.Io.net.Server,
    state: *ayllu_camouflage.server.State,
    cert_stub: *const ayllu_camouflage.tls.cert_stub.CertStub,
) !void {
    while (true) {
        const client_stream = server.accept(io) catch |err| switch (err) {
            error.SocketNotListening => return,
            else => {
                std.log.warn("reality accept failed: {t}", .{err});
                continue;
            },
        };
        _ = io.async(realitySessionWrapper, .{ io, client_stream.socket, state, cert_stub });
    }
}

fn realitySessionWrapper(
    io: std.Io,
    socket: std.Io.net.Socket,
    state: *ayllu_camouflage.server.State,
    cert_stub: *const ayllu_camouflage.tls.cert_stub.CertStub,
) void {
    var xport = ayllu_camouflage.tls.reality_transport.RealityTransport.init(.{
        .config = state.config.pivot.reality,
        .cert_stub = cert_stub,
        .metrics = state.metrics,
    });
    ayllu_camouflage.server.dispatch(io, socket, state, xport.outerTransport()) catch |err| switch (err) {
        error.EndOfStream, error.Canceled => {},
        else => std.log.warn("reality session ended: {t}", .{err}),
    };
}

fn sessionWrapper(io: std.Io, socket: std.Io.net.Socket, state: *ayllu_camouflage.server.State) void {
    ayllu_camouflage.server.sessionWithState(io, socket, state) catch |err| switch (err) {
        error.EndOfStream, error.Canceled => {},
        else => std.log.warn("camouflage session ended: {t}", .{err}),
    };
}

fn printUsage(io: std.Io) !void {
    var buf: [1536]u8 = undefined;
    var w: std.Io.File.Writer = .init(.stdout(), io, &buf);
    try w.interface.writeAll(
        \\ayllu-camouflage-proxy — HTTP-like camouflage gate + inner SOCKS5
        \\
        \\Usage:
        \\  ayllu-camouflage-proxy --target HOST:PORT --server-name NAME --private-key KEY --short-id HEX [options]
        \\
        \\Required:
        \\  --target HOST:PORT         camouflage target identity (for transcript binding)
        \\  --server-name NAME         accepted Host header / server name (repeatable)
        \\  --private-key KEY          REALITY private key (base64url, no padding)
        \\  --short-id HEX             accepted short id (repeatable)
        \\
        \\Options:
        \\  --listen HOST:PORT         legacy-HTTP bind address (default 0.0.0.0:443)
        \\  --reality-listen HOST:PORT optional second listener speaking TLS 1.3
        \\                             REALITY (Xray v25.x wire-compat).
        \\  --inner-protocol {socks5|vless}  inner protocol inside the
        \\                             REALITY stream. Default socks5.
        \\  --vless-uuid UUID          required when --inner-protocol=vless.
        \\                             Accepts the canonical dashed form
        \\                             (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
        \\                             or the flat 32-hex form.
        \\  --auth-file PATH           inner SOCKS username:password file
        \\  --max-time-diff-ms N       clock skew allowance (default 5000)
        \\  --token-slot-ms N          token slot size (default 1000)
        \\  --token-max-age-slots N    accepted stale slots (default 2)
        \\  --token-max-future-slots N accepted future slots (default 1)
        \\  --min-client-ver X.Y.Z     minimum client version
        \\  --max-client-ver X.Y.Z     maximum client version
        \\  --cover-target HOST:PORT   single honest reverse-proxy destination
        \\                             for failed admissions (default: static 404)
        \\  --cover-site  HOST:PORT[:W] add to weighted cover pool (repeatable);
        \\                             pool takes precedence over --cover-target
        \\  --admission-fail-threshold N  failures/window before silent-drop
        \\                             (default 20)
        \\  --admission-window-ms N    window length for failure count
        \\                             (default 60000)
        \\  --admission-silent-ms N    how long to drop silently after trip
        \\                             (default 300000)
        \\  --metrics-listen HOST:PORT serve Prometheus /metrics on a separate
        \\                             port; counters for sessions, fallbacks,
        \\                             silent drops, and upstream errors
        \\  --help                     show this help
        \\
    );
    try w.interface.flush();
}

fn parseCoverTarget(spec: []const u8) !ayllu_camouflage.reverse_proxy.CoverTarget {
    const colon = std.mem.lastIndexOfScalar(u8, spec, ':') orelse
        return .{ .host = spec, .port = 443 };
    const port = std.fmt.parseInt(u16, spec[colon + 1 ..], 10) catch return error.BadCoverTargetValue;
    return .{ .host = spec[0..colon], .port = port };
}

/// Parses "HOST", "HOST:PORT", or "HOST:PORT:WEIGHT" for the cover pool.
fn parseCoverSite(spec: []const u8) !ayllu_camouflage.cover_pool.WeightedCover {
    // Split on ':' with at most 2 splits to support HOST:PORT:WEIGHT.
    var host: []const u8 = spec;
    var port: u16 = 443;
    var weight: u32 = 1;

    const first = std.mem.indexOfScalar(u8, spec, ':') orelse
        return .{ .target = .{ .host = spec, .port = 443 }, .weight = 1 };
    host = spec[0..first];
    const after = spec[first + 1 ..];
    const second = std.mem.indexOfScalar(u8, after, ':');
    if (second) |k| {
        port = std.fmt.parseInt(u16, after[0..k], 10) catch return error.BadCoverSiteValue;
        weight = std.fmt.parseInt(u32, after[k + 1 ..], 10) catch return error.BadCoverSiteValue;
    } else {
        port = std.fmt.parseInt(u16, after, 10) catch return error.BadCoverSiteValue;
    }
    return .{ .target = .{ .host = host, .port = port }, .weight = weight };
}

test "parseCoverSite: HOST:PORT:WEIGHT" {
    const c = try parseCoverSite("archive.ubuntu.com:443:3");
    try std.testing.expectEqualStrings("archive.ubuntu.com", c.target.host);
    try std.testing.expectEqual(@as(u16, 443), c.target.port);
    try std.testing.expectEqual(@as(u32, 3), c.weight);
}

test "parseCoverSite: HOST:PORT defaults weight=1" {
    const c = try parseCoverSite("www.debian.org:443");
    try std.testing.expectEqual(@as(u32, 1), c.weight);
}

test "parseCoverTarget: HOST:PORT" {
    const c = try parseCoverTarget("archive.ubuntu.com:443");
    try std.testing.expectEqualStrings("archive.ubuntu.com", c.host);
    try std.testing.expectEqual(@as(u16, 443), c.port);
}

test "parseCoverTarget: HOST only defaults to 443" {
    const c = try parseCoverTarget("www.microsoft.com");
    try std.testing.expectEqualStrings("www.microsoft.com", c.host);
    try std.testing.expectEqual(@as(u16, 443), c.port);
}

fn parseListenSpec(spec: []const u8) !struct { []const u8, u16, std.Io.net.IpAddress } {
    if (spec.len == 0) return error.BadListenSpec;

    if (spec[0] == '[') {
        const end = std.mem.indexOfScalar(u8, spec, ']') orelse return error.BadListenSpec;
        if (end + 1 >= spec.len or spec[end + 1] != ':') return error.BadListenSpec;
        const host = spec[1..end];
        const port = std.fmt.parseInt(u16, spec[end + 2 ..], 10) catch return error.BadListenSpec;
        return .{ host, port, try std.Io.net.IpAddress.parse(host, port) };
    }

    const colon = std.mem.lastIndexOfScalar(u8, spec, ':') orelse return error.BadListenSpec;
    if (std.mem.indexOfScalar(u8, spec[0..colon], ':') != null) return error.BadListenSpec;
    const host = spec[0..colon];
    const port = std.fmt.parseInt(u16, spec[colon + 1 ..], 10) catch return error.BadListenSpec;
    return .{ host, port, try std.Io.net.IpAddress.parse(host, port) };
}

test "parseListenSpec parses IPv4 and bracketed IPv6" {
    const host4, const port4, const addr4 = try parseListenSpec("127.0.0.1:443");
    try std.testing.expectEqualStrings("127.0.0.1", host4);
    try std.testing.expectEqual(@as(u16, 443), port4);
    try std.testing.expect(addr4 == .ip4);

    const host6, const port6, const addr6 = try parseListenSpec("[::1]:8443");
    try std.testing.expectEqualStrings("::1", host6);
    try std.testing.expectEqual(@as(u16, 8443), port6);
    try std.testing.expect(addr6 == .ip6);
}
