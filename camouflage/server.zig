//! Runtime bridge: HTTP-like camouflage head -> REALITY admission -> SOCKS.

const std = @import("std");
const ayllu = @import("ayllu");
const proxy = @import("ayllu-proxy");
const pivot = @import("pivot.zig");
const reality = @import("reality.zig");
const tokens = @import("tokens.zig");
const reverse_proxy = @import("reverse_proxy.zig");
const rate_limit = @import("rate_limit.zig");
const cover_pool = @import("cover_pool.zig");
const metrics_mod = @import("metrics.zig");

pub const replay_cache_entries = 4096;
pub const max_request_head_bytes = 8192;

const default_fallback_body =
    "<!doctype html><html><head><title>404 Not Found</title></head>" ++
    "<body><h1>Not Found</h1><p>The requested resource was not found on this server.</p></body></html>";

pub const FallbackResponse = struct {
    status: []const u8 = "404 Not Found",
    content_type: []const u8 = "text/html; charset=utf-8",
    body: []const u8 = default_fallback_body,
};

pub const Config = struct {
    pivot: pivot.Config,
    proxy: proxy.daemon.Config = .{},
    fallback: FallbackResponse = .{},
    /// Optional cover-site reverse proxy: when admission fails (probe,
    /// non-SOCKS bytes, wrong token), we TCP-passthrough the session to
    /// one of these hosts (weighted rotation per-session). Gives active
    /// probes a byte-for-byte real response and burns fewer IPs.
    cover_target: ?reverse_proxy.CoverTarget = null,
    /// Optional weighted pool of cover hosts. When set, takes precedence
    /// over `cover_target`. Entries are picked via std.Io.random per
    /// session.
    cover_pool: cover_pool.Pool = cover_pool.Pool.init(&.{}),
    /// Per-source admission-failure rate limit. Enabled by default so a
    /// single adversary can't enumerate the short_id space for free.
    rate_limit: rate_limit.Config = .{},
};

pub const State = struct {
    config: Config,
    mutex: std.Io.Mutex = .init,
    replay_cache: tokens.ReplayCache(replay_cache_entries) = .{},
    limiter: ?rate_limit.RateLimiter = null,
    metrics: ?*metrics_mod.Registry = null,

    pub fn initLimiter(self: *State, allocator: std.mem.Allocator) void {
        self.limiter = rate_limit.RateLimiter.init(allocator, self.config.rate_limit);
    }

    pub fn deinitLimiter(self: *State) void {
        if (self.limiter) |*l| l.deinit();
        self.limiter = null;
    }
};

pub fn sessionWithState(io: std.Io, client_socket: std.Io.net.Socket, state: *State) !void {
    const client_stream: std.Io.net.Stream = .{ .socket = client_socket };
    defer client_stream.close(io);

    if (state.metrics) |m| m.sessions_total.inc();

    // Rate-limit check BEFORE any crypto. Silent-drop indistinguishable
    // from a random TCP stall from the client's point of view.
    const peer_key = peerPrefixFromSocket(client_socket);
    if (state.limiter) |*l| {
        state.mutex.lockUncancelable(io);
        const verdict = l.consult(peer_key, nowUnixMs(io));
        state.mutex.unlock(io);
        if (verdict == .drop_silently) {
            if (state.metrics) |m| m.admission_silent_drops_total.inc();
            return;
        }
    }

    var rbuf: [max_request_head_bytes]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(client_stream, io, &rbuf);
    var writer = std.Io.net.Stream.Writer.init(client_stream, io, &wbuf);

    const admission_deadline = proxy.timeouts.deadlineFromNowMs(io, proxy.timeouts.Defaults.handshake_ms);
    const head = takeRequestHeadWithDeadline(io, &reader.interface, state.config.pivot.max_request_bytes, admission_deadline) catch |err| switch (err) {
        error.EndOfStream, error.Timeout => return err,
        else => {
            recordAdmissionFailure(state, peer_key, io);
            if (state.metrics) |m| m.admission_fallback_total.inc();
            const partial = reader.interface.buffered();
            try serveFallback(io, state, partial, &reader.interface, &writer.interface, &client_stream);
            return;
        },
    };

    state.mutex.lockUncancelable(io);
    const decision = pivot.classify(
        replay_cache_entries,
        head,
        state.config.pivot,
        nowUnixMs(io),
        &state.replay_cache,
    ) catch {
        state.mutex.unlock(io);
        recordAdmissionFailure(state, peer_key, io);
        try serveFallback(io, state, head, &reader.interface, &writer.interface, &client_stream);
        return;
    };
    state.mutex.unlock(io);

    switch (decision) {
        .fallback => {
            recordAdmissionFailure(state, peer_key, io);
            if (state.metrics) |m| m.admission_fallback_total.inc();
            try serveFallback(io, state, head, &reader.interface, &writer.interface, &client_stream);
        },
        .pivot => {
            recordAdmissionSuccess(state, peer_key, io);
            if (state.metrics) |m| m.admission_success_total.inc();
            try writer.interface.writeAll(
                "HTTP/1.1 101 Switching Protocols\r\n" ++
                    "Connection: Upgrade\r\n" ++
                    "Upgrade: ayllu-socks\r\n\r\n",
            );
            try writer.interface.flush();
            try proxy.daemon.sessionOnPreparedStream(io, .{
                .reader = &reader.interface,
                .writer = &writer.interface,
                .net_stream = &client_stream,
            }, state.config.proxy);
        },
    }
}

fn takeRequestHead(reader: *std.Io.Reader, max_request_bytes: usize) ![]const u8 {
    if (max_request_bytes == 0 or max_request_bytes > max_request_head_bytes) {
        return error.HeaderTooLarge;
    }

    var need: usize = 1;
    while (true) {
        const buffered = try reader.peekGreedy(need);
        if (std.mem.indexOf(u8, buffered, "\r\n\r\n")) |header_end| {
            return reader.take(header_end + 4);
        }
        if (buffered.len >= max_request_bytes) return error.HeaderTooLarge;
        need = @min(max_request_bytes, buffered.len + 1);
    }
}

/// Wraps takeRequestHead in a deadline race so an idle client on the
/// admission port doesn't pin a worker. Returns error.Timeout when the
/// deadline fires before `\r\n\r\n` appears.
fn takeRequestHeadWithDeadline(
    io: std.Io,
    reader: *std.Io.Reader,
    max_request_bytes: usize,
    deadline: std.Io.Clock.Timestamp,
) ![]const u8 {
    const Outcome = union(enum) {
        ok: anyerror![]const u8,
        expire: std.Io.Cancelable!void,
    };
    var buf: [2]Outcome = undefined;
    var select = std.Io.Select(Outcome).init(io, &buf);
    defer select.cancelDiscard();
    select.async(.ok, takeRequestHead, .{ reader, max_request_bytes });
    select.async(.expire, std.Io.Timeout.sleep, .{ .{ .deadline = deadline }, io });
    return switch (try select.await()) {
        .ok => |r| try r,
        .expire => error.Timeout,
    };
}

fn writeFallbackResponse(writer: *std.Io.Writer, fallback: FallbackResponse) !void {
    var head_buf: [512]u8 = undefined;
    const head = try std.fmt.bufPrint(
        &head_buf,
        "HTTP/1.1 {s}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n",
        .{ fallback.status, fallback.content_type, fallback.body.len },
    );
    try writer.writeAll(head);
    try writer.writeAll(fallback.body);
    try writer.flush();
}

/// Decides between reverse-proxy to cover (if configured) and the static
/// 404. The reverse-proxy path is the preferred one for any deploy that
/// expects active probes; the static path is kept for tests and for
/// operators who can't reach a cover host from the VPS.
fn serveFallback(
    io: std.Io,
    state: *State,
    buffered_head: []const u8,
    reader_iface: *std.Io.Reader,
    writer_iface: *std.Io.Writer,
    client_stream: *const std.Io.net.Stream,
) !void {
    // Prefer the weighted pool; fall back to the single cover_target; then
    // to the static 404.
    const chosen: ?reverse_proxy.CoverTarget = blk: {
        if (state.config.cover_pool.pickRandom(io)) |t| break :blk t;
        break :blk state.config.cover_target;
    };
    if (chosen) |cover| {
        const cover_deadline = proxy.timeouts.deadlineFromNowMs(io, proxy.timeouts.Defaults.upstream_connect_ms);
        reverse_proxy.forwardBuffered(
            io,
            cover,
            buffered_head,
            reader_iface,
            writer_iface,
            client_stream,
            cover_deadline,
        ) catch {
            // Cover unreachable / pipe failed. Fall back to static so the
            // client still gets a closed socket cleanly instead of a hang.
            writeFallbackResponse(writer_iface, state.config.fallback) catch {};
        };
    } else {
        try writeFallbackResponse(writer_iface, state.config.fallback);
    }
}

fn nowUnixMs(io: std.Io) i64 {
    return @intCast(@divFloor(std.Io.Clock.real.now(io).nanoseconds, 1_000_000));
}

fn recordAdmissionFailure(state: *State, key: rate_limit.PrefixKey, io: std.Io) void {
    if (state.limiter) |*l| {
        state.mutex.lockUncancelable(io);
        l.recordFailure(key, nowUnixMs(io));
        state.mutex.unlock(io);
    }
}

fn recordAdmissionSuccess(state: *State, key: rate_limit.PrefixKey, io: std.Io) void {
    if (state.limiter) |*l| {
        state.mutex.lockUncancelable(io);
        l.recordSuccess(key, nowUnixMs(io));
        state.mutex.unlock(io);
    }
}

/// Extract a /24 or /64 prefix for the peer from a connected socket handle.
/// On failure (unsupported address family, syscall error) returns the zero
/// prefix — all anonymous peers then share one bucket, which is still
/// enough to rate-limit an adversary probing without a stable source IP.
fn peerPrefixFromSocket(socket: std.Io.net.Socket) rate_limit.PrefixKey {
    var addr: std.posix.sockaddr.storage = undefined;
    var addrlen: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
    std.posix.getpeername(socket.handle, @ptrCast(&addr), &addrlen) catch return rate_limit.ipv4_zero_prefix;
    switch (addr.family) {
        std.posix.AF.INET => {
            const sin: *const std.posix.sockaddr.in = @ptrCast(@alignCast(&addr));
            const raw = std.mem.asBytes(&sin.addr)[0..4].*;
            return rate_limit.prefixFromIpv4(raw);
        },
        std.posix.AF.INET6 => {
            const sin6: *const std.posix.sockaddr.in6 = @ptrCast(@alignCast(&addr));
            return rate_limit.prefixFromIpv6(sin6.addr);
        },
        else => return rate_limit.ipv4_zero_prefix,
    }
}

fn echoOnce(io: std.Io, server: *std.Io.net.Server, expected_len: usize) anyerror!void {
    const stream = try server.accept(io);
    defer stream.close(io);

    var rbuf: [256]u8 = undefined;
    var wbuf: [256]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(stream, io, &rbuf);
    var writer = std.Io.net.Stream.Writer.init(stream, io, &wbuf);

    const payload = try reader.interface.take(expected_len);
    try writer.interface.writeAll(payload);
    try writer.interface.flush();
}

fn acceptOneSession(io: std.Io, server: *std.Io.net.Server, state: *State) anyerror!void {
    const accepted = try server.accept(io);
    try sessionWithState(io, accepted.socket, state);
}

fn hex32(comptime s: *const [64]u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "sessionWithState falls back with honest HTTP response when token is absent" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try (@as(std.Io.net.IpAddress, .{
        .ip4 = std.Io.net.Ip4Address.loopback(0),
    })).listen(io, .{ .reuse_address = true });
    defer server.deinit(io);

    var state: State = .{
        .config = .{
            .pivot = .{
                .reality = .{
                    .target = .{ .host = "example.com", .port = 443 },
                    .server_names = &.{"example.com"},
                    .private_key = hex32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
                    .short_ids = &[_]reality.ShortId{try reality.parseShortId("aabb")},
                },
            },
        },
    };

    var session_task = io.async(acceptOneSession, .{ io, &server, &state });
    errdefer session_task.cancel(io) catch {};

    const port = server.socket.address.getPort();
    const client = try (@as(std.Io.net.IpAddress, .{
        .ip4 = std.Io.net.Ip4Address.loopback(port),
    })).connect(io, .{ .mode = .stream });
    var client_open = true;
    defer if (client_open) client.close(io);

    var cr_buf: [512]u8 = undefined;
    var cw_buf: [512]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(client, io, &cr_buf);
    var writer = std.Io.net.Stream.Writer.init(client, io, &cw_buf);

    try writer.interface.writeAll("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    try writer.interface.flush();

    const response = try reader.interface.peekGreedy(1);
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 404 Not Found"));

    client.close(io);
    client_open = false;
    try session_task.await(io);
}

test "sessionWithState reverse-proxies to cover host on admission fallback" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Fake cover server: reads some bytes and echoes them back.
    var cover = try (@as(std.Io.net.IpAddress, .{
        .ip4 = std.Io.net.Ip4Address.loopback(0),
    })).listen(io, .{ .reuse_address = true });
    defer cover.deinit(io);
    const cover_port = cover.socket.address.getPort();
    const probe = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    var cover_task = io.async(echoOnce, .{ io, &cover, probe.len });
    errdefer cover_task.cancel(io) catch {};

    // Camouflage server configured to reverse-proxy fallbacks to the fake.
    var camo = try (@as(std.Io.net.IpAddress, .{
        .ip4 = std.Io.net.Ip4Address.loopback(0),
    })).listen(io, .{ .reuse_address = true });
    defer camo.deinit(io);

    var state: State = .{
        .config = .{
            .pivot = .{
                .reality = .{
                    .target = .{ .host = "example.com", .port = 443 },
                    .server_names = &.{"example.com"},
                    .private_key = hex32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
                    .short_ids = &[_]reality.ShortId{try reality.parseShortId("aabb")},
                },
            },
            .cover_target = .{ .host = "127.0.0.1", .port = cover_port },
        },
    };

    var camo_task = io.async(acceptOneSession, .{ io, &camo, &state });
    errdefer camo_task.cancel(io) catch {};

    const camo_port = camo.socket.address.getPort();
    const client = try (@as(std.Io.net.IpAddress, .{
        .ip4 = std.Io.net.Ip4Address.loopback(camo_port),
    })).connect(io, .{ .mode = .stream });
    var client_open = true;
    defer if (client_open) client.close(io);

    var cr_buf: [512]u8 = undefined;
    var cw_buf: [512]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(client, io, &cr_buf);
    var writer = std.Io.net.Stream.Writer.init(client, io, &cw_buf);

    // Probe: a plain HTTP request without REALITY admission headers —
    // classify -> .fallback -> reverse-proxy -> cover echoes bytes back.
    try writer.interface.writeAll(probe);
    try writer.interface.flush();

    const echoed = try reader.interface.take(probe.len);
    try std.testing.expectEqualStrings(probe, echoed);

    client.close(io);
    client_open = false;
    try cover_task.await(io);
    try camo_task.await(io);
}

test "rate limiter silences the source after repeated admission failures" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var camo = try (@as(std.Io.net.IpAddress, .{
        .ip4 = std.Io.net.Ip4Address.loopback(0),
    })).listen(io, .{ .reuse_address = true });
    defer camo.deinit(io);

    var state: State = .{
        .config = .{
            .pivot = .{
                .reality = .{
                    .target = .{ .host = "example.com", .port = 443 },
                    .server_names = &.{"example.com"},
                    .private_key = hex32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
                    .short_ids = &[_]reality.ShortId{try reality.parseShortId("aabb")},
                },
            },
            .rate_limit = .{
                .failures_per_window = 2,
                .window_ms = 60_000,
                .silent_duration_ms = 60_000,
            },
        },
    };
    state.initLimiter(std.testing.allocator);
    defer state.deinitLimiter();

    const camo_port = camo.socket.address.getPort();

    // Fire enough failed admissions to trip the limiter: 2 failures (under
    // failures_per_window=2) flips the /24 into silent-drop for 60s.
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        var session_task = io.async(acceptOneSession, .{ io, &camo, &state });
        errdefer session_task.cancel(io) catch {};

        const client = try (@as(std.Io.net.IpAddress, .{
            .ip4 = std.Io.net.Ip4Address.loopback(camo_port),
        })).connect(io, .{ .mode = .stream });
        var client_open = true;
        defer if (client_open) client.close(io);

        var cr_buf: [128]u8 = undefined;
        var cw_buf: [128]u8 = undefined;
        var reader = std.Io.net.Stream.Reader.init(client, io, &cr_buf);
        var writer = std.Io.net.Stream.Writer.init(client, io, &cw_buf);

        // Probe with no admission token => classify .fallback => records failure.
        writer.interface.writeAll("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n") catch {};
        writer.interface.flush() catch {};

        // Read whatever the server gives us (fallback body or silent EOF).
        var scratch: [64]u8 = undefined;
        const n = reader.interface.readVec(@constCast(&[_][]u8{&scratch})) catch 0;
        _ = n;
        client.close(io);
        client_open = false;
        session_task.await(io) catch {};
    }

    // Next connection should be silent-dropped: limiter consult returns
    // .drop_silently before any reads; server closes the socket with no
    // response.
    var final_task = io.async(acceptOneSession, .{ io, &camo, &state });
    errdefer final_task.cancel(io) catch {};
    const final_client = try (@as(std.Io.net.IpAddress, .{
        .ip4 = std.Io.net.Ip4Address.loopback(camo_port),
    })).connect(io, .{ .mode = .stream });
    defer final_client.close(io);

    var cr_buf: [64]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(final_client, io, &cr_buf);

    // Silent drop manifests as an immediate EOF from the server side.
    const peek_result = reader.interface.peek(1);
    try std.testing.expectError(error.EndOfStream, peek_result);
    try final_task.await(io);
}

test "sessionWithState pivots then serves inner SOCKS over the same socket" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var upstream = try (@as(std.Io.net.IpAddress, .{
        .ip4 = std.Io.net.Ip4Address.loopback(0),
    })).listen(io, .{ .reuse_address = true });
    defer upstream.deinit(io);
    const upstream_port = upstream.socket.address.getPort();
    var upstream_task = io.async(echoOnce, .{ io, &upstream, 4 });
    errdefer upstream_task.cancel(io) catch {};

    const server_cfg: reality.Config = .{
        .target = .{ .host = "example.com", .port = 443 },
        .server_names = &.{"example.com"},
        .private_key = hex32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
        .min_client_version = try std.SemanticVersion.parse("1.0.0"),
        .max_client_version = try std.SemanticVersion.parse("2.0.0"),
        .max_time_diff_ms = 5_000,
        .short_ids = &[_]reality.ShortId{try reality.parseShortId("aabb")},
    };
    const public_cfg = try server_cfg.exportPublic();
    const client_private = hex32("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40");
    const now_ms = nowUnixMs(io);
    const hello: reality.Hello = .{
        .server_name = "example.com",
        .short_id = try reality.parseShortId("aabb"),
        .client_public_key = try ayllu.crypto.X25519.recoverPublicKey(client_private),
        .client_version = try std.SemanticVersion.parse("1.5.0"),
        .unix_ms = now_ms,
    };
    const client_material = try reality.deriveClientMaterial(public_cfg, client_private, hello);
    const token = try tokens.issue(.{
        .auth_key = client_material.auth_key,
        .method = "GET",
        .path = "/pivot",
        .short_id = hello.short_id,
    }, now_ms, .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 }, .{});

    var camo = try (@as(std.Io.net.IpAddress, .{
        .ip4 = std.Io.net.Ip4Address.loopback(0),
    })).listen(io, .{ .reuse_address = true });
    defer camo.deinit(io);

    var state: State = .{
        .config = .{
            .pivot = .{ .reality = server_cfg },
        },
    };
    const camo_port = camo.socket.address.getPort();
    var session_task = io.async(acceptOneSession, .{ io, &camo, &state });
    errdefer session_task.cancel(io) catch {};

    const client = try (@as(std.Io.net.IpAddress, .{
        .ip4 = std.Io.net.Ip4Address.loopback(camo_port),
    })).connect(io, .{ .mode = .stream });
    var client_open = true;
    defer if (client_open) client.close(io);

    var cr_buf: [1024]u8 = undefined;
    var cw_buf: [1024]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(client, io, &cr_buf);
    var writer = std.Io.net.Stream.Writer.init(client, io, &cw_buf);

    var client_key_text: [reality.encoded_key_length]u8 = undefined;
    const client_key = try reality.encodeKey(&client_key_text, hello.client_public_key);
    var token_text: [tokens.encoded_length]u8 = undefined;
    const encoded_token = try tokens.encode(&token_text, token);

    var request_head_buf: [1024]u8 = undefined;
    const request_head = try std.fmt.bufPrint(
        &request_head_buf,
        "GET /pivot HTTP/1.1\r\nHost: example.com\r\nX-Ayllu-Client-Key: {s}\r\nX-Ayllu-Time: {d}\r\nX-Ayllu-Client-Version: 1.5.0\r\nX-Ayllu-Short-Id: aabb\r\nX-Ayllu-Token: {s}\r\n\r\n",
        .{ client_key, now_ms, encoded_token },
    );
    try writer.interface.writeAll(request_head);
    try writer.interface.flush();

    const pivot_response = try reader.interface.peekGreedy(1);
    try std.testing.expect(std.mem.startsWith(u8, pivot_response, "HTTP/1.1 101 Switching Protocols"));
    const pivot_response_end = std.mem.indexOf(u8, pivot_response, "\r\n\r\n") orelse return error.TestUnexpectedResult;
    _ = try reader.interface.take(pivot_response_end + 4);

    const greeting = [_]u8{ 0x05, 0x01, 0x00 };
    var socks_request = [_]u8{ 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 0 };
    std.mem.writeInt(u16, socks_request[8..10], upstream_port, .big);
    try writer.interface.writeAll(&greeting);
    try writer.interface.writeAll(&socks_request);
    try writer.interface.flush();

    const method_reply = try reader.interface.take(2);
    try std.testing.expectEqualSlices(u8, &.{ 0x05, 0x00 }, method_reply);
    const connect_reply = try reader.interface.take(10);
    try std.testing.expectEqualSlices(u8, &.{ 0x05, 0x00, 0x00, 0x01 }, connect_reply[0..4]);

    try writer.interface.writeAll("ping");
    try writer.interface.flush();
    const echoed = try reader.interface.take(4);
    try std.testing.expectEqualStrings("ping", echoed);

    client.close(io);
    client_open = false;
    try session_task.await(io);
    try upstream_task.await(io);
}
