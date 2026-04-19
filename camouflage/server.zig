//! Runtime bridge: HTTP-like camouflage head -> REALITY admission -> SOCKS.

const std = @import("std");
const ayllu = @import("ayllu");
const proxy = @import("ayllu-proxy");
const pivot = @import("pivot.zig");
const reality = @import("reality.zig");
const tokens = @import("tokens.zig");

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
};

pub const State = struct {
    config: Config,
    mutex: std.Io.Mutex = .init,
    replay_cache: tokens.ReplayCache(replay_cache_entries) = .{},
};

pub fn sessionWithState(io: std.Io, client_socket: std.Io.net.Socket, state: *State) !void {
    const client_stream: std.Io.net.Stream = .{ .socket = client_socket };
    defer client_stream.close(io);

    var rbuf: [max_request_head_bytes]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(client_stream, io, &rbuf);
    var writer = std.Io.net.Stream.Writer.init(client_stream, io, &wbuf);

    const head = takeRequestHead(&reader.interface, state.config.pivot.max_request_bytes) catch |err| switch (err) {
        error.EndOfStream => return err,
        else => {
            writeFallbackResponse(&writer.interface, state.config.fallback) catch {};
            return err;
        },
    };

    state.mutex.lockUncancelable(io);
    const decision = pivot.classify(
        replay_cache_entries,
        head,
        state.config.pivot,
        nowUnixMs(io),
        &state.replay_cache,
    ) catch |err| {
        state.mutex.unlock(io);
        writeFallbackResponse(&writer.interface, state.config.fallback) catch {};
        return err;
    };
    state.mutex.unlock(io);

    switch (decision) {
        .fallback => {
            try writeFallbackResponse(&writer.interface, state.config.fallback);
        },
        .pivot => {
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

fn nowUnixMs(io: std.Io) i64 {
    return @intCast(@divFloor(std.Io.Clock.real.now(io).nanoseconds, 1_000_000));
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
