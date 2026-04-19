//! Local bridge: plain local SOCKS client traffic -> outer camouflage gate.

const std = @import("std");
const ayllu = @import("ayllu");
const proxy = @import("ayllu-proxy");
const pivot = @import("pivot.zig");
const reality = @import("reality.zig");
const tokens = @import("tokens.zig");

pub const max_response_head_bytes = 8192;

pub const Config = struct {
    connect: reality.Target,
    public: reality.PublicConfig,
    server_name: []const u8,
    short_id: reality.ShortId,
    client_private_key: [reality.key_length]u8,
    client_version: std.SemanticVersion = .{ .major = 1, .minor = 0, .patch = 0 },
    request_method: []const u8 = "GET",
    request_path: []const u8 = "/pivot",
    headers: pivot.HeaderNames = .{},
    token_policy: tokens.Policy = .{},
    max_response_bytes: usize = 4096,

    pub fn validate(self: Config) !void {
        if (self.connect.host.len == 0 or self.connect.port == 0) return error.InvalidConnectTarget;
        if (self.server_name.len == 0) return error.InvalidServerName;
        if (self.request_method.len == 0 or self.request_path.len == 0) return error.InvalidRequestShape;
        if (self.max_response_bytes == 0 or self.max_response_bytes > max_response_head_bytes) {
            return error.BadResponseLimit;
        }
        _ = try ayllu.crypto.X25519.recoverPublicKey(self.client_private_key);
    }
};

pub fn sessionWithConfig(io: std.Io, client_socket: std.Io.net.Socket, config: Config) !void {
    try config.validate();

    const client_stream: std.Io.net.Stream = .{ .socket = client_socket };
    defer client_stream.close(io);

    var cr_buf: [4096]u8 = undefined;
    var cw_buf: [4096]u8 = undefined;
    var client_reader = std.Io.net.Stream.Reader.init(client_stream, io, &cr_buf);
    var client_writer = std.Io.net.Stream.Writer.init(client_stream, io, &cw_buf);

    const gateway_stream = try connectAndPivot(io, config);
    defer gateway_stream.close(io);

    var gr_buf: [4096]u8 = undefined;
    var gw_buf: [4096]u8 = undefined;
    var gateway_reader = std.Io.net.Stream.Reader.init(gateway_stream, io, &gr_buf);
    var gateway_writer = std.Io.net.Stream.Writer.init(gateway_stream, io, &gw_buf);

    try proxy.relay.bidirectional(
        io,
        .{
            .reader = &client_reader.interface,
            .writer = &client_writer.interface,
            .net_stream = &client_stream,
        },
        .{
            .reader = &gateway_reader.interface,
            .writer = &gateway_writer.interface,
            .net_stream = &gateway_stream,
        },
    );
}

pub fn connectAndPivot(io: std.Io, config: Config) !std.Io.net.Stream {
    try config.validate();

    const gateway_stream = try connectTarget(io, config.connect);
    errdefer gateway_stream.close(io);

    var rbuf: [max_response_head_bytes]u8 = undefined;
    var wbuf: [2048]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(gateway_stream, io, &rbuf);
    var writer = std.Io.net.Stream.Writer.init(gateway_stream, io, &wbuf);

    const now_ms = nowUnixMs(io);
    const client_public_key = try ayllu.crypto.X25519.recoverPublicKey(config.client_private_key);
    const hello: reality.Hello = .{
        .server_name = config.server_name,
        .short_id = config.short_id,
        .client_public_key = client_public_key,
        .client_version = config.client_version,
        .unix_ms = now_ms,
    };
    const material = try reality.deriveClientMaterial(config.public, config.client_private_key, hello);

    var nonce: [tokens.nonce_length]u8 = undefined;
    io.random(&nonce);
    const token = try tokens.issue(.{
        .auth_key = material.auth_key,
        .method = config.request_method,
        .path = config.request_path,
        .short_id = config.short_id,
    }, now_ms, nonce, config.token_policy);

    var client_key_buf: [reality.encoded_key_length]u8 = undefined;
    const client_key = try reality.encodeKey(&client_key_buf, client_public_key);
    var token_buf: [tokens.encoded_length]u8 = undefined;
    const token_text = try tokens.encode(&token_buf, token);
    var short_id_buf: [reality.max_short_id_length * 2]u8 = undefined;
    const short_id_text = try reality.formatShortId(&short_id_buf, config.short_id);
    var version_buf: [32]u8 = undefined;
    const version_text = try versionText(&version_buf, config.client_version);

    var request_buf: [1536]u8 = undefined;
    const request = try std.fmt.bufPrint(
        &request_buf,
        "{s} {s} HTTP/1.1\r\nHost: {s}\r\n{s}: {s}\r\n{s}: {d}\r\n{s}: {s}\r\n{s}: {s}\r\n{s}: {s}\r\n\r\n",
        .{
            config.request_method,
            config.request_path,
            config.server_name,
            config.headers.client_key_header_name,
            client_key,
            config.headers.client_time_header_name,
            now_ms,
            config.headers.client_version_header_name,
            version_text,
            config.headers.short_id_header_name,
            short_id_text,
            config.headers.token_header_name,
            token_text,
        },
    );
    try writer.interface.writeAll(request);
    try writer.interface.flush();

    const response = try takeResponseHead(&reader.interface, config.max_response_bytes);
    try expectSwitchingProtocols(response);
    return gateway_stream;
}

fn expectSwitchingProtocols(response: []const u8) !void {
    const line_end = std.mem.indexOf(u8, response, "\r\n") orelse return error.MalformedGatewayResponse;
    const status_line = response[0..line_end];
    if (!std.mem.startsWith(u8, status_line, "HTTP/1.1 ")) return error.MalformedGatewayResponse;
    if (!std.mem.startsWith(u8, status_line, "HTTP/1.1 101 ")) return error.BadGatewayResponse;
}

fn takeResponseHead(reader: *std.Io.Reader, max_response_bytes: usize) ![]const u8 {
    var need: usize = 1;
    while (true) {
        const buffered = try reader.peekGreedy(need);
        if (std.mem.indexOf(u8, buffered, "\r\n\r\n")) |header_end| {
            return reader.take(header_end + 4);
        }
        if (buffered.len >= max_response_bytes) return error.ResponseTooLarge;
        need = @min(max_response_bytes, buffered.len + 1);
    }
}

fn connectTarget(io: std.Io, target: reality.Target) !std.Io.net.Stream {
    if (std.Io.net.IpAddress.parse(target.host, target.port)) |addr| {
        return addr.connect(io, .{ .mode = .stream });
    } else |_| {}

    const host = try std.Io.net.HostName.init(target.host);
    return host.connect(io, target.port, .{ .mode = .stream });
}

fn nowUnixMs(io: std.Io) i64 {
    return @intCast(@divFloor(std.Io.Clock.real.now(io).nanoseconds, 1_000_000));
}

fn versionText(buf: []u8, version: std.SemanticVersion) ![]const u8 {
    return std.fmt.bufPrint(buf, "{}.{}.{}", .{ version.major, version.minor, version.patch });
}

fn acceptOneClientSession(io: std.Io, server: *std.Io.net.Server, config: Config) anyerror!void {
    const accepted = try server.accept(io);
    try sessionWithConfig(io, accepted.socket, config);
}

fn acceptOneCamouflageSession(io: std.Io, server: *std.Io.net.Server, state: *@import("server.zig").State) anyerror!void {
    const accepted = try server.accept(io);
    try @import("server.zig").sessionWithState(io, accepted.socket, state);
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

fn hex32(comptime s: *const [64]u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "connectAndPivot rejects non-101 gateway response" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var gateway = try (@as(std.Io.net.IpAddress, .{
        .ip4 = std.Io.net.Ip4Address.loopback(0),
    })).listen(io, .{ .reuse_address = true });
    defer gateway.deinit(io);

    var gateway_task = io.async(struct {
        fn run(io2: std.Io, server: *std.Io.net.Server) anyerror!void {
            const stream = try server.accept(io2);
            defer stream.close(io2);

            var rbuf: [512]u8 = undefined;
            var wbuf: [512]u8 = undefined;
            var reader = std.Io.net.Stream.Reader.init(stream, io2, &rbuf);
            var writer = std.Io.net.Stream.Writer.init(stream, io2, &wbuf);
            _ = try takeResponseHead(&reader.interface, 1024);
            try writer.interface.writeAll("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
            try writer.interface.flush();
        }
    }.run, .{ io, &gateway });
    errdefer gateway_task.cancel(io) catch {};

    const config: Config = .{
        .connect = .{ .host = "127.0.0.1", .port = gateway.socket.address.getPort() },
        .public = .{
            .target = .{ .host = "example.com", .port = 443 },
            .server_public_key = try ayllu.crypto.X25519.recoverPublicKey(
                hex32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
            ),
        },
        .server_name = "example.com",
        .short_id = try reality.parseShortId("aabb"),
        .client_private_key = hex32("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"),
        .client_version = try std.SemanticVersion.parse("1.5.0"),
    };

    try std.testing.expectError(error.BadGatewayResponse, connectAndPivot(io, config));
    try gateway_task.await(io);
}

test "sessionWithConfig exposes local SOCKS path through camouflage gateway" {
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
    var camo_state: @import("server.zig").State = .{
        .config = .{
            .pivot = .{ .reality = server_cfg },
        },
    };

    var camo = try (@as(std.Io.net.IpAddress, .{
        .ip4 = std.Io.net.Ip4Address.loopback(0),
    })).listen(io, .{ .reuse_address = true });
    defer camo.deinit(io);
    var camo_task = io.async(acceptOneCamouflageSession, .{ io, &camo, &camo_state });
    errdefer camo_task.cancel(io) catch {};

    const public_cfg = try server_cfg.exportPublic();
    const bridge_cfg: Config = .{
        .connect = .{ .host = "127.0.0.1", .port = camo.socket.address.getPort() },
        .public = public_cfg,
        .server_name = "example.com",
        .short_id = try reality.parseShortId("aabb"),
        .client_private_key = hex32("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"),
        .client_version = try std.SemanticVersion.parse("1.5.0"),
    };

    var bridge = try (@as(std.Io.net.IpAddress, .{
        .ip4 = std.Io.net.Ip4Address.loopback(0),
    })).listen(io, .{ .reuse_address = true });
    defer bridge.deinit(io);
    var bridge_task = io.async(acceptOneClientSession, .{ io, &bridge, bridge_cfg });
    errdefer bridge_task.cancel(io) catch {};

    const local = try (@as(std.Io.net.IpAddress, .{
        .ip4 = std.Io.net.Ip4Address.loopback(bridge.socket.address.getPort()),
    })).connect(io, .{ .mode = .stream });
    var local_open = true;
    defer if (local_open) local.close(io);

    var lr_buf: [1024]u8 = undefined;
    var lw_buf: [1024]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(local, io, &lr_buf);
    var writer = std.Io.net.Stream.Writer.init(local, io, &lw_buf);

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

    local.close(io);
    local_open = false;
    try bridge_task.await(io);
    try camo_task.await(io);
    try upstream_task.await(io);
}
