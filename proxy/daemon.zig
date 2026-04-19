//! SOCKS5 handshake + per-session orchestration (pure over std.Io.Reader/
//! Writer). The server loop with accept and DNS lives in proxy/main.zig;
//! here there's only protocol logic, convenient to test on fixed-streams
//! without the network.

const std = @import("std");
const socks5 = @import("socks5.zig");
const auth = @import("auth.zig");
const relay = @import("relay.zig");

pub const Config = struct {
    auth: auth.Config = .none,
};

pub const GreetingError = error{
    NoAcceptableMethods,
    CredentialsRejected,
} || socks5.DecodeError || std.Io.Reader.Error || std.Io.Writer.Error;

pub const RequestError = socks5.DecodeError || std.Io.Reader.Error;

pub const HandshakeError = GreetingError || RequestError;

/// Reads greeting, sends greeting-reply (no-auth or no-acceptable), reads the
/// CONNECT request. Returns the parsed Request. The client writer is already
/// flushed; the next `encodeReply` lets you ship the CONNECT reply right away.
pub fn handshake(
    client_r: *std.Io.Reader,
    client_w: *std.Io.Writer,
) HandshakeError!socks5.Request {
    return handshakeWithConfig(client_r, client_w, .{});
}

pub fn handshakeWithConfig(
    client_r: *std.Io.Reader,
    client_w: *std.Io.Writer,
    config: Config,
) HandshakeError!socks5.Request {
    try negotiateMethod(client_r, client_w, config);
    return try readRequest(client_r);
}

/// Prepares a SOCKS5 session at the greeting/method-negotiation level.
///
/// Important property for anti-probing: if the first packet doesn't look
/// like SOCKS5, the function fails silently and the caller must close the
/// socket without a reply.
pub fn negotiateMethod(
    client_r: *std.Io.Reader,
    client_w: *std.Io.Writer,
    config: Config,
) GreetingError!void {
    // Greeting: 2 header bytes + nmethods.
    const header = try client_r.peek(2);
    if (header[0] != socks5.version) return error.BadVersion;
    const nmethods = header[1];
    if (nmethods == 0) return error.NoMethods;
    const greeting_bytes = try client_r.take(2 + @as(usize, nmethods));
    const greeting = try socks5.decodeGreeting(greeting_bytes);

    const selected_method: socks5.Method = switch (config.auth) {
        .none => if (greeting.offersNoAuth()) .no_auth else {
            try client_w.writeAll(&socks5.encodeGreetingReply(.no_acceptable));
            try client_w.flush();
            return error.NoAcceptableMethods;
        },
        .username_password => blk: {
            if (std.mem.indexOfScalar(u8, greeting.methods, @intFromEnum(socks5.Method.username_password)) == null) {
                try client_w.writeAll(&socks5.encodeGreetingReply(.no_acceptable));
                try client_w.flush();
                return error.NoAcceptableMethods;
            }
            break :blk socks5.Method.username_password;
        },
    };
    try client_w.writeAll(&socks5.encodeGreetingReply(selected_method));
    try client_w.flush();

    if (selected_method == .username_password) {
        switch (config.auth) {
            .username_password => |creds| if (!try authenticateUsernamePassword(client_r, client_w, creds)) {
                return error.CredentialsRejected;
            },
            .none => unreachable,
        }
    }
}

/// Reads and decodes the SOCKS5 request after method negotiation succeeded.
pub fn readRequest(client_r: *std.Io.Reader) RequestError!socks5.Request {
    // Request: VER CMD RSV ATYP (4) + variable addr + port (2).
    const req_head = try client_r.peek(4);
    if (req_head[0] != socks5.version) return error.BadVersion;
    const atyp_byte = req_head[3];
    const req_len: usize = switch (atyp_byte) {
        @intFromEnum(socks5.AddressKind.ipv4) => 4 + 4 + 2,
        @intFromEnum(socks5.AddressKind.ipv6) => 4 + 16 + 2,
        @intFromEnum(socks5.AddressKind.domain) => blk: {
            const peek_with_len = try client_r.peek(5);
            const dlen = peek_with_len[4];
            if (dlen == 0) return error.EmptyDomain;
            break :blk 4 + 1 + @as(usize, dlen) + 2;
        },
        else => return error.BadAddressType,
    };
    const req_bytes = try client_r.take(req_len);
    return try socks5.decodeRequest(req_bytes);
}

fn authenticateUsernamePassword(
    client_r: *std.Io.Reader,
    client_w: *std.Io.Writer,
    creds: auth.Credentials,
) (socks5.DecodeError || std.Io.Reader.Error || std.Io.Writer.Error)!bool {
    const header = try client_r.peek(2);
    if (header[0] != socks5.username_password_auth_version) return error.BadAuthVersion;
    const ulen = header[1];
    if (ulen == 0) return error.EmptyUsername;
    const prefix_len = 2 + @as(usize, ulen) + 1;
    const prefix = try client_r.peek(prefix_len);
    const plen = prefix[prefix_len - 1];
    if (plen == 0) return error.EmptyPassword;
    const auth_bytes = try client_r.take(prefix_len + @as(usize, plen));
    const req = try socks5.decodeUsernamePasswordAuth(auth_bytes);
    const ok = creds.matches(req.username, req.password);
    try client_w.writeAll(&socks5.encodeUsernamePasswordReply(ok));
    try client_w.flush();
    return ok;
}

/// Encodes and sends the CONNECT reply; used on success and on any error
/// (the daemon has to notify the client before closing).
pub fn sendReply(
    client_w: *std.Io.Writer,
    reply: socks5.Reply,
    bound_addr: socks5.Address,
    bound_port: u16,
) !void {
    var buf: [4 + 1 + 255 + 2]u8 = undefined;
    const written = try socks5.encodeReply(&buf, reply, bound_addr, bound_port);
    try client_w.writeAll(written);
    try client_w.flush();
}

/// Map a SOCKS5-decode error to the corresponding Reply code per RFC 1928 §6.
pub fn errorToReply(err: RequestError) socks5.Reply {
    return switch (err) {
        error.BadCommand => .command_not_supported,
        error.BadAddressType => .address_type_not_supported,
        else => .general_failure,
    };
}

fn makeHandshakeBytes(buf: []u8, greeting: []const u8, request: []const u8) []const u8 {
    @memcpy(buf[0..greeting.len], greeting);
    @memcpy(buf[greeting.len .. greeting.len + request.len], request);
    return buf[0 .. greeting.len + request.len];
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

fn acceptOneSession(io: std.Io, server: *std.Io.net.Server) anyerror!void {
    const accepted = try server.accept(io);
    try session(io, accepted.socket);
}

fn acceptOneSessionWithConfig(io: std.Io, server: *std.Io.net.Server, config: Config) anyerror!void {
    const accepted = try server.accept(io);
    try sessionWithConfig(io, accepted.socket, config);
}

fn connectUpstream(io: std.Io, address: socks5.Address, port: u16) !std.Io.net.Stream {
    switch (address) {
        .ipv4 => |bytes| {
            const addr: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = bytes, .port = port } };
            return addr.connect(io, .{ .mode = .stream });
        },
        .ipv6 => |bytes| {
            const addr: std.Io.net.IpAddress = .{ .ip6 = .{ .bytes = bytes, .port = port } };
            return addr.connect(io, .{ .mode = .stream });
        },
        .domain => |name| {
            const host = try std.Io.net.HostName.init(name);
            return host.connect(io, port, .{ .mode = .stream });
        },
    }
}

/// Full lifecycle of one client SOCKS5 connection: handshake ->
/// connect upstream -> reply -> bidirectional relay -> close. Propagates
/// the error upward but closes both sockets itself so the client doesn't hang.
pub fn session(io: std.Io, client_socket: std.Io.net.Socket) !void {
    return sessionWithConfig(io, client_socket, .{});
}

pub fn sessionOnPreparedStream(io: std.Io, client: relay.Stream, config: Config) !void {
    negotiateMethod(client.reader, client.writer, config) catch |err| switch (err) {
        error.CredentialsRejected => return err,
        error.NoAcceptableMethods => return err,
        else => return err,
    };

    const req = readRequest(client.reader) catch |err| {
        sendReply(client.writer, errorToReply(err), socks5.zero_ipv4, 0) catch {};
        return err;
    };

    if (req.command != .connect) {
        try sendReply(client.writer, .command_not_supported, socks5.zero_ipv4, 0);
        return error.UnsupportedCommand;
    }

    const upstream_stream = connectUpstream(io, req.address, req.port) catch |err| {
        const reply: socks5.Reply = if (err == error.ConnectionRefused)
            .connection_refused
        else if (err == error.NetworkUnreachable)
            .network_unreachable
        else
            .host_unreachable;
        try sendReply(client.writer, reply, socks5.zero_ipv4, 0);
        return err;
    };
    defer upstream_stream.close(io);

    try sendReply(client.writer, .succeeded, socks5.zero_ipv4, 0);

    var ur_buf: [4096]u8 = undefined;
    var uw_buf: [4096]u8 = undefined;
    var upstream_reader = std.Io.net.Stream.Reader.init(upstream_stream, io, &ur_buf);
    var upstream_writer = std.Io.net.Stream.Writer.init(upstream_stream, io, &uw_buf);

    try relay.bidirectional(
        io,
        client,
        .{
            .reader = &upstream_reader.interface,
            .writer = &upstream_writer.interface,
            .net_stream = &upstream_stream,
        },
    );
}

pub fn sessionWithConfig(io: std.Io, client_socket: std.Io.net.Socket, config: Config) !void {
    const client_stream: std.Io.net.Stream = .{ .socket = client_socket };
    defer client_stream.close(io);

    var cr_buf: [4096]u8 = undefined;
    var cw_buf: [4096]u8 = undefined;
    var client_reader = std.Io.net.Stream.Reader.init(client_stream, io, &cr_buf);
    var client_writer = std.Io.net.Stream.Writer.init(client_stream, io, &cw_buf);
    try sessionOnPreparedStream(io, .{
        .reader = &client_reader.interface,
        .writer = &client_writer.interface,
        .net_stream = &client_stream,
    }, config);
}

test "handshake happy path: no-auth greeting + CONNECT IPv4" {
    var backing: [512]u8 = undefined;
    const greeting = &[_]u8{ 0x05, 0x01, 0x00 };
    const request = &[_]u8{ 0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xBB };
    const bytes = makeHandshakeBytes(&backing, greeting, request);
    var r: std.Io.Reader = .fixed(bytes);

    var out: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);

    const req = try handshake(&r, &w);
    try std.testing.expectEqual(socks5.Command.connect, req.command);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, &req.address.ipv4);
    try std.testing.expectEqual(@as(u16, 443), req.port);
    // Reply shipped: 0x05 0x00 (no-auth accepted).
    try std.testing.expectEqualSlices(u8, &.{ 0x05, 0x00 }, w.buffered()[0..2]);
}

test "handshake happy path: username/password auth + CONNECT IPv4" {
    var backing: [512]u8 = undefined;
    const greeting = &[_]u8{ 0x05, 0x01, 0x02 };
    const auth_req = &[_]u8{ 0x01, 0x05, 'a', 'l', 'i', 'c', 'e', 0x06, 's', 'e', 'c', 'r', 'e', 't' };
    const request = &[_]u8{ 0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xBB };
    @memcpy(backing[0..greeting.len], greeting);
    @memcpy(backing[greeting.len .. greeting.len + auth_req.len], auth_req);
    @memcpy(backing[greeting.len + auth_req.len ..][0..request.len], request);
    const bytes = backing[0 .. greeting.len + auth_req.len + request.len];
    var r: std.Io.Reader = .fixed(bytes);

    var out: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);

    const req = try handshakeWithConfig(&r, &w, .{
        .auth = .{ .username_password = .{ .username = "alice", .password = "secret" } },
    });
    try std.testing.expectEqual(socks5.Command.connect, req.command);
    try std.testing.expectEqualSlices(u8, &.{ 0x05, 0x02, 0x01, 0x00 }, w.buffered()[0..4]);
}

test "negotiateMethod rejects non-SOCKS preface without writing fingerprint bytes" {
    var r: std.Io.Reader = .fixed("GET / HTTP/1.1\r\n\r\n");
    var out: [8]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try std.testing.expectError(error.BadVersion, negotiateMethod(&r, &w, .{}));
    try std.testing.expectEqual(@as(usize, 0), w.buffered().len);
}

test "handshake CONNECT domain" {
    const greeting = &[_]u8{ 0x05, 0x01, 0x00 };
    const domain = "api.telegram.org";
    var request_buf: [5 + domain.len + 2]u8 = undefined;
    request_buf[0..5].* = .{ 0x05, 0x01, 0x00, 0x03, @intCast(domain.len) };
    @memcpy(request_buf[5 .. 5 + domain.len], domain);
    std.mem.writeInt(u16, request_buf[5 + domain.len ..][0..2], 443, .big);
    var bytes_buf: [64]u8 = undefined;
    const bytes = makeHandshakeBytes(&bytes_buf, greeting, &request_buf);
    var r: std.Io.Reader = .fixed(bytes);

    var out: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);

    const req = try handshake(&r, &w);
    try std.testing.expectEqualStrings(domain, req.address.domain);
}

test "handshake sends no-acceptable when client omits no-auth" {
    const greeting = &[_]u8{ 0x05, 0x01, 0x02 }; // only username/password
    var r: std.Io.Reader = .fixed(greeting);
    var out: [8]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);

    try std.testing.expectError(error.NoAcceptableMethods, handshake(&r, &w));
    try std.testing.expectEqualSlices(u8, &.{ 0x05, 0xFF }, w.buffered()[0..2]);
}

test "negotiateMethod rejects bad username/password credentials" {
    const greeting = &[_]u8{ 0x05, 0x01, 0x02 };
    const auth_req = &[_]u8{ 0x01, 0x05, 'a', 'l', 'i', 'c', 'e', 0x05, 'w', 'r', 'o', 'n', 'g' };
    var bytes: [32]u8 = undefined;
    @memcpy(bytes[0..greeting.len], greeting);
    @memcpy(bytes[greeting.len .. greeting.len + auth_req.len], auth_req);
    var r: std.Io.Reader = .fixed(bytes[0 .. greeting.len + auth_req.len]);
    var out: [8]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try std.testing.expectError(error.CredentialsRejected, negotiateMethod(&r, &w, .{
        .auth = .{ .username_password = .{ .username = "alice", .password = "secret" } },
    }));
    try std.testing.expectEqualSlices(u8, &.{ 0x05, 0x02, 0x01, 0x01 }, w.buffered()[0..4]);
}

test "handshake rejects greeting with wrong version" {
    var r: std.Io.Reader = .fixed(&[_]u8{ 0x04, 0x01, 0x00 });
    var out: [8]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try std.testing.expectError(error.BadVersion, handshake(&r, &w));
}

test "handshake rejects request with empty domain" {
    const greeting = &[_]u8{ 0x05, 0x01, 0x00 };
    const request = &[_]u8{ 0x05, 0x01, 0x00, 0x03, 0x00, 0x01, 0xBB };
    var bytes_buf: [16]u8 = undefined;
    const bytes = makeHandshakeBytes(&bytes_buf, greeting, request);
    var r: std.Io.Reader = .fixed(bytes);
    var out: [8]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try std.testing.expectError(error.EmptyDomain, handshake(&r, &w));
}

test "handshake rejects request with unknown ATYP after valid greeting" {
    const greeting = &[_]u8{ 0x05, 0x01, 0x00 };
    const request = &[_]u8{ 0x05, 0x01, 0x00, 0x02, 0, 0, 0, 0, 0, 0 };
    var bytes_buf: [16]u8 = undefined;
    const bytes = makeHandshakeBytes(&bytes_buf, greeting, request);
    var r: std.Io.Reader = .fixed(bytes);
    var out: [8]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try std.testing.expectError(error.BadAddressType, handshake(&r, &w));
}

test "sendReply encodes success + succeeds through fixed writer" {
    var out: [10]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try sendReply(&w, .succeeded, socks5.zero_ipv4, 0);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 },
        w.buffered(),
    );
}

test "errorToReply maps request-stage errors to RFC 1928 reply codes" {
    try std.testing.expectEqual(socks5.Reply.command_not_supported, errorToReply(error.BadCommand));
    try std.testing.expectEqual(socks5.Reply.address_type_not_supported, errorToReply(error.BadAddressType));
    try std.testing.expectEqual(socks5.Reply.general_failure, errorToReply(error.BadVersion));
    try std.testing.expectEqual(socks5.Reply.general_failure, errorToReply(error.EmptyDomain));
}

test "session end-to-end proxies bytes to an upstream TCP server" {
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

    var proxy = try (@as(std.Io.net.IpAddress, .{
        .ip4 = std.Io.net.Ip4Address.loopback(0),
    })).listen(io, .{ .reuse_address = true });
    defer proxy.deinit(io);
    const proxy_port = proxy.socket.address.getPort();
    var session_task = io.async(acceptOneSession, .{ io, &proxy });
    errdefer session_task.cancel(io) catch {};

    const client_stream = try (@as(std.Io.net.IpAddress, .{
        .ip4 = std.Io.net.Ip4Address.loopback(proxy_port),
    })).connect(io, .{ .mode = .stream });
    errdefer client_stream.close(io);

    var cr_buf: [256]u8 = undefined;
    var cw_buf: [256]u8 = undefined;
    var client_reader = std.Io.net.Stream.Reader.init(client_stream, io, &cr_buf);
    var client_writer = std.Io.net.Stream.Writer.init(client_stream, io, &cw_buf);

    const greeting = [_]u8{ 0x05, 0x01, 0x00 };
    var request = [_]u8{ 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 0 };
    std.mem.writeInt(u16, request[8..10], upstream_port, .big);

    try client_writer.interface.writeAll(&greeting);
    try client_writer.interface.writeAll(&request);
    try client_writer.interface.flush();

    const method_reply = try client_reader.interface.take(2);
    try std.testing.expectEqualSlices(u8, &.{ 0x05, 0x00 }, method_reply);

    const connect_reply = try client_reader.interface.take(10);
    try std.testing.expectEqualSlices(u8, &.{ 0x05, 0x00, 0x00, 0x01 }, connect_reply[0..4]);

    try client_writer.interface.writeAll("ping");
    try client_writer.interface.flush();
    const echoed = try client_reader.interface.take(4);
    try std.testing.expectEqualStrings("ping", echoed);

    client_stream.close(io);
    try session_task.await(io);
    try upstream_task.await(io);
}

test "session end-to-end proxies bytes with RFC 1929 auth enabled" {
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

    var proxy = try (@as(std.Io.net.IpAddress, .{
        .ip4 = std.Io.net.Ip4Address.loopback(0),
    })).listen(io, .{ .reuse_address = true });
    defer proxy.deinit(io);
    const proxy_port = proxy.socket.address.getPort();
    var session_task = io.async(acceptOneSessionWithConfig, .{
        io,
        &proxy,
        Config{
            .auth = .{ .username_password = .{ .username = "alice", .password = "secret" } },
        },
    });
    errdefer session_task.cancel(io) catch {};

    const client_stream = try (@as(std.Io.net.IpAddress, .{
        .ip4 = std.Io.net.Ip4Address.loopback(proxy_port),
    })).connect(io, .{ .mode = .stream });
    errdefer client_stream.close(io);

    var cr_buf: [256]u8 = undefined;
    var cw_buf: [256]u8 = undefined;
    var client_reader = std.Io.net.Stream.Reader.init(client_stream, io, &cr_buf);
    var client_writer = std.Io.net.Stream.Writer.init(client_stream, io, &cw_buf);

    const greeting = [_]u8{ 0x05, 0x01, 0x02 };
    const auth_req = [_]u8{ 0x01, 0x05, 'a', 'l', 'i', 'c', 'e', 0x06, 's', 'e', 'c', 'r', 'e', 't' };
    var request = [_]u8{ 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 0 };
    std.mem.writeInt(u16, request[8..10], upstream_port, .big);

    try client_writer.interface.writeAll(&greeting);
    try client_writer.interface.writeAll(&auth_req);
    try client_writer.interface.writeAll(&request);
    try client_writer.interface.flush();

    const method_reply = try client_reader.interface.take(2);
    try std.testing.expectEqualSlices(u8, &.{ 0x05, 0x02 }, method_reply);

    const auth_reply = try client_reader.interface.take(2);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x00 }, auth_reply);

    const connect_reply = try client_reader.interface.take(10);
    try std.testing.expectEqualSlices(u8, &.{ 0x05, 0x00, 0x00, 0x01 }, connect_reply[0..4]);

    try client_writer.interface.writeAll("ping");
    try client_writer.interface.flush();
    const echoed = try client_reader.interface.take(4);
    try std.testing.expectEqualStrings("ping", echoed);

    client_stream.close(io);
    try session_task.await(io);
    try upstream_task.await(io);
}
