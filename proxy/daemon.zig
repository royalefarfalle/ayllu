//! SOCKS5 handshake + per-session orchestration (pure над std.Io.Reader/
//! Writer). Серверный loop с accept и DNS живёт в proxy/main.zig; здесь
//! только протокольная логика, которую удобно тестировать на fixed-streams
//! без сети.

const std = @import("std");
const socks5 = @import("socks5.zig");

pub const HandshakeError = error{
    NoAcceptableMethods,
} || socks5.DecodeError || std.Io.Reader.Error || std.Io.Writer.Error;

/// Читает greeting, шлёт greeting-reply (no-auth либо no-acceptable), читает
/// CONNECT-запрос. Возвращает распарсенный Request. Клиентский писатель уже
/// отфлашен; следующий `encodeReply` даёт сразу отправить ответ на CONNECT.
pub fn handshake(
    client_r: *std.Io.Reader,
    client_w: *std.Io.Writer,
) HandshakeError!socks5.Request {
    // Greeting: 2 заголовочных байта + nmethods.
    const header = try client_r.peek(2);
    if (header[0] != socks5.version) return error.BadVersion;
    const nmethods = header[1];
    if (nmethods == 0) return error.NoMethods;
    const greeting_bytes = try client_r.take(2 + @as(usize, nmethods));
    const greeting = try socks5.decodeGreeting(greeting_bytes);

    if (!greeting.offersNoAuth()) {
        try client_w.writeAll(&socks5.encodeGreetingReply(.no_acceptable));
        try client_w.flush();
        return error.NoAcceptableMethods;
    }
    try client_w.writeAll(&socks5.encodeGreetingReply(.no_auth));
    try client_w.flush();

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

/// Кодирует и отправляет reply на CONNECT; используется и при успехе, и
/// при любой ошибке (daemon'у нужно уведомить клиента перед закрытием).
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
pub fn errorToReply(err: HandshakeError) socks5.Reply {
    return switch (err) {
        error.NoAcceptableMethods, error.BadCommand => .command_not_supported,
        error.BadAddressType => .address_type_not_supported,
        else => .general_failure,
    };
}

fn makeHandshakeBytes(buf: []u8, greeting: []const u8, request: []const u8) []const u8 {
    @memcpy(buf[0..greeting.len], greeting);
    @memcpy(buf[greeting.len .. greeting.len + request.len], request);
    return buf[0 .. greeting.len + request.len];
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

test "errorToReply maps handshake errors to RFC 1928 reply codes" {
    try std.testing.expectEqual(socks5.Reply.command_not_supported, errorToReply(error.NoAcceptableMethods));
    try std.testing.expectEqual(socks5.Reply.command_not_supported, errorToReply(error.BadCommand));
    try std.testing.expectEqual(socks5.Reply.address_type_not_supported, errorToReply(error.BadAddressType));
    try std.testing.expectEqual(socks5.Reply.general_failure, errorToReply(error.BadVersion));
    try std.testing.expectEqual(socks5.Reply.general_failure, errorToReply(error.EmptyDomain));
}
