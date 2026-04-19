//! SOCKS5 protocol (RFC 1928). Pure parsers/encoders — не трогает сеть.
//! Phase-3 scope: no-auth greeting + CONNECT request, IPv4/IPv6/domain.
//! BIND и UDP ASSOCIATE не реализованы (не нужны для Telegram/HTTP).

const std = @import("std");

pub const version: u8 = 5;

pub const Method = enum(u8) {
    no_auth = 0x00,
    gssapi = 0x01,
    username_password = 0x02,
    no_acceptable = 0xFF,
    _,

    pub fn fromByte(byte: u8) Method {
        return @enumFromInt(byte);
    }

    pub fn toByte(self: Method) u8 {
        return @intFromEnum(self);
    }
};

pub const Command = enum(u8) {
    connect = 0x01,
    bind = 0x02,
    udp_associate = 0x03,
};

pub const AddressKind = enum(u8) {
    ipv4 = 0x01,
    domain = 0x03,
    ipv6 = 0x04,
};

pub const Address = union(AddressKind) {
    ipv4: [4]u8,
    domain: []const u8,
    ipv6: [16]u8,
};

pub const Reply = enum(u8) {
    succeeded = 0x00,
    general_failure = 0x01,
    not_allowed = 0x02,
    network_unreachable = 0x03,
    host_unreachable = 0x04,
    connection_refused = 0x05,
    ttl_expired = 0x06,
    command_not_supported = 0x07,
    address_type_not_supported = 0x08,
};

pub const max_methods = 255;
pub const max_domain_len = 255;

pub const DecodeError = error{
    ShortBuffer,
    BadVersion,
    NoMethods,
    BadCommand,
    BadAddressType,
    BadReserved,
    EmptyDomain,
};

pub const Greeting = struct {
    methods: []const u8,
    bytes_consumed: usize,

    pub fn offersNoAuth(self: Greeting) bool {
        return std.mem.indexOfScalar(u8, self.methods, @intFromEnum(Method.no_auth)) != null;
    }
};

pub fn decodeGreeting(buf: []const u8) DecodeError!Greeting {
    if (buf.len < 2) return error.ShortBuffer;
    if (buf[0] != version) return error.BadVersion;
    const nmethods = buf[1];
    if (nmethods == 0) return error.NoMethods;
    const need = 2 + @as(usize, nmethods);
    if (buf.len < need) return error.ShortBuffer;
    return .{
        .methods = buf[2..need],
        .bytes_consumed = need,
    };
}

/// Encodes the 2-byte greeting reply. Returns it by value (no allocation).
pub fn encodeGreetingReply(method: Method) [2]u8 {
    return .{ version, method.toByte() };
}

pub const Request = struct {
    command: Command,
    address: Address,
    port: u16,
    bytes_consumed: usize,
};

pub fn decodeRequest(buf: []const u8) DecodeError!Request {
    if (buf.len < 4) return error.ShortBuffer;
    if (buf[0] != version) return error.BadVersion;
    const command: Command = switch (buf[1]) {
        0x01 => .connect,
        0x02 => .bind,
        0x03 => .udp_associate,
        else => return error.BadCommand,
    };
    if (buf[2] != 0x00) return error.BadReserved;
    const atyp: AddressKind = switch (buf[3]) {
        0x01 => .ipv4,
        0x03 => .domain,
        0x04 => .ipv6,
        else => return error.BadAddressType,
    };

    const addr_start = 4;
    var addr: Address = undefined;
    var port_start: usize = undefined;

    switch (atyp) {
        .ipv4 => {
            port_start = addr_start + 4;
            if (buf.len < port_start + 2) return error.ShortBuffer;
            addr = .{ .ipv4 = buf[addr_start..][0..4].* };
        },
        .ipv6 => {
            port_start = addr_start + 16;
            if (buf.len < port_start + 2) return error.ShortBuffer;
            addr = .{ .ipv6 = buf[addr_start..][0..16].* };
        },
        .domain => {
            if (buf.len < addr_start + 1) return error.ShortBuffer;
            const domain_len = buf[addr_start];
            if (domain_len == 0) return error.EmptyDomain;
            port_start = addr_start + 1 + domain_len;
            if (buf.len < port_start + 2) return error.ShortBuffer;
            addr = .{ .domain = buf[addr_start + 1 .. port_start] };
        },
    }

    const port = std.mem.readInt(u16, buf[port_start..][0..2], .big);
    return .{
        .command = command,
        .address = addr,
        .port = port,
        .bytes_consumed = port_start + 2,
    };
}

/// Encodes a SOCKS5 reply into `out`. Returns the written slice.
/// Caller must size `out` to at least `replySize(address)`.
pub fn encodeReply(out: []u8, reply: Reply, address: Address, port: u16) error{ShortBuffer}![]u8 {
    const size = replySize(address);
    if (out.len < size) return error.ShortBuffer;
    out[0] = version;
    out[1] = @intFromEnum(reply);
    out[2] = 0x00;
    out[3] = @intFromEnum(std.meta.activeTag(address));

    var cursor: usize = 4;
    switch (address) {
        .ipv4 => |bytes| {
            @memcpy(out[cursor..][0..4], &bytes);
            cursor += 4;
        },
        .ipv6 => |bytes| {
            @memcpy(out[cursor..][0..16], &bytes);
            cursor += 16;
        },
        .domain => |name| {
            out[cursor] = @intCast(name.len);
            cursor += 1;
            @memcpy(out[cursor..][0..name.len], name);
            cursor += name.len;
        },
    }
    std.mem.writeInt(u16, out[cursor..][0..2], port, .big);
    cursor += 2;
    return out[0..cursor];
}

pub fn replySize(address: Address) usize {
    return 4 + switch (address) {
        .ipv4 => 4,
        .ipv6 => 16,
        .domain => |name| 1 + name.len,
    } + 2;
}

pub const zero_ipv4_reply_size: usize = 4 + 4 + 2;
pub const zero_ipv4: Address = .{ .ipv4 = .{ 0, 0, 0, 0 } };

test "decodeGreeting single method" {
    const buf = [_]u8{ 0x05, 0x01, 0x00 };
    const g = try decodeGreeting(&buf);
    try std.testing.expectEqualSlices(u8, &.{0x00}, g.methods);
    try std.testing.expectEqual(@as(usize, 3), g.bytes_consumed);
    try std.testing.expect(g.offersNoAuth());
}

test "decodeGreeting multiple methods" {
    const buf = [_]u8{ 0x05, 0x03, 0x00, 0x02, 0xFF };
    const g = try decodeGreeting(&buf);
    try std.testing.expectEqual(@as(usize, 3), g.methods.len);
    try std.testing.expectEqual(@as(usize, 5), g.bytes_consumed);
    try std.testing.expect(g.offersNoAuth());
}

test "decodeGreeting without no-auth method" {
    const buf = [_]u8{ 0x05, 0x01, 0x02 };
    const g = try decodeGreeting(&buf);
    try std.testing.expect(!g.offersNoAuth());
}

test "decodeGreeting rejects wrong version" {
    const buf = [_]u8{ 0x04, 0x01, 0x00 };
    try std.testing.expectError(error.BadVersion, decodeGreeting(&buf));
}

test "decodeGreeting rejects empty buffer and truncated variants" {
    try std.testing.expectError(error.ShortBuffer, decodeGreeting(&[_]u8{}));
    try std.testing.expectError(error.ShortBuffer, decodeGreeting(&[_]u8{0x05}));
    try std.testing.expectError(error.NoMethods, decodeGreeting(&[_]u8{ 0x05, 0x00 }));
    try std.testing.expectError(error.ShortBuffer, decodeGreeting(&[_]u8{ 0x05, 0x02, 0x00 }));
}

test "decodeGreeting ignores trailing bytes via bytes_consumed" {
    const buf = [_]u8{ 0x05, 0x01, 0x00, 0xAA, 0xBB };
    const g = try decodeGreeting(&buf);
    try std.testing.expectEqual(@as(usize, 3), g.bytes_consumed);
    try std.testing.expectEqual(@as(u8, 0xAA), buf[g.bytes_consumed]);
}

test "encodeGreetingReply no-auth" {
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x05, 0x00 },
        &encodeGreetingReply(.no_auth),
    );
}

test "encodeGreetingReply no-acceptable" {
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x05, 0xFF },
        &encodeGreetingReply(.no_acceptable),
    );
}

test "decodeRequest CONNECT to IPv4" {
    const buf = [_]u8{ 0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0x01, 0xBB };
    const r = try decodeRequest(&buf);
    try std.testing.expectEqual(Command.connect, r.command);
    try std.testing.expectEqual(@as(u16, 443), r.port);
    try std.testing.expectEqualSlices(u8, &.{ 93, 184, 216, 34 }, &r.address.ipv4);
    try std.testing.expectEqual(buf.len, r.bytes_consumed);
}

test "decodeRequest CONNECT to IPv6" {
    var buf: [22]u8 = undefined;
    buf[0..4].* = .{ 0x05, 0x01, 0x00, 0x04 };
    @memset(buf[4..20], 0);
    buf[19] = 1;
    buf[20] = 0x01;
    buf[21] = 0xBB;
    const r = try decodeRequest(&buf);
    try std.testing.expectEqual(Command.connect, r.command);
    try std.testing.expectEqual(@as(u16, 443), r.port);
    try std.testing.expectEqualSlices(u8, buf[4..20], &r.address.ipv6);
    try std.testing.expectEqual(buf.len, r.bytes_consumed);
}

test "decodeRequest CONNECT to domain" {
    const domain = "api.telegram.org";
    var buf: [5 + domain.len + 2]u8 = undefined;
    buf[0..5].* = .{ 0x05, 0x01, 0x00, 0x03, @intCast(domain.len) };
    @memcpy(buf[5 .. 5 + domain.len], domain);
    std.mem.writeInt(u16, buf[5 + domain.len ..][0..2], 443, .big);
    const r = try decodeRequest(&buf);
    try std.testing.expectEqualStrings(domain, r.address.domain);
    try std.testing.expectEqual(@as(u16, 443), r.port);
    try std.testing.expectEqual(buf.len, r.bytes_consumed);
}

test "decodeRequest rejects BIND and UDP ASSOCIATE (unsupported MVP)" {
    // Actually: phase-3 scope says we decode all commands; daemon rejects
    // BIND/UDP at dispatch layer with command_not_supported. So decode
    // itself must ACCEPT the byte — test that it parses the command cleanly.
    const buf_bind = [_]u8{ 0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
    const r_bind = try decodeRequest(&buf_bind);
    try std.testing.expectEqual(Command.bind, r_bind.command);
    const buf_udp = [_]u8{ 0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
    const r_udp = try decodeRequest(&buf_udp);
    try std.testing.expectEqual(Command.udp_associate, r_udp.command);
}

test "decodeRequest rejects wrong version / RSV / unknown CMD / ATYP" {
    try std.testing.expectError(
        error.BadVersion,
        decodeRequest(&[_]u8{ 0x04, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }),
    );
    try std.testing.expectError(
        error.BadCommand,
        decodeRequest(&[_]u8{ 0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }),
    );
    try std.testing.expectError(
        error.BadReserved,
        decodeRequest(&[_]u8{ 0x05, 0x01, 0x01, 0x01, 0, 0, 0, 0, 0, 0 }),
    );
    try std.testing.expectError(
        error.BadAddressType,
        decodeRequest(&[_]u8{ 0x05, 0x01, 0x00, 0x02, 0, 0, 0, 0, 0, 0 }),
    );
}

test "decodeRequest rejects empty-domain and truncated buffers" {
    try std.testing.expectError(
        error.EmptyDomain,
        decodeRequest(&[_]u8{ 0x05, 0x01, 0x00, 0x03, 0x00, 0x01, 0xBB }),
    );
    try std.testing.expectError(error.ShortBuffer, decodeRequest(&[_]u8{}));
    try std.testing.expectError(
        error.ShortBuffer,
        decodeRequest(&[_]u8{ 0x05, 0x01, 0x00, 0x01, 1, 2, 3 }),
    );
    try std.testing.expectError(
        error.ShortBuffer,
        decodeRequest(&[_]u8{ 0x05, 0x01, 0x00, 0x03, 0x05, 'h', 'e', 'l' }),
    );
}

test "encodeReply CONNECT success with IPv4 bound address" {
    var out: [10]u8 = undefined;
    const written = try encodeReply(&out, .succeeded, zero_ipv4, 0);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 },
        written,
    );
}

test "encodeReply IPv6 bound address" {
    var out: [22]u8 = undefined;
    const ipv6: Address = .{ .ipv6 = @splat(0) };
    const written = try encodeReply(&out, .succeeded, ipv6, 443);
    try std.testing.expectEqual(@as(usize, 22), written.len);
    try std.testing.expectEqual(@as(u8, 0x04), written[3]);
    try std.testing.expectEqual(@as(u8, 0x01), written[20]);
    try std.testing.expectEqual(@as(u8, 0xBB), written[21]);
}

test "encodeReply domain-form reply" {
    const name = "example.com";
    var out: [4 + 1 + name.len + 2]u8 = undefined;
    const written = try encodeReply(&out, .host_unreachable, .{ .domain = name }, 80);
    try std.testing.expectEqual(@as(u8, 0x04), written[1]);
    try std.testing.expectEqual(@as(u8, 0x03), written[3]);
    try std.testing.expectEqual(@as(u8, name.len), written[4]);
    try std.testing.expectEqualSlices(u8, name, written[5 .. 5 + name.len]);
}

test "encodeReply rejects undersized buffer" {
    var out: [4]u8 = undefined;
    try std.testing.expectError(
        error.ShortBuffer,
        encodeReply(&out, .succeeded, zero_ipv4, 0),
    );
}

test "replySize matches actual encoded length" {
    var out: [300]u8 = undefined;
    const ipv4 = try encodeReply(&out, .succeeded, zero_ipv4, 0);
    try std.testing.expectEqual(ipv4.len, replySize(zero_ipv4));

    const ipv6: Address = .{ .ipv6 = @splat(0) };
    const ipv6_out = try encodeReply(&out, .succeeded, ipv6, 0);
    try std.testing.expectEqual(ipv6_out.len, replySize(ipv6));

    const dom: Address = .{ .domain = "host.example" };
    const dom_out = try encodeReply(&out, .succeeded, dom, 0);
    try std.testing.expectEqual(dom_out.len, replySize(dom));
}

test "CONNECT IPv4 roundtrip: decode then re-encode matches" {
    const request = [_]u8{ 0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1, 0x01, 0xBB };
    const r = try decodeRequest(&request);
    try std.testing.expectEqual(Command.connect, r.command);
    var out: [10]u8 = undefined;
    const reencoded = try encodeReply(&out, .succeeded, r.address, r.port);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x05, 0x00, 0x00, 0x01, 192, 168, 1, 1, 0x01, 0xBB },
        reencoded,
    );
}
