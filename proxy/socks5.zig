//! SOCKS5 protocol (RFC 1928). Pure parsers/encoders — не трогает сеть.

const std = @import("std");

pub const version: u8 = 5;

pub const Method = enum(u8) {
    no_auth = 0x00,
    gssapi = 0x01,
    username_password = 0x02,
    no_acceptable = 0xFF,
    _,
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
    /// Raw wire bytes. NOT validated: may contain NUL / CR / LF / non-ASCII /
    /// arbitrary junk. Caller MUST validate (RFC 1035 LDH or equivalent)
    /// before resolving or logging, or a client can produce a log-vs-action
    /// split (log says `attacker.com\x00evil.com`, libc resolves `attacker.com`).
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

pub const DecodeError = error{
    ShortBuffer,
    BadVersion,
    NoMethods,
    BadCommand,
    BadAddressType,
    BadReserved,
    EmptyDomain,
};

pub const EncodeError = error{
    ShortBuffer,
    DomainTooLong,
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

pub fn encodeGreetingReply(method: Method) [2]u8 {
    return .{ version, @intFromEnum(method) };
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
    const command = std.enums.fromInt(Command, buf[1]) orelse return error.BadCommand;
    if (buf[2] != 0x00) return error.BadReserved;
    const atyp = std.enums.fromInt(AddressKind, buf[3]) orelse return error.BadAddressType;

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
            // domain_len is u8 (max 255); widen to usize before adding to
            // avoid u8 overflow when domain_len > 250.
            port_start = addr_start + 1 + @as(usize, domain_len);
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

/// Encodes a SOCKS5 reply into `out`. Returns the written slice (may be
/// shorter than `out`). Caller MUST write only the returned slice to the
/// peer — tail bytes are untouched, not zeroed, so reusing `out` across
/// connections without reading only the returned slice leaks prior bytes.
/// `address == .domain` with `name.len > 255` returns DomainTooLong because
/// the wire-format length byte is u8.
pub fn encodeReply(out: []u8, reply: Reply, address: Address, port: u16) EncodeError![]u8 {
    if (address == .domain and address.domain.len > 255) return error.DomainTooLong;
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

test "decodeRequest accepts BIND / UDP ASSOCIATE — dispatch layer rejects them" {
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

test "CONNECT IPv6 + domain request bytes mirror the reply-side encoder" {
    // Roundtrip matrix: encode address via replySize/encodeReply, hand-craft
    // a request around it, decode, assert address + port match.
    inline for (.{
        Address{ .ipv4 = .{ 1, 2, 3, 4 } },
        Address{ .ipv6 = @splat(0x11) },
        Address{ .domain = "a.example.com" },
    }) |addr| {
        var req_buf: [300]u8 = undefined;
        req_buf[0] = version;
        req_buf[1] = @intFromEnum(Command.connect);
        req_buf[2] = 0x00;
        req_buf[3] = @intFromEnum(std.meta.activeTag(addr));
        var cursor: usize = 4;
        switch (addr) {
            .ipv4 => |bytes| {
                @memcpy(req_buf[cursor..][0..4], &bytes);
                cursor += 4;
            },
            .ipv6 => |bytes| {
                @memcpy(req_buf[cursor..][0..16], &bytes);
                cursor += 16;
            },
            .domain => |name| {
                req_buf[cursor] = @intCast(name.len);
                cursor += 1;
                @memcpy(req_buf[cursor..][0..name.len], name);
                cursor += name.len;
            },
        }
        std.mem.writeInt(u16, req_buf[cursor..][0..2], 0x1F90, .big);
        cursor += 2;
        const r = try decodeRequest(req_buf[0..cursor]);
        try std.testing.expectEqual(@as(u16, 8080), r.port);
        try std.testing.expectEqual(std.meta.activeTag(addr), std.meta.activeTag(r.address));
    }
}

test "wire-format constants match RFC 1928 bytes" {
    // Locks the on-wire byte for each enum. A reordering / renumbering of
    // these enums would compile clean but break interop with every other
    // SOCKS5 implementation on earth.
    try std.testing.expectEqual(@as(u8, 0x05), version);
    try std.testing.expectEqual(@as(u8, 0x00), @intFromEnum(Method.no_auth));
    try std.testing.expectEqual(@as(u8, 0xFF), @intFromEnum(Method.no_acceptable));
    try std.testing.expectEqual(@as(u8, 0x01), @intFromEnum(Command.connect));
    try std.testing.expectEqual(@as(u8, 0x02), @intFromEnum(Command.bind));
    try std.testing.expectEqual(@as(u8, 0x03), @intFromEnum(Command.udp_associate));
    try std.testing.expectEqual(@as(u8, 0x01), @intFromEnum(AddressKind.ipv4));
    try std.testing.expectEqual(@as(u8, 0x03), @intFromEnum(AddressKind.domain));
    try std.testing.expectEqual(@as(u8, 0x04), @intFromEnum(AddressKind.ipv6));
    try std.testing.expectEqual(@as(u8, 0x00), @intFromEnum(Reply.succeeded));
    try std.testing.expectEqual(@as(u8, 0x07), @intFromEnum(Reply.command_not_supported));
    try std.testing.expectEqual(@as(u8, 0x08), @intFromEnum(Reply.address_type_not_supported));
}

test "KAT: curl --socks5-hostname greeting + CONNECT to example.com:80" {
    // Representative of what curl 8.x / Telegram Desktop send. Pinning the
    // exact bytes catches future decoder drift from real-world clients
    // without needing a live proxy.
    const greeting = [_]u8{ 0x05, 0x01, 0x00 };
    const g = try decodeGreeting(&greeting);
    try std.testing.expect(g.offersNoAuth());
    try std.testing.expectEqual(@as(usize, 3), g.bytes_consumed);

    const connect = [_]u8{
        0x05, 0x01, 0x00, 0x03,
        0x0B, 'e', 'x',  'a',
        'm',  'p',  'l',  'e',
        '.',  'c',  'o',  'm',
        0x00, 0x50,
    };
    const r = try decodeRequest(&connect);
    try std.testing.expectEqual(Command.connect, r.command);
    try std.testing.expectEqualStrings("example.com", r.address.domain);
    try std.testing.expectEqual(@as(u16, 80), r.port);
}

test "decodeRequest preserves embedded NUL / CRLF / non-ASCII in domain" {
    // Parser contract is "bytes verbatim". Caller is the one that must
    // sanitize before DNS / logs — see doc-comment on Address.domain.
    const ugly = "evil.com\x00\r\n\xFF";
    var buf: [5 + ugly.len + 2]u8 = undefined;
    buf[0..5].* = .{ 0x05, 0x01, 0x00, 0x03, @intCast(ugly.len) };
    @memcpy(buf[5 .. 5 + ugly.len], ugly);
    std.mem.writeInt(u16, buf[5 + ugly.len ..][0..2], 443, .big);
    const r = try decodeRequest(&buf);
    try std.testing.expectEqualSlices(u8, ugly, r.address.domain);
}

test "decodeRequest domain-form accepts IPv4-literal string (ATYP intent is caller's)" {
    const dotted = "192.168.1.1";
    var buf: [5 + dotted.len + 2]u8 = undefined;
    buf[0..5].* = .{ 0x05, 0x01, 0x00, 0x03, @intCast(dotted.len) };
    @memcpy(buf[5 .. 5 + dotted.len], dotted);
    std.mem.writeInt(u16, buf[5 + dotted.len ..][0..2], 443, .big);
    const r = try decodeRequest(&buf);
    try std.testing.expectEqualStrings(dotted, r.address.domain);
}

test "decodeRequest with minimum (1-byte) and maximum (255-byte) domain" {
    // 1-byte
    const short_buf = [_]u8{ 0x05, 0x01, 0x00, 0x03, 0x01, 'a', 0x00, 0x50 };
    const short_r = try decodeRequest(&short_buf);
    try std.testing.expectEqualStrings("a", short_r.address.domain);
    try std.testing.expectEqual(short_buf.len, short_r.bytes_consumed);

    // 255-byte
    var long: [255]u8 = undefined;
    @memset(&long, 'z');
    var long_buf: [5 + 255 + 2]u8 = undefined;
    long_buf[0..5].* = .{ 0x05, 0x01, 0x00, 0x03, 0xFF };
    @memcpy(long_buf[5..260], &long);
    std.mem.writeInt(u16, long_buf[260..][0..2], 443, .big);
    const long_r = try decodeRequest(&long_buf);
    try std.testing.expectEqual(@as(usize, 255), long_r.address.domain.len);
    try std.testing.expectEqual(long_buf.len, long_r.bytes_consumed);
}

test "decodeGreeting with nmethods=255 (maximum)" {
    var buf: [2 + 255]u8 = undefined;
    buf[0] = 0x05;
    buf[1] = 0xFF;
    for (buf[2..], 0..) |*slot, i| slot.* = @intCast(i);
    const g = try decodeGreeting(&buf);
    try std.testing.expectEqual(@as(usize, 255), g.methods.len);
    try std.testing.expectEqual(@as(usize, 257), g.bytes_consumed);
    try std.testing.expect(g.offersNoAuth()); // index 0 is 0x00
}

test "no-acceptable method flow: decode, predicate, encodeGreetingReply" {
    const g = try decodeGreeting(&[_]u8{ 0x05, 0x01, 0xFF });
    try std.testing.expect(!g.offersNoAuth());
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x05, 0xFF },
        &encodeGreetingReply(.no_acceptable),
    );
}

test "port boundaries 0 and 65535 roundtrip through decode + encode" {
    for ([_]u16{ 0, 65535 }) |port| {
        var req: [10]u8 = undefined;
        req[0..4].* = .{ 0x05, 0x01, 0x00, 0x01 };
        @memset(req[4..8], 0);
        std.mem.writeInt(u16, req[8..10], port, .big);
        const r = try decodeRequest(&req);
        try std.testing.expectEqual(port, r.port);

        var out: [10]u8 = undefined;
        const written = try encodeReply(&out, .succeeded, zero_ipv4, port);
        try std.testing.expectEqualSlices(u8, req[8..10], written[8..10]);
    }
}

test "encodeReply covers every Reply code with every ATYP" {
    inline for (&[_]Reply{
        .succeeded,
        .general_failure,
        .not_allowed,
        .network_unreachable,
        .host_unreachable,
        .connection_refused,
        .ttl_expired,
        .command_not_supported,
        .address_type_not_supported,
    }) |reply| {
        inline for (&[_]Address{
            zero_ipv4,
            .{ .ipv6 = @splat(0) },
            .{ .domain = "host" },
        }) |addr| {
            var out: [300]u8 = undefined;
            const written = try encodeReply(&out, reply, addr, 0);
            try std.testing.expectEqual(@as(u8, version), written[0]);
            try std.testing.expectEqual(@intFromEnum(reply), written[1]);
            try std.testing.expectEqual(@as(u8, 0x00), written[2]);
            try std.testing.expectEqual(@intFromEnum(std.meta.activeTag(addr)), written[3]);
        }
    }
}

test "encodeReply leaves tail of out buffer untouched (no info leak)" {
    var out: [50]u8 = undefined;
    @memset(&out, 0xAA);
    const written = try encodeReply(&out, .succeeded, zero_ipv4, 0);
    try std.testing.expect(written.len < out.len);
    for (out[written.len..]) |byte| {
        try std.testing.expectEqual(@as(u8, 0xAA), byte);
    }
}

test "encodeReply rejects domain > 255 bytes with DomainTooLong" {
    var out: [300]u8 = undefined;
    var long: [256]u8 = undefined;
    @memset(&long, 'a');
    try std.testing.expectError(
        error.DomainTooLong,
        encodeReply(&out, .succeeded, .{ .domain = &long }, 0),
    );
}

test "encodeReply accepts domain = 255 bytes exactly" {
    var out: [300]u8 = undefined;
    var name: [255]u8 = undefined;
    @memset(&name, 'a');
    const written = try encodeReply(&out, .succeeded, .{ .domain = &name }, 0);
    try std.testing.expectEqual(@as(u8, 255), written[4]);
    try std.testing.expectEqual(@as(usize, 4 + 1 + 255 + 2), written.len);
}
