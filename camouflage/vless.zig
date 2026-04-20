//! VLESS (v1) request-header parser — the inner protocol inside the
//! TLS stream for REALITY connections from third-party clients
//! (Nekobox / v2rayN / sing-box, configured with `--inner-protocol
//! vless`).
//!
//! Wire format of the per-connection request header:
//!
//!     offset          | len       | field
//!     ----------------+-----------+----------------------------------
//!      0              |  1        | version (== 0x00 for vless v1)
//!      1              | 16        | uuid (client identity)
//!     17              |  1        | addon_len (usually 0; we skip the bytes)
//!     18              |  addon_len| addon (protocol extensions)
//!     18 + addon_len  |  1        | command (0x01 TCP, 0x02 UDP, 0x03 MUX)
//!     19 + addon_len  |  2        | port (big-endian)
//!     21 + addon_len  |  1        | addr_type (0x01 IPv4, 0x02 Domain, 0x03 IPv6)
//!     22 + addon_len  |  variable | address
//!                                   ipv4:   4 bytes
//!                                   domain: 1-byte length + N bytes (1..255)
//!                                   ipv6:   16 bytes
//!
//! The header is consumed from the first decrypted application_data
//! record after the TLS handshake completes. Everything after the
//! header (inside the same TLS record or subsequent records) is
//! tunnelled traffic — the dispatcher relays it to `address:port`.
//!
//! Out of scope for this slice: MUX command (0x03), UDP command, and
//! per-client UUID lookup. `parseHeader` decodes the fields; a
//! separate UUID gate + TCP-only check happens at the call site.

const std = @import("std");

pub const version_v1: u8 = 0x00;
pub const uuid_length: usize = 16;
pub const max_addon_length: usize = 255;
pub const min_header_length: usize = 1 + uuid_length + 1 + 1 + 2 + 1 + 4;
pub const max_domain_length: usize = 255;

pub const Command = enum(u8) {
    tcp = 0x01,
    udp = 0x02,
    mux = 0x03,
    _,
};

pub const AddressType = enum(u8) {
    ipv4 = 0x01,
    domain = 0x02,
    ipv6 = 0x03,
    _,
};

pub const Address = union(enum) {
    ipv4: [4]u8,
    /// Slice into the input buffer; callers must copy before the
    /// buffer is reused.
    domain: []const u8,
    ipv6: [16]u8,
};

pub const Header = struct {
    version: u8,
    uuid: [uuid_length]u8,
    command: Command,
    port: u16,
    address: Address,
};

pub const ParseError = error{
    ShortBuffer,
    UnsupportedVersion,
    InvalidAddonLength,
    UnsupportedCommand,
    UnsupportedAddressType,
    InvalidDomainLength,
    InvalidPort,
};

/// Parse a VLESS v1 request header from the first decrypted
/// application_data record. Returns the parsed header and the number
/// of bytes consumed; any bytes after `consumed` are the start of the
/// tunnelled application payload.
pub fn parseHeader(bytes: []const u8) ParseError!struct { Header, usize } {
    if (bytes.len < 1) return error.ShortBuffer;
    const version = bytes[0];
    if (version != version_v1) return error.UnsupportedVersion;

    if (bytes.len < 1 + uuid_length + 1) return error.ShortBuffer;
    var uuid: [uuid_length]u8 = undefined;
    @memcpy(&uuid, bytes[1 .. 1 + uuid_length]);

    const addon_len = bytes[1 + uuid_length];
    const after_addon = 1 + uuid_length + 1 + @as(usize, addon_len);
    if (addon_len > max_addon_length) return error.InvalidAddonLength;
    if (bytes.len < after_addon + 4) return error.ShortBuffer;

    const command_byte = bytes[after_addon];
    const command: Command = switch (command_byte) {
        0x01 => .tcp,
        0x02 => .udp,
        0x03 => .mux,
        else => return error.UnsupportedCommand,
    };

    const port = std.mem.readInt(u16, bytes[after_addon + 1 ..][0..2], .big);
    if (port == 0) return error.InvalidPort;

    const addr_type_byte = bytes[after_addon + 3];
    const addr_start = after_addon + 4;

    switch (addr_type_byte) {
        0x01 => {
            if (bytes.len < addr_start + 4) return error.ShortBuffer;
            var v4: [4]u8 = undefined;
            @memcpy(&v4, bytes[addr_start .. addr_start + 4]);
            return .{
                .{
                    .version = version,
                    .uuid = uuid,
                    .command = command,
                    .port = port,
                    .address = .{ .ipv4 = v4 },
                },
                addr_start + 4,
            };
        },
        0x02 => {
            if (bytes.len < addr_start + 1) return error.ShortBuffer;
            const domain_len = bytes[addr_start];
            if (domain_len == 0 or domain_len > max_domain_length) return error.InvalidDomainLength;
            const end = addr_start + 1 + @as(usize, domain_len);
            if (bytes.len < end) return error.ShortBuffer;
            return .{
                .{
                    .version = version,
                    .uuid = uuid,
                    .command = command,
                    .port = port,
                    .address = .{ .domain = bytes[addr_start + 1 .. end] },
                },
                end,
            };
        },
        0x03 => {
            if (bytes.len < addr_start + 16) return error.ShortBuffer;
            var v6: [16]u8 = undefined;
            @memcpy(&v6, bytes[addr_start .. addr_start + 16]);
            return .{
                .{
                    .version = version,
                    .uuid = uuid,
                    .command = command,
                    .port = port,
                    .address = .{ .ipv6 = v6 },
                },
                addr_start + 16,
            };
        },
        else => return error.UnsupportedAddressType,
    }
}

// -------------------- Tests --------------------

const testing = std.testing;

fn buildHeader(
    out: []u8,
    version: u8,
    uuid: [16]u8,
    addon: []const u8,
    command: u8,
    port: u16,
    addr_bytes: []const u8, // addr_type + variable-length addr
) usize {
    var p: usize = 0;
    out[p] = version;
    p += 1;
    @memcpy(out[p .. p + 16], &uuid);
    p += 16;
    out[p] = @intCast(addon.len);
    p += 1;
    @memcpy(out[p .. p + addon.len], addon);
    p += addon.len;
    out[p] = command;
    p += 1;
    std.mem.writeInt(u16, out[p..][0..2], port, .big);
    p += 2;
    @memcpy(out[p .. p + addr_bytes.len], addr_bytes);
    p += addr_bytes.len;
    return p;
}

test "VLESS parseHeader: IPv4 + no addon + TCP command" {
    const uuid = [_]u8{0x42} ** 16;
    const addr = [_]u8{ 0x01, 192, 168, 1, 1 }; // ipv4 type + 4 octets
    var buf: [64]u8 = undefined;
    const n = buildHeader(&buf, 0x00, uuid, "", 0x01, 443, &addr);

    const hdr, const consumed = try parseHeader(buf[0..n]);
    try testing.expectEqual(@as(u8, 0x00), hdr.version);
    try testing.expectEqualSlices(u8, &uuid, &hdr.uuid);
    try testing.expectEqual(Command.tcp, hdr.command);
    try testing.expectEqual(@as(u16, 443), hdr.port);
    try testing.expectEqualSlices(u8, &.{ 192, 168, 1, 1 }, &hdr.address.ipv4);
    try testing.expectEqual(n, consumed);
}

test "VLESS parseHeader: Domain address" {
    const uuid = [_]u8{0xAB} ** 16;
    const domain = "example.com";
    var addr_buf: [64]u8 = undefined;
    addr_buf[0] = 0x02; // domain type
    addr_buf[1] = @intCast(domain.len);
    @memcpy(addr_buf[2 .. 2 + domain.len], domain);
    const addr_len = 2 + domain.len;

    var buf: [128]u8 = undefined;
    const n = buildHeader(&buf, 0x00, uuid, "", 0x01, 80, addr_buf[0..addr_len]);

    const hdr, const consumed = try parseHeader(buf[0..n]);
    try testing.expectEqual(Command.tcp, hdr.command);
    try testing.expectEqual(@as(u16, 80), hdr.port);
    try testing.expectEqualStrings(domain, hdr.address.domain);
    try testing.expectEqual(n, consumed);
}

test "VLESS parseHeader: IPv6 address" {
    const uuid = [_]u8{0xEE} ** 16;
    var addr_buf: [17]u8 = undefined;
    addr_buf[0] = 0x03; // ipv6 type
    for (addr_buf[1..17], 0..) |*b, i| b.* = @intCast(i);

    var buf: [64]u8 = undefined;
    const n = buildHeader(&buf, 0x00, uuid, "", 0x02, 53, &addr_buf);

    const hdr, const consumed = try parseHeader(buf[0..n]);
    try testing.expectEqual(Command.udp, hdr.command);
    try testing.expectEqual(@as(u16, 53), hdr.port);
    for (hdr.address.ipv6, 0..) |b, i| try testing.expectEqual(@as(u8, @intCast(i)), b);
    try testing.expectEqual(n, consumed);
}

test "VLESS parseHeader: addon bytes are skipped but present" {
    const uuid = [_]u8{0x11} ** 16;
    const addon: [3]u8 = .{ 0xAA, 0xBB, 0xCC };
    const addr = [_]u8{ 0x01, 10, 0, 0, 1 };
    var buf: [64]u8 = undefined;
    const n = buildHeader(&buf, 0x00, uuid, &addon, 0x01, 1080, &addr);

    const hdr, const consumed = try parseHeader(buf[0..n]);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, &hdr.address.ipv4);
    try testing.expectEqual(@as(u16, 1080), hdr.port);
    try testing.expectEqual(n, consumed);
}

test "VLESS parseHeader: truncated (header missing port bytes)" {
    const uuid = [_]u8{0} ** 16;
    var buf: [64]u8 = undefined;
    buf[0] = 0x00;
    @memcpy(buf[1..17], &uuid);
    buf[17] = 0; // addon_len = 0
    buf[18] = 0x01; // command
    // intentionally stop here — no port bytes
    try testing.expectError(error.ShortBuffer, parseHeader(buf[0..19]));
}

test "VLESS parseHeader: unsupported version => UnsupportedVersion" {
    var buf: [32]u8 = undefined;
    buf[0] = 0x07;
    try testing.expectError(error.UnsupportedVersion, parseHeader(buf[0..1]));
}

test "VLESS parseHeader: unknown command => UnsupportedCommand" {
    const uuid = [_]u8{0} ** 16;
    const addr = [_]u8{ 0x01, 0, 0, 0, 0 };
    var buf: [64]u8 = undefined;
    const n = buildHeader(&buf, 0x00, uuid, "", 0x7F, 443, &addr);
    try testing.expectError(error.UnsupportedCommand, parseHeader(buf[0..n]));
}

test "VLESS parseHeader: zero-length domain => InvalidDomainLength" {
    const uuid = [_]u8{0} ** 16;
    const addr = [_]u8{ 0x02, 0x00 }; // domain type, length=0
    var buf: [64]u8 = undefined;
    const n = buildHeader(&buf, 0x00, uuid, "", 0x01, 443, &addr);
    try testing.expectError(error.InvalidDomainLength, parseHeader(buf[0..n]));
}

test "VLESS parseHeader: unsupported addr_type (0x09) => UnsupportedAddressType" {
    const uuid = [_]u8{0} ** 16;
    const addr = [_]u8{ 0x09, 0, 0, 0, 0 };
    var buf: [64]u8 = undefined;
    const n = buildHeader(&buf, 0x00, uuid, "", 0x01, 443, &addr);
    try testing.expectError(error.UnsupportedAddressType, parseHeader(buf[0..n]));
}

test "VLESS parseHeader: port 0 rejected as InvalidPort" {
    const uuid = [_]u8{0} ** 16;
    const addr = [_]u8{ 0x01, 1, 2, 3, 4 };
    var buf: [64]u8 = undefined;
    const n = buildHeader(&buf, 0x00, uuid, "", 0x01, 0, &addr);
    try testing.expectError(error.InvalidPort, parseHeader(buf[0..n]));
}

test "VLESS parseHeader: extra bytes after header remain in caller's slice" {
    const uuid = [_]u8{0xAA} ** 16;
    const addr = [_]u8{ 0x01, 127, 0, 0, 1 };
    var buf: [128]u8 = undefined;
    const n = buildHeader(&buf, 0x00, uuid, "", 0x01, 8080, &addr);
    // append 10 bytes of tunnelled payload immediately after the header.
    @memset(buf[n .. n + 10], 0xEE);
    const total = n + 10;

    const hdr, const consumed = try parseHeader(buf[0..total]);
    try testing.expectEqual(@as(u16, 8080), hdr.port);
    try testing.expectEqual(n, consumed);
    // The caller can extract payload = buf[consumed..total].
    try testing.expectEqualSlices(u8, &[_]u8{0xEE} ** 10, buf[consumed..total]);
}
