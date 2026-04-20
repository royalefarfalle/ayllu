//! TLS 1.3 ServerHello synthesis (RFC 8446 §4.1.3).
//!
//! Wire format (body — without the 4-byte handshake-message header):
//!
//!     struct {
//!         ProtocolVersion legacy_version = 0x0303;
//!         Random random;                              // 32 bytes
//!         opaque legacy_session_id_echo<0..32>;       // 1B len + data
//!         CipherSuite cipher_suite;                   // 2 bytes
//!         uint8 legacy_compression_method = 0;        // 1 byte
//!         Extension extensions<6..2^16-1>;            // 2B len + data
//!     } ServerHello;
//!
//! REALITY emits exactly two extensions:
//!   * supported_versions (43): selected_version = 0x0304 (TLS 1.3)
//!   * key_share          (51): NamedGroup x25519 (0x001D) + 32-byte server public
//!
//! The cipher_suite value is picked from the ClientHello's offered
//! list upstream; this module lays it down verbatim. `session_id_echo`
//! is copied from the ClientHello verbatim (TLS 1.3 middlebox-compat
//! requirement).
//!
//! `wrapHandshake` prepends the 4-byte handshake message header
//! (HandshakeType u8 || u24 body length); REALITY's Certificate,
//! CertificateVerify and Finished messages reuse the same helper.
//!
//! Pure stack-only: no allocator, no I/O. Callers supply the output
//! buffer.

const std = @import("std");
const tls = std.crypto.tls;

pub const legacy_version: u16 = 0x0303;
pub const random_length: usize = 32;
pub const max_session_id_length: usize = 32;

pub const EmitError = error{
    ShortBuffer,
    InvalidSessionIdLength,
    PayloadTooLarge,
};

pub const ServerHelloParams = struct {
    /// Cipher suite chosen from the ClientHello's offered list. Raw
    /// u16 code (e.g. 0x1301 for TLS_AES_128_GCM_SHA256).
    cipher_suite: u16,
    /// 32 random bytes from the server. Supplied by caller; REALITY
    /// has no constraints on this field beyond TLS 1.3's.
    server_random: [random_length]u8,
    /// Bytes from ClientHello.session_id, echoed verbatim for TLS 1.3
    /// middlebox compat. 0..32 bytes; longer rejects.
    session_id_echo: []const u8,
    /// Server's X25519 public key, bound to this REALITY session.
    server_x25519_public: [32]u8,
};

/// Encoded ServerHello *body* size for a given session_id length.
/// Stays in sync with the fixed two-extension layout emitted below.
///   2  legacy_version
///   32 random
///   1  session_id length prefix
///   N  session_id bytes
///   2  cipher_suite
///   1  legacy_compression_method
///   2  extensions outer length
///   6  supported_versions extension (type 2 + len 2 + body 2)
///   40 key_share extension (type 2 + len 2 + group 2 + kx_len 2 + 32)
pub fn bodyLen(session_id_length: usize) usize {
    return 2 + random_length + 1 + session_id_length + 2 + 1 + 2 + 6 + 40;
}

/// Emit a TLS 1.3 ServerHello body into `buf`. Returns the number
/// of bytes written. Does NOT include the 4-byte handshake header —
/// use `wrapHandshake` for that.
pub fn emit(buf: []u8, params: ServerHelloParams) EmitError!usize {
    if (params.session_id_echo.len > max_session_id_length) return error.InvalidSessionIdLength;
    const total = bodyLen(params.session_id_echo.len);
    if (buf.len < total) return error.ShortBuffer;

    var w: Writer = .{ .buf = buf };
    w.writeU16(legacy_version);
    w.writeFixed(&params.server_random);
    w.writeVecU8(params.session_id_echo);
    w.writeU16(params.cipher_suite);
    w.writeU8(0); // legacy_compression_method

    // Build extension block into a fixed-size scratch, then wrap with
    // a u16 length prefix. The two extensions below total 46 bytes.
    var ext_scratch: [64]u8 = undefined;
    var ew: Writer = .{ .buf = &ext_scratch };

    // supported_versions (43): selected_version = 0x0304.
    ew.writeU16(@intFromEnum(tls.ExtensionType.supported_versions));
    ew.writeU16(2);
    ew.writeU16(0x0304);

    // key_share (51): NamedGroup x25519 + 32-byte key_exchange.
    ew.writeU16(@intFromEnum(tls.ExtensionType.key_share));
    ew.writeU16(2 + 2 + 32);
    ew.writeU16(@intFromEnum(tls.NamedGroup.x25519));
    ew.writeU16(32);
    ew.writeFixed(&params.server_x25519_public);

    w.writeVecU16(ext_scratch[0..ew.pos]);

    std.debug.assert(w.pos == total);
    return w.pos;
}

/// Prepend the 4-byte handshake message header `[type u8 | length u24]`
/// to `payload`, writing the result into `buf`. Returns total bytes
/// written (= 4 + payload.len). Used for server_hello, certificate,
/// certificate_verify, finished.
pub fn wrapHandshake(
    buf: []u8,
    msg_type: tls.HandshakeType,
    payload: []const u8,
) EmitError!usize {
    if (payload.len > 0x00FF_FFFF) return error.PayloadTooLarge;
    const total = 4 + payload.len;
    if (buf.len < total) return error.ShortBuffer;
    buf[0] = @intFromEnum(msg_type);
    buf[1] = @intCast((payload.len >> 16) & 0xFF);
    buf[2] = @intCast((payload.len >> 8) & 0xFF);
    buf[3] = @intCast(payload.len & 0xFF);
    @memcpy(buf[4..total], payload);
    return total;
}

// -------------------- Writer --------------------

const Writer = struct {
    buf: []u8,
    pos: usize = 0,

    fn writeU8(self: *Writer, v: u8) void {
        self.buf[self.pos] = v;
        self.pos += 1;
    }
    fn writeU16(self: *Writer, v: u16) void {
        std.mem.writeInt(u16, self.buf[self.pos..][0..2], v, .big);
        self.pos += 2;
    }
    fn writeFixed(self: *Writer, bytes: []const u8) void {
        @memcpy(self.buf[self.pos .. self.pos + bytes.len], bytes);
        self.pos += bytes.len;
    }
    fn writeVecU8(self: *Writer, bytes: []const u8) void {
        self.writeU8(@intCast(bytes.len));
        self.writeFixed(bytes);
    }
    fn writeVecU16(self: *Writer, bytes: []const u8) void {
        self.writeU16(@intCast(bytes.len));
        self.writeFixed(bytes);
    }
};

// -------------------- Tests --------------------

const testing = std.testing;

/// Minimal inline parser for the round-trip test. Not exposed —
/// client_hello.zig has a private Reader with the same shape;
/// duplicating here keeps both modules self-contained.
const TestReader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn remaining(self: TestReader) usize {
        return self.buf.len - self.pos;
    }
    fn readU8(self: *TestReader) ?u8 {
        if (self.remaining() < 1) return null;
        const v = self.buf[self.pos];
        self.pos += 1;
        return v;
    }
    fn readU16(self: *TestReader) ?u16 {
        if (self.remaining() < 2) return null;
        const v = std.mem.readInt(u16, self.buf[self.pos..][0..2], .big);
        self.pos += 2;
        return v;
    }
    fn readFixed(self: *TestReader, n: usize) ?[]const u8 {
        if (self.remaining() < n) return null;
        const s = self.buf[self.pos .. self.pos + n];
        self.pos += n;
        return s;
    }
    fn readVecU8(self: *TestReader) ?[]const u8 {
        const len = self.readU8() orelse return null;
        return self.readFixed(len);
    }
    fn readVecU16(self: *TestReader) ?[]const u8 {
        const len = self.readU16() orelse return null;
        return self.readFixed(len);
    }
};

test "wrapHandshake: emits [type u8 | u24 length | payload]" {
    var buf: [32]u8 = undefined;
    const payload = "hello";
    const n = try wrapHandshake(&buf, .server_hello, payload);
    try testing.expectEqual(@as(usize, 4 + payload.len), n);
    try testing.expectEqual(@as(u8, 2), buf[0]); // HandshakeType.server_hello = 2
    try testing.expectEqual(@as(u8, 0), buf[1]);
    try testing.expectEqual(@as(u8, 0), buf[2]);
    try testing.expectEqual(@as(u8, 5), buf[3]);
    try testing.expectEqualSlices(u8, payload, buf[4 .. 4 + payload.len]);
}

test "wrapHandshake: rejects short buffer" {
    var tiny: [3]u8 = undefined;
    try testing.expectError(error.ShortBuffer, wrapHandshake(&tiny, .server_hello, ""));
}

test "emit: fixed inputs produce expected golden bytes" {
    const params: ServerHelloParams = .{
        .cipher_suite = 0x1301,
        .server_random = [_]u8{0xAA} ** 32,
        .session_id_echo = &.{ 0x11, 0x22, 0x33, 0x44 },
        .server_x25519_public = [_]u8{0xBB} ** 32,
    };
    var buf: [128]u8 = undefined;
    const n = try emit(&buf, params);
    try testing.expectEqual(@as(usize, 90), n);

    // legacy_version
    try testing.expectEqualSlices(u8, &.{ 0x03, 0x03 }, buf[0..2]);
    // random
    for (2..34) |i| try testing.expectEqual(@as(u8, 0xAA), buf[i]);
    // session_id (length 4 + 4 bytes)
    try testing.expectEqual(@as(u8, 4), buf[34]);
    try testing.expectEqualSlices(u8, &.{ 0x11, 0x22, 0x33, 0x44 }, buf[35..39]);
    // cipher_suite (0x1301)
    try testing.expectEqualSlices(u8, &.{ 0x13, 0x01 }, buf[39..41]);
    // compression
    try testing.expectEqual(@as(u8, 0), buf[41]);
    // extensions outer length (46 = 0x002E)
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x2E }, buf[42..44]);
    // supported_versions (type 0x002B, len 2, body 0x0304)
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x2B, 0x00, 0x02, 0x03, 0x04 }, buf[44..50]);
    // key_share (type 0x0033, len 36, group 0x001D, kx_len 32)
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x33, 0x00, 0x24, 0x00, 0x1D, 0x00, 0x20 }, buf[50..58]);
    for (58..90) |i| try testing.expectEqual(@as(u8, 0xBB), buf[i]);
}

test "emit: session_id echoed verbatim for lengths 0, 8, 32" {
    var sid: [32]u8 = undefined;
    for (&sid, 0..) |*b, i| b.* = @intCast(i & 0xFF);
    inline for (.{ 0, 8, 32 }) |sid_len| {
        const params: ServerHelloParams = .{
            .cipher_suite = 0x1301,
            .server_random = [_]u8{0} ** 32,
            .session_id_echo = sid[0..sid_len],
            .server_x25519_public = [_]u8{0} ** 32,
        };
        var buf: [128]u8 = undefined;
        const n = try emit(&buf, params);
        try testing.expectEqual(bodyLen(sid_len), n);
        try testing.expectEqual(@as(u8, @intCast(sid_len)), buf[34]);
        try testing.expectEqualSlices(u8, sid[0..sid_len], buf[35 .. 35 + sid_len]);
    }
}

test "emit: supported_versions extension advertises TLS 1.3 (0x0304)" {
    const params: ServerHelloParams = .{
        .cipher_suite = 0x1302,
        .server_random = [_]u8{0} ** 32,
        .session_id_echo = "",
        .server_x25519_public = [_]u8{0} ** 32,
    };
    var buf: [128]u8 = undefined;
    _ = try emit(&buf, params);
    // Body with empty session_id: extensions outer length at offset 38,
    // extensions body starts at offset 40.
    const ext_type = std.mem.readInt(u16, buf[40..42], .big);
    const ext_len = std.mem.readInt(u16, buf[42..44], .big);
    const selected = std.mem.readInt(u16, buf[44..46], .big);
    try testing.expectEqual(@intFromEnum(tls.ExtensionType.supported_versions), ext_type);
    try testing.expectEqual(@as(u16, 2), ext_len);
    try testing.expectEqual(@as(u16, 0x0304), selected);
}

test "emit: key_share extension carries X25519 group and 32-byte server public" {
    var server_pub: [32]u8 = undefined;
    for (&server_pub, 0..) |*b, i| b.* = @intCast(i);
    const params: ServerHelloParams = .{
        .cipher_suite = 0x1301,
        .server_random = [_]u8{0} ** 32,
        .session_id_echo = "",
        .server_x25519_public = server_pub,
    };
    var buf: [128]u8 = undefined;
    _ = try emit(&buf, params);
    // supported_versions ext is 6 bytes. key_share starts at 40 + 6 = 46.
    const ks_type = std.mem.readInt(u16, buf[46..48], .big);
    const ks_body_len = std.mem.readInt(u16, buf[48..50], .big);
    const ks_group = std.mem.readInt(u16, buf[50..52], .big);
    const kx_len = std.mem.readInt(u16, buf[52..54], .big);
    try testing.expectEqual(@intFromEnum(tls.ExtensionType.key_share), ks_type);
    try testing.expectEqual(@as(u16, 36), ks_body_len);
    try testing.expectEqual(@intFromEnum(tls.NamedGroup.x25519), ks_group);
    try testing.expectEqual(@as(u16, 32), kx_len);
    try testing.expectEqualSlices(u8, &server_pub, buf[54..86]);
}

test "emit: cipher_suite is laid down as big-endian u16 at the spec offset" {
    inline for ([_]u16{ 0x1301, 0x1302, 0x1303 }) |suite| {
        const params: ServerHelloParams = .{
            .cipher_suite = suite,
            .server_random = [_]u8{0} ** 32,
            .session_id_echo = "",
            .server_x25519_public = [_]u8{0} ** 32,
        };
        var buf: [128]u8 = undefined;
        _ = try emit(&buf, params);
        try testing.expectEqual(suite, std.mem.readInt(u16, buf[35..37], .big));
    }
}

test "emit: server_random is laid down verbatim at offset 2" {
    var r: [32]u8 = undefined;
    for (&r, 0..) |*b, i| b.* = @intCast(i ^ 0x55);
    const params: ServerHelloParams = .{
        .cipher_suite = 0x1301,
        .server_random = r,
        .session_id_echo = "",
        .server_x25519_public = [_]u8{0} ** 32,
    };
    var buf: [128]u8 = undefined;
    _ = try emit(&buf, params);
    try testing.expectEqualSlices(u8, &r, buf[2..34]);
}

test "emit: rejects session_id longer than 32 bytes" {
    var too_long: [33]u8 = undefined;
    @memset(&too_long, 0);
    const params: ServerHelloParams = .{
        .cipher_suite = 0x1301,
        .server_random = [_]u8{0} ** 32,
        .session_id_echo = &too_long,
        .server_x25519_public = [_]u8{0} ** 32,
    };
    var buf: [128]u8 = undefined;
    try testing.expectError(error.InvalidSessionIdLength, emit(&buf, params));
}

test "emit: rejects buffer smaller than encoded body" {
    const params: ServerHelloParams = .{
        .cipher_suite = 0x1301,
        .server_random = [_]u8{0} ** 32,
        .session_id_echo = "",
        .server_x25519_public = [_]u8{0} ** 32,
    };
    var too_small: [32]u8 = undefined;
    try testing.expectError(error.ShortBuffer, emit(&too_small, params));
}

test "emit: produces bytes parseable by a minimal ServerHello reader" {
    const params: ServerHelloParams = .{
        .cipher_suite = 0x1303,
        .server_random = [_]u8{0xCC} ** 32,
        .session_id_echo = &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04 },
        .server_x25519_public = [_]u8{0xEE} ** 32,
    };
    var buf: [128]u8 = undefined;
    const n = try emit(&buf, params);

    var r: TestReader = .{ .buf = buf[0..n] };
    try testing.expectEqual(legacy_version, r.readU16().?);
    try testing.expectEqualSlices(u8, &params.server_random, r.readFixed(random_length).?);
    try testing.expectEqualSlices(u8, params.session_id_echo, r.readVecU8().?);
    try testing.expectEqual(@as(u16, 0x1303), r.readU16().?);
    try testing.expectEqual(@as(u8, 0), r.readU8().?);
    const exts = r.readVecU16().?;
    try testing.expectEqual(@as(usize, 0), r.remaining());

    var er: TestReader = .{ .buf = exts };
    try testing.expectEqual(
        @intFromEnum(tls.ExtensionType.supported_versions),
        er.readU16().?,
    );
    const sv_body = er.readVecU16().?;
    try testing.expectEqual(@as(u16, 0x0304), std.mem.readInt(u16, sv_body[0..2], .big));

    try testing.expectEqual(
        @intFromEnum(tls.ExtensionType.key_share),
        er.readU16().?,
    );
    const ks_body = er.readVecU16().?;
    try testing.expectEqual(@as(usize, 0), er.remaining());

    var kr: TestReader = .{ .buf = ks_body };
    try testing.expectEqual(
        @intFromEnum(tls.NamedGroup.x25519),
        kr.readU16().?,
    );
    try testing.expectEqualSlices(u8, &params.server_x25519_public, kr.readVecU16().?);
    try testing.expectEqual(@as(usize, 0), kr.remaining());
}

test "wrapHandshake: composes cleanly with emit to produce a server_hello handshake message" {
    const params: ServerHelloParams = .{
        .cipher_suite = 0x1301,
        .server_random = [_]u8{0x77} ** 32,
        .session_id_echo = "",
        .server_x25519_public = [_]u8{0x88} ** 32,
    };
    var body_buf: [128]u8 = undefined;
    const body_len = try emit(&body_buf, params);

    var msg_buf: [256]u8 = undefined;
    const msg_len = try wrapHandshake(&msg_buf, .server_hello, body_buf[0..body_len]);
    try testing.expectEqual(4 + body_len, msg_len);
    try testing.expectEqual(@as(u8, 2), msg_buf[0]);
    const wrapped_len = (@as(u24, msg_buf[1]) << 16) |
        (@as(u24, msg_buf[2]) << 8) |
        @as(u24, msg_buf[3]);
    try testing.expectEqual(@as(u24, @intCast(body_len)), wrapped_len);
    try testing.expectEqualSlices(u8, body_buf[0..body_len], msg_buf[4..msg_len]);
}
