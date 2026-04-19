//! TLS 1.3 ClientHello parser (RFC 8446 §4.1.2).
//!
//! Wire format:
//!
//!     struct {
//!         ProtocolVersion legacy_version = 0x0303;
//!         Random random;                                       // 32 bytes
//!         opaque legacy_session_id<0..32>;                     // 1B len + data
//!         CipherSuite cipher_suites<2..2^16-2>;                // 2B len + N*2
//!         opaque legacy_compression_methods<1..2^8-1>;         // 1B len + bytes
//!         Extension extensions<8..2^16-1>;                     // 2B len + data
//!     } ClientHello;
//!
//! This module gives back a `ClientHello` struct with just the
//! fields REALITY cares about. It is explicitly NOT a general TLS
//! parser — extensions outside the REALITY-relevant set are skipped
//! silently, and any parse failure is converted to a single
//! `error.MalformedClientHello` so the dispatcher's fallback path
//! never depends on the specific wire deviation.
//!
//! Called with the body of a `handshake`-type record AFTER the
//! handshake header (HandshakeType = client_hello, 3-byte length)
//! has been validated and stripped.

const std = @import("std");
const tls = std.crypto.tls;

pub const legacy_version: u16 = 0x0303;
pub const random_length: usize = 32;
pub const max_session_id_length: usize = 32;

pub const ParseError = error{
    MalformedClientHello,
    UnsupportedTlsVersion,
    MissingSupportedVersions,
    MissingKeyShare,
    UnsupportedKeyShareGroup,
};

pub const X25519KeyShare = struct {
    /// Raw 32-byte X25519 public key. REALITY derives its AuthKey MAC
    /// via X25519(server_private, client_public); see camouflage/reality.zig.
    public_key: [32]u8,
};

/// Reference into the caller's buffer. Lifetimes match the input
/// `record_body` slice; callers must copy out before the buffer
/// is reused.
pub const ClientHello = struct {
    /// Full wire bytes of the ClientHello body (from legacy_version
    /// through the final extension). Used as input to the REALITY
    /// transcript-hash and for the ServerHello session_id_echo.
    raw: []const u8,

    random: [random_length]u8,
    /// Legacy-TLS session id. In TLS 1.3 this has been pressed into
    /// service as an opaque "middlebox" field; REALITY v25.x places
    /// the per-connection AuthKey material here (see xray_wire.zig,
    /// C4c). 0..32 bytes.
    session_id: []const u8,

    /// Offered cipher suites as raw big-endian bytes (length = 2N).
    /// Read individual entries via `cipherAt(i)` or test with
    /// `offersCipher(id)` — direct indexing as u16 would require a
    /// 2-byte-aligned pointer, which ClientHello wire bytes rarely are.
    cipher_suites_raw: []const u8,

    /// Server name (SNI) if present. The REALITY config enumerates
    /// accepted server_names; a mismatch routes to the TCP
    /// passthrough fallback without reply.
    server_name: ?[]const u8 = null,

    /// Present if the client offered TLS 1.3 (0x0304) in the
    /// supported_versions extension. MUST be present for us to
    /// proceed; REALITY rejects any other TLS version.
    supports_tls_13: bool = false,

    /// Client's X25519 public key extracted from the key_share
    /// extension. REALITY requires this (named group X25519, 0x001D).
    x25519_key_share: ?X25519KeyShare = null,

    /// signature_algorithms extension body — raw big-endian bytes
    /// (length = 2N). Access via `sigAlgAt(i)` or iterate.
    signature_algorithms_raw: []const u8 = &.{},

    /// ALPN identifiers the client offered, in order. Server's
    /// selection goes back in the ServerHello's ALPN extension.
    alpn_protocols: [][]const u8 = &.{},

    pub fn cipherCount(self: ClientHello) usize {
        return self.cipher_suites_raw.len / 2;
    }

    pub fn cipherAt(self: ClientHello, index: usize) u16 {
        return std.mem.readInt(u16, self.cipher_suites_raw[index * 2 ..][0..2], .big);
    }

    pub fn offersCipher(self: ClientHello, id: u16) bool {
        var i: usize = 0;
        while (i < self.cipherCount()) : (i += 1) if (self.cipherAt(i) == id) return true;
        return false;
    }

    pub fn sigAlgCount(self: ClientHello) usize {
        return self.signature_algorithms_raw.len / 2;
    }

    pub fn sigAlgAt(self: ClientHello, index: usize) u16 {
        return std.mem.readInt(u16, self.signature_algorithms_raw[index * 2 ..][0..2], .big);
    }

    pub fn offersAlpn(self: ClientHello, id: []const u8) bool {
        for (self.alpn_protocols) |p| if (std.mem.eql(u8, p, id)) return true;
        return false;
    }
};

/// Parse an already-de-framed ClientHello body. Does NOT read the
/// outer record header or handshake type/length — caller already
/// validated those.
pub fn parse(body: []const u8, scratch_alpn: []?[]const u8) ParseError!ClientHello {
    var r: Reader = .init(body);

    const version = r.readU16() orelse return error.MalformedClientHello;
    if (version != legacy_version) return error.UnsupportedTlsVersion;

    const random_bytes = r.readFixed(random_length) orelse return error.MalformedClientHello;
    var random_copy: [random_length]u8 = undefined;
    @memcpy(&random_copy, random_bytes);

    const session_id = r.readVecU8() orelse return error.MalformedClientHello;
    if (session_id.len > max_session_id_length) return error.MalformedClientHello;

    const cipher_suites_bytes = r.readVecU16() orelse return error.MalformedClientHello;
    if (cipher_suites_bytes.len == 0 or cipher_suites_bytes.len % 2 != 0) return error.MalformedClientHello;

    const compression_methods = r.readVecU8() orelse return error.MalformedClientHello;
    // TLS 1.3 requires a single "null" (0) compression method.
    if (compression_methods.len == 0) return error.MalformedClientHello;

    const extensions_bytes = r.readVecU16() orelse return error.MalformedClientHello;
    if (r.remaining() != 0) return error.MalformedClientHello;

    var ext_reader: Reader = .init(extensions_bytes);
    var server_name: ?[]const u8 = null;
    var supports_tls_13 = false;
    var x25519_key_share: ?X25519KeyShare = null;
    var signature_algorithms: []const u8 = &.{};
    var alpn_protocols: [][]const u8 = &.{};
    var alpn_count: usize = 0;

    while (ext_reader.remaining() > 0) {
        const ext_type_raw = ext_reader.readU16() orelse return error.MalformedClientHello;
        const ext_data = ext_reader.readVecU16() orelse return error.MalformedClientHello;
        const ext_type: tls.ExtensionType = @enumFromInt(ext_type_raw);
        switch (ext_type) {
            .server_name => {
                server_name = parseServerName(ext_data) catch return error.MalformedClientHello;
            },
            .supported_versions => {
                supports_tls_13 = parseSupportedVersionsClient(ext_data) catch return error.MalformedClientHello;
            },
            .key_share => {
                x25519_key_share = parseKeyShareClient(ext_data) catch return error.MalformedClientHello;
            },
            .signature_algorithms => {
                signature_algorithms = parseSignatureAlgorithms(ext_data) catch return error.MalformedClientHello;
            },
            .application_layer_protocol_negotiation => {
                alpn_count = parseAlpnInto(ext_data, scratch_alpn) catch return error.MalformedClientHello;
                // Convert parallel []?[]const u8 into a dense [][]const u8
                // slice. Callers pass scratch_alpn sized to maximum
                // expected ALPN count.
                const non_opt: [][]const u8 = @as([*][]const u8, @ptrCast(scratch_alpn.ptr))[0..alpn_count];
                alpn_protocols = non_opt;
            },
            else => {}, // Ignored for REALITY.
        }
    }

    if (!supports_tls_13) return error.UnsupportedTlsVersion;

    return .{
        .raw = body,
        .random = random_copy,
        .session_id = session_id,
        .cipher_suites_raw = cipher_suites_bytes,
        .server_name = server_name,
        .supports_tls_13 = supports_tls_13,
        .x25519_key_share = x25519_key_share,
        .signature_algorithms_raw = signature_algorithms,
        .alpn_protocols = alpn_protocols,
    };
}

// -------------------- Extension parsers --------------------

fn parseServerName(data: []const u8) !?[]const u8 {
    // server_name_list<1..2^16-1>:
    //   NameType name_type = host_name (0)  -- 1 byte
    //   opaque HostName<1..2^16-1>           -- 2-byte length + bytes
    var r: Reader = .init(data);
    const list = r.readVecU16() orelse return error.MalformedClientHello;
    if (r.remaining() != 0) return error.MalformedClientHello;

    var inner: Reader = .init(list);
    while (inner.remaining() > 0) {
        const name_type = inner.readU8() orelse return error.MalformedClientHello;
        const name_bytes = inner.readVecU16() orelse return error.MalformedClientHello;
        if (name_type == 0) return name_bytes; // first host_name wins
    }
    return null;
}

fn parseSupportedVersionsClient(data: []const u8) !bool {
    // Client form: opaque versions<2..254>  -- 1 byte length + N*2 bytes
    var r: Reader = .init(data);
    const versions_bytes = r.readVecU8() orelse return error.MalformedClientHello;
    if (r.remaining() != 0) return error.MalformedClientHello;
    if (versions_bytes.len == 0 or versions_bytes.len % 2 != 0) return error.MalformedClientHello;

    var i: usize = 0;
    while (i + 1 < versions_bytes.len) : (i += 2) {
        const v = std.mem.readInt(u16, versions_bytes[i..][0..2], .big);
        if (v == 0x0304) return true; // TLS 1.3
    }
    return false;
}

fn parseKeyShareClient(data: []const u8) !?X25519KeyShare {
    // client form: KeyShareEntry client_shares<0..2^16-1>
    //   each: NamedGroup (2) + opaque key_exchange<1..2^16-1>
    var r: Reader = .init(data);
    const list = r.readVecU16() orelse return error.MalformedClientHello;
    if (r.remaining() != 0) return error.MalformedClientHello;

    var inner: Reader = .init(list);
    while (inner.remaining() > 0) {
        const group = inner.readU16() orelse return error.MalformedClientHello;
        const kx = inner.readVecU16() orelse return error.MalformedClientHello;
        if (group == @intFromEnum(tls.NamedGroup.x25519)) {
            if (kx.len != 32) return error.MalformedClientHello;
            var pub_key: [32]u8 = undefined;
            @memcpy(&pub_key, kx);
            return .{ .public_key = pub_key };
        }
    }
    return null;
}

fn parseSignatureAlgorithms(data: []const u8) ![]const u8 {
    var r: Reader = .init(data);
    const list = r.readVecU16() orelse return error.MalformedClientHello;
    if (r.remaining() != 0) return error.MalformedClientHello;
    if (list.len == 0 or list.len % 2 != 0) return error.MalformedClientHello;
    return list;
}

fn parseAlpnInto(data: []const u8, out: []?[]const u8) !usize {
    var r: Reader = .init(data);
    const list = r.readVecU16() orelse return error.MalformedClientHello;
    if (r.remaining() != 0) return error.MalformedClientHello;

    var inner: Reader = .init(list);
    var count: usize = 0;
    while (inner.remaining() > 0) {
        const name = inner.readVecU8() orelse return error.MalformedClientHello;
        if (count >= out.len) return count; // overflow silently — REALITY only cares about presence
        out[count] = name;
        count += 1;
    }
    return count;
}

// -------------------- Cursor --------------------

const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn init(bytes: []const u8) Reader {
        return .{ .bytes = bytes };
    }

    pub fn remaining(self: Reader) usize {
        return self.bytes.len - self.pos;
    }

    pub fn readU8(self: *Reader) ?u8 {
        if (self.remaining() < 1) return null;
        const v = self.bytes[self.pos];
        self.pos += 1;
        return v;
    }

    pub fn readU16(self: *Reader) ?u16 {
        if (self.remaining() < 2) return null;
        const v = std.mem.readInt(u16, self.bytes[self.pos..][0..2], .big);
        self.pos += 2;
        return v;
    }

    pub fn readFixed(self: *Reader, n: usize) ?[]const u8 {
        if (self.remaining() < n) return null;
        const slice = self.bytes[self.pos .. self.pos + n];
        self.pos += n;
        return slice;
    }

    pub fn readVecU8(self: *Reader) ?[]const u8 {
        const len = self.readU8() orelse return null;
        return self.readFixed(len);
    }

    pub fn readVecU16(self: *Reader) ?[]const u8 {
        const len = self.readU16() orelse return null;
        return self.readFixed(len);
    }
};

// -------------------- Tests --------------------

const testing = std.testing;

/// Helper: build a minimal valid ClientHello body with the given
/// extensions. Cipher suites = just AES_128_GCM_SHA256.
fn buildMinimalClientHello(buf: []u8, session_id: []const u8, extensions: []const u8) []const u8 {
    var w = ChWriter{ .buf = buf };
    w.writeU16(legacy_version);
    w.writeFixed(&[_]u8{0x42} ** random_length);
    w.writeVecU8(session_id);
    // cipher_suites
    w.writeU16(2); // length
    w.writeU16(0x1301); // AES_128_GCM_SHA256
    w.writeVecU8(&[_]u8{0}); // null compression
    w.writeVecU16(extensions);
    return buf[0..w.pos];
}

const ChWriter = struct {
    buf: []u8,
    pos: usize = 0,

    fn writeU8(self: *ChWriter, v: u8) void {
        self.buf[self.pos] = v;
        self.pos += 1;
    }
    fn writeU16(self: *ChWriter, v: u16) void {
        std.mem.writeInt(u16, self.buf[self.pos..][0..2], v, .big);
        self.pos += 2;
    }
    fn writeFixed(self: *ChWriter, bytes: []const u8) void {
        @memcpy(self.buf[self.pos .. self.pos + bytes.len], bytes);
        self.pos += bytes.len;
    }
    fn writeVecU8(self: *ChWriter, bytes: []const u8) void {
        self.writeU8(@intCast(bytes.len));
        self.writeFixed(bytes);
    }
    fn writeVecU16(self: *ChWriter, bytes: []const u8) void {
        self.writeU16(@intCast(bytes.len));
        self.writeFixed(bytes);
    }
};

/// Helper: build a single extension body wrapped in the u16-length
/// framing the outer loop expects. Emits `ext_type(2) || len(2) || data`.
fn wrapExt(buf: []u8, pos: *usize, ext_type: tls.ExtensionType, data: []const u8) void {
    std.mem.writeInt(u16, buf[pos.*..][0..2], @intFromEnum(ext_type), .big);
    std.mem.writeInt(u16, buf[pos.* + 2 ..][0..2], @intCast(data.len), .big);
    @memcpy(buf[pos.* + 4 .. pos.* + 4 + data.len], data);
    pos.* += 4 + data.len;
}

test "ClientHello parse: rejects wrong legacy_version" {
    var buf: [256]u8 = undefined;
    buf[0] = 0x03;
    buf[1] = 0x02; // wrong
    var scratch: [4]?[]const u8 = .{ null, null, null, null };
    try testing.expectError(error.UnsupportedTlsVersion, parse(buf[0..2], &scratch));
}

test "ClientHello parse: rejects truncated body" {
    var scratch: [4]?[]const u8 = .{ null, null, null, null };
    try testing.expectError(error.MalformedClientHello, parse(&[_]u8{ 0x03, 0x03, 0x00 }, &scratch));
}

test "ClientHello parse: happy path with SNI + supported_versions + X25519 key_share" {
    var buf: [512]u8 = undefined;
    var ext_buf: [256]u8 = undefined;
    var ep: usize = 0;

    // SNI: server_name = "example.com"
    const sni = "example.com";
    var sni_data: [64]u8 = undefined;
    var sp: usize = 0;
    // list_length (u16) wraps { name_type(1) + host_name_len(2) + host_name }
    std.mem.writeInt(u16, sni_data[sp..][0..2], @intCast(1 + 2 + sni.len), .big);
    sp += 2;
    sni_data[sp] = 0; // host_name
    sp += 1;
    std.mem.writeInt(u16, sni_data[sp..][0..2], @intCast(sni.len), .big);
    sp += 2;
    @memcpy(sni_data[sp .. sp + sni.len], sni);
    sp += sni.len;
    wrapExt(&ext_buf, &ep, .server_name, sni_data[0..sp]);

    // supported_versions: [0x0304]
    var sv_data: [8]u8 = undefined;
    sv_data[0] = 2; // u8 length
    std.mem.writeInt(u16, sv_data[1..3], 0x0304, .big);
    wrapExt(&ext_buf, &ep, .supported_versions, sv_data[0..3]);

    // key_share: [(x25519, 32 bytes)]
    var ks_data: [64]u8 = undefined;
    std.mem.writeInt(u16, ks_data[0..2], 2 + 2 + 32, .big); // client_shares list length
    std.mem.writeInt(u16, ks_data[2..4], @intFromEnum(tls.NamedGroup.x25519), .big);
    std.mem.writeInt(u16, ks_data[4..6], 32, .big);
    @memset(ks_data[6..38], 0xAB);
    wrapExt(&ext_buf, &ep, .key_share, ks_data[0..38]);

    const body = buildMinimalClientHello(&buf, "", ext_buf[0..ep]);

    var scratch: [4]?[]const u8 = .{ null, null, null, null };
    const ch = try parse(body, &scratch);
    try testing.expectEqualStrings(sni, ch.server_name orelse return error.TestUnexpectedResult);
    try testing.expect(ch.supports_tls_13);
    try testing.expect(ch.x25519_key_share != null);
    try testing.expectEqual(@as(u8, 0xAB), ch.x25519_key_share.?.public_key[0]);
    try testing.expectEqual(@as(u8, 0xAB), ch.x25519_key_share.?.public_key[31]);
    try testing.expectEqual(@as(usize, 1), ch.cipherCount());
    try testing.expect(ch.offersCipher(0x1301));
    try testing.expectEqual(@as(usize, 32), ch.random.len);
    try testing.expectEqual(@as(u8, 0x42), ch.random[0]);
}

test "ClientHello parse: session_id up to 32 bytes is preserved verbatim" {
    var buf: [256]u8 = undefined;
    // Minimum valid extensions: just supported_versions + key_share.
    var ext_buf: [64]u8 = undefined;
    var ep: usize = 0;
    var sv_data: [8]u8 = undefined;
    sv_data[0] = 2;
    std.mem.writeInt(u16, sv_data[1..3], 0x0304, .big);
    wrapExt(&ext_buf, &ep, .supported_versions, sv_data[0..3]);
    var ks_data: [64]u8 = undefined;
    std.mem.writeInt(u16, ks_data[0..2], 2 + 2 + 32, .big);
    std.mem.writeInt(u16, ks_data[2..4], @intFromEnum(tls.NamedGroup.x25519), .big);
    std.mem.writeInt(u16, ks_data[4..6], 32, .big);
    @memset(ks_data[6..38], 0xFE);
    wrapExt(&ext_buf, &ep, .key_share, ks_data[0..38]);

    const sid = [_]u8{0xEE} ** 32;
    const body = buildMinimalClientHello(&buf, &sid, ext_buf[0..ep]);
    var scratch: [4]?[]const u8 = .{ null, null, null, null };
    const ch = try parse(body, &scratch);
    try testing.expectEqualSlices(u8, &sid, ch.session_id);
}

test "ClientHello parse: absence of supported_versions => UnsupportedTlsVersion" {
    var buf: [256]u8 = undefined;
    var ext_buf: [64]u8 = undefined;
    var ep: usize = 0;
    // Only key_share, no supported_versions.
    var ks_data: [64]u8 = undefined;
    std.mem.writeInt(u16, ks_data[0..2], 2 + 2 + 32, .big);
    std.mem.writeInt(u16, ks_data[2..4], @intFromEnum(tls.NamedGroup.x25519), .big);
    std.mem.writeInt(u16, ks_data[4..6], 32, .big);
    @memset(ks_data[6..38], 0x00);
    wrapExt(&ext_buf, &ep, .key_share, ks_data[0..38]);
    const body = buildMinimalClientHello(&buf, "", ext_buf[0..ep]);
    var scratch: [4]?[]const u8 = .{ null, null, null, null };
    try testing.expectError(error.UnsupportedTlsVersion, parse(body, &scratch));
}

test "ClientHello parse: supported_versions present but no TLS 1.3 => UnsupportedTlsVersion" {
    var buf: [256]u8 = undefined;
    var ext_buf: [64]u8 = undefined;
    var ep: usize = 0;
    var sv_data: [8]u8 = undefined;
    sv_data[0] = 2;
    std.mem.writeInt(u16, sv_data[1..3], 0x0303, .big); // only TLS 1.2
    wrapExt(&ext_buf, &ep, .supported_versions, sv_data[0..3]);
    const body = buildMinimalClientHello(&buf, "", ext_buf[0..ep]);
    var scratch: [4]?[]const u8 = .{ null, null, null, null };
    try testing.expectError(error.UnsupportedTlsVersion, parse(body, &scratch));
}

test "ClientHello parse: key_share without X25519 leaves x25519_key_share null" {
    var buf: [256]u8 = undefined;
    var ext_buf: [128]u8 = undefined;
    var ep: usize = 0;
    var sv_data: [8]u8 = undefined;
    sv_data[0] = 2;
    std.mem.writeInt(u16, sv_data[1..3], 0x0304, .big);
    wrapExt(&ext_buf, &ep, .supported_versions, sv_data[0..3]);

    // key_share with only secp256r1 (0x0017, 65-byte uncompressed point).
    var ks_data: [128]u8 = undefined;
    std.mem.writeInt(u16, ks_data[0..2], 2 + 2 + 65, .big);
    std.mem.writeInt(u16, ks_data[2..4], @intFromEnum(tls.NamedGroup.secp256r1), .big);
    std.mem.writeInt(u16, ks_data[4..6], 65, .big);
    @memset(ks_data[6..71], 0x04);
    wrapExt(&ext_buf, &ep, .key_share, ks_data[0..71]);

    const body = buildMinimalClientHello(&buf, "", ext_buf[0..ep]);
    var scratch: [4]?[]const u8 = .{ null, null, null, null };
    const ch = try parse(body, &scratch);
    try testing.expect(ch.x25519_key_share == null);
}

test "ClientHello parse: ALPN extension is captured into scratch" {
    var buf: [512]u8 = undefined;
    var ext_buf: [256]u8 = undefined;
    var ep: usize = 0;
    var sv_data: [8]u8 = undefined;
    sv_data[0] = 2;
    std.mem.writeInt(u16, sv_data[1..3], 0x0304, .big);
    wrapExt(&ext_buf, &ep, .supported_versions, sv_data[0..3]);
    var ks_data: [64]u8 = undefined;
    std.mem.writeInt(u16, ks_data[0..2], 2 + 2 + 32, .big);
    std.mem.writeInt(u16, ks_data[2..4], @intFromEnum(tls.NamedGroup.x25519), .big);
    std.mem.writeInt(u16, ks_data[4..6], 32, .big);
    @memset(ks_data[6..38], 0);
    wrapExt(&ext_buf, &ep, .key_share, ks_data[0..38]);

    // ALPN: ["h2", "http/1.1"]
    var alpn_data: [32]u8 = undefined;
    var ap: usize = 0;
    // outer u16 list length: 1 + 2 + 1 + 8 = 12
    std.mem.writeInt(u16, alpn_data[ap..][0..2], 12, .big);
    ap += 2;
    alpn_data[ap] = 2;
    ap += 1;
    @memcpy(alpn_data[ap .. ap + 2], "h2");
    ap += 2;
    alpn_data[ap] = 8;
    ap += 1;
    @memcpy(alpn_data[ap .. ap + 8], "http/1.1");
    ap += 8;
    wrapExt(&ext_buf, &ep, .application_layer_protocol_negotiation, alpn_data[0..ap]);

    const body = buildMinimalClientHello(&buf, "", ext_buf[0..ep]);
    var scratch: [4]?[]const u8 = .{ null, null, null, null };
    const ch = try parse(body, &scratch);
    try testing.expectEqual(@as(usize, 2), ch.alpn_protocols.len);
    try testing.expectEqualStrings("h2", ch.alpn_protocols[0]);
    try testing.expectEqualStrings("http/1.1", ch.alpn_protocols[1]);
    try testing.expect(ch.offersAlpn("h2"));
    try testing.expect(!ch.offersAlpn("quic"));
}

test "ClientHello parse: signature_algorithms list captured as big-endian u16 view" {
    var buf: [512]u8 = undefined;
    var ext_buf: [128]u8 = undefined;
    var ep: usize = 0;
    var sv_data: [8]u8 = undefined;
    sv_data[0] = 2;
    std.mem.writeInt(u16, sv_data[1..3], 0x0304, .big);
    wrapExt(&ext_buf, &ep, .supported_versions, sv_data[0..3]);
    var ks_data: [64]u8 = undefined;
    std.mem.writeInt(u16, ks_data[0..2], 2 + 2 + 32, .big);
    std.mem.writeInt(u16, ks_data[2..4], @intFromEnum(tls.NamedGroup.x25519), .big);
    std.mem.writeInt(u16, ks_data[4..6], 32, .big);
    @memset(ks_data[6..38], 0);
    wrapExt(&ext_buf, &ep, .key_share, ks_data[0..38]);

    // signature_algorithms: [ed25519 (0x0807), rsa_pss_rsae_sha256 (0x0804)]
    var sig_data: [16]u8 = undefined;
    std.mem.writeInt(u16, sig_data[0..2], 4, .big); // list length
    std.mem.writeInt(u16, sig_data[2..4], 0x0807, .big);
    std.mem.writeInt(u16, sig_data[4..6], 0x0804, .big);
    wrapExt(&ext_buf, &ep, .signature_algorithms, sig_data[0..6]);

    const body = buildMinimalClientHello(&buf, "", ext_buf[0..ep]);
    var scratch: [4]?[]const u8 = .{ null, null, null, null };
    const ch = try parse(body, &scratch);
    try testing.expectEqual(@as(usize, 2), ch.sigAlgCount());
    try testing.expectEqual(@as(u16, 0x0807), ch.sigAlgAt(0));
    try testing.expectEqual(@as(u16, 0x0804), ch.sigAlgAt(1));
}

test "ClientHello parse: trailing garbage after extensions is rejected" {
    var buf: [256]u8 = undefined;
    var ext_buf: [128]u8 = undefined;
    var ep: usize = 0;
    var sv_data: [8]u8 = undefined;
    sv_data[0] = 2;
    std.mem.writeInt(u16, sv_data[1..3], 0x0304, .big);
    wrapExt(&ext_buf, &ep, .supported_versions, sv_data[0..3]);
    var ks_data: [64]u8 = undefined;
    std.mem.writeInt(u16, ks_data[0..2], 2 + 2 + 32, .big);
    std.mem.writeInt(u16, ks_data[2..4], @intFromEnum(tls.NamedGroup.x25519), .big);
    std.mem.writeInt(u16, ks_data[4..6], 32, .big);
    @memset(ks_data[6..38], 0);
    wrapExt(&ext_buf, &ep, .key_share, ks_data[0..38]);

    const body = buildMinimalClientHello(&buf, "", ext_buf[0..ep]);
    // Tack on a byte of garbage at the end.
    var padded: [512]u8 = undefined;
    @memcpy(padded[0..body.len], body);
    padded[body.len] = 0xFF;
    var scratch: [4]?[]const u8 = .{ null, null, null, null };
    try testing.expectError(error.MalformedClientHello, parse(padded[0 .. body.len + 1], &scratch));
}

test "ClientHello parse: oversized session_id (>32 bytes) is rejected" {
    // Build by hand because buildMinimalClientHello asserts session_id <= max.
    var buf: [128]u8 = undefined;
    var w = ChWriter{ .buf = &buf };
    w.writeU16(legacy_version);
    w.writeFixed(&[_]u8{0} ** random_length);
    // session_id with length 33 (invalid).
    w.writeU8(33);
    w.writeFixed(&[_]u8{0} ** 33);
    w.writeU16(2);
    w.writeU16(0x1301);
    w.writeVecU8(&[_]u8{0});
    w.writeVecU16(&.{});

    var scratch: [4]?[]const u8 = .{ null, null, null, null };
    try testing.expectError(error.MalformedClientHello, parse(buf[0..w.pos], &scratch));
}

test "ClientHello parse: empty cipher_suites list rejected" {
    var buf: [128]u8 = undefined;
    var w = ChWriter{ .buf = &buf };
    w.writeU16(legacy_version);
    w.writeFixed(&[_]u8{0} ** random_length);
    w.writeVecU8(""); // empty session_id
    w.writeU16(0); // empty cipher_suites (invalid per spec: 2..2^16-2)
    w.writeVecU8(&[_]u8{0});
    w.writeVecU16(&.{});

    var scratch: [4]?[]const u8 = .{ null, null, null, null };
    try testing.expectError(error.MalformedClientHello, parse(buf[0..w.pos], &scratch));
}

test "ClientHello parse: SNI with unknown name_type skipped, server_name stays null" {
    var buf: [256]u8 = undefined;
    var ext_buf: [128]u8 = undefined;
    var ep: usize = 0;

    // SNI with a non-host_name entry only.
    var sni_data: [32]u8 = undefined;
    var sp: usize = 0;
    std.mem.writeInt(u16, sni_data[sp..][0..2], 1 + 2 + 4, .big);
    sp += 2;
    sni_data[sp] = 99; // unknown name_type
    sp += 1;
    std.mem.writeInt(u16, sni_data[sp..][0..2], 4, .big);
    sp += 2;
    @memcpy(sni_data[sp .. sp + 4], "blob");
    sp += 4;
    wrapExt(&ext_buf, &ep, .server_name, sni_data[0..sp]);

    var sv_data: [8]u8 = undefined;
    sv_data[0] = 2;
    std.mem.writeInt(u16, sv_data[1..3], 0x0304, .big);
    wrapExt(&ext_buf, &ep, .supported_versions, sv_data[0..3]);
    var ks_data: [64]u8 = undefined;
    std.mem.writeInt(u16, ks_data[0..2], 2 + 2 + 32, .big);
    std.mem.writeInt(u16, ks_data[2..4], @intFromEnum(tls.NamedGroup.x25519), .big);
    std.mem.writeInt(u16, ks_data[4..6], 32, .big);
    @memset(ks_data[6..38], 0);
    wrapExt(&ext_buf, &ep, .key_share, ks_data[0..38]);

    const body = buildMinimalClientHello(&buf, "", ext_buf[0..ep]);
    var scratch: [4]?[]const u8 = .{ null, null, null, null };
    const ch = try parse(body, &scratch);
    try testing.expect(ch.server_name == null);
}

test "ClientHello: raw captures the full body for transcript hashing" {
    var buf: [256]u8 = undefined;
    var ext_buf: [64]u8 = undefined;
    var ep: usize = 0;
    var sv_data: [8]u8 = undefined;
    sv_data[0] = 2;
    std.mem.writeInt(u16, sv_data[1..3], 0x0304, .big);
    wrapExt(&ext_buf, &ep, .supported_versions, sv_data[0..3]);
    var ks_data: [64]u8 = undefined;
    std.mem.writeInt(u16, ks_data[0..2], 2 + 2 + 32, .big);
    std.mem.writeInt(u16, ks_data[2..4], @intFromEnum(tls.NamedGroup.x25519), .big);
    std.mem.writeInt(u16, ks_data[4..6], 32, .big);
    @memset(ks_data[6..38], 0x77);
    wrapExt(&ext_buf, &ep, .key_share, ks_data[0..38]);

    const body = buildMinimalClientHello(&buf, "abcd", ext_buf[0..ep]);
    var scratch: [4]?[]const u8 = .{ null, null, null, null };
    const ch = try parse(body, &scratch);
    // `raw` should be identical (same pointer into caller's buffer).
    try testing.expectEqual(body.ptr, ch.raw.ptr);
    try testing.expectEqual(body.len, ch.raw.len);
}
