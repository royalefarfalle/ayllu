//! Xray v25.x REALITY AuthKey binding, carried inside the TLS 1.3
//! `legacy_session_id` field of the ClientHello.
//!
//! Session-ID layout (exactly 32 bytes):
//!
//!     offset | len | field
//!     -------+-----+------------------------------------------------
//!        0   |  8  | short_id        (picks one of the configured IDs)
//!        8   |  8  | auth_mac        (HMAC-SHA256(auth_key, CH-with-mac-zeroed)[0..8])
//!       16   |  8  | nonce_time      (big-endian i64 unix milliseconds)
//!       24   |  8  | nonce_random    (8 bytes of client-chosen freshness)
//!
//! Why the slot and not an extension?  TLS 1.3 deprecates
//! legacy_session_id in favour of `pre_shared_key` but middleboxes
//! still echo it verbatim — Xray exploits that to avoid advertising
//! any REALITY-specific TLS extension which DPI could match on.
//!
//! Verification pipeline:
//!
//!   1. Require `ClientHello.session_id.len == 32` and an X25519 key_share.
//!   2. Parse the four fields from session_id.
//!   3. Build a `reality.Hello { server_name, short_id(8), client_public, unix_ms }`.
//!   4. Call `reality.authorize` — this runs the server_name / short_id /
//!      time-skew gates and returns the per-session `auth_key`.
//!   5. Compute `expected_mac = HMAC-SHA256(auth_key, CH-raw-with-mac-zeroed)[0..8]`.
//!   6. Constant-time compare. Any mismatch → `error.AuthMacMismatch`.
//!
//! KAT vectors from an actual Xray v25.x handshake are pending a
//! live-server capture — see [docs/test-vectors.md]. The wire format
//! and MAC recipe above match the public spec; subtle differences
//! (e.g. v25's covertext-length exemption on the ChangeCipherSpec
//! record) come in later slices that touch real record emission.

const std = @import("std");
const tls = std.crypto.tls;
const reality = @import("../reality.zig");
const client_hello_mod = @import("client_hello.zig");

pub const session_id_length: usize = 32;
pub const short_id_length: usize = 8;
pub const auth_mac_length: usize = 8;
pub const nonce_time_length: usize = 8;
pub const nonce_random_length: usize = 8;

pub const short_id_offset: usize = 0;
pub const auth_mac_offset: usize = short_id_offset + short_id_length;
pub const nonce_time_offset: usize = auth_mac_offset + auth_mac_length;
pub const nonce_random_offset: usize = nonce_time_offset + nonce_time_length;

/// Offset of the auth_mac slot within the ClientHello *body* (raw):
///   legacy_version (2) + random (32) + session_id length prefix (1)
///   + short_id (8) = 43.
pub const raw_auth_mac_offset: usize = 2 + 32 + 1 + auth_mac_offset;

const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;

pub const SessionId = struct {
    short_id: [short_id_length]u8,
    auth_mac: [auth_mac_length]u8,
    nonce_time: [nonce_time_length]u8,
    nonce_random: [nonce_random_length]u8,

    pub fn unixMs(self: SessionId) i64 {
        return std.mem.readInt(i64, &self.nonce_time, .big);
    }

    pub fn pack(self: SessionId) [session_id_length]u8 {
        var out: [session_id_length]u8 = undefined;
        @memcpy(out[short_id_offset..][0..short_id_length], &self.short_id);
        @memcpy(out[auth_mac_offset..][0..auth_mac_length], &self.auth_mac);
        @memcpy(out[nonce_time_offset..][0..nonce_time_length], &self.nonce_time);
        @memcpy(out[nonce_random_offset..][0..nonce_random_length], &self.nonce_random);
        return out;
    }
};

pub const ParseSessionIdError = error{InvalidSessionIdLength};

pub fn parseSessionId(bytes: []const u8) ParseSessionIdError!SessionId {
    if (bytes.len != session_id_length) return error.InvalidSessionIdLength;
    var s: SessionId = undefined;
    @memcpy(&s.short_id, bytes[short_id_offset..][0..short_id_length]);
    @memcpy(&s.auth_mac, bytes[auth_mac_offset..][0..auth_mac_length]);
    @memcpy(&s.nonce_time, bytes[nonce_time_offset..][0..nonce_time_length]);
    @memcpy(&s.nonce_random, bytes[nonce_random_offset..][0..nonce_random_length]);
    return s;
}

/// Pack 8 random tail bytes and a big-endian `unix_ms` into a 16-byte
/// nonce. Helper for constructing a synthetic ClientHello.
pub fn packNonce(
    unix_ms: i64,
    random_tail: [nonce_random_length]u8,
) [nonce_time_length + nonce_random_length]u8 {
    var out: [nonce_time_length + nonce_random_length]u8 = undefined;
    std.mem.writeInt(i64, out[0..nonce_time_length], unix_ms, .big);
    @memcpy(out[nonce_time_length..], &random_tail);
    return out;
}

/// Pack a full Xray v25 session_id from its four components.
pub fn packSessionId(
    short_id: [short_id_length]u8,
    auth_mac: [auth_mac_length]u8,
    unix_ms: i64,
    nonce_random: [nonce_random_length]u8,
) [session_id_length]u8 {
    var out: [session_id_length]u8 = undefined;
    @memcpy(out[short_id_offset..][0..short_id_length], &short_id);
    @memcpy(out[auth_mac_offset..][0..auth_mac_length], &auth_mac);
    std.mem.writeInt(i64, out[nonce_time_offset..][0..nonce_time_length], unix_ms, .big);
    @memcpy(out[nonce_random_offset..][0..nonce_random_length], &nonce_random);
    return out;
}

/// Compute `HMAC-SHA256(auth_key, CH_raw_with_auth_mac_zeroed)[0..8]`.
/// Same function is used by the client (to fill the slot before
/// sending) and the server (to verify after receipt).
pub fn computeAuthMac(
    auth_key: [32]u8,
    client_hello_raw: []const u8,
) error{ClientHelloTooShort}![auth_mac_length]u8 {
    const slot_end = raw_auth_mac_offset + auth_mac_length;
    if (client_hello_raw.len < slot_end) return error.ClientHelloTooShort;

    var hmac = Hmac.init(&auth_key);
    hmac.update(client_hello_raw[0..raw_auth_mac_offset]);
    const zeros: [auth_mac_length]u8 = @splat(0);
    hmac.update(&zeros);
    hmac.update(client_hello_raw[slot_end..]);

    var full: [Hmac.mac_length]u8 = undefined;
    hmac.final(&full);
    var out: [auth_mac_length]u8 = undefined;
    @memcpy(&out, full[0..auth_mac_length]);
    return out;
}

pub const VerifyError = error{
    InvalidSessionIdLength,
    MissingServerName,
    MissingX25519KeyShare,
    ClientHelloTooShort,
    AuthMacMismatch,
} || reality.AuthorizeError;

pub const VerifiedSession = struct {
    session_id: SessionId,
    material: reality.SessionMaterial,
    unix_ms: i64,
};

/// Verify a parsed TLS 1.3 ClientHello against a REALITY config. On
/// success returns the derived `SessionMaterial`; on any structural
/// or cryptographic failure returns a `VerifyError` so callers can
/// route to `.fallback`.
pub fn verifyClientHello(
    config: reality.Config,
    hello: client_hello_mod.ClientHello,
    now_ms: i64,
) VerifyError!VerifiedSession {
    if (hello.session_id.len != session_id_length) return error.InvalidSessionIdLength;
    const sni = hello.server_name orelse return error.MissingServerName;
    const key_share = hello.x25519_key_share orelse return error.MissingX25519KeyShare;

    const session = try parseSessionId(hello.session_id);

    var short_id: reality.ShortId = .{ .len = short_id_length };
    @memcpy(&short_id.bytes, &session.short_id);

    const reality_hello: reality.Hello = .{
        .server_name = sni,
        .short_id = short_id,
        .client_public_key = key_share.public_key,
        .client_version = null,
        .unix_ms = session.unixMs(),
    };

    const material = try reality.authorize(config, reality_hello, now_ms);
    const expected = try computeAuthMac(material.auth_key, hello.raw);
    if (!std.crypto.timing_safe.eql([auth_mac_length]u8, expected, session.auth_mac)) {
        return error.AuthMacMismatch;
    }

    return .{
        .session_id = session,
        .material = material,
        .unix_ms = session.unixMs(),
    };
}

// -------------------- Tests --------------------

const testing = std.testing;
const ayllu = @import("ayllu");

fn hex32(comptime s: *const [64]u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "SessionId: pack + parse round-trip" {
    const s: SessionId = .{
        .short_id = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
        .auth_mac = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 },
        .nonce_time = [_]u8{ 0, 0, 0, 0, 0, 0, 0x04, 0xD2 }, // 1234
        .nonce_random = [_]u8{ 0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB },
    };
    const packed_bytes = s.pack();
    const parsed = try parseSessionId(&packed_bytes);
    try testing.expectEqualSlices(u8, &s.short_id, &parsed.short_id);
    try testing.expectEqualSlices(u8, &s.auth_mac, &parsed.auth_mac);
    try testing.expectEqualSlices(u8, &s.nonce_time, &parsed.nonce_time);
    try testing.expectEqualSlices(u8, &s.nonce_random, &parsed.nonce_random);
    try testing.expectEqual(@as(i64, 1234), parsed.unixMs());
}

test "parseSessionId: rejects any length other than 32" {
    var too_short: [31]u8 = undefined;
    try testing.expectError(error.InvalidSessionIdLength, parseSessionId(&too_short));
    var too_long: [33]u8 = undefined;
    try testing.expectError(error.InvalidSessionIdLength, parseSessionId(&too_long));
    try testing.expectError(error.InvalidSessionIdLength, parseSessionId(""));
}

test "SessionId.unixMs: big-endian i64 read" {
    const s: SessionId = .{
        .short_id = @splat(0),
        .auth_mac = @splat(0),
        .nonce_time = [_]u8{ 0x00, 0x00, 0x01, 0x8E, 0x23, 0xF1, 0x4C, 0x00 }, // 1_710_000_000_000
        .nonce_random = @splat(0),
    };
    try testing.expectEqual(@as(i64, 1_710_000_000_000), s.unixMs());
}

test "packNonce: writes big-endian i64 and tail" {
    const tail: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const n = packNonce(0x0123456789ABCDEF, tail);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF }, n[0..8]);
    try testing.expectEqualSlices(u8, &tail, n[8..16]);
}

test "packSessionId: composes short_id/auth_mac/unix_ms/nonce_random" {
    const sid = packSessionId(
        [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 },
        [_]u8{ 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x0, 0x1 },
        0x7FFF_FFFF_FFFF_FFFF,
        [_]u8{0x42} ** 8,
    );
    const s = try parseSessionId(&sid);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, &s.short_id);
    try testing.expectEqualSlices(u8, &.{ 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x0, 0x1 }, &s.auth_mac);
    try testing.expectEqual(@as(i64, 0x7FFF_FFFF_FFFF_FFFF), s.unixMs());
    try testing.expectEqualSlices(u8, &[_]u8{0x42} ** 8, &s.nonce_random);
}

test "computeAuthMac: deterministic and differs across keys" {
    var buf: [256]u8 = undefined;
    const n = try buildClientHello(&buf, "example.com", @splat(0), packSessionId(
        [_]u8{0xAA} ** 8,
        @splat(0),
        0,
        @splat(0),
    ));
    const raw = buf[0..n];
    const k1 = [_]u8{0xAA} ** 32;
    const k2 = [_]u8{0xBB} ** 32;
    const m1 = try computeAuthMac(k1, raw);
    const m2 = try computeAuthMac(k1, raw);
    try testing.expectEqualSlices(u8, &m1, &m2);
    const m3 = try computeAuthMac(k2, raw);
    try testing.expect(!std.mem.eql(u8, &m1, &m3));
}

test "computeAuthMac: rejects short ClientHello" {
    var tiny: [32]u8 = undefined;
    try testing.expectError(error.ClientHelloTooShort, computeAuthMac([_]u8{0} ** 32, &tiny));
}

test "computeAuthMac: byte before the slot affects the MAC" {
    var buf: [256]u8 = undefined;
    const n = try buildClientHello(&buf, "example.com", @splat(0), packSessionId(
        [_]u8{0xAA} ** 8,
        @splat(0),
        0,
        @splat(0),
    ));
    const k = [_]u8{0x77} ** 32;
    const base = try computeAuthMac(k, buf[0..n]);
    // Mutate a byte just before the auth_mac slot (index 42 = last byte of short_id).
    buf[raw_auth_mac_offset - 1] ^= 0xFF;
    const mutated = try computeAuthMac(k, buf[0..n]);
    try testing.expect(!std.mem.eql(u8, &base, &mutated));
}

test "verifyClientHello: happy path with a synthetic CH + matching AuthKey" {
    const server_seed = hex32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    const client_seed = hex32("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40");
    const client_public = try ayllu.crypto.X25519.recoverPublicKey(client_seed);
    const short_id = try reality.parseShortId("0ed36d458733a0bc");

    const cfg: reality.Config = .{
        .target = .{ .host = "example.com", .port = 443 },
        .server_names = &.{"example.com"},
        .private_key = server_seed,
        .max_time_diff_ms = 5_000,
        .short_ids = &.{short_id},
    };

    const unix_ms: i64 = 1_710_000_000_000;

    // Preview the auth_key the server will derive.
    const preview = try reality.authorize(cfg, .{
        .server_name = "example.com",
        .short_id = short_id,
        .client_public_key = client_public,
        .client_version = null,
        .unix_ms = unix_ms,
    }, unix_ms);

    // Build CH with zero auth_mac slot, MAC it, patch the slot in place.
    var buf: [256]u8 = undefined;
    const zero_mac_sid = packSessionId(short_id.bytes, @splat(0), unix_ms, [_]u8{0xEE} ** 8);
    const n = try buildClientHello(&buf, "example.com", client_public, zero_mac_sid);
    const mac = try computeAuthMac(preview.auth_key, buf[0..n]);
    @memcpy(buf[raw_auth_mac_offset..][0..auth_mac_length], &mac);

    var scratch: [4]?[]const u8 = @splat(null);
    const hello = try client_hello_mod.parse(buf[0..n], &scratch);

    const verified = try verifyClientHello(cfg, hello, unix_ms);
    try testing.expectEqualSlices(u8, &short_id.bytes, &verified.session_id.short_id);
    try testing.expectEqualSlices(u8, &preview.auth_key, &verified.material.auth_key);
    try testing.expectEqual(unix_ms, verified.unix_ms);
}

test "verifyClientHello: rejects session_id != 32 bytes" {
    var buf: [256]u8 = undefined;
    const n = try buildClientHelloShortSession(&buf, "example.com", @splat(0));
    var scratch: [4]?[]const u8 = @splat(null);
    const hello = try client_hello_mod.parse(buf[0..n], &scratch);
    const cfg = testMinimalConfig();
    try testing.expectError(error.InvalidSessionIdLength, verifyClientHello(cfg, hello, 0));
}

test "verifyClientHello: rejects CH without X25519 key_share" {
    var buf: [256]u8 = undefined;
    const n = try buildClientHelloNoX25519(&buf, "example.com");
    var scratch: [4]?[]const u8 = @splat(null);
    const hello = try client_hello_mod.parse(buf[0..n], &scratch);
    const cfg = testMinimalConfig();
    try testing.expectError(error.MissingX25519KeyShare, verifyClientHello(cfg, hello, 0));
}

test "verifyClientHello: flipped auth_mac byte => AuthMacMismatch" {
    const server_seed = hex32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    const client_seed = hex32("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40");
    const client_public = try ayllu.crypto.X25519.recoverPublicKey(client_seed);
    const short_id = try reality.parseShortId("0ed36d458733a0bc");

    const cfg: reality.Config = .{
        .target = .{ .host = "example.com", .port = 443 },
        .server_names = &.{"example.com"},
        .private_key = server_seed,
        .max_time_diff_ms = 5_000,
        .short_ids = &.{short_id},
    };
    const unix_ms: i64 = 1_710_000_000_000;

    const preview = try reality.authorize(cfg, .{
        .server_name = "example.com",
        .short_id = short_id,
        .client_public_key = client_public,
        .client_version = null,
        .unix_ms = unix_ms,
    }, unix_ms);

    var buf: [256]u8 = undefined;
    const sid = packSessionId(short_id.bytes, @splat(0), unix_ms, @splat(0));
    const n = try buildClientHello(&buf, "example.com", client_public, sid);
    const mac = try computeAuthMac(preview.auth_key, buf[0..n]);
    @memcpy(buf[raw_auth_mac_offset..][0..auth_mac_length], &mac);
    buf[raw_auth_mac_offset + 3] ^= 0x01;

    var scratch: [4]?[]const u8 = @splat(null);
    const hello = try client_hello_mod.parse(buf[0..n], &scratch);
    try testing.expectError(error.AuthMacMismatch, verifyClientHello(cfg, hello, unix_ms));
}

test "verifyClientHello: SNI not in config => UnknownServerName" {
    const server_seed = hex32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    const client_seed = hex32("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40");
    const client_public = try ayllu.crypto.X25519.recoverPublicKey(client_seed);
    const short_id = try reality.parseShortId("0ed36d458733a0bc");

    const cfg: reality.Config = .{
        .target = .{ .host = "example.com", .port = 443 },
        .server_names = &.{"example.com"},
        .private_key = server_seed,
        .max_time_diff_ms = 0,
        .short_ids = &.{short_id},
    };

    var buf: [256]u8 = undefined;
    const sid = packSessionId(short_id.bytes, @splat(0), 0, @splat(0));
    const n = try buildClientHello(&buf, "other.example.net", client_public, sid);
    var scratch: [4]?[]const u8 = @splat(null);
    const hello = try client_hello_mod.parse(buf[0..n], &scratch);
    try testing.expectError(error.UnknownServerName, verifyClientHello(cfg, hello, 0));
}

test "verifyClientHello: short_id not in config => UnknownShortId" {
    const server_seed = hex32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    const client_seed = hex32("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40");
    const client_public = try ayllu.crypto.X25519.recoverPublicKey(client_seed);
    const configured = try reality.parseShortId("0ed36d458733a0bc");

    const cfg: reality.Config = .{
        .target = .{ .host = "example.com", .port = 443 },
        .server_names = &.{"example.com"},
        .private_key = server_seed,
        .max_time_diff_ms = 0,
        .short_ids = &.{configured},
    };

    var buf: [256]u8 = undefined;
    const sid = packSessionId(
        [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11 },
        @splat(0),
        0,
        @splat(0),
    );
    const n = try buildClientHello(&buf, "example.com", client_public, sid);
    var scratch: [4]?[]const u8 = @splat(null);
    const hello = try client_hello_mod.parse(buf[0..n], &scratch);
    try testing.expectError(error.UnknownShortId, verifyClientHello(cfg, hello, 0));
}

test "verifyClientHello: stale timestamp => TimeSkewTooLarge" {
    const server_seed = hex32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    const client_seed = hex32("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40");
    const client_public = try ayllu.crypto.X25519.recoverPublicKey(client_seed);
    const short_id = try reality.parseShortId("0ed36d458733a0bc");

    const cfg: reality.Config = .{
        .target = .{ .host = "example.com", .port = 443 },
        .server_names = &.{"example.com"},
        .private_key = server_seed,
        .max_time_diff_ms = 1_000,
        .short_ids = &.{short_id},
    };

    var buf: [256]u8 = undefined;
    const sid = packSessionId(short_id.bytes, @splat(0), 0, @splat(0));
    const n = try buildClientHello(&buf, "example.com", client_public, sid);
    var scratch: [4]?[]const u8 = @splat(null);
    const hello = try client_hello_mod.parse(buf[0..n], &scratch);
    // now = 1e9 ms, hello unix_ms = 0 — outside max_time_diff_ms of 1000.
    try testing.expectError(error.TimeSkewTooLarge, verifyClientHello(cfg, hello, 1_000_000_000));
}

// -------------------- Test helpers --------------------

fn testMinimalConfig() reality.Config {
    const short_id: reality.ShortId = .{
        .len = 8,
        .bytes = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11 },
    };
    return .{
        .target = .{ .host = "example.com", .port = 443 },
        .server_names = &.{"example.com"},
        .private_key = hex32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
        .max_time_diff_ms = 0,
        .short_ids = &.{short_id},
    };
}

/// Build a ClientHello body with SNI + supported_versions + X25519 key_share
/// + a 32-byte session_id in the Xray v25 layout. Writes into `out`, returns
/// bytes written.
fn buildClientHello(
    out: []u8,
    sni: []const u8,
    client_public: [32]u8,
    session_id: [session_id_length]u8,
) !usize {
    var w = TestWriter{ .buf = out };
    w.writeU16(0x0303);
    w.writeFixed(&[_]u8{0x00} ** 32);
    w.writeVecU8(&session_id);
    w.writeU16(2);
    w.writeU16(0x1301);
    w.writeVecU8(&[_]u8{0});

    var ext_buf: [256]u8 = undefined;
    var ew = TestWriter{ .buf = &ext_buf };

    var sni_body: [128]u8 = undefined;
    var swr = TestWriter{ .buf = &sni_body };
    swr.writeU16(@intCast(1 + 2 + sni.len));
    swr.writeU8(0);
    swr.writeU16(@intCast(sni.len));
    swr.writeFixed(sni);
    writeExt(&ew, .server_name, sni_body[0..swr.pos]);

    var sv: [4]u8 = undefined;
    sv[0] = 2;
    std.mem.writeInt(u16, sv[1..3], 0x0304, .big);
    writeExt(&ew, .supported_versions, sv[0..3]);

    var ks_body: [64]u8 = undefined;
    std.mem.writeInt(u16, ks_body[0..2], 2 + 2 + 32, .big);
    std.mem.writeInt(u16, ks_body[2..4], @intFromEnum(tls.NamedGroup.x25519), .big);
    std.mem.writeInt(u16, ks_body[4..6], 32, .big);
    @memcpy(ks_body[6..38], &client_public);
    writeExt(&ew, .key_share, ks_body[0..38]);

    w.writeVecU16(ext_buf[0..ew.pos]);
    return w.pos;
}

/// Build a ClientHello with a 16-byte session_id (invalid for Xray v25).
fn buildClientHelloShortSession(out: []u8, sni: []const u8, client_public: [32]u8) !usize {
    var w = TestWriter{ .buf = out };
    w.writeU16(0x0303);
    w.writeFixed(&[_]u8{0x00} ** 32);
    w.writeVecU8(&[_]u8{0xAA} ** 16);
    w.writeU16(2);
    w.writeU16(0x1301);
    w.writeVecU8(&[_]u8{0});

    var ext_buf: [256]u8 = undefined;
    var ew = TestWriter{ .buf = &ext_buf };

    var sni_body: [128]u8 = undefined;
    var swr = TestWriter{ .buf = &sni_body };
    swr.writeU16(@intCast(1 + 2 + sni.len));
    swr.writeU8(0);
    swr.writeU16(@intCast(sni.len));
    swr.writeFixed(sni);
    writeExt(&ew, .server_name, sni_body[0..swr.pos]);

    var sv: [4]u8 = undefined;
    sv[0] = 2;
    std.mem.writeInt(u16, sv[1..3], 0x0304, .big);
    writeExt(&ew, .supported_versions, sv[0..3]);

    var ks_body: [64]u8 = undefined;
    std.mem.writeInt(u16, ks_body[0..2], 2 + 2 + 32, .big);
    std.mem.writeInt(u16, ks_body[2..4], @intFromEnum(tls.NamedGroup.x25519), .big);
    std.mem.writeInt(u16, ks_body[4..6], 32, .big);
    @memcpy(ks_body[6..38], &client_public);
    writeExt(&ew, .key_share, ks_body[0..38]);

    w.writeVecU16(ext_buf[0..ew.pos]);
    return w.pos;
}

/// Build a ClientHello offering only secp256r1 in key_share (no X25519).
/// Session_id is 32 bytes of 0xAA (parses fine; verify will reject on
/// MissingX25519KeyShare).
fn buildClientHelloNoX25519(out: []u8, sni: []const u8) !usize {
    var w = TestWriter{ .buf = out };
    w.writeU16(0x0303);
    w.writeFixed(&[_]u8{0x00} ** 32);
    w.writeVecU8(&[_]u8{0xAA} ** session_id_length);
    w.writeU16(2);
    w.writeU16(0x1301);
    w.writeVecU8(&[_]u8{0});

    var ext_buf: [256]u8 = undefined;
    var ew = TestWriter{ .buf = &ext_buf };

    var sni_body: [128]u8 = undefined;
    var swr = TestWriter{ .buf = &sni_body };
    swr.writeU16(@intCast(1 + 2 + sni.len));
    swr.writeU8(0);
    swr.writeU16(@intCast(sni.len));
    swr.writeFixed(sni);
    writeExt(&ew, .server_name, sni_body[0..swr.pos]);

    var sv: [4]u8 = undefined;
    sv[0] = 2;
    std.mem.writeInt(u16, sv[1..3], 0x0304, .big);
    writeExt(&ew, .supported_versions, sv[0..3]);

    var ks_body: [128]u8 = undefined;
    std.mem.writeInt(u16, ks_body[0..2], 2 + 2 + 65, .big);
    std.mem.writeInt(u16, ks_body[2..4], @intFromEnum(tls.NamedGroup.secp256r1), .big);
    std.mem.writeInt(u16, ks_body[4..6], 65, .big);
    @memset(ks_body[6..71], 0x04);
    writeExt(&ew, .key_share, ks_body[0..71]);

    w.writeVecU16(ext_buf[0..ew.pos]);
    return w.pos;
}

fn writeExt(ew: *TestWriter, ext_type: tls.ExtensionType, data: []const u8) void {
    ew.writeU16(@intFromEnum(ext_type));
    ew.writeU16(@intCast(data.len));
    ew.writeFixed(data);
}

const TestWriter = struct {
    buf: []u8,
    pos: usize = 0,

    fn writeU8(self: *TestWriter, v: u8) void {
        self.buf[self.pos] = v;
        self.pos += 1;
    }
    fn writeU16(self: *TestWriter, v: u16) void {
        std.mem.writeInt(u16, self.buf[self.pos..][0..2], v, .big);
        self.pos += 2;
    }
    fn writeFixed(self: *TestWriter, bytes: []const u8) void {
        @memcpy(self.buf[self.pos .. self.pos + bytes.len], bytes);
        self.pos += bytes.len;
    }
    fn writeVecU8(self: *TestWriter, bytes: []const u8) void {
        self.writeU8(@intCast(bytes.len));
        self.writeFixed(bytes);
    }
    fn writeVecU16(self: *TestWriter, bytes: []const u8) void {
        self.writeU16(@intCast(bytes.len));
        self.writeFixed(bytes);
    }
};
