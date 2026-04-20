//! Server-side REALITY admission core.
//!
//! This is not a full TLS fork. It implements the configuration rules and
//! cryptographic admission material that phase-4 needs before wiring the
//! outer transport.

const std = @import("std");
const ayllu = @import("ayllu");

pub const key_length = ayllu.crypto.X25519.secret_length;
pub const encoded_key_length = std.base64.url_safe_no_pad.Encoder.calcSize(key_length);
pub const max_short_id_length = 8;

pub const Target = struct {
    host: []const u8,
    port: u16,
};

pub const PublicConfig = struct {
    target: Target,
    server_public_key: [key_length]u8,
    min_client_version: ?std.SemanticVersion = null,
    max_client_version: ?std.SemanticVersion = null,
};

pub const ShortId = struct {
    bytes: [max_short_id_length]u8 = @splat(0),
    len: u8 = 0,

    pub fn slice(self: *const ShortId) []const u8 {
        return self.bytes[0..@as(usize, self.len)];
    }

    pub fn eql(self: ShortId, other: ShortId) bool {
        return self.len == other.len and std.mem.eql(
            u8,
            self.bytes[0..@as(usize, self.len)],
            other.bytes[0..@as(usize, other.len)],
        );
    }
};

/// Inner protocol spoken on top of the REALITY TLS stream once the
/// handshake completes. `socks5` keeps the pre-C5b behaviour: the
/// dispatcher runs a full SOCKS5 greeting/request on the TLS-wrapped
/// stream. `vless` parses a VLESS v1 request header from the first
/// app_data record, gates on `vless_uuid`, and pivots directly to the
/// decoded target — see [../tls/reality_transport.zig](../tls/reality_transport.zig).
pub const InnerProtocol = enum {
    socks5,
    vless,
};

pub const Config = struct {
    target: Target,
    server_names: []const []const u8,
    private_key: [key_length]u8,
    min_client_version: ?std.SemanticVersion = null,
    max_client_version: ?std.SemanticVersion = null,
    max_time_diff_ms: u64 = 0,
    short_ids: []const ShortId,
    /// Inner protocol the cooperating client is expected to speak once
    /// the TLS handshake finishes. Defaults to SOCKS5 for backwards
    /// compatibility with the pre-C5b `ayllu-camouflage-client`.
    inner_protocol: InnerProtocol = .socks5,
    /// Required when `inner_protocol == .vless`. 16-byte UUID the
    /// transport compares (constant-time) against `VlessHeader.uuid`;
    /// a mismatch drops the session silently. Ignored for SOCKS5 inner.
    vless_uuid: ?[16]u8 = null,

    pub fn validate(self: Config) ValidateError!void {
        if (self.target.host.len == 0 or self.target.port == 0) return error.InvalidTarget;
        if (self.server_names.len == 0) return error.MissingServerNames;
        for (self.server_names) |server_name| try validateServerName(server_name);
        _ = try ayllu.crypto.X25519.recoverPublicKey(self.private_key);
        if (self.short_ids.len == 0) return error.MissingShortIds;
        for (self.short_ids) |short_id| try validateShortId(short_id);
        if (self.min_client_version != null and self.max_client_version != null) {
            if (self.min_client_version.?.order(self.max_client_version.?) == .gt) {
                return error.InvalidVersionRange;
            }
        }
        if (self.inner_protocol == .vless and self.vless_uuid == null) {
            return error.MissingVlessUuid;
        }
    }

    pub fn publicKey(self: Config) ![key_length]u8 {
        return ayllu.crypto.X25519.recoverPublicKey(self.private_key);
    }

    pub fn exportPublic(self: Config) !PublicConfig {
        return .{
            .target = self.target,
            .server_public_key = try self.publicKey(),
            .min_client_version = self.min_client_version,
            .max_client_version = self.max_client_version,
        };
    }
};

pub const Hello = struct {
    server_name: []const u8,
    short_id: ShortId,
    client_public_key: [key_length]u8,
    client_version: ?std.SemanticVersion = null,
    unix_ms: i64,
};

pub const SessionMaterial = struct {
    shared_secret: [ayllu.crypto.X25519.shared_length]u8,
    auth_key: [32]u8,
    response_seed: [32]u8,
};

pub const ParseError = error{
    InvalidKeyLength,
    InvalidShortId,
    InvalidTarget,
    ShortBuffer,
} || std.base64.Error || std.fmt.ParseIntError;

pub const ValidateError = error{
    MissingServerNames,
    InvalidServerName,
    MissingShortIds,
    InvalidShortId,
    InvalidVersionRange,
    InvalidTarget,
    MissingVlessUuid,
} || std.crypto.errors.IdentityElementError;

pub const AuthorizeError = ValidateError || error{
    UnknownServerName,
    UnknownShortId,
    MissingClientVersion,
    ClientVersionTooLow,
    ClientVersionTooHigh,
    TimeSkewTooLarge,
} || std.crypto.errors.IdentityElementError;

pub fn generateKeyPair(io: std.Io) ayllu.crypto.X25519.KeyPair {
    return ayllu.crypto.X25519.KeyPair.generate(io);
}

pub fn encodeKey(out: []u8, key: [key_length]u8) ParseError![]const u8 {
    if (out.len < encoded_key_length) return error.ShortBuffer;
    return std.base64.url_safe_no_pad.Encoder.encode(out[0..encoded_key_length], &key);
}

pub fn decodeKey(encoded: []const u8) ParseError![key_length]u8 {
    if (try std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(encoded) != key_length) {
        return error.InvalidKeyLength;
    }
    var out: [key_length]u8 = undefined;
    try std.base64.url_safe_no_pad.Decoder.decode(&out, encoded);
    return out;
}

pub fn parseShortId(encoded: []const u8) ParseError!ShortId {
    if (encoded.len == 0) return .{};
    if (encoded.len > max_short_id_length * 2 or encoded.len % 2 != 0) {
        return error.InvalidShortId;
    }

    const byte_len = encoded.len / 2;
    var raw: [max_short_id_length]u8 = @splat(0);
    _ = std.fmt.hexToBytes(raw[0..byte_len], encoded) catch return error.InvalidShortId;
    return .{
        .bytes = raw,
        .len = @intCast(byte_len),
    };
}

pub fn formatShortId(out: []u8, short_id: ShortId) ParseError![]const u8 {
    const need = @as(usize, short_id.len) * 2;
    if (out.len < need) return error.ShortBuffer;
    const hex_chars = "0123456789abcdef";
    for (short_id.slice(), 0..) |byte, i| {
        out[i * 2] = hex_chars[byte >> 4];
        out[i * 2 + 1] = hex_chars[byte & 0x0F];
    }
    return out[0..need];
}

pub fn parseTarget(spec: []const u8) ParseError!Target {
    if (spec.len == 0) return error.InvalidTarget;

    if (spec[0] == '[') {
        const end = std.mem.indexOfScalar(u8, spec, ']') orelse return error.InvalidTarget;
        if (end == 1 or end + 1 >= spec.len or spec[end + 1] != ':') return error.InvalidTarget;
        const port = std.fmt.parseInt(u16, spec[end + 2 ..], 10) catch return error.InvalidTarget;
        if (port == 0) return error.InvalidTarget;
        return .{ .host = spec[1..end], .port = port };
    }

    const colon = std.mem.lastIndexOfScalar(u8, spec, ':') orelse return error.InvalidTarget;
    if (colon == 0 or colon + 1 >= spec.len) return error.InvalidTarget;
    if (std.mem.indexOfScalar(u8, spec[0..colon], ':') != null) return error.InvalidTarget;
    const port = std.fmt.parseInt(u16, spec[colon + 1 ..], 10) catch return error.InvalidTarget;
    if (port == 0) return error.InvalidTarget;
    return .{ .host = spec[0..colon], .port = port };
}

pub const UuidParseError = error{
    InvalidUuidLength,
    InvalidUuidChar,
};

/// Parse a VLESS UUID from either the canonical dashed form
/// (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, 36 chars) or a flat 32-hex
/// form. Case-insensitive.
pub fn parseVlessUuid(encoded: []const u8) UuidParseError![16]u8 {
    var hex_only: [32]u8 = undefined;
    switch (encoded.len) {
        32 => @memcpy(&hex_only, encoded),
        36 => {
            // Dashes must be at positions 8, 13, 18, 23.
            if (encoded[8] != '-' or encoded[13] != '-' or encoded[18] != '-' or encoded[23] != '-') {
                return error.InvalidUuidChar;
            }
            var w: usize = 0;
            for (encoded, 0..) |c, i| {
                if (i == 8 or i == 13 or i == 18 or i == 23) continue;
                hex_only[w] = c;
                w += 1;
            }
        },
        else => return error.InvalidUuidLength,
    }
    var out: [16]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, &hex_only) catch return error.InvalidUuidChar;
    return out;
}

pub fn authorize(config: Config, hello: Hello, now_ms: i64) AuthorizeError!SessionMaterial {
    try config.validate();

    if (!containsServerName(config.server_names, hello.server_name)) return error.UnknownServerName;
    try validateShortId(hello.short_id);
    if (!containsShortId(config.short_ids, hello.short_id)) return error.UnknownShortId;

    if (config.max_time_diff_ms != 0) {
        const diff = absDiff(now_ms, hello.unix_ms);
        if (diff > config.max_time_diff_ms) return error.TimeSkewTooLarge;
    }

    if (config.min_client_version != null or config.max_client_version != null) {
        const client_version = hello.client_version orelse return error.MissingClientVersion;
        if (config.min_client_version) |min| {
            if (client_version.order(min) == .lt) return error.ClientVersionTooLow;
        }
        if (config.max_client_version) |max| {
            if (client_version.order(max) == .gt) return error.ClientVersionTooHigh;
        }
    }

    const shared_secret = try ayllu.crypto.X25519.scalarmult(config.private_key, hello.client_public_key);
    return deriveMaterial(config.target, config.min_client_version, config.max_client_version, hello, shared_secret);
}

pub fn deriveClientMaterial(
    public_config: PublicConfig,
    client_private_key: [key_length]u8,
    hello: Hello,
) !SessionMaterial {
    const shared_secret = try ayllu.crypto.X25519.scalarmult(client_private_key, public_config.server_public_key);
    return deriveMaterial(
        public_config.target,
        public_config.min_client_version,
        public_config.max_client_version,
        hello,
        shared_secret,
    );
}

fn containsServerName(server_names: []const []const u8, candidate: []const u8) bool {
    for (server_names) |server_name| {
        if (std.mem.eql(u8, server_name, candidate)) return true;
    }
    return false;
}

fn containsShortId(short_ids: []const ShortId, candidate: ShortId) bool {
    for (short_ids) |short_id| {
        if (short_id.eql(candidate)) return true;
    }
    return false;
}

fn validateShortId(short_id: ShortId) ValidateError!void {
    if (short_id.len > max_short_id_length) return error.InvalidShortId;
}

fn validateServerName(server_name: []const u8) ValidateError!void {
    if (server_name.len == 0 or std.mem.indexOfScalar(u8, server_name, '*') != null) {
        return error.InvalidServerName;
    }

    var label_start: usize = 0;
    for (server_name, 0..) |ch, i| {
        if (ch == '.') {
            try validateLabel(server_name[label_start..i]);
            label_start = i + 1;
            continue;
        }
        if (!std.ascii.isAlphanumeric(ch) and ch != '-') return error.InvalidServerName;
    }
    try validateLabel(server_name[label_start..]);
}

fn validateLabel(label: []const u8) ValidateError!void {
    if (label.len == 0 or label.len > 63) return error.InvalidServerName;
    if (label[0] == '-' or label[label.len - 1] == '-') return error.InvalidServerName;
}

fn transcriptDigest(
    target: Target,
    min_client_version: ?std.SemanticVersion,
    max_client_version: ?std.SemanticVersion,
    hello: Hello,
) [32]u8 {
    var hash = ayllu.crypto.Sha256.init(.{});
    hash.update("ayllu.reality.v1");
    hash.update(target.host);
    hash.update(hello.server_name);
    hash.update(hello.short_id.slice());
    hash.update(&hello.client_public_key);

    var int_buf: [8]u8 = undefined;
    std.mem.writeInt(u16, int_buf[0..2], target.port, .big);
    hash.update(int_buf[0..2]);
    std.mem.writeInt(i64, &int_buf, hello.unix_ms, .big);
    hash.update(&int_buf);

    updateOptionalVersion(&hash, min_client_version);
    updateOptionalVersion(&hash, max_client_version);
    updateOptionalVersion(&hash, hello.client_version);

    var out: [32]u8 = undefined;
    hash.final(&out);
    return out;
}

fn deriveMaterial(
    target: Target,
    min_client_version: ?std.SemanticVersion,
    max_client_version: ?std.SemanticVersion,
    hello: Hello,
    shared_secret: [ayllu.crypto.X25519.shared_length]u8,
) SessionMaterial {
    const digest = transcriptDigest(target, min_client_version, max_client_version, hello);
    const prk = std.crypto.kdf.hkdf.HkdfSha256.extract(&digest, &shared_secret);

    var auth_key: [32]u8 = undefined;
    std.crypto.kdf.hkdf.HkdfSha256.expand(&auth_key, "ayllu.reality.v1.auth", prk);

    var response_seed: [32]u8 = undefined;
    std.crypto.kdf.hkdf.HkdfSha256.expand(&response_seed, "ayllu.reality.v1.response", prk);

    return .{
        .shared_secret = shared_secret,
        .auth_key = auth_key,
        .response_seed = response_seed,
    };
}

fn updateOptionalVersion(hash: *ayllu.crypto.Sha256, version: ?std.SemanticVersion) void {
    var buf: [24]u8 = undefined;
    if (version) |v| {
        std.mem.writeInt(u64, buf[0..8], v.major, .big);
        std.mem.writeInt(u64, buf[8..16], v.minor, .big);
        std.mem.writeInt(u64, buf[16..24], v.patch, .big);
        hash.update(&buf);
    } else {
        @memset(&buf, 0);
        hash.update(&buf);
    }
}

fn absDiff(a: i64, b: i64) u64 {
    const delta: i128 = @as(i128, a) - @as(i128, b);
    return @intCast(if (delta < 0) -delta else delta);
}

fn hex32(comptime s: *const [64]u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "encodeKey and decodeKey roundtrip deterministic X25519 private key" {
    const seed = hex32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    var encoded: [encoded_key_length]u8 = undefined;
    const out = try encodeKey(&encoded, seed);
    const decoded = try decodeKey(out);
    try std.testing.expectEqualSlices(u8, &seed, &decoded);
}

test "parseShortId accepts empty and 8-byte hex values" {
    const empty = try parseShortId("");
    try std.testing.expectEqual(@as(u8, 0), empty.len);

    const short_id = try parseShortId("0ed36d458733a0bc");
    try std.testing.expectEqual(@as(u8, 8), short_id.len);

    var formatted: [16]u8 = undefined;
    try std.testing.expectEqualStrings("0ed36d458733a0bc", try formatShortId(&formatted, short_id));
}

test "parseShortId rejects odd or oversized hex" {
    try std.testing.expectError(error.InvalidShortId, parseShortId("abc"));
    try std.testing.expectError(error.InvalidShortId, parseShortId("001122334455667788"));
}

test "parseTarget parses domain and bracketed IPv6 forms" {
    const domain = try parseTarget("example.com:443");
    try std.testing.expectEqualStrings("example.com", domain.host);
    try std.testing.expectEqual(@as(u16, 443), domain.port);

    const ipv6 = try parseTarget("[2606:4700:4700::1111]:443");
    try std.testing.expectEqualStrings("2606:4700:4700::1111", ipv6.host);
    try std.testing.expectEqual(@as(u16, 443), ipv6.port);
}

test "config validation rejects wildcard server names and inverted versions" {
    const short_ids = [_]ShortId{try parseShortId("aabb")};
    const cfg: Config = .{
        .target = .{ .host = "example.com", .port = 443 },
        .server_names = &.{"*.example.com"},
        .private_key = hex32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
        .min_client_version = try std.SemanticVersion.parse("2.0.0"),
        .max_client_version = try std.SemanticVersion.parse("1.0.0"),
        .short_ids = &short_ids,
    };
    try std.testing.expectError(error.InvalidServerName, cfg.validate());
}

test "authorize accepts matching hello and derives stable material" {
    const server_seed = hex32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    const client_seed = hex32("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40");
    const client_public = try ayllu.crypto.X25519.recoverPublicKey(client_seed);
    const short_ids = [_]ShortId{
        try parseShortId(""),
        try parseShortId("0ed36d458733a0bc"),
    };
    const cfg: Config = .{
        .target = .{ .host = "example.com", .port = 443 },
        .server_names = &.{"example.com"},
        .private_key = server_seed,
        .min_client_version = try std.SemanticVersion.parse("1.0.0"),
        .max_client_version = try std.SemanticVersion.parse("2.0.0"),
        .max_time_diff_ms = 5_000,
        .short_ids = &short_ids,
    };
    const hello: Hello = .{
        .server_name = "example.com",
        .short_id = try parseShortId("0ed36d458733a0bc"),
        .client_public_key = client_public,
        .client_version = try std.SemanticVersion.parse("1.5.0"),
        .unix_ms = 1_710_000_000_000,
    };

    const material = try authorize(cfg, hello, 1_710_000_000_500);
    try std.testing.expectEqualSlices(
        u8,
        &hex32("a84dc7c3c8f058b1b2dc4cd1e9b5dc0a7987f88b6a9564cde3391fc421159e77"),
        &material.shared_secret,
    );
    try std.testing.expectEqualSlices(
        u8,
        &hex32("72440f6b4a9804198b778371ef14f29e84b3418afd3d6cf011dc1bfcbdaaa56c"),
        &material.auth_key,
    );
    try std.testing.expectEqualSlices(
        u8,
        &hex32("68619a9b1988cbdcc96b032f80249e8837a2b57dac7c92726cbc05d030d312e6"),
        &material.response_seed,
    );
}

test "authorize rejects server name, short id, version and stale time" {
    const short_ids = [_]ShortId{try parseShortId("aabb")};
    const client_seed = hex32("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40");
    const cfg: Config = .{
        .target = .{ .host = "example.com", .port = 443 },
        .server_names = &.{"example.com"},
        .private_key = hex32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
        .min_client_version = try std.SemanticVersion.parse("1.0.0"),
        .max_client_version = try std.SemanticVersion.parse("2.0.0"),
        .max_time_diff_ms = 2_000,
        .short_ids = &short_ids,
    };
    const client_public = try ayllu.crypto.X25519.recoverPublicKey(client_seed);
    const bad_short_id = try parseShortId("ccdd");

    try std.testing.expect(!short_ids[0].eql(bad_short_id));
    try std.testing.expect(!containsShortId(&short_ids, bad_short_id));

    try std.testing.expectError(error.UnknownServerName, authorize(cfg, .{
        .server_name = "www.example.com",
        .short_id = try parseShortId("aabb"),
        .client_public_key = client_public,
        .client_version = try std.SemanticVersion.parse("1.5.0"),
        .unix_ms = 1_000,
    }, 1_000));

    try std.testing.expectError(error.UnknownShortId, authorize(cfg, .{
        .server_name = "example.com",
        .short_id = bad_short_id,
        .client_public_key = client_public,
        .client_version = try std.SemanticVersion.parse("1.5.0"),
        .unix_ms = 1_000,
    }, 1_000));

    try std.testing.expectError(error.ClientVersionTooLow, authorize(cfg, .{
        .server_name = "example.com",
        .short_id = try parseShortId("aabb"),
        .client_public_key = client_public,
        .client_version = try std.SemanticVersion.parse("0.9.0"),
        .unix_ms = 1_000,
    }, 1_000));

    try std.testing.expectError(error.TimeSkewTooLarge, authorize(cfg, .{
        .server_name = "example.com",
        .short_id = try parseShortId("aabb"),
        .client_public_key = client_public,
        .client_version = try std.SemanticVersion.parse("1.5.0"),
        .unix_ms = 1_000,
    }, 4_500));
}

test "client and server derive identical session material" {
    const server_cfg: Config = .{
        .target = .{ .host = "example.com", .port = 443 },
        .server_names = &.{"example.com"},
        .private_key = hex32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
        .min_client_version = try std.SemanticVersion.parse("1.0.0"),
        .max_client_version = try std.SemanticVersion.parse("2.0.0"),
        .short_ids = &[_]ShortId{try parseShortId("aabb")},
    };
    const public_cfg = try server_cfg.exportPublic();
    const client_private = hex32("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40");
    const hello: Hello = .{
        .server_name = "example.com",
        .short_id = try parseShortId("aabb"),
        .client_public_key = try ayllu.crypto.X25519.recoverPublicKey(client_private),
        .client_version = try std.SemanticVersion.parse("1.5.0"),
        .unix_ms = 1_710_000_000_000,
    };

    const server_material = try authorize(server_cfg, hello, hello.unix_ms);
    const client_material = try deriveClientMaterial(public_cfg, client_private, hello);
    try std.testing.expectEqualDeep(server_material, client_material);
}

test "parseVlessUuid accepts dashed and flat 32-hex forms" {
    const dashed = try parseVlessUuid("b831381d-6324-4d53-ad4f-8cda48b30811");
    const flat = try parseVlessUuid("b831381d63244d53ad4f8cda48b30811");
    try std.testing.expectEqualSlices(u8, &dashed, &flat);

    const expected = [_]u8{ 0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08, 0x11 };
    try std.testing.expectEqualSlices(u8, &expected, &dashed);
}

test "parseVlessUuid rejects bad length and misplaced dashes" {
    try std.testing.expectError(error.InvalidUuidLength, parseVlessUuid("abc"));
    // 40-char string → neither 32 nor 36 → length error
    try std.testing.expectError(
        error.InvalidUuidLength,
        parseVlessUuid("b831381d63244d53ad4f8cda48b3081100000000"),
    );
    // 36 chars with dashes in wrong positions → InvalidUuidChar
    try std.testing.expectError(
        error.InvalidUuidChar,
        parseVlessUuid("b831381d6-3244d53-ad4f-8cda-48b30811"),
    );
}

test "parseVlessUuid rejects non-hex bytes in flat form" {
    try std.testing.expectError(
        error.InvalidUuidChar,
        parseVlessUuid("ZZ31381d63244d53ad4f8cda48b30811"),
    );
}

test "Config.validate: vless inner without uuid => MissingVlessUuid" {
    const cfg: Config = .{
        .target = .{ .host = "example.com", .port = 443 },
        .server_names = &.{"example.com"},
        .private_key = hex32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
        .short_ids = &[_]ShortId{try parseShortId("aabb")},
        .inner_protocol = .vless,
        // vless_uuid = null → should fail
    };
    try std.testing.expectError(error.MissingVlessUuid, cfg.validate());
}

test "Config.validate: vless inner with uuid is accepted" {
    const cfg: Config = .{
        .target = .{ .host = "example.com", .port = 443 },
        .server_names = &.{"example.com"},
        .private_key = hex32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
        .short_ids = &[_]ShortId{try parseShortId("aabb")},
        .inner_protocol = .vless,
        .vless_uuid = try parseVlessUuid("b831381d-6324-4d53-ad4f-8cda48b30811"),
    };
    try cfg.validate();
}

test "Config.validate: socks5 inner ignores vless_uuid state" {
    const cfg: Config = .{
        .target = .{ .host = "example.com", .port = 443 },
        .server_names = &.{"example.com"},
        .private_key = hex32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
        .short_ids = &[_]ShortId{try parseShortId("aabb")},
        // inner_protocol defaults to .socks5
    };
    try cfg.validate();
}
