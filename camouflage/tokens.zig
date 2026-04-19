//! Time-windowed camouflage tokens bound to an HTTP-like request shape.

const std = @import("std");
const reality = @import("reality.zig");

pub const version: u8 = 1;
pub const nonce_length = 12;
pub const mac_length = 16;
pub const wire_length = 1 + 8 + nonce_length + mac_length;
pub const encoded_length = std.base64.url_safe_no_pad.Encoder.calcSize(wire_length);

pub const Policy = struct {
    slot_ms: u64 = 1_000,
    max_age_slots: u8 = 2,
    max_future_slots: u8 = 1,
};

pub const Context = struct {
    auth_key: [32]u8,
    method: []const u8,
    path: []const u8,
    short_id: reality.ShortId,
};

pub const Token = struct {
    slot: u64,
    nonce: [nonce_length]u8,
    mac: [mac_length]u8,
};

pub const ParseError = error{
    BadVersion,
    InvalidTokenLength,
    ShortBuffer,
    NegativeTime,
} || std.base64.Error;

pub const ValidationError = ParseError || error{
    BadVersion,
    InvalidMac,
    TokenExpired,
    TokenFromFuture,
    ReplayDetected,
};

pub fn ReplayCache(comptime entries: usize) type {
    return struct {
        slots: [entries][mac_length]u8 = [_][mac_length]u8{@splat(0)} ** entries,
        used: [entries]bool = [_]bool{false} ** entries,
        cursor: usize = 0,

        const Self = @This();

        pub fn checkAndRemember(self: *Self, mac: [mac_length]u8) bool {
            for (self.used, self.slots) |is_used, seen_mac| {
                if (is_used and std.mem.eql(u8, &seen_mac, &mac)) return false;
            }
            self.slots[self.cursor] = mac;
            self.used[self.cursor] = true;
            self.cursor = (self.cursor + 1) % entries;
            return true;
        }
    };
}

pub fn issue(context: Context, issued_at_ms: i64, nonce: [nonce_length]u8, policy: Policy) ParseError!Token {
    const slot = try slotFromUnixMs(issued_at_ms, policy.slot_ms);
    return .{
        .slot = slot,
        .nonce = nonce,
        .mac = computeMac(context, slot, nonce),
    };
}

pub fn encode(out: []u8, token: Token) ParseError![]const u8 {
    if (out.len < encoded_length) return error.ShortBuffer;

    var wire: [wire_length]u8 = undefined;
    wire[0] = version;
    std.mem.writeInt(u64, wire[1..9], token.slot, .big);
    @memcpy(wire[9 .. 9 + nonce_length], &token.nonce);
    @memcpy(wire[9 + nonce_length ..][0..mac_length], &token.mac);
    return std.base64.url_safe_no_pad.Encoder.encode(out[0..encoded_length], &wire);
}

pub fn decode(encoded: []const u8) ParseError!Token {
    if (try std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(encoded) != wire_length) {
        return error.InvalidTokenLength;
    }

    var wire: [wire_length]u8 = undefined;
    try std.base64.url_safe_no_pad.Decoder.decode(&wire, encoded);
    if (wire[0] != version) return error.BadVersion;

    return .{
        .slot = std.mem.readInt(u64, wire[1..9], .big),
        .nonce = wire[9 .. 9 + nonce_length].*,
        .mac = wire[9 + nonce_length ..][0..mac_length].*,
    };
}

pub fn validate(
    comptime cache_entries: usize,
    encoded: []const u8,
    context: Context,
    now_ms: i64,
    policy: Policy,
    replay_cache: *ReplayCache(cache_entries),
) ValidationError!Token {
    const token = try decode(encoded);
    try validateDecoded(cache_entries, token, context, now_ms, policy, replay_cache);
    return token;
}

pub fn validateDecoded(
    comptime cache_entries: usize,
    token: Token,
    context: Context,
    now_ms: i64,
    policy: Policy,
    replay_cache: *ReplayCache(cache_entries),
) ValidationError!void {
    const now_slot = try slotFromUnixMs(now_ms, policy.slot_ms);
    if (token.slot > now_slot + policy.max_future_slots) return error.TokenFromFuture;
    if (now_slot > token.slot + policy.max_age_slots) return error.TokenExpired;

    const expected_mac = computeMac(context, token.slot, token.nonce);
    if (!timingSafeEql(expected_mac, token.mac)) {
        return error.InvalidMac;
    }
    if (!replay_cache.checkAndRemember(token.mac)) return error.ReplayDetected;
}

fn computeMac(context: Context, slot: u64, nonce: [nonce_length]u8) [mac_length]u8 {
    var full: [32]u8 = undefined;
    var state = std.crypto.auth.hmac.sha2.HmacSha256.init(&context.auth_key);
    state.update("ayllu.camouflage.v1");
    state.update(context.method);
    state.update("\x00");
    state.update(context.path);
    state.update("\x00");
    state.update(context.short_id.slice());

    var slot_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &slot_buf, slot, .big);
    state.update(&slot_buf);
    state.update(&nonce);
    state.final(&full);
    return full[0..mac_length].*;
}

fn slotFromUnixMs(unix_ms: i64, slot_ms: u64) ParseError!u64 {
    if (unix_ms < 0) return error.NegativeTime;
    return @intCast(@divFloor(unix_ms, @as(i64, @intCast(slot_ms))));
}

fn timingSafeEql(a: [mac_length]u8, b: [mac_length]u8) bool {
    var diff: u8 = 0;
    for (a, 0..) |byte, i| diff |= byte ^ b[i];
    return diff == 0;
}

fn hex32(comptime s: *const [64]u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "issue encode decode roundtrip" {
    const token = try issue(.{
        .auth_key = hex32("72440f6b4a9804198b778371ef14f29e84b3418afd3d6cf011dc1bfcbdaaa56c"),
        .method = "GET",
        .path = "/assets/app.js",
        .short_id = try reality.parseShortId("0ed36d458733a0bc"),
    }, 1_710_000_000_000, .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 }, .{});

    var encoded: [encoded_length]u8 = undefined;
    const wire = try encode(&encoded, token);
    const decoded = try decode(wire);
    try std.testing.expectEqualDeep(token, decoded);
}

test "validate accepts current token and rejects replay" {
    var cache: ReplayCache(8) = .{};
    const context: Context = .{
        .auth_key = hex32("72440f6b4a9804198b778371ef14f29e84b3418afd3d6cf011dc1bfcbdaaa56c"),
        .method = "GET",
        .path = "/pivot",
        .short_id = try reality.parseShortId("aabb"),
    };
    const token = try issue(context, 10_000, .{ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 }, .{});
    try validateDecoded(8, token, context, 10_500, .{}, &cache);
    try std.testing.expectError(error.ReplayDetected, validateDecoded(8, token, context, 10_500, .{}, &cache));
}

test "validate rejects stale, future and path-mismatched tokens" {
    const context: Context = .{
        .auth_key = hex32("72440f6b4a9804198b778371ef14f29e84b3418afd3d6cf011dc1bfcbdaaa56c"),
        .method = "GET",
        .path = "/pivot",
        .short_id = try reality.parseShortId("aabb"),
    };
    const token = try issue(context, 10_000, .{ 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2 }, .{});

    var stale_cache: ReplayCache(8) = .{};
    try std.testing.expectError(
        error.TokenExpired,
        validateDecoded(8, token, context, 20_000, .{}, &stale_cache),
    );

    var future_cache: ReplayCache(8) = .{};
    try std.testing.expectError(
        error.TokenFromFuture,
        validateDecoded(8, token, context, 8_000, .{}, &future_cache),
    );

    var wrong_path_cache: ReplayCache(8) = .{};
    try std.testing.expectError(error.InvalidMac, validateDecoded(8, token, .{
        .auth_key = context.auth_key,
        .method = context.method,
        .path = "/fallback",
        .short_id = context.short_id,
    }, 10_500, .{}, &wrong_path_cache));
}
