//! HTTP-like pivot classifier for camouflage handshakes.

const std = @import("std");
const reality = @import("reality.zig");
const tokens = @import("tokens.zig");

pub const Request = struct {
    method: []const u8,
    path: []const u8,
    host: []const u8,
    token: ?[]const u8,
};

pub const Pivot = struct {
    request: Request,
    token: tokens.Token,
};

pub const FallbackReason = enum {
    no_token,
    invalid_token,
};

pub const Fallback = struct {
    request: Request,
    reason: FallbackReason,
};

pub const Decision = union(enum) {
    pivot: Pivot,
    fallback: Fallback,
};

pub const Config = struct {
    token_header_name: []const u8 = "X-Ayllu-Token",
    max_request_bytes: usize = 4096,
};

pub const ParseError = error{
    HeaderTooLarge,
    MalformedRequest,
    MissingHost,
};

pub fn classify(
    comptime cache_entries: usize,
    request_bytes: []const u8,
    config: Config,
    auth_key: [32]u8,
    short_id: reality.ShortId,
    now_ms: i64,
    policy: tokens.Policy,
    replay_cache: *tokens.ReplayCache(cache_entries),
) ParseError!Decision {
    const request = try parseRequest(request_bytes, config);
    const token_value = request.token orelse return .{ .fallback = .{
        .request = request,
        .reason = .no_token,
    } };

    const token = tokens.validate(cache_entries, token_value, .{
        .auth_key = auth_key,
        .method = request.method,
        .path = request.path,
        .short_id = short_id,
    }, now_ms, policy, replay_cache) catch {
        return .{ .fallback = .{
            .request = request,
            .reason = .invalid_token,
        } };
    };

    return .{ .pivot = .{
        .request = request,
        .token = token,
    } };
}

pub fn parseRequest(request_bytes: []const u8, config: Config) ParseError!Request {
    if (request_bytes.len > config.max_request_bytes) return error.HeaderTooLarge;
    const header_end = std.mem.indexOf(u8, request_bytes, "\r\n\r\n") orelse return error.MalformedRequest;
    const head = request_bytes[0..header_end];

    var lines = std.mem.splitSequence(u8, head, "\r\n");
    const request_line = lines.next() orelse return error.MalformedRequest;
    const method_end = std.mem.indexOfScalar(u8, request_line, ' ') orelse return error.MalformedRequest;
    const version_start = std.mem.lastIndexOfScalar(u8, request_line, ' ') orelse return error.MalformedRequest;
    if (version_start <= method_end + 1) return error.MalformedRequest;

    const method = request_line[0..method_end];
    const path = request_line[method_end + 1 .. version_start];
    const version = request_line[version_start + 1 ..];
    if (!std.mem.eql(u8, version, "HTTP/1.1")) return error.MalformedRequest;

    var host: ?[]const u8 = null;
    var token: ?[]const u8 = null;
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.MalformedRequest;
        const name = trimAscii(line[0..colon]);
        const value = trimAscii(line[colon + 1 ..]);
        if (std.ascii.eqlIgnoreCase(name, "Host")) {
            host = value;
        } else if (std.ascii.eqlIgnoreCase(name, config.token_header_name)) {
            token = value;
        }
    }

    return .{
        .method = method,
        .path = path,
        .host = host orelse return error.MissingHost,
        .token = token,
    };
}

fn trimAscii(bytes: []const u8) []const u8 {
    var start: usize = 0;
    var end = bytes.len;
    while (start < end and (bytes[start] == ' ' or bytes[start] == '\t')) start += 1;
    while (end > start and (bytes[end - 1] == ' ' or bytes[end - 1] == '\t')) end -= 1;
    return bytes[start..end];
}

fn hex32(comptime s: *const [64]u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "parseRequest extracts method path host and optional token header" {
    const request = try parseRequest(
        "GET /pivot HTTP/1.1\r\nHost: example.com\r\nX-Ayllu-Token: abc123\r\n\r\n",
        .{},
    );
    try std.testing.expectEqualStrings("GET", request.method);
    try std.testing.expectEqualStrings("/pivot", request.path);
    try std.testing.expectEqualStrings("example.com", request.host);
    try std.testing.expectEqualStrings("abc123", request.token.?);
}

test "classify returns fallback when request has no token" {
    var cache: tokens.ReplayCache(8) = .{};
    const decision = try classify(8,
        "GET /pivot HTTP/1.1\r\nHost: example.com\r\n\r\n",
        .{},
        hex32("72440f6b4a9804198b778371ef14f29e84b3418afd3d6cf011dc1bfcbdaaa56c"),
        try reality.parseShortId("aabb"),
        10_000,
        .{},
        &cache,
    );
    try std.testing.expect(decision == .fallback);
    try std.testing.expectEqual(FallbackReason.no_token, decision.fallback.reason);
}

test "classify pivots valid token and falls back on invalid/replayed token" {
    const auth_key = hex32("72440f6b4a9804198b778371ef14f29e84b3418afd3d6cf011dc1bfcbdaaa56c");
    const short_id = try reality.parseShortId("aabb");
    const token = try tokens.issue(.{
        .auth_key = auth_key,
        .method = "GET",
        .path = "/pivot",
        .short_id = short_id,
    }, 10_000, .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 }, .{});
    var encoded: [tokens.encoded_length]u8 = undefined;
    const token_text = try tokens.encode(&encoded, token);

    var request_buf: [256]u8 = undefined;
    const request = try std.fmt.bufPrint(
        &request_buf,
        "GET /pivot HTTP/1.1\r\nHost: example.com\r\nX-Ayllu-Token: {s}\r\n\r\n",
        .{token_text},
    );

    var good_cache: tokens.ReplayCache(8) = .{};
    const good = try classify(8, request, .{}, auth_key, short_id, 10_500, .{}, &good_cache);
    try std.testing.expect(good == .pivot);
    try std.testing.expectEqualStrings("/pivot", good.pivot.request.path);

    var replay_cache: tokens.ReplayCache(8) = .{};
    _ = try classify(8, request, .{}, auth_key, short_id, 10_500, .{}, &replay_cache);
    const replayed = try classify(8, request, .{}, auth_key, short_id, 10_500, .{}, &replay_cache);
    try std.testing.expect(replayed == .fallback);
    try std.testing.expectEqual(FallbackReason.invalid_token, replayed.fallback.reason);

    var bad_request_buf: [256]u8 = undefined;
    const bad_request = try std.fmt.bufPrint(
        &bad_request_buf,
        "GET /other HTTP/1.1\r\nHost: example.com\r\nX-Ayllu-Token: {s}\r\n\r\n",
        .{token_text},
    );
    var bad_cache: tokens.ReplayCache(8) = .{};
    const bad = try classify(8, bad_request, .{}, auth_key, short_id, 10_500, .{}, &bad_cache);
    try std.testing.expect(bad == .fallback);
    try std.testing.expectEqual(FallbackReason.invalid_token, bad.fallback.reason);
}
