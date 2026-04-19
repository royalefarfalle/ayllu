//! HTTP-like pivot classifier that ties request parsing to REALITY admission.

const std = @import("std");
const ayllu = @import("ayllu");
const reality = @import("reality.zig");
const tokens = @import("tokens.zig");

pub const Request = struct {
    method: []const u8,
    path: []const u8,
    host: []const u8,
};

pub const HeaderNames = struct {
    token_header_name: []const u8 = "X-Ayllu-Token",
    client_key_header_name: []const u8 = "X-Ayllu-Client-Key",
    client_time_header_name: []const u8 = "X-Ayllu-Time",
    client_version_header_name: []const u8 = "X-Ayllu-Client-Version",
    short_id_header_name: []const u8 = "X-Ayllu-Short-Id",
};

pub const Config = struct {
    headers: HeaderNames = .{},
    max_request_bytes: usize = 4096,
    reality: reality.Config,
    token_policy: tokens.Policy = .{},
};

pub const ParsedRequest = struct {
    request: Request,
    token: ?[]const u8 = null,
    client_public_key: ?[reality.key_length]u8 = null,
    client_time_ms: ?i64 = null,
    client_version: ?std.SemanticVersion = null,
    short_id: ?reality.ShortId = null,
};

pub const Pivot = struct {
    request: Request,
    hello: reality.Hello,
    material: reality.SessionMaterial,
    token: tokens.Token,
};

pub const FallbackReason = enum {
    no_token,
    invalid_reality,
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

pub const ParseError = error{
    HeaderTooLarge,
    MalformedRequest,
    MissingHost,
    InvalidClientVersion,
} || reality.ParseError || std.fmt.ParseIntError;

pub fn classify(
    comptime cache_entries: usize,
    request_bytes: []const u8,
    config: Config,
    now_ms: i64,
    replay_cache: *tokens.ReplayCache(cache_entries),
) ParseError!Decision {
    const parsed = try parseAdmissionRequest(request_bytes, config);
    const token_value = parsed.token orelse return .{
        .fallback = .{
            .request = parsed.request,
            .reason = .no_token,
        },
    };

    const hello = buildHello(parsed) orelse return .{
        .fallback = .{
            .request = parsed.request,
            .reason = .invalid_reality,
        },
    };

    const material = reality.authorize(config.reality, hello, now_ms) catch return .{
        .fallback = .{
            .request = parsed.request,
            .reason = .invalid_reality,
        },
    };

    const token = tokens.validate(cache_entries, token_value, .{
        .auth_key = material.auth_key,
        .method = parsed.request.method,
        .path = parsed.request.path,
        .short_id = hello.short_id,
    }, now_ms, config.token_policy, replay_cache) catch return .{
        .fallback = .{
            .request = parsed.request,
            .reason = .invalid_token,
        },
    };

    return .{
        .pivot = .{
            .request = parsed.request,
            .hello = hello,
            .material = material,
            .token = token,
        },
    };
}

pub fn parseRequest(request_bytes: []const u8, config: Config) ParseError!Request {
    return (try parseAdmissionRequest(request_bytes, config)).request;
}

pub fn parseAdmissionRequest(request_bytes: []const u8, config: Config) ParseError!ParsedRequest {
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

    var parsed: ParsedRequest = .{
        .request = .{
            .method = method,
            .path = path,
            .host = "",
        },
    };
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.MalformedRequest;
        const name = trimAscii(line[0..colon]);
        const value = trimAscii(line[colon + 1 ..]);
        if (std.ascii.eqlIgnoreCase(name, "Host")) {
            parsed.request.host = value;
        } else if (std.ascii.eqlIgnoreCase(name, config.headers.token_header_name)) {
            parsed.token = value;
        } else if (std.ascii.eqlIgnoreCase(name, config.headers.client_key_header_name)) {
            parsed.client_public_key = try reality.decodeKey(value);
        } else if (std.ascii.eqlIgnoreCase(name, config.headers.client_time_header_name)) {
            parsed.client_time_ms = try std.fmt.parseInt(i64, value, 10);
        } else if (std.ascii.eqlIgnoreCase(name, config.headers.client_version_header_name)) {
            parsed.client_version = std.SemanticVersion.parse(value) catch return error.InvalidClientVersion;
        } else if (std.ascii.eqlIgnoreCase(name, config.headers.short_id_header_name)) {
            parsed.short_id = try reality.parseShortId(value);
        }
    }
    if (parsed.request.host.len == 0) return error.MissingHost;
    return parsed;
}

fn buildHello(parsed: ParsedRequest) ?reality.Hello {
    const client_public_key = parsed.client_public_key orelse return null;
    const client_time_ms = parsed.client_time_ms orelse return null;
    const short_id = parsed.short_id orelse return null;
    return .{
        .server_name = parsed.request.host,
        .short_id = short_id,
        .client_public_key = client_public_key,
        .client_version = parsed.client_version,
        .unix_ms = client_time_ms,
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

test "parseRequest extracts host and ignores admission headers" {
    const cfg: Config = .{
        .reality = .{
            .target = .{ .host = "example.com", .port = 443 },
            .server_names = &.{"example.com"},
            .private_key = hex32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
            .short_ids = &[_]reality.ShortId{try reality.parseShortId("aabb")},
        },
    };
    const request = try parseRequest(
        "GET /pivot HTTP/1.1\r\nHost: example.com\r\nX-Ayllu-Token: abc123\r\n\r\n",
        cfg,
    );
    try std.testing.expectEqualStrings("GET", request.method);
    try std.testing.expectEqualStrings("/pivot", request.path);
    try std.testing.expectEqualStrings("example.com", request.host);
}

test "parseAdmissionRequest decodes reality headers" {
    const server_cfg: reality.Config = .{
        .target = .{ .host = "example.com", .port = 443 },
        .server_names = &.{"example.com"},
        .private_key = hex32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
        .short_ids = &[_]reality.ShortId{try reality.parseShortId("aabb")},
    };
    var key_text: [reality.encoded_key_length]u8 = undefined;
    const client_key = try reality.encodeKey(
        &key_text,
        reality.generateKeyPair(std.testing.io).public_key,
    );
    var req_buf: [512]u8 = undefined;
    const raw = try std.fmt.bufPrint(
        &req_buf,
        "GET /pivot HTTP/1.1\r\nHost: example.com\r\nX-Ayllu-Client-Key: {s}\r\nX-Ayllu-Time: 1234\r\nX-Ayllu-Client-Version: 1.2.3\r\nX-Ayllu-Short-Id: aabb\r\nX-Ayllu-Token: abc\r\n\r\n",
        .{client_key},
    );
    const parsed = try parseAdmissionRequest(raw, .{ .reality = server_cfg });
    try std.testing.expectEqualStrings("example.com", parsed.request.host);
    try std.testing.expectEqual(@as(i64, 1234), parsed.client_time_ms.?);
    try std.testing.expectEqualStrings("abc", parsed.token.?);
    try std.testing.expectEqualDeep(try reality.parseShortId("aabb"), parsed.short_id.?);
}

test "classify returns fallback when request has no token" {
    var cache: tokens.ReplayCache(8) = .{};
    const decision = try classify(
        8,
        "GET /pivot HTTP/1.1\r\nHost: example.com\r\n\r\n",
        .{
            .reality = .{
                .target = .{ .host = "example.com", .port = 443 },
                .server_names = &.{"example.com"},
                .private_key = hex32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
                .short_ids = &[_]reality.ShortId{try reality.parseShortId("aabb")},
            },
        },
        10_000,
        &cache,
    );
    try std.testing.expect(decision == .fallback);
    try std.testing.expectEqual(FallbackReason.no_token, decision.fallback.reason);
}

test "classify ties reality admission and token validation together" {
    const server_cfg: reality.Config = .{
        .target = .{ .host = "example.com", .port = 443 },
        .server_names = &.{"example.com"},
        .private_key = hex32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
        .min_client_version = try std.SemanticVersion.parse("1.0.0"),
        .max_client_version = try std.SemanticVersion.parse("2.0.0"),
        .max_time_diff_ms = 5_000,
        .short_ids = &[_]reality.ShortId{try reality.parseShortId("aabb")},
    };
    const public_cfg = try server_cfg.exportPublic();
    const client_private = hex32("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40");
    const hello: reality.Hello = .{
        .server_name = "example.com",
        .short_id = try reality.parseShortId("aabb"),
        .client_public_key = try ayllu.crypto.X25519.recoverPublicKey(client_private),
        .client_version = try std.SemanticVersion.parse("1.5.0"),
        .unix_ms = 10_000,
    };
    const client_material = try reality.deriveClientMaterial(public_cfg, client_private, hello);
    const token = try tokens.issue(.{
        .auth_key = client_material.auth_key,
        .method = "GET",
        .path = "/pivot",
        .short_id = hello.short_id,
    }, hello.unix_ms, .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 }, .{});

    var client_key_text: [reality.encoded_key_length]u8 = undefined;
    const client_key = try reality.encodeKey(&client_key_text, hello.client_public_key);
    var token_text: [tokens.encoded_length]u8 = undefined;
    const encoded_token = try tokens.encode(&token_text, token);
    var req_buf: [768]u8 = undefined;
    const raw = try std.fmt.bufPrint(
        &req_buf,
        "GET /pivot HTTP/1.1\r\nHost: example.com\r\nX-Ayllu-Client-Key: {s}\r\nX-Ayllu-Time: {d}\r\nX-Ayllu-Client-Version: 1.5.0\r\nX-Ayllu-Short-Id: aabb\r\nX-Ayllu-Token: {s}\r\n\r\n",
        .{ client_key, hello.unix_ms, encoded_token },
    );

    var cache: tokens.ReplayCache(8) = .{};
    const decision = try classify(8, raw, .{ .reality = server_cfg }, 10_500, &cache);
    try std.testing.expect(decision == .pivot);
    try std.testing.expectEqualStrings("/pivot", decision.pivot.request.path);
    try std.testing.expectEqualDeep(hello.short_id, decision.pivot.hello.short_id);
    try std.testing.expectEqualDeep(client_material.auth_key, decision.pivot.material.auth_key);
}

test "classify falls back on bad reality headers or token mismatch" {
    const server_cfg: reality.Config = .{
        .target = .{ .host = "example.com", .port = 443 },
        .server_names = &.{"example.com"},
        .private_key = hex32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
        .short_ids = &[_]reality.ShortId{try reality.parseShortId("aabb")},
    };
    const public_cfg = try server_cfg.exportPublic();
    const client_private = hex32("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40");
    const hello: reality.Hello = .{
        .server_name = "example.com",
        .short_id = try reality.parseShortId("aabb"),
        .client_public_key = try ayllu.crypto.X25519.recoverPublicKey(client_private),
        .unix_ms = 10_000,
    };
    const client_material = try reality.deriveClientMaterial(public_cfg, client_private, hello);
    const token = try tokens.issue(.{
        .auth_key = client_material.auth_key,
        .method = "GET",
        .path = "/pivot",
        .short_id = hello.short_id,
    }, hello.unix_ms, .{ 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2 }, .{});

    var client_key_text: [reality.encoded_key_length]u8 = undefined;
    const client_key = try reality.encodeKey(&client_key_text, hello.client_public_key);
    var token_text: [tokens.encoded_length]u8 = undefined;
    const encoded_token = try tokens.encode(&token_text, token);

    var bad_reality_req_buf: [768]u8 = undefined;
    const bad_reality = try std.fmt.bufPrint(
        &bad_reality_req_buf,
        "GET /pivot HTTP/1.1\r\nHost: example.com\r\nX-Ayllu-Time: {d}\r\nX-Ayllu-Short-Id: aabb\r\nX-Ayllu-Token: {s}\r\n\r\n",
        .{ hello.unix_ms, encoded_token },
    );
    var bad_reality_cache: tokens.ReplayCache(8) = .{};
    const bad_reality_decision = try classify(8, bad_reality, .{ .reality = server_cfg }, 10_500, &bad_reality_cache);
    try std.testing.expect(bad_reality_decision == .fallback);
    try std.testing.expectEqual(FallbackReason.invalid_reality, bad_reality_decision.fallback.reason);

    var bad_token_req_buf: [768]u8 = undefined;
    const bad_token = try std.fmt.bufPrint(
        &bad_token_req_buf,
        "GET /other HTTP/1.1\r\nHost: example.com\r\nX-Ayllu-Client-Key: {s}\r\nX-Ayllu-Time: {d}\r\nX-Ayllu-Short-Id: aabb\r\nX-Ayllu-Token: {s}\r\n\r\n",
        .{ client_key, hello.unix_ms, encoded_token },
    );
    var bad_token_cache: tokens.ReplayCache(8) = .{};
    const bad_token_decision = try classify(8, bad_token, .{ .reality = server_cfg }, 10_500, &bad_token_cache);
    try std.testing.expect(bad_token_decision == .fallback);
    try std.testing.expectEqual(FallbackReason.invalid_token, bad_token_decision.fallback.reason);
}
