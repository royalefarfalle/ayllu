const std = @import("std");
const ayllu_camouflage = @import("ayllu-camouflage");
const ayllu_proxy = @import("ayllu-proxy");

const default_listen_host = "0.0.0.0";
const default_listen_port: u16 = 443;

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(gpa);

    var listen_host: []const u8 = default_listen_host;
    var listen_port: u16 = default_listen_port;
    var listen_addr: ?std.Io.net.IpAddress = null;
    var target: ?ayllu_camouflage.reality.Target = null;
    var private_key: ?[ayllu_camouflage.reality.key_length]u8 = null;
    var min_client_version: ?std.SemanticVersion = null;
    var max_client_version: ?std.SemanticVersion = null;
    var max_time_diff_ms: u64 = 5_000;
    var token_policy: ayllu_camouflage.tokens.Policy = .{};
    var proxy_config: ayllu_proxy.daemon.Config = .{};
    var server_names = std.ArrayList([]const u8).empty;
    var short_ids = std.ArrayList(ayllu_camouflage.reality.ShortId).empty;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--listen")) {
            i += 1;
            if (i >= args.len) return error.MissingListenValue;
            const parsed_host, const parsed_port, const parsed_addr = try parseListenSpec(args[i]);
            listen_host = parsed_host;
            listen_port = parsed_port;
            listen_addr = parsed_addr;
        } else if (std.mem.eql(u8, args[i], "--target")) {
            i += 1;
            if (i >= args.len) return error.MissingTargetValue;
            target = try ayllu_camouflage.reality.parseTarget(args[i]);
        } else if (std.mem.eql(u8, args[i], "--server-name")) {
            i += 1;
            if (i >= args.len) return error.MissingServerNameValue;
            try server_names.append(gpa, args[i]);
        } else if (std.mem.eql(u8, args[i], "--private-key")) {
            i += 1;
            if (i >= args.len) return error.MissingPrivateKeyValue;
            private_key = try ayllu_camouflage.reality.decodeKey(args[i]);
        } else if (std.mem.eql(u8, args[i], "--short-id")) {
            i += 1;
            if (i >= args.len) return error.MissingShortIdValue;
            try short_ids.append(gpa, try ayllu_camouflage.reality.parseShortId(args[i]));
        } else if (std.mem.eql(u8, args[i], "--auth-file")) {
            i += 1;
            if (i >= args.len) return error.MissingAuthFileValue;
            proxy_config.auth = try ayllu_proxy.auth.loadFromFile(io, gpa, args[i]);
        } else if (std.mem.eql(u8, args[i], "--max-time-diff-ms")) {
            i += 1;
            if (i >= args.len) return error.MissingMaxTimeDiffValue;
            max_time_diff_ms = std.fmt.parseInt(u64, args[i], 10) catch return error.BadMaxTimeDiffValue;
        } else if (std.mem.eql(u8, args[i], "--token-slot-ms")) {
            i += 1;
            if (i >= args.len) return error.MissingTokenSlotValue;
            token_policy.slot_ms = std.fmt.parseInt(u64, args[i], 10) catch return error.BadTokenSlotValue;
        } else if (std.mem.eql(u8, args[i], "--token-max-age-slots")) {
            i += 1;
            if (i >= args.len) return error.MissingTokenMaxAgeValue;
            token_policy.max_age_slots = std.fmt.parseInt(u8, args[i], 10) catch return error.BadTokenMaxAgeValue;
        } else if (std.mem.eql(u8, args[i], "--token-max-future-slots")) {
            i += 1;
            if (i >= args.len) return error.MissingTokenMaxFutureValue;
            token_policy.max_future_slots = std.fmt.parseInt(u8, args[i], 10) catch return error.BadTokenMaxFutureValue;
        } else if (std.mem.eql(u8, args[i], "--min-client-ver")) {
            i += 1;
            if (i >= args.len) return error.MissingMinClientVerValue;
            min_client_version = std.SemanticVersion.parse(args[i]) catch return error.BadMinClientVerValue;
        } else if (std.mem.eql(u8, args[i], "--max-client-ver")) {
            i += 1;
            if (i >= args.len) return error.MissingMaxClientVerValue;
            max_client_version = std.SemanticVersion.parse(args[i]) catch return error.BadMaxClientVerValue;
        } else if (std.mem.eql(u8, args[i], "--help") or std.mem.eql(u8, args[i], "-h")) {
            try printUsage(io);
            return;
        } else {
            try printUsage(io);
            return error.UnknownArg;
        }
    }

    const reality_config: ayllu_camouflage.reality.Config = .{
        .target = target orelse return error.MissingTargetValue,
        .server_names = server_names.items,
        .private_key = private_key orelse return error.MissingPrivateKeyValue,
        .min_client_version = min_client_version,
        .max_client_version = max_client_version,
        .max_time_diff_ms = max_time_diff_ms,
        .short_ids = short_ids.items,
    };
    try reality_config.validate();

    var state: ayllu_camouflage.server.State = .{
        .config = .{
            .pivot = .{
                .reality = reality_config,
                .token_policy = token_policy,
            },
            .proxy = proxy_config,
        },
    };

    const addr = listen_addr orelse try std.Io.net.IpAddress.parse(listen_host, listen_port);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);

    var stdout_buffer: [512]u8 = undefined;
    var stdout_writer: std.Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    try stdout_writer.interface.print(
        "ayllu-camouflage-proxy listening on {s}:{d} -> camouflage target {s}:{d}\n",
        .{ listen_host, listen_port, reality_config.target.host, reality_config.target.port },
    );
    try stdout_writer.interface.flush();

    while (true) {
        const client_stream = server.accept(io) catch |err| {
            std.log.warn("accept failed: {t}", .{err});
            continue;
        };
        _ = io.async(sessionWrapper, .{ io, client_stream.socket, &state });
    }
}

fn sessionWrapper(io: std.Io, socket: std.Io.net.Socket, state: *ayllu_camouflage.server.State) void {
    ayllu_camouflage.server.sessionWithState(io, socket, state) catch |err| switch (err) {
        error.EndOfStream, error.Canceled => {},
        else => std.log.warn("camouflage session ended: {t}", .{err}),
    };
}

fn printUsage(io: std.Io) !void {
    var buf: [1536]u8 = undefined;
    var w: std.Io.File.Writer = .init(.stdout(), io, &buf);
    try w.interface.writeAll(
        \\ayllu-camouflage-proxy — HTTP-like camouflage gate + inner SOCKS5
        \\
        \\Usage:
        \\  ayllu-camouflage-proxy --target HOST:PORT --server-name NAME --private-key KEY --short-id HEX [options]
        \\
        \\Required:
        \\  --target HOST:PORT         camouflage target identity (for transcript binding)
        \\  --server-name NAME         accepted Host header / server name (repeatable)
        \\  --private-key KEY          REALITY private key (base64url, no padding)
        \\  --short-id HEX             accepted short id (repeatable)
        \\
        \\Options:
        \\  --listen HOST:PORT         bind address (default 0.0.0.0:443)
        \\  --auth-file PATH           inner SOCKS username:password file
        \\  --max-time-diff-ms N       clock skew allowance (default 5000)
        \\  --token-slot-ms N          token slot size (default 1000)
        \\  --token-max-age-slots N    accepted stale slots (default 2)
        \\  --token-max-future-slots N accepted future slots (default 1)
        \\  --min-client-ver X.Y.Z     minimum client version
        \\  --max-client-ver X.Y.Z     maximum client version
        \\  --help                     show this help
        \\
    );
    try w.interface.flush();
}

fn parseListenSpec(spec: []const u8) !struct { []const u8, u16, std.Io.net.IpAddress } {
    if (spec.len == 0) return error.BadListenSpec;

    if (spec[0] == '[') {
        const end = std.mem.indexOfScalar(u8, spec, ']') orelse return error.BadListenSpec;
        if (end + 1 >= spec.len or spec[end + 1] != ':') return error.BadListenSpec;
        const host = spec[1..end];
        const port = std.fmt.parseInt(u16, spec[end + 2 ..], 10) catch return error.BadListenSpec;
        return .{ host, port, try std.Io.net.IpAddress.parse(host, port) };
    }

    const colon = std.mem.lastIndexOfScalar(u8, spec, ':') orelse return error.BadListenSpec;
    if (std.mem.indexOfScalar(u8, spec[0..colon], ':') != null) return error.BadListenSpec;
    const host = spec[0..colon];
    const port = std.fmt.parseInt(u16, spec[colon + 1 ..], 10) catch return error.BadListenSpec;
    return .{ host, port, try std.Io.net.IpAddress.parse(host, port) };
}

test "parseListenSpec parses IPv4 and bracketed IPv6" {
    const host4, const port4, const addr4 = try parseListenSpec("127.0.0.1:443");
    try std.testing.expectEqualStrings("127.0.0.1", host4);
    try std.testing.expectEqual(@as(u16, 443), port4);
    try std.testing.expect(addr4 == .ip4);

    const host6, const port6, const addr6 = try parseListenSpec("[::1]:8443");
    try std.testing.expectEqualStrings("::1", host6);
    try std.testing.expectEqual(@as(u16, 8443), port6);
    try std.testing.expect(addr6 == .ip6);
}
