const std = @import("std");
const ayllu_camouflage = @import("ayllu-camouflage");

const default_listen_host = "127.0.0.1";
const default_listen_port: u16 = 1080;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);

    var listen_host: []const u8 = default_listen_host;
    var listen_port: u16 = default_listen_port;
    var listen_addr: ?std.Io.net.IpAddress = null;
    var connect_target: ?ayllu_camouflage.reality.Target = null;
    var transcript_target: ?ayllu_camouflage.reality.Target = null;
    var server_name: ?[]const u8 = null;
    var server_public_key: ?[ayllu_camouflage.reality.key_length]u8 = null;
    var client_private_key: ?[ayllu_camouflage.reality.key_length]u8 = null;
    var short_id: ?ayllu_camouflage.reality.ShortId = null;
    var client_version = std.SemanticVersion{ .major = 1, .minor = 0, .patch = 0 };
    var min_client_version: ?std.SemanticVersion = null;
    var max_client_version: ?std.SemanticVersion = null;
    var request_path: []const u8 = "/pivot";
    var token_policy: ayllu_camouflage.tokens.Policy = .{};
    var max_response_bytes: usize = 4096;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--listen")) {
            i += 1;
            if (i >= args.len) return error.MissingListenValue;
            const parsed_host, const parsed_port, const parsed_addr = try parseListenSpec(args[i]);
            listen_host = parsed_host;
            listen_port = parsed_port;
            listen_addr = parsed_addr;
        } else if (std.mem.eql(u8, args[i], "--connect")) {
            i += 1;
            if (i >= args.len) return error.MissingConnectValue;
            connect_target = try ayllu_camouflage.reality.parseTarget(args[i]);
        } else if (std.mem.eql(u8, args[i], "--target")) {
            i += 1;
            if (i >= args.len) return error.MissingTargetValue;
            transcript_target = try ayllu_camouflage.reality.parseTarget(args[i]);
        } else if (std.mem.eql(u8, args[i], "--server-name")) {
            i += 1;
            if (i >= args.len) return error.MissingServerNameValue;
            server_name = args[i];
        } else if (std.mem.eql(u8, args[i], "--server-public-key")) {
            i += 1;
            if (i >= args.len) return error.MissingServerPublicKeyValue;
            server_public_key = try ayllu_camouflage.reality.decodeKey(args[i]);
        } else if (std.mem.eql(u8, args[i], "--client-private-key")) {
            i += 1;
            if (i >= args.len) return error.MissingClientPrivateKeyValue;
            client_private_key = try ayllu_camouflage.reality.decodeKey(args[i]);
        } else if (std.mem.eql(u8, args[i], "--short-id")) {
            i += 1;
            if (i >= args.len) return error.MissingShortIdValue;
            short_id = try ayllu_camouflage.reality.parseShortId(args[i]);
        } else if (std.mem.eql(u8, args[i], "--client-ver")) {
            i += 1;
            if (i >= args.len) return error.MissingClientVerValue;
            client_version = std.SemanticVersion.parse(args[i]) catch return error.BadClientVerValue;
        } else if (std.mem.eql(u8, args[i], "--min-client-ver")) {
            i += 1;
            if (i >= args.len) return error.MissingMinClientVerValue;
            min_client_version = std.SemanticVersion.parse(args[i]) catch return error.BadMinClientVerValue;
        } else if (std.mem.eql(u8, args[i], "--max-client-ver")) {
            i += 1;
            if (i >= args.len) return error.MissingMaxClientVerValue;
            max_client_version = std.SemanticVersion.parse(args[i]) catch return error.BadMaxClientVerValue;
        } else if (std.mem.eql(u8, args[i], "--path")) {
            i += 1;
            if (i >= args.len) return error.MissingPathValue;
            request_path = args[i];
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
        } else if (std.mem.eql(u8, args[i], "--max-response-bytes")) {
            i += 1;
            if (i >= args.len) return error.MissingMaxResponseBytesValue;
            max_response_bytes = std.fmt.parseInt(usize, args[i], 10) catch return error.BadMaxResponseBytesValue;
        } else if (std.mem.eql(u8, args[i], "--help") or std.mem.eql(u8, args[i], "-h")) {
            try printUsage(io);
            return;
        } else {
            try printUsage(io);
            return error.UnknownArg;
        }
    }

    const config: ayllu_camouflage.client.Config = .{
        .connect = connect_target orelse return error.MissingConnectValue,
        .public = .{
            .target = transcript_target orelse return error.MissingTargetValue,
            .server_public_key = server_public_key orelse return error.MissingServerPublicKeyValue,
            .min_client_version = min_client_version,
            .max_client_version = max_client_version,
        },
        .server_name = server_name orelse return error.MissingServerNameValue,
        .short_id = short_id orelse return error.MissingShortIdValue,
        .client_private_key = client_private_key orelse return error.MissingClientPrivateKeyValue,
        .client_version = client_version,
        .request_path = request_path,
        .token_policy = token_policy,
        .max_response_bytes = max_response_bytes,
    };
    try config.validate();

    const addr = listen_addr orelse try std.Io.net.IpAddress.parse(listen_host, listen_port);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);

    var stdout_buffer: [512]u8 = undefined;
    var stdout_writer: std.Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    try stdout_writer.interface.print(
        "ayllu-camouflage-client listening on {s}:{d} -> gateway {s}:{d} as {s}\n",
        .{ listen_host, listen_port, config.connect.host, config.connect.port, config.server_name },
    );
    try stdout_writer.interface.flush();

    while (true) {
        const client = server.accept(io) catch |err| {
            std.log.warn("accept failed: {t}", .{err});
            continue;
        };
        _ = io.async(sessionWrapper, .{ io, client.socket, config });
    }
}

fn sessionWrapper(io: std.Io, socket: std.Io.net.Socket, config: ayllu_camouflage.client.Config) void {
    ayllu_camouflage.client.sessionWithConfig(io, socket, config) catch |err| switch (err) {
        error.EndOfStream, error.Canceled => {},
        else => std.log.warn("camouflage client session ended: {t}", .{err}),
    };
}

fn printUsage(io: std.Io) !void {
    var buf: [2048]u8 = undefined;
    var w: std.Io.File.Writer = .init(.stdout(), io, &buf);
    try w.interface.writeAll(
        \\ayllu-camouflage-client — local SOCKS bridge over outer camouflage
        \\
        \\Usage:
        \\  ayllu-camouflage-client --connect HOST:PORT --target HOST:PORT --server-name NAME
        \\    --server-public-key KEY --client-private-key KEY --short-id HEX [options]
        \\
        \\Required:
        \\  --connect HOST:PORT       remote camouflage gateway address
        \\  --target HOST:PORT        public transcript target identity
        \\  --server-name NAME        Host header / server name
        \\  --server-public-key KEY   server public key (base64url, no padding)
        \\  --client-private-key KEY  client private key (base64url, no padding)
        \\  --short-id HEX            selected short id
        \\
        \\Options:
        \\  --listen HOST:PORT         local bind address (default 127.0.0.1:1080)
        \\  --client-ver X.Y.Z         client version sent in admission (default 1.0.0)
        \\  --min-client-ver X.Y.Z     transcript min client version, if server uses one
        \\  --max-client-ver X.Y.Z     transcript max client version, if server uses one
        \\  --path PATH                admission path (default /pivot)
        \\  --token-slot-ms N          token slot size (default 1000)
        \\  --token-max-age-slots N    accepted stale slots (default 2)
        \\  --token-max-future-slots N accepted future slots (default 1)
        \\  --max-response-bytes N     max gateway head size (default 4096)
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
    const host4, const port4, const addr4 = try parseListenSpec("127.0.0.1:1080");
    try std.testing.expectEqualStrings("127.0.0.1", host4);
    try std.testing.expectEqual(@as(u16, 1080), port4);
    try std.testing.expect(addr4 == .ip4);

    const host6, const port6, const addr6 = try parseListenSpec("[::1]:1081");
    try std.testing.expectEqualStrings("::1", host6);
    try std.testing.expectEqual(@as(u16, 1081), port6);
    try std.testing.expect(addr6 == .ip6);
}
