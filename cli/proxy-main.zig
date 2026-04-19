const std = @import("std");
const ayllu_proxy = @import("ayllu-proxy");

const default_listen_host = "0.0.0.0";
const default_listen_port: u16 = 1080;

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const io = init.io;

    const args = try init.minimal.args.toSlice(gpa);

    var listen_host: []const u8 = default_listen_host;
    var listen_port: u16 = default_listen_port;
    var listen_addr: ?std.Io.net.IpAddress = null;
    var config: ayllu_proxy.daemon.Config = .{};

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--listen")) {
            i += 1;
            if (i >= args.len) return error.MissingListenValue;
            const spec = args[i];
            const parsed_host, const parsed_port, const parsed_addr = try parseListenSpec(spec);
            listen_host = parsed_host;
            listen_port = parsed_port;
            listen_addr = parsed_addr;
        } else if (std.mem.eql(u8, args[i], "--auth-file")) {
            i += 1;
            if (i >= args.len) return error.MissingAuthFileValue;
            config.auth = try ayllu_proxy.auth.loadFromFile(io, gpa, args[i]);
        } else if (std.mem.eql(u8, args[i], "--help") or std.mem.eql(u8, args[i], "-h")) {
            try printUsage(io);
            return;
        } else {
            try printUsage(io);
            return error.UnknownArg;
        }
    }

    const addr = listen_addr orelse try std.Io.net.IpAddress.parse(listen_host, listen_port);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);

    var stdout_buffer: [256]u8 = undefined;
    var stdout_writer: std.Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    try stdout_writer.interface.print(
        "ayllu-proxy SOCKS5 listening on {s}:{d}\n",
        .{ listen_host, listen_port },
    );
    try stdout_writer.interface.flush();

    while (true) {
        const client_stream = server.accept(io) catch |err| {
            std.log.warn("accept failed: {t}", .{err});
            continue;
        };
        _ = io.async(sessionWrapper, .{ io, client_stream.socket, config });
    }
}

fn sessionWrapper(io: std.Io, socket: std.Io.net.Socket, config: ayllu_proxy.daemon.Config) void {
    ayllu_proxy.daemon.sessionWithConfig(io, socket, config) catch |err| switch (err) {
        error.EndOfStream, error.Canceled => {},
        else => std.log.warn("session ended: {t}", .{err}),
    };
}

fn printUsage(io: std.Io) !void {
    var buf: [512]u8 = undefined;
    var w: std.Io.File.Writer = .init(.stdout(), io, &buf);
    try w.interface.writeAll(
        \\ayllu-proxy — SOCKS5 (RFC 1928) proxy daemon
        \\
        \\Usage: ayllu-proxy [--listen HOST:PORT] [--auth-file PATH]
        \\
        \\Options:
        \\  --listen     Interface to bind (default 0.0.0.0:1080)
        \\  --auth-file  File with `username:password` for RFC 1929 auth
        \\  --help       Show this help
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
    if (std.mem.indexOfScalar(u8, spec[0..colon], ':') != null) {
        return error.BadListenSpec;
    }
    const host = spec[0..colon];
    const port = std.fmt.parseInt(u16, spec[colon + 1 ..], 10) catch return error.BadListenSpec;
    return .{ host, port, try std.Io.net.IpAddress.parse(host, port) };
}

test "parseListenSpec parses IPv4 listen spec" {
    const host, const port, const addr = try parseListenSpec("127.0.0.1:1080");
    try std.testing.expectEqualStrings("127.0.0.1", host);
    try std.testing.expect(addr == .ip4);
    try std.testing.expectEqual(@as(u16, 1080), port);
    try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &addr.ip4.bytes);
}

test "parseListenSpec parses bracketed IPv6 listen spec" {
    const host, const port, const addr = try parseListenSpec("[::1]:1080");
    try std.testing.expectEqualStrings("::1", host);
    try std.testing.expect(addr == .ip6);
    try std.testing.expectEqual(@as(u16, 1080), port);
}

test "parseListenSpec rejects bare IPv6 form" {
    try std.testing.expectError(error.BadListenSpec, parseListenSpec("::1:1080"));
}
