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

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--listen")) {
            i += 1;
            if (i >= args.len) return error.MissingListenValue;
            const spec = args[i];
            const colon = std.mem.lastIndexOfScalar(u8, spec, ':') orelse return error.BadListenSpec;
            listen_host = spec[0..colon];
            listen_port = try std.fmt.parseInt(u16, spec[colon + 1 ..], 10);
        } else if (std.mem.eql(u8, args[i], "--help") or std.mem.eql(u8, args[i], "-h")) {
            try printUsage(io);
            return;
        } else {
            try printUsage(io);
            return error.UnknownArg;
        }
    }

    const addr: std.Io.net.IpAddress = try std.Io.net.IpAddress.parse(listen_host, listen_port);
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
        _ = io.async(sessionWrapper, .{ io, client_stream.socket });
    }
}

fn sessionWrapper(io: std.Io, socket: std.Io.net.Socket) void {
    ayllu_proxy.daemon.session(io, socket) catch |err| switch (err) {
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
        \\Usage: ayllu-proxy [--listen HOST:PORT]
        \\
        \\Options:
        \\  --listen  Interface to bind (default 0.0.0.0:1080)
        \\  --help    Show this help
        \\
    );
    try w.interface.flush();
}
