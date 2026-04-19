//! Relay — forwards bytes between two std.Io streams. In the SOCKS5 daemon
//! it's called after a successful handshake: client <-> upstream.

const std = @import("std");

pub const PipeError = std.Io.Reader.StreamRemainingError || std.Io.Writer.Error;

/// Pumps everything src can read into dst until EOF, then flushes dst.
/// Returns the number of bytes pumped.
pub fn pipeAll(src: *std.Io.Reader, dst: *std.Io.Writer) PipeError!usize {
    var total: usize = 0;
    while (true) {
        const n = src.stream(dst, .unlimited) catch |err| switch (err) {
            error.EndOfStream => break,
            else => |e| return e,
        };
        total += n;
        try dst.flush();
    }
    try dst.flush();
    return total;
}

pub const Stream = struct {
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    net_stream: ?*const std.Io.net.Stream = null,
};

/// Runs two `pipeAll`s in parallel: client.reader -> upstream.writer and
/// upstream.reader -> client.writer. When the first direction finishes,
/// half-closes the peer and waits for the second, so an ordinary FIN
/// doesn't turn into a hung task.
pub fn bidirectional(io: std.Io, client: Stream, upstream: Stream) !void {
    const Outcome = union(enum) {
        up: PipeError!usize,
        down: PipeError!usize,
    };

    var select_buf: [2]Outcome = undefined;
    var select = std.Io.Select(Outcome).init(io, &select_buf);
    defer select.cancelDiscard();

    select.async(.up, pipeAll, .{ client.reader, upstream.writer });
    select.async(.down, pipeAll, .{ upstream.reader, client.writer });

    switch (try select.await()) {
        .up => |up_res| {
            _ = try up_res;
            halfCloseSend(upstream, io);
            switch (try select.await()) {
                .down => |down_res| _ = try down_res,
                .up => unreachable,
            }
        },
        .down => |down_res| {
            _ = try down_res;
            halfCloseSend(client, io);
            switch (try select.await()) {
                .up => |up_res| _ = try up_res,
                .down => unreachable,
            }
        },
    }
}

fn halfCloseSend(stream: Stream, io: std.Io) void {
    const net_stream = stream.net_stream orelse return;
    net_stream.shutdown(io, .send) catch {};
}

test "pipeAll copies fixed reader into fixed writer" {
    const payload = "hello, ayllu proxy";
    var r: std.Io.Reader = .fixed(payload);
    var out: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    const n = try pipeAll(&r, &w);
    try std.testing.expectEqual(payload.len, n);
    try std.testing.expectEqualStrings(payload, out[0..n]);
}

test "pipeAll on empty reader returns 0" {
    var r: std.Io.Reader = .fixed("");
    var out: [8]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try std.testing.expectEqual(@as(usize, 0), try pipeAll(&r, &w));
}

test "pipeAll on large-ish payload passes bytes through unchanged" {
    const size = 64 * 1024;
    var payload: [size]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @as(u8, @truncate(i *% 31));
    var r: std.Io.Reader = .fixed(&payload);
    var out: [size]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    const n = try pipeAll(&r, &w);
    try std.testing.expectEqual(size, n);
    try std.testing.expectEqualSlices(u8, &payload, out[0..n]);
}

test "bidirectional under Threaded io exchanges both directions to EOF" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_to_upstream = "C->U payload";
    const upstream_to_client = "U->C payload";

    var client_r: std.Io.Reader = .fixed(client_to_upstream);
    var upstream_r: std.Io.Reader = .fixed(upstream_to_client);

    var client_out: [64]u8 = undefined;
    var upstream_out: [64]u8 = undefined;
    var client_w: std.Io.Writer = .fixed(&client_out);
    var upstream_w: std.Io.Writer = .fixed(&upstream_out);

    try bidirectional(
        io,
        .{ .reader = &client_r, .writer = &client_w },
        .{ .reader = &upstream_r, .writer = &upstream_w },
    );

    try std.testing.expectEqualStrings(client_to_upstream, upstream_out[0..client_to_upstream.len]);
    try std.testing.expectEqualStrings(upstream_to_client, client_out[0..upstream_to_client.len]);
}
