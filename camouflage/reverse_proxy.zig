//! Honest fallback: when admission fails (or the client turns out to be an
//! active probe), we forward the client's bytes to a real whitelisted cover
//! host and pipe the cover's response back. DPI probing therefore gets a
//! genuine response byte-for-byte from the cover site; our IP is not
//! distinguishable from that cover host at the TCP-payload level.
//!
//! Key design: this is TCP-level passthrough, not TLS termination. We buffer
//! what the client already sent (e.g., a TLS ClientHello we partially read)
//! and write it to the cover server first, then bidirectional-relay the
//! rest. No second TLS session on our side means no telltale MITM cert.

const std = @import("std");
const proxy = @import("ayllu-proxy");

pub const CoverTarget = struct {
    host: []const u8,
    port: u16 = 443,
};

pub const Error = error{
    CoverUnreachable,
} || proxy.relay.PipeError || proxy.timeouts.Error || std.Io.Cancelable || std.Io.Writer.Error;

/// Dials the cover target, writes `buffered_head` (bytes the client already
/// sent and we peeked/consumed), then bidirectional-relays between the
/// client and the cover. Exits cleanly on either side's EOF; on the cover-
/// unreachable path bubbles up error.CoverUnreachable.
///
/// `client_reader` MUST be a `std.Io.net.Stream.Reader` (or compatible
/// interface) whose remaining input will also be forwarded after
/// `buffered_head`. `client_writer` receives bytes coming back from cover.
pub fn forwardBuffered(
    io: std.Io,
    cover: CoverTarget,
    buffered_head: []const u8,
    client_reader: *std.Io.Reader,
    client_writer: *std.Io.Writer,
    client_net_stream: ?*const std.Io.net.Stream,
    deadline: std.Io.Clock.Timestamp,
) Error!void {
    const host = std.Io.net.HostName.init(cover.host) catch return error.CoverUnreachable;
    const cover_stream = proxy.timeouts.connectHostNameDeadline(io, host, cover.port, deadline) catch |err| switch (err) {
        error.Timeout => return error.Timeout,
        else => return error.CoverUnreachable,
    };
    defer cover_stream.close(io);

    var ur_buf: [4096]u8 = undefined;
    var uw_buf: [4096]u8 = undefined;
    var cover_reader = std.Io.net.Stream.Reader.init(cover_stream, io, &ur_buf);
    var cover_writer = std.Io.net.Stream.Writer.init(cover_stream, io, &uw_buf);

    // Replay the bytes the client already sent onto the cover socket BEFORE
    // any relay kicks in, so the cover's parser sees the exact stream it
    // would have seen from the client directly.
    if (buffered_head.len > 0) {
        try cover_writer.interface.writeAll(buffered_head);
        try cover_writer.interface.flush();
    }

    try proxy.relay.bidirectionalWithDeadline(
        io,
        .{
            .reader = client_reader,
            .writer = client_writer,
            .net_stream = client_net_stream,
        },
        .{
            .reader = &cover_reader.interface,
            .writer = &cover_writer.interface,
            .net_stream = &cover_stream,
        },
        null,
    );
}

test "CoverTarget defaults to port 443" {
    const c: CoverTarget = .{ .host = "archive.ubuntu.com" };
    try std.testing.expectEqual(@as(u16, 443), c.port);
}
