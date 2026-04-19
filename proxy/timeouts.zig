//! Deadline / timeout helpers shared across proxy and camouflage paths.
//!
//! Every long-lived I/O step (handshake read, upstream connect, idle relay)
//! must either finish before a deadline or fail with error.Timeout. Without
//! this a slow-loris or stalled upstream pins a worker forever.
//!
//! Each wrapper races the real op against `std.Io.Timeout.sleep` on a
//! `std.Io.Select`; loser is cancelled via `cancelDiscard`.

const std = @import("std");
const relay = @import("relay.zig");

pub const Error = error{Timeout};

/// Default deadlines (milliseconds). Tuned for Telegram-class interactive
/// traffic. Idle relay is longer because a parked Telegram session can sit
/// quiet between pings for minutes.
pub const Defaults = struct {
    pub const handshake_ms: i64 = 10_000;
    pub const upstream_connect_ms: i64 = 10_000;
    pub const idle_relay_ms: i64 = 180_000;
};

pub fn deadlineFromNowMs(io: std.Io, ms: i64) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .raw = .fromMilliseconds(ms), .clock = .awake });
}

inline fn asTimeout(deadline: std.Io.Clock.Timestamp) std.Io.Timeout {
    return .{ .deadline = deadline };
}

/// Run `relay.pipeAll(src, dst)` with a hard deadline. Returns the number of
/// bytes piped on success; `error.Timeout` if the deadline fires before EOF.
pub fn pipeAllDeadline(
    io: std.Io,
    src: *std.Io.Reader,
    dst: *std.Io.Writer,
    deadline: std.Io.Clock.Timestamp,
) (relay.PipeError || Error || std.Io.Cancelable)!usize {
    const Outcome = union(enum) {
        pipe: relay.PipeError!usize,
        expire: std.Io.Cancelable!void,
    };
    var buf: [2]Outcome = undefined;
    var select = std.Io.Select(Outcome).init(io, &buf);
    defer select.cancelDiscard();

    select.async(.pipe, relay.pipeAll, .{ src, dst });
    select.async(.expire, std.Io.Timeout.sleep, .{ asTimeout(deadline), io });

    return switch (try select.await()) {
        .pipe => |r| try r,
        .expire => error.Timeout,
    };
}

/// Peek N bytes from `reader` with a hard deadline. Returns the peeked slice
/// (still in the reader's buffer) on success.
pub fn peekDeadline(
    io: std.Io,
    reader: *std.Io.Reader,
    n: usize,
    deadline: std.Io.Clock.Timestamp,
) (std.Io.Reader.Error || Error || std.Io.Cancelable)![]u8 {
    const Outcome = union(enum) {
        ok: std.Io.Reader.Error![]u8,
        expire: std.Io.Cancelable!void,
    };
    var buf: [2]Outcome = undefined;
    var select = std.Io.Select(Outcome).init(io, &buf);
    defer select.cancelDiscard();

    select.async(.ok, std.Io.Reader.peek, .{ reader, n });
    select.async(.expire, std.Io.Timeout.sleep, .{ asTimeout(deadline), io });

    return switch (try select.await()) {
        .ok => |r| try r,
        .expire => error.Timeout,
    };
}

/// Connect to an IpAddress, giving up after `deadline`. Uses a Select race
/// rather than `ConnectOptions.timeout` because `std.Io.Threaded` currently
/// `@panic`s on that path (TODO in 0.16 stdlib). Switching to Uring/Kqueue
/// at runtime will benefit automatically if/when the stdlib fills it in.
pub fn connectDeadline(
    io: std.Io,
    address: *const std.Io.net.IpAddress,
    deadline: std.Io.Clock.Timestamp,
) (std.Io.net.IpAddress.ConnectError || Error || std.Io.Cancelable)!std.Io.net.Stream {
    const Outcome = union(enum) {
        ok: std.Io.net.IpAddress.ConnectError!std.Io.net.Stream,
        expire: std.Io.Cancelable!void,
    };
    var buf: [2]Outcome = undefined;
    var select = std.Io.Select(Outcome).init(io, &buf);
    defer select.cancelDiscard();

    select.async(.ok, std.Io.net.IpAddress.connect, .{ address, io, .{ .mode = .stream } });
    select.async(.expire, std.Io.Timeout.sleep, .{ asTimeout(deadline), io });

    return switch (try select.await()) {
        .ok => |r| try r,
        .expire => error.Timeout,
    };
}

/// Connect via HostName (DNS + connect) with a single deadline covering both.
/// Returns error.Timeout if either DNS or connect runs past the deadline.
pub fn connectHostNameDeadline(
    io: std.Io,
    host_name: std.Io.net.HostName,
    port: u16,
    deadline: std.Io.Clock.Timestamp,
) (std.Io.net.HostName.ConnectError || Error || std.Io.Cancelable)!std.Io.net.Stream {
    const Outcome = union(enum) {
        ok: std.Io.net.HostName.ConnectError!std.Io.net.Stream,
        expire: std.Io.Cancelable!void,
    };
    var buf: [2]Outcome = undefined;
    var select = std.Io.Select(Outcome).init(io, &buf);
    defer select.cancelDiscard();

    select.async(.ok, std.Io.net.HostName.connect, .{ host_name, io, port, .{ .mode = .stream } });
    select.async(.expire, std.Io.Timeout.sleep, .{ asTimeout(deadline), io });

    return switch (try select.await()) {
        .ok => |r| try r,
        .expire => error.Timeout,
    };
}

test "deadlineFromNowMs: later deadline compares greater" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const a = deadlineFromNowMs(io, 1_000);
    const b = deadlineFromNowMs(io, 2_000);
    try std.testing.expect(a.compare(.lt, b));
}

test "pipeAllDeadline returns byte count when pipe finishes before deadline" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const payload = "fast path bytes";
    var r: std.Io.Reader = .fixed(payload);
    var out: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);

    const n = try pipeAllDeadline(io, &r, &w, deadlineFromNowMs(io, 5_000));
    try std.testing.expectEqual(payload.len, n);
    try std.testing.expectEqualStrings(payload, out[0..n]);
}

test "peekDeadline returns bytes when present within deadline" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var r: std.Io.Reader = .fixed("abcdef");
    const got = try peekDeadline(io, &r, 3, deadlineFromNowMs(io, 5_000));
    try std.testing.expectEqualStrings("abc", got);
}

test "Defaults carry sane values" {
    try std.testing.expect(Defaults.handshake_ms > 0);
    try std.testing.expect(Defaults.upstream_connect_ms > 0);
    try std.testing.expect(Defaults.idle_relay_ms > Defaults.handshake_ms);
}
