//! Minimal Prometheus-style counters. No HistogramVec yet — just counters,
//! which is enough to distinguish "REALITY rejected" from "upstream
//! unreachable" from "DPI-probe silent drop" in the field. Operator runs a
//! scraper pointing at `--metrics-listen` and can alert on counter jumps.
//!
//! All counters are lock-free via `std.atomic.Value(u64)` so `inc()` from a
//! session task is safe without any global mutex.

const std = @import("std");

pub const Counter = struct {
    value: std.atomic.Value(u64) = .init(0),

    pub fn inc(self: *Counter) void {
        _ = self.value.fetchAdd(1, .monotonic);
    }

    pub fn add(self: *Counter, n: u64) void {
        _ = self.value.fetchAdd(n, .monotonic);
    }

    pub fn load(self: *const Counter) u64 {
        return self.value.load(.monotonic);
    }
};

pub const Registry = struct {
    sessions_total: Counter = .{},
    admission_success_total: Counter = .{},
    admission_fallback_total: Counter = .{},
    admission_silent_drops_total: Counter = .{},
    upstream_connect_errors_total: Counter = .{},
    handshake_timeouts_total: Counter = .{},
    bytes_relayed_total: Counter = .{},
    /// Sub-counter of admission_fallback_total: bumped only when the
    /// REALITY transport rejects a session (SNI miss, missing X25519,
    /// bad AuthKey MAC, etc.). Exists alongside the generic fallback
    /// counter so operators can tell REALITY-specific probes apart
    /// from the LegacyHttp admission traffic.
    admission_reality_rejected_total: Counter = .{},

    /// Render the full registry in Prometheus text format (openmetrics 0.0.4).
    pub fn render(self: *const Registry, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try renderCounter(w, "ayllu_sessions_total", self.sessions_total.load());
        try renderCounter(w, "ayllu_admission_success_total", self.admission_success_total.load());
        try renderCounter(w, "ayllu_admission_fallback_total", self.admission_fallback_total.load());
        try renderCounter(w, "ayllu_admission_silent_drops_total", self.admission_silent_drops_total.load());
        try renderCounter(w, "ayllu_upstream_connect_errors_total", self.upstream_connect_errors_total.load());
        try renderCounter(w, "ayllu_handshake_timeouts_total", self.handshake_timeouts_total.load());
        try renderCounter(w, "ayllu_bytes_relayed_total", self.bytes_relayed_total.load());
        try renderCounter(w, "ayllu_admission_reality_rejected_total", self.admission_reality_rejected_total.load());
    }
};

fn renderCounter(w: *std.Io.Writer, name: []const u8, v: u64) std.Io.Writer.Error!void {
    try w.print("# TYPE {s} counter\n{s} {d}\n", .{ name, name, v });
}

/// HTTP handler loop for a dedicated metrics listener. Expects any incoming
/// HTTP/1.x GET (path ignored in this MVP) and responds with the full
/// Prometheus text payload. Runs until `server.deinit` is called from
/// elsewhere.
pub fn serve(io: std.Io, server: *std.Io.net.Server, registry: *const Registry) !void {
    while (true) {
        const stream = server.accept(io) catch |err| {
            if (err == error.SocketNotListening) return;
            continue;
        };
        handleOnce(io, stream, registry) catch {};
    }
}

pub fn handleOnce(io: std.Io, stream: std.Io.net.Stream, registry: *const Registry) !void {
    defer stream.close(io);

    var rbuf: [2048]u8 = undefined;
    var wbuf: [8192]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(stream, io, &rbuf);
    var writer = std.Io.net.Stream.Writer.init(stream, io, &wbuf);

    // Drain HTTP request head (best effort — we don't care about path).
    var need: usize = 1;
    while (true) {
        const buffered = try reader.interface.peekGreedy(need);
        if (std.mem.indexOf(u8, buffered, "\r\n\r\n")) |end| {
            _ = try reader.interface.take(end + 4);
            break;
        }
        if (buffered.len >= 4096) return error.HeaderTooLarge;
        need = buffered.len + 1;
    }

    try writer.interface.writeAll(
        "HTTP/1.1 200 OK\r\n" ++
            "Content-Type: text/plain; version=0.0.4\r\n" ++
            "Connection: close\r\n\r\n",
    );
    try registry.render(&writer.interface);
    try writer.interface.flush();
}

test "Counter: atomic inc/add/load" {
    var c: Counter = .{};
    c.inc();
    c.inc();
    c.add(5);
    try std.testing.expectEqual(@as(u64, 7), c.load());
}

test "Registry: render produces Prometheus-style counter lines" {
    var reg: Registry = .{};
    reg.sessions_total.inc();
    reg.admission_success_total.add(3);
    reg.bytes_relayed_total.add(1024);

    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try reg.render(&w);

    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "# TYPE ayllu_sessions_total counter\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "ayllu_sessions_total 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "ayllu_admission_success_total 3\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "ayllu_bytes_relayed_total 1024\n") != null);
}

test "Registry: zero-counter renders zero values" {
    const reg: Registry = .{};
    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try reg.render(&w);
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "ayllu_sessions_total 0\n") != null);
}

test "Registry: admission_reality_rejected_total is exposed in render output" {
    var reg: Registry = .{};
    reg.admission_reality_rejected_total.add(7);

    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try reg.render(&w);

    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "# TYPE ayllu_admission_reality_rejected_total counter\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "ayllu_admission_reality_rejected_total 7\n") != null);
}

fn acceptAndHandleOnce(io: std.Io, server: *std.Io.net.Server, registry: *const Registry) anyerror!void {
    const stream = try server.accept(io);
    try handleOnce(io, stream, registry);
}

test "handleOnce: GET /metrics returns 200 with counter payload" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var reg: Registry = .{};
    reg.sessions_total.inc();

    var server = try (@as(std.Io.net.IpAddress, .{
        .ip4 = std.Io.net.Ip4Address.loopback(0),
    })).listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();

    var accept_task = io.async(acceptAndHandleOnce, .{ io, &server, &reg });
    errdefer accept_task.cancel(io) catch {};

    const client = try (@as(std.Io.net.IpAddress, .{
        .ip4 = std.Io.net.Ip4Address.loopback(port),
    })).connect(io, .{ .mode = .stream });
    defer client.close(io);

    var cr_buf: [4096]u8 = undefined;
    var cw_buf: [512]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(client, io, &cr_buf);
    var writer = std.Io.net.Stream.Writer.init(client, io, &cw_buf);

    try writer.interface.writeAll("GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n");
    try writer.interface.flush();

    // Consume full response (server closes on completion).
    const body = reader.interface.allocRemaining(std.testing.allocator, .unlimited) catch |err| blk: {
        if (err == error.EndOfStream) break :blk &.{};
        return err;
    };
    defer std.testing.allocator.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "200 OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "ayllu_sessions_total 1") != null);

    try accept_task.await(io);
}
