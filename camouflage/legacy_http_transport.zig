//! HTTP-like admission over plain TCP. The client sends a GET/POST
//! with `X-Ayllu-*` headers carrying a REALITY client key, a short
//! id, a timestamp, and a signed token. On a valid token the server
//! writes `101 Switching Protocols` and the dispatcher pivots to
//! SOCKS5 on the same socket. On any parse or validation failure the
//! transport returns the buffered bytes to the dispatcher, which
//! forwards them to a cover host via reverse-proxy so an active probe
//! receives a byte-for-byte real response.
//!
//! This is the pre-REALITY-TLS admission shape, retained as a
//! first-class `OuterTransport` impl for the `ayllu-camouflage-client`
//! local bridge and for backward-compat of the SVA test surface.

const std = @import("std");
const proxy = @import("ayllu-proxy");
const transport = @import("transport.zig");
const pivot = @import("pivot.zig");
const tokens = @import("tokens.zig");

pub const max_request_head_bytes = 8192;
pub const replay_cache_entries = 4096;

/// Configuration owned by the caller (the server `State`). The
/// transport itself borrows `replay_cache` and `mutex`; those live
/// beyond an individual session because the replay cache has to span
/// the lifetime of the process.
pub const Shared = struct {
    pivot_config: pivot.Config,
    replay_cache: *tokens.ReplayCache(replay_cache_entries),
    mutex: *std.Io.Mutex,
};

pub const LegacyHttpTransport = struct {
    shared: Shared,

    pub fn init(shared: Shared) LegacyHttpTransport {
        return .{ .shared = shared };
    }

    pub fn outerTransport(self: *LegacyHttpTransport) transport.OuterTransport {
        return .{ .ctx = @ptrCast(self), .vtable = &vtable };
    }

    const vtable: transport.OuterTransport.VTable = .{
        .admit = admitFn,
        .name = nameFn,
    };

    fn nameFn(_: *anyopaque) []const u8 {
        return "legacy-http";
    }

    fn admitFn(
        ctx: *anyopaque,
        admission: transport.AdmissionContext,
    ) anyerror!transport.AdmitOutcome {
        const self: *LegacyHttpTransport = @ptrCast(@alignCast(ctx));
        return self.admit(admission);
    }

    pub fn admit(
        self: *LegacyHttpTransport,
        admission: transport.AdmissionContext,
    ) anyerror!transport.AdmitOutcome {
        const admission_deadline = proxy.timeouts.deadlineFromNowMs(
            admission.io,
            proxy.timeouts.Defaults.handshake_ms,
        );
        const head = takeRequestHeadWithDeadline(
            admission.io,
            admission.reader,
            self.shared.pivot_config.max_request_bytes,
            admission_deadline,
        ) catch |err| switch (err) {
            error.EndOfStream, error.Timeout => return err,
            else => {
                // Malformed / oversized header. Replay whatever the
                // client already sent to the cover host so an active
                // probe of arbitrary HTTP trash still sees authentic
                // upstream bytes.
                return transport.AdmitOutcome{
                    .fallback = .{ .buffered_head = admission.reader.buffered() },
                };
            },
        };

        self.shared.mutex.lockUncancelable(admission.io);
        const decision = pivot.classify(
            replay_cache_entries,
            head,
            self.shared.pivot_config,
            nowUnixMs(admission.io),
            self.shared.replay_cache,
        ) catch {
            self.shared.mutex.unlock(admission.io);
            return transport.AdmitOutcome{ .fallback = .{ .buffered_head = head } };
        };
        self.shared.mutex.unlock(admission.io);

        switch (decision) {
            .fallback => return transport.AdmitOutcome{
                .fallback = .{ .buffered_head = head },
            },
            .pivot => {
                try admission.writer.writeAll(
                    "HTTP/1.1 101 Switching Protocols\r\n" ++
                        "Connection: Upgrade\r\n" ++
                        "Upgrade: ayllu-socks\r\n\r\n",
                );
                try admission.writer.flush();
                return transport.AdmitOutcome{
                    .pivoted = .{
                        .stream = .{
                            .reader = admission.reader,
                            .writer = admission.writer,
                            .net_stream = admission.net_stream,
                        },
                    },
                };
            },
        }
    }
};

fn nowUnixMs(io: std.Io) i64 {
    return @intCast(@divFloor(std.Io.Clock.real.now(io).nanoseconds, 1_000_000));
}

fn takeRequestHead(reader: *std.Io.Reader, max_request_bytes: usize) ![]const u8 {
    if (max_request_bytes == 0 or max_request_bytes > max_request_head_bytes) {
        return error.HeaderTooLarge;
    }

    var need: usize = 1;
    while (true) {
        const buffered = try reader.peekGreedy(need);
        if (std.mem.indexOf(u8, buffered, "\r\n\r\n")) |header_end| {
            return reader.take(header_end + 4);
        }
        if (buffered.len >= max_request_bytes) return error.HeaderTooLarge;
        need = @min(max_request_bytes, buffered.len + 1);
    }
}

fn takeRequestHeadWithDeadline(
    io: std.Io,
    reader: *std.Io.Reader,
    max_request_bytes: usize,
    deadline: std.Io.Clock.Timestamp,
) ![]const u8 {
    const Outcome = union(enum) {
        ok: anyerror![]const u8,
        expire: std.Io.Cancelable!void,
    };
    var buf: [2]Outcome = undefined;
    var select = std.Io.Select(Outcome).init(io, &buf);
    defer select.cancelDiscard();
    select.async(.ok, takeRequestHead, .{ reader, max_request_bytes });
    select.async(.expire, std.Io.Timeout.sleep, .{ .{ .deadline = deadline }, io });
    return switch (try select.await()) {
        .ok => |r| try r,
        .expire => error.Timeout,
    };
}

test "LegacyHttpTransport: admit returns fallback on malformed header (no CRLFCRLF)" {
    // Header without the \r\n\r\n terminator up to the limit -> HeaderTooLarge
    // -> fallback with the buffered bytes, NOT an error.
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Use an 80-byte body and a 64-byte max so we trip HeaderTooLarge
    // before finding the terminator. `peekGreedy` will buffer what
    // it sees and then admit returns .fallback.
    const junk = "A" ** 80;
    var fixed_reader: std.Io.Reader = .fixed(junk);
    var wbuf: [64]u8 = undefined;
    var fixed_writer: std.Io.Writer = .fixed(&wbuf);
    const stream: std.Io.net.Stream = .{ .socket = undefined };

    var cache: tokens.ReplayCache(replay_cache_entries) = .{};
    var mu: std.Io.Mutex = .init;
    var xport = LegacyHttpTransport.init(.{
        .pivot_config = .{
            .max_request_bytes = 64,
            .reality = .{
                .target = .{ .host = "example.com", .port = 443 },
                .server_names = &.{"example.com"},
                .private_key = [_]u8{0} ** 32,
                .short_ids = &.{},
            },
        },
        .replay_cache = &cache,
        .mutex = &mu,
    });

    const outcome = try xport.admit(.{
        .io = io,
        .reader = &fixed_reader,
        .writer = &fixed_writer,
        .net_stream = &stream,
        .peer_key = @import("rate_limit.zig").ipv4_zero_prefix,
        .allocator = std.testing.allocator,
    });
    try std.testing.expectEqual(
        std.meta.Tag(transport.AdmitOutcome).fallback,
        std.meta.activeTag(outcome),
    );
    // Nothing written back to the client.
    try std.testing.expectEqual(@as(usize, 0), fixed_writer.buffered().len);
}

test "LegacyHttpTransport: admit returns fallback when pivot.classify rejects the head" {
    // Well-formed HTTP head but no admission token -> pivot.classify
    // returns .fallback -> admit returns .fallback with the full head.
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const head = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    var fixed_reader: std.Io.Reader = .fixed(head);
    var wbuf: [128]u8 = undefined;
    var fixed_writer: std.Io.Writer = .fixed(&wbuf);
    const stream: std.Io.net.Stream = .{ .socket = undefined };

    var cache: tokens.ReplayCache(replay_cache_entries) = .{};
    var mu: std.Io.Mutex = .init;
    var xport = LegacyHttpTransport.init(.{
        .pivot_config = .{
            .max_request_bytes = 4096,
            .reality = .{
                .target = .{ .host = "example.com", .port = 443 },
                .server_names = &.{"example.com"},
                .private_key = [_]u8{0} ** 32,
                .short_ids = &.{},
            },
        },
        .replay_cache = &cache,
        .mutex = &mu,
    });

    const outcome = try xport.admit(.{
        .io = io,
        .reader = &fixed_reader,
        .writer = &fixed_writer,
        .net_stream = &stream,
        .peer_key = @import("rate_limit.zig").ipv4_zero_prefix,
        .allocator = std.testing.allocator,
    });
    try std.testing.expectEqual(
        std.meta.Tag(transport.AdmitOutcome).fallback,
        std.meta.activeTag(outcome),
    );
    try std.testing.expectEqualStrings(head, outcome.fallback.buffered_head);
    // Still no bytes written back to the client on fallback.
    try std.testing.expectEqual(@as(usize, 0), fixed_writer.buffered().len);
}

test "LegacyHttpTransport.name() returns \"legacy-http\" through the vtable" {
    var cache: tokens.ReplayCache(replay_cache_entries) = .{};
    var mu: std.Io.Mutex = .init;
    var xport = LegacyHttpTransport.init(.{
        .pivot_config = .{
            .max_request_bytes = 4096,
            .reality = .{
                .target = .{ .host = "example.com", .port = 443 },
                .server_names = &.{"example.com"},
                .private_key = [_]u8{0} ** 32,
                .short_ids = &.{},
            },
        },
        .replay_cache = &cache,
        .mutex = &mu,
    });
    const t = xport.outerTransport();
    try std.testing.expectEqualStrings("legacy-http", t.name());
}
