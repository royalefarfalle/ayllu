//! Outer-transport vtable. Each transport (Reality, Shadowsocks,
//! LegacyHttp) implements `OuterTransport.VTable.admit`, which reads
//! enough bytes to decide the fate of a session and returns an
//! `AdmitOutcome` telling the dispatcher in `server.zig` whether to
//! pivot (with possibly-wrapped stream + optional inner target),
//! reverse-proxy to a cover site, or silently close.
//!
//! The vtable is the seam where REALITY TLS 1.3 and SS-2022 slot in
//! without touching the dispatcher. Rate-limit, metrics, and cover
//! routing live in the dispatcher and are transport-agnostic.

const std = @import("std");
const ayllu_proxy = @import("ayllu-proxy");
const rate_limit = @import("rate_limit.zig");

/// Target extracted by a transport that carries addressing in-band (e.g.
/// Shadowsocks-2022 encodes the destination inside the first encrypted
/// frame). REALITY leaves this null — the dispatcher runs SOCKS5 inside
/// the pivoted stream and the client picks the target itself.
pub const InnerTarget = struct {
    address: ayllu_proxy.socks5.Address,
    port: u16,
};

/// Returned when a transport accepted a session. `stream` MAY point at
/// the raw client reader/writer (LegacyHttp), or at transport-owned
/// wrappers that encrypt/decrypt records (REALITY, SS).
///
/// `on_close` is invoked after the session ends, letting a transport
/// free any state it allocated while building the wrapped stream (TLS
/// session keys, salt cache entry, etc.). `ctx_for_close` is passed
/// verbatim; it can alias the transport's own ctx or point at
/// per-session state.
pub const Pivoted = struct {
    stream: ayllu_proxy.relay.Stream,
    inner_target: ?InnerTarget = null,
    on_close: ?*const fn (ctx: ?*anyopaque, io: std.Io) void = null,
    ctx_for_close: ?*anyopaque = null,
};

/// Returned when a transport rejected admission in a way that still
/// wants a genuine cover-host response. The dispatcher will forward
/// `buffered_head` + the rest of the stream through
/// `reverse_proxy.forwardBuffered`. `buffered_head` MUST remain valid
/// (no alloc needed; it's typically a slice of the reader's ring).
pub const Fallback = struct {
    buffered_head: []const u8,
};

pub const AdmitOutcome = union(enum) {
    pivoted: Pivoted,
    fallback: Fallback,
    /// Drop the connection with no response. Indistinguishable from a
    /// TCP stall from the client's POV. Used by SS when the first
    /// frame fails AEAD verification.
    silent: void,
};

/// Context the dispatcher hands to `admit`. The reader/writer are
/// already attached to `net_stream` with dispatcher-owned buffers.
/// Transports read up to the handshake's deadline from `reader`, and
/// may write early protocol responses (101 Switching Protocols, TLS
/// ServerHello, ...) directly to `writer`. For `.fallback` the
/// transport MUST NOT have written anything — the dispatcher will
/// replay `buffered_head` to the cover host byte-for-byte.
pub const AdmissionContext = struct {
    io: std.Io,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    net_stream: *const std.Io.net.Stream,
    peer_key: rate_limit.PrefixKey,
    /// Long-lived allocator for per-session heap that must outlive the
    /// `admit` call (e.g. REALITY's TLS record layers feeding
    /// `Pivoted.on_close`). Transports that pivot with raw reader/writer
    /// references don't need to touch it.
    allocator: std.mem.Allocator,
};

pub const OuterTransport = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        admit: *const fn (ctx: *anyopaque, admission: AdmissionContext) anyerror!AdmitOutcome,
        name: *const fn (ctx: *anyopaque) []const u8,
    };

    pub fn admit(self: OuterTransport, admission: AdmissionContext) anyerror!AdmitOutcome {
        return self.vtable.admit(self.ctx, admission);
    }

    pub fn name(self: OuterTransport) []const u8 {
        return self.vtable.name(self.ctx);
    }
};

test "OuterTransport vtable dispatches name() and admit() through the pointer" {
    const DummyCtx = struct {
        name_calls: u32 = 0,
        admit_calls: u32 = 0,
        outcome: AdmitOutcome,

        fn nameFn(ctx: *anyopaque) []const u8 {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.name_calls += 1;
            return "dummy";
        }

        fn admitFn(ctx: *anyopaque, _: AdmissionContext) anyerror!AdmitOutcome {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.admit_calls += 1;
            return self.outcome;
        }

        const vtable: OuterTransport.VTable = .{ .admit = admitFn, .name = nameFn };
    };

    var dummy: DummyCtx = .{ .outcome = .silent };
    const t: OuterTransport = .{ .ctx = @ptrCast(&dummy), .vtable = &DummyCtx.vtable };
    try std.testing.expectEqualStrings("dummy", t.name());

    var fake_reader: std.Io.Reader = .fixed("");
    var fake_writer_buf: [4]u8 = undefined;
    var fake_writer: std.Io.Writer = .fixed(&fake_writer_buf);
    const fake_stream: std.Io.net.Stream = .{ .socket = undefined };
    const outcome = try t.admit(.{
        .io = undefined,
        .reader = &fake_reader,
        .writer = &fake_writer,
        .net_stream = &fake_stream,
        .peer_key = rate_limit.ipv4_zero_prefix,
        .allocator = std.testing.allocator,
    });
    try std.testing.expectEqual(AdmitOutcome.silent, outcome);
    try std.testing.expectEqual(@as(u32, 1), dummy.name_calls);
    try std.testing.expectEqual(@as(u32, 1), dummy.admit_calls);
}
