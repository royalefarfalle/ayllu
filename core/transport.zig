//! Transport — abstraction for envelope delivery between nodes (tambo).
//!
//! Real transports (WebSocket, WireGuard, LoRa, etc.) land in later
//! phases; here there's only the vtable interface plus `InMemoryTransport`
//! for tests of other core/ modules (registry, chat).

const std = @import("std");
const envelope_mod = @import("envelope.zig");
const Envelope = envelope_mod.Envelope;
const Identity = @import("identity.zig").Identity;

pub const Transport = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        send: *const fn (ctx: *anyopaque, envelope: *const Envelope) anyerror!void,
        recv: *const fn (ctx: *anyopaque) anyerror!?Envelope,
        name: *const fn (ctx: *anyopaque) []const u8,
    };

    pub fn send(self: Transport, envelope: *const Envelope) !void {
        return self.vtable.send(self.ptr, envelope);
    }

    pub fn recv(self: Transport) !?Envelope {
        return self.vtable.recv(self.ptr);
    }

    pub fn name(self: Transport) []const u8 {
        return self.vtable.name(self.ptr);
    }
};

/// In-memory FIFO loopback. Copies payload bytes on send and retains every
/// buffer (both in-queue and already-recv'd) until `deinit`, so callers never
/// have to track lifetimes.
pub const InMemoryTransport = struct {
    allocator: std.mem.Allocator,
    inbox: std.Deque(Envelope) = .empty,
    consumed_payloads: std.ArrayList([]u8) = .empty,

    /// Frees the queued inbox AND all already-recv'd payload buffers. Any
    /// `Envelope` previously returned by `recv` has its `.payload` slice
    /// invalidated — callers must finish with those envelopes before deinit.
    pub fn deinit(self: *InMemoryTransport) void {
        while (self.inbox.popFront()) |env| self.allocator.free(@constCast(env.payload));
        self.inbox.deinit(self.allocator);
        for (self.consumed_payloads.items) |p| self.allocator.free(p);
        self.consumed_payloads.deinit(self.allocator);
    }

    pub fn transport(self: *InMemoryTransport) Transport {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Transport.VTable = .{
        .send = sendImpl,
        .recv = recvImpl,
        .name = nameImpl,
    };

    fn sendImpl(ctx: *anyopaque, envelope: *const Envelope) anyerror!void {
        const self: *InMemoryTransport = @ptrCast(@alignCast(ctx));
        const owned_payload = try self.allocator.dupe(u8, envelope.payload);
        errdefer self.allocator.free(owned_payload);
        var copy = envelope.*;
        copy.payload = owned_payload;
        try self.inbox.pushBack(self.allocator, copy);
    }

    fn recvImpl(ctx: *anyopaque) anyerror!?Envelope {
        const self: *InMemoryTransport = @ptrCast(@alignCast(ctx));
        const env = self.inbox.popFront() orelse return null;
        try self.consumed_payloads.append(self.allocator, @constCast(env.payload));
        return env;
    }

    fn nameImpl(_: *anyopaque) []const u8 {
        return "in-memory";
    }
};

test "InMemoryTransport: recv returns null on empty" {
    var t: InMemoryTransport = .{ .allocator = std.testing.allocator };
    defer t.deinit();
    try std.testing.expectEqual(@as(?Envelope, null), try t.transport().recv());
}

test "InMemoryTransport: send then recv roundtrips" {
    var t: InMemoryTransport = .{ .allocator = std.testing.allocator };
    defer t.deinit();
    const alice = try Identity.fromSeed(@splat(0x41));
    const env = try envelope_mod.buildAndSign(std.testing.io, alice, .broadcast, 0, 1, "hi");
    try t.transport().send(&env);
    const got = try t.transport().recv();
    try std.testing.expect(got != null);
    try std.testing.expectEqualSlices(u8, &env.id, &got.?.id);
    try got.?.verify(alice.publicView());
}

test "InMemoryTransport: FIFO order preserved" {
    var t: InMemoryTransport = .{ .allocator = std.testing.allocator };
    defer t.deinit();
    const alice = try Identity.fromSeed(@splat(0x42));
    const e1 = try envelope_mod.buildAndSign(std.testing.io, alice, .broadcast, 0, 1, "one");
    const e2 = try envelope_mod.buildAndSign(std.testing.io, alice, .broadcast, 0, 1, "two");
    const e3 = try envelope_mod.buildAndSign(std.testing.io, alice, .broadcast, 0, 1, "three");
    const tr = t.transport();
    try tr.send(&e1);
    try tr.send(&e2);
    try tr.send(&e3);
    const r1 = (try tr.recv()).?;
    const r2 = (try tr.recv()).?;
    const r3 = (try tr.recv()).?;
    try std.testing.expectEqualSlices(u8, &e1.id, &r1.id);
    try std.testing.expectEqualSlices(u8, &e2.id, &r2.id);
    try std.testing.expectEqualSlices(u8, &e3.id, &r3.id);
    try std.testing.expectEqual(@as(?Envelope, null), try tr.recv());
}

test "InMemoryTransport: name returns identifier" {
    var t: InMemoryTransport = .{ .allocator = std.testing.allocator };
    defer t.deinit();
    try std.testing.expectEqualStrings("in-memory", t.transport().name());
}

test "Transport: vtable dispatch reaches concrete impl" {
    var t: InMemoryTransport = .{ .allocator = std.testing.allocator };
    defer t.deinit();
    const alice = try Identity.fromSeed(@splat(0x43));
    const env = try envelope_mod.buildAndSign(std.testing.io, alice, .broadcast, 0, 1, "p");
    try t.transport().send(&env);
    try std.testing.expectEqual(@as(usize, 1), t.inbox.len);
}

test "Transport: tampered envelope traverses unchanged, verify rejects at receiver" {
    var t: InMemoryTransport = .{ .allocator = std.testing.allocator };
    defer t.deinit();
    const alice = try Identity.fromSeed(@splat(0x44));
    var env = try envelope_mod.buildAndSign(std.testing.io, alice, .broadcast, 0, 1, "p");
    env.payload = "TAMPERED";
    try t.transport().send(&env);
    const got = (try t.transport().recv()).?;
    try std.testing.expectEqualStrings("TAMPERED", got.payload);
    try std.testing.expectError(
        error.SignatureVerificationFailed,
        got.verify(alice.publicView()),
    );
}

test "InMemoryTransport: send copies payload — overwriting source after send is safe" {
    var t: InMemoryTransport = .{ .allocator = std.testing.allocator };
    defer t.deinit();
    const alice = try Identity.fromSeed(@splat(0x45));
    var payload_buf: [8]u8 = "original".*;
    var env = try envelope_mod.buildAndSign(std.testing.io, alice, .broadcast, 0, 1, &payload_buf);
    try t.transport().send(&env);
    @memset(&payload_buf, 'X');
    const got = (try t.transport().recv()).?;
    try std.testing.expectEqualStrings("original", got.payload);
}

test "InMemoryTransport: same envelope sent twice produces two independent inbox entries" {
    var t: InMemoryTransport = .{ .allocator = std.testing.allocator };
    defer t.deinit();
    const alice = try Identity.fromSeed(@splat(0x46));
    const env = try envelope_mod.buildAndSign(std.testing.io, alice, .broadcast, 0, 1, "twice");
    const tr = t.transport();
    try tr.send(&env);
    try tr.send(&env);
    try std.testing.expectEqual(@as(usize, 2), t.inbox.len);
    const r1 = (try tr.recv()).?;
    const r2 = (try tr.recv()).?;
    try std.testing.expect(r1.payload.ptr != r2.payload.ptr);
    try std.testing.expectEqualStrings("twice", r1.payload);
    try std.testing.expectEqualStrings("twice", r2.payload);
}

test "InMemoryTransport: recv preserves every envelope field" {
    var t: InMemoryTransport = .{ .allocator = std.testing.allocator };
    defer t.deinit();
    const alice = try Identity.fromSeed(@splat(0x47));
    const env = try envelope_mod.buildAndSign(
        std.testing.io,
        alice,
        .{ .fingerprint = @splat(0xF1) },
        1_700,
        1_800,
        "fields",
    );
    try t.transport().send(&env);
    const got = (try t.transport().recv()).?;
    try std.testing.expectEqual(env.version, got.version);
    try std.testing.expectEqualSlices(u8, &env.id, &got.id);
    try std.testing.expectEqualSlices(u8, &env.from, &got.from);
    try std.testing.expectEqual(env.created_at, got.created_at);
    try std.testing.expectEqual(env.expires_at, got.expires_at);
    try std.testing.expectEqualSlices(u8, &env.signature.toBytes(), &got.signature.toBytes());
    try std.testing.expect(std.meta.activeTag(got.to) == .fingerprint);
    try std.testing.expectEqualSlices(u8, &env.to.fingerprint, &got.to.fingerprint);
}

test "InMemoryTransport: deinit drops un-recv'd envelopes without leaking" {
    var t: InMemoryTransport = .{ .allocator = std.testing.allocator };
    const alice = try Identity.fromSeed(@splat(0x48));
    const e1 = try envelope_mod.buildAndSign(std.testing.io, alice, .broadcast, 0, 1, "a");
    const e2 = try envelope_mod.buildAndSign(std.testing.io, alice, .broadcast, 0, 1, "b");
    const e3 = try envelope_mod.buildAndSign(std.testing.io, alice, .broadcast, 0, 1, "c");
    try t.transport().send(&e1);
    try t.transport().send(&e2);
    try t.transport().send(&e3);
    t.deinit(); // testing.allocator will report on any leak
}

test "InMemoryTransport: deinit after partial recv frees both inbox and consumed" {
    var t: InMemoryTransport = .{ .allocator = std.testing.allocator };
    const alice = try Identity.fromSeed(@splat(0x49));
    const e1 = try envelope_mod.buildAndSign(std.testing.io, alice, .broadcast, 0, 1, "a");
    const e2 = try envelope_mod.buildAndSign(std.testing.io, alice, .broadcast, 0, 1, "b");
    const e3 = try envelope_mod.buildAndSign(std.testing.io, alice, .broadcast, 0, 1, "c");
    try t.transport().send(&e1);
    try t.transport().send(&e2);
    try t.transport().send(&e3);
    _ = try t.transport().recv();
    t.deinit();
}

test "InMemoryTransport: empty payload roundtrip" {
    var t: InMemoryTransport = .{ .allocator = std.testing.allocator };
    defer t.deinit();
    const alice = try Identity.fromSeed(@splat(0x4A));
    const env = try envelope_mod.buildAndSign(std.testing.io, alice, .broadcast, 0, 1, "");
    try t.transport().send(&env);
    const got = (try t.transport().recv()).?;
    try std.testing.expectEqual(@as(usize, 0), got.payload.len);
    try got.verify(alice.publicView());
}

test "InMemoryTransport: two instances do not share inbox" {
    var a: InMemoryTransport = .{ .allocator = std.testing.allocator };
    defer a.deinit();
    var b: InMemoryTransport = .{ .allocator = std.testing.allocator };
    defer b.deinit();
    const alice = try Identity.fromSeed(@splat(0x4B));
    const env = try envelope_mod.buildAndSign(std.testing.io, alice, .broadcast, 0, 1, "to-a");
    try a.transport().send(&env);
    try std.testing.expectEqual(@as(?Envelope, null), try b.transport().recv());
}

test "InMemoryTransport: send propagates OOM from inbox growth without leaking duped payload" {
    var fa = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 1 });
    var t: InMemoryTransport = .{ .allocator = fa.allocator() };
    defer t.deinit();
    const alice = try Identity.fromSeed(@splat(0x4C));
    const env = try envelope_mod.buildAndSign(std.testing.io, alice, .broadcast, 0, 1, "oom");
    try std.testing.expectError(error.OutOfMemory, t.transport().send(&env));
    try std.testing.expectEqual(@as(usize, 0), t.inbox.len);
}
