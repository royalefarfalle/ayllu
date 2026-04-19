//! Transport — абстракция доставки envelope между узлами (tambo).
//!
//! Реальные транспорты (WebSocket, WireGuard, LoRa, и т.п.) приходят в
//! следующих фазах; здесь только vtable-интерфейс + `InMemoryTransport`
//! для тестов других модулей core/ (registry, chat).

const std = @import("std");
const Envelope = @import("envelope.zig").Envelope;

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

pub const InMemoryTransport = struct {
    allocator: std.mem.Allocator,
    inbox: std.ArrayList(Envelope) = .empty,

    pub fn deinit(self: *InMemoryTransport) void {
        self.inbox.deinit(self.allocator);
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
        try self.inbox.append(self.allocator, envelope.*);
    }

    fn recvImpl(ctx: *anyopaque) anyerror!?Envelope {
        const self: *InMemoryTransport = @ptrCast(@alignCast(ctx));
        if (self.inbox.items.len == 0) return null;
        return self.inbox.orderedRemove(0);
    }

    fn nameImpl(_: *anyopaque) []const u8 {
        return "in-memory";
    }
};

const envelope_mod = @import("envelope.zig");
const Identity = @import("identity.zig").Identity;

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

test "InMemoryTransport: name() returns identifier" {
    var t: InMemoryTransport = .{ .allocator = std.testing.allocator };
    defer t.deinit();
    try std.testing.expectEqualStrings("in-memory", t.transport().name());
}

test "Transport vtable dispatch: calls reach the concrete impl" {
    var t: InMemoryTransport = .{ .allocator = std.testing.allocator };
    defer t.deinit();
    const alice = try Identity.fromSeed(@splat(0x43));
    const env = try envelope_mod.buildAndSign(std.testing.io, alice, .broadcast, 0, 1, "p");
    try t.transport().send(&env);
    try std.testing.expectEqual(@as(usize, 1), t.inbox.items.len);
}

test "Transport: send-recv with tampered envelope still carries same bytes" {
    // Transport is unaware of envelope semantics — it moves bytes. A tampered
    // envelope must traverse the transport unchanged; verify's job is to
    // reject it at the receiver.
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
