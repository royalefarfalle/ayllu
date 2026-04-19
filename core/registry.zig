//! Registry — CRDT for group membership (OR-Set).
//!
//! Each add event is uniquely identified by `event_id` (16 bytes, same
//! shape as envelope.Id — these events travel in envelope payloads).
//! A remove event carries `target_event_id` and cancels the matching add.
//! Phase-1 scope: local inventory. Event signing/authorization is the
//! responsibility of a higher layer (phase-2 chat); hence no `actor`
//! field here — nothing reads it yet.

const std = @import("std");
const crypto = @import("crypto.zig");
const envelope = @import("envelope.zig");

pub const MembershipEvent = union(enum) {
    add: Add,
    remove: Remove,

    pub const Add = struct {
        member: crypto.Fingerprint,
        event_id: envelope.Id,
    };

    pub const Remove = struct {
        target_event_id: envelope.Id,
    };
};

pub const Group = struct {
    allocator: std.mem.Allocator,
    id: crypto.Fingerprint,
    adds: std.ArrayList(MembershipEvent.Add) = .empty,
    tombstones: std.ArrayList(envelope.Id) = .empty,

    pub fn deinit(self: *Group) void {
        self.adds.deinit(self.allocator);
        self.tombstones.deinit(self.allocator);
    }

    pub fn apply(self: *Group, event: MembershipEvent) !void {
        switch (event) {
            .add => |a| {
                for (self.adds.items) |existing| {
                    if (std.mem.eql(u8, &existing.event_id, &a.event_id)) return;
                }
                try self.adds.append(self.allocator, a);
            },
            .remove => |r| {
                for (self.tombstones.items) |t| {
                    if (std.mem.eql(u8, &t, &r.target_event_id)) return;
                }
                try self.tombstones.append(self.allocator, r.target_event_id);
            },
        }
    }

    pub fn isMember(self: Group, fingerprint: crypto.Fingerprint) bool {
        for (self.adds.items) |add| {
            if (!std.mem.eql(u8, &add.member, &fingerprint)) continue;
            if (!isTombstoned(self.tombstones.items, add.event_id)) return true;
        }
        return false;
    }

    pub fn memberCount(self: Group) usize {
        var n: usize = 0;
        for (self.adds.items) |add| {
            if (!isTombstoned(self.tombstones.items, add.event_id)) n += 1;
        }
        return n;
    }
};

fn isTombstoned(tombstones: []const envelope.Id, id: envelope.Id) bool {
    for (tombstones) |t| if (std.mem.eql(u8, &t, &id)) return true;
    return false;
}

fn makeAdd(member_byte: u8, event_byte: u8) MembershipEvent {
    return .{ .add = .{
        .member = @splat(member_byte),
        .event_id = @splat(event_byte),
    } };
}

fn makeRemove(event_byte: u8) MembershipEvent {
    return .{ .remove = .{ .target_event_id = @splat(event_byte) } };
}

test "empty group has no members" {
    var g: Group = .{ .allocator = std.testing.allocator, .id = @splat(0) };
    defer g.deinit();
    const fp: crypto.Fingerprint = @splat(0xAA);
    try std.testing.expect(!g.isMember(fp));
    try std.testing.expectEqual(@as(usize, 0), g.memberCount());
}

test "apply add makes member visible" {
    var g: Group = .{ .allocator = std.testing.allocator, .id = @splat(0) };
    defer g.deinit();
    try g.apply(makeAdd(0xAA, 0x01));
    try std.testing.expect(g.isMember(@splat(0xAA)));
    try std.testing.expectEqual(@as(usize, 1), g.memberCount());
}

test "apply add with existing event_id is idempotent" {
    var g: Group = .{ .allocator = std.testing.allocator, .id = @splat(0) };
    defer g.deinit();
    try g.apply(makeAdd(0xAA, 0x01));
    try g.apply(makeAdd(0xAA, 0x01));
    try g.apply(makeAdd(0xAA, 0x01));
    try std.testing.expectEqual(@as(usize, 1), g.adds.items.len);
    try std.testing.expectEqual(@as(usize, 1), g.memberCount());
}

test "remove tombstones the matching add event" {
    var g: Group = .{ .allocator = std.testing.allocator, .id = @splat(0) };
    defer g.deinit();
    try g.apply(makeAdd(0xAA, 0x01));
    try g.apply(makeRemove(0x01));
    try std.testing.expect(!g.isMember(@splat(0xAA)));
    try std.testing.expectEqual(@as(usize, 0), g.memberCount());
}

test "two add events for the same member: removing one leaves the other" {
    var g: Group = .{ .allocator = std.testing.allocator, .id = @splat(0) };
    defer g.deinit();
    try g.apply(makeAdd(0xAA, 0x01));
    try g.apply(makeAdd(0xAA, 0x02));
    try g.apply(makeRemove(0x01));
    try std.testing.expect(g.isMember(@splat(0xAA)));
    try std.testing.expectEqual(@as(usize, 1), g.memberCount());
}

test "remove before add (out-of-order) still gates membership" {
    var g: Group = .{ .allocator = std.testing.allocator, .id = @splat(0) };
    defer g.deinit();
    try g.apply(makeRemove(0x01));
    try g.apply(makeAdd(0xAA, 0x01));
    try std.testing.expect(!g.isMember(@splat(0xAA)));
}

test "idempotent remove" {
    var g: Group = .{ .allocator = std.testing.allocator, .id = @splat(0) };
    defer g.deinit();
    try g.apply(makeAdd(0xAA, 0x01));
    try g.apply(makeRemove(0x01));
    try g.apply(makeRemove(0x01));
    try std.testing.expectEqual(@as(usize, 1), g.tombstones.items.len);
}

test "CRDT: two apply orders converge to the same state" {
    const events = [_]MembershipEvent{
        makeAdd(0xAA, 0x01),
        makeAdd(0xBB, 0x02),
        makeAdd(0xCC, 0x03),
        makeRemove(0x02),
        makeAdd(0xDD, 0x04),
    };

    var g1: Group = .{ .allocator = std.testing.allocator, .id = @splat(0) };
    defer g1.deinit();
    for (events) |e| try g1.apply(e);

    var g2: Group = .{ .allocator = std.testing.allocator, .id = @splat(0) };
    defer g2.deinit();
    var i: usize = events.len;
    while (i > 0) {
        i -= 1;
        try g2.apply(events[i]);
    }

    try std.testing.expectEqual(g1.memberCount(), g2.memberCount());
    try std.testing.expect(g1.isMember(@splat(0xAA)) == g2.isMember(@splat(0xAA)));
    try std.testing.expect(g1.isMember(@splat(0xBB)) == g2.isMember(@splat(0xBB)));
    try std.testing.expect(g1.isMember(@splat(0xCC)) == g2.isMember(@splat(0xCC)));
    try std.testing.expect(g1.isMember(@splat(0xDD)) == g2.isMember(@splat(0xDD)));
    try std.testing.expect(!g1.isMember(@splat(0xBB)));
}

test "group id is stored and accessible" {
    const id: crypto.Fingerprint = @splat(0x77);
    var g: Group = .{ .allocator = std.testing.allocator, .id = id };
    defer g.deinit();
    try std.testing.expectEqualSlices(u8, &id, &g.id);
}

test "member not matching any add event is not a member" {
    var g: Group = .{ .allocator = std.testing.allocator, .id = @splat(0) };
    defer g.deinit();
    try g.apply(makeAdd(0xAA, 0x01));
    try std.testing.expect(!g.isMember(@splat(0xBB)));
}

test "CRDT: two replicas with asymmetric histories converge after exchange" {
    // Real OR-Set property: replicas apply DIFFERENT event subsets, then
    // exchange. After each applies the other's events, both converge.
    const ra_only = [_]MembershipEvent{ makeAdd(0xAA, 0x01), makeAdd(0xBB, 0x02), makeRemove(0x02) };
    const rb_only = [_]MembershipEvent{ makeAdd(0xCC, 0x03), makeAdd(0xDD, 0x04) };

    var replica_a: Group = .{ .allocator = std.testing.allocator, .id = @splat(0) };
    defer replica_a.deinit();
    var replica_b: Group = .{ .allocator = std.testing.allocator, .id = @splat(0) };
    defer replica_b.deinit();

    for (ra_only) |e| try replica_a.apply(e);
    for (rb_only) |e| try replica_b.apply(e);

    // Exchange: each replica receives the other's events.
    for (rb_only) |e| try replica_a.apply(e);
    for (ra_only) |e| try replica_b.apply(e);

    try std.testing.expectEqual(replica_a.memberCount(), replica_b.memberCount());
    try std.testing.expectEqual(replica_a.adds.items.len, replica_b.adds.items.len);
    try std.testing.expectEqual(replica_a.tombstones.items.len, replica_b.tombstones.items.len);
    inline for ([_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE }) |byte| {
        try std.testing.expectEqual(
            replica_a.isMember(@splat(byte)),
            replica_b.isMember(@splat(byte)),
        );
    }
}

test "two Groups have independent tombstones — no cross-group contamination" {
    var g_a: Group = .{ .allocator = std.testing.allocator, .id = @splat(0xA) };
    defer g_a.deinit();
    var g_b: Group = .{ .allocator = std.testing.allocator, .id = @splat(0xB) };
    defer g_b.deinit();
    try g_a.apply(makeRemove(0x01));
    try g_b.apply(makeAdd(0xAA, 0x01));
    try std.testing.expect(g_b.isMember(@splat(0xAA)));
}

test "dedup is keyed by event_id alone — second add with same id is dropped" {
    // Pins the OR-Set contract: event_id is the unique tag. A regression
    // that switched dedup to (member, event_id) would silently admit a
    // second member under the same tag — breaking convergence with peers
    // that saw only the first event.
    var g: Group = .{ .allocator = std.testing.allocator, .id = @splat(0) };
    defer g.deinit();
    try g.apply(makeAdd(0xAA, 0x01));
    try g.apply(makeAdd(0xBB, 0x01));
    try std.testing.expectEqual(@as(usize, 1), g.adds.items.len);
    try std.testing.expect(g.isMember(@splat(0xAA)));
    try std.testing.expect(!g.isMember(@splat(0xBB)));
}

test "apply propagates OutOfMemory without partial update" {
    var fa = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var g: Group = .{ .allocator = fa.allocator(), .id = @splat(0) };
    defer g.deinit();
    try std.testing.expectError(error.OutOfMemory, g.apply(makeAdd(0xAA, 0x01)));
    try std.testing.expectEqual(@as(usize, 0), g.adds.items.len);
}

test "real Identity fingerprint roundtrips through apply + isMember" {
    const Identity = @import("identity.zig").Identity;
    var g: Group = .{ .allocator = std.testing.allocator, .id = @splat(0) };
    defer g.deinit();
    const alice = try Identity.fromSeed(@splat(0x42));
    try g.apply(.{ .add = .{
        .member = alice.fingerprint(),
        .event_id = @splat(0x11),
    } });
    try std.testing.expect(g.isMember(alice.fingerprint()));
    const bob = try Identity.fromSeed(@splat(0x43));
    try std.testing.expect(!g.isMember(bob.fingerprint()));
}

test "all-zero event_id is a normal value (no sentinel behavior)" {
    var g: Group = .{ .allocator = std.testing.allocator, .id = @splat(0) };
    defer g.deinit();
    try g.apply(makeAdd(0xAA, 0x00));
    try std.testing.expect(g.isMember(@splat(0xAA)));
    try g.apply(makeRemove(0x00));
    try std.testing.expect(!g.isMember(@splat(0xAA)));
}
