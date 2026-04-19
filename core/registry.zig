//! Registry — CRDT для членства в группах.
//!
//! Реализация OR-Set (Observed-Remove Set). Каждое `add`-событие уникально
//! идентифицируется `event_id` (16 байт — см. envelope.Id). `remove`-событие
//! несёт `target_event_id` и «гасит» соответствующий `add`. Итоговое
//! `isMember(fp)` = существует add(fp, id) такой, что id нет в tombstones.
//!
//! Свойства: идемпотентность (повтор apply одного и того же event — no-op),
//! коммутативность (любой порядок apply сходится к одному состоянию),
//! монотонность (удалить нельзя — только погасить).
//!
//! Phase-1 scope: локальный инвентарь, без подписей/верификации событий.
//! Источник событий (кто имеет право на add/remove, кто подписывает
//! envelope) — ответственность вышележащих слоёв (phase-2 chat/group).

const std = @import("std");
const crypto = @import("crypto.zig");
const envelope_mod = @import("envelope.zig");

pub const EventId = envelope_mod.Id;

pub const MembershipEvent = union(enum) {
    add: Add,
    remove: Remove,

    pub const Add = struct {
        member: crypto.Fingerprint,
        event_id: EventId,
        actor: crypto.Fingerprint,
    };

    pub const Remove = struct {
        target_event_id: EventId,
        actor: crypto.Fingerprint,
    };
};

pub const Group = struct {
    allocator: std.mem.Allocator,
    id: crypto.Fingerprint,
    adds: std.ArrayList(MembershipEvent.Add) = .empty,
    tombstones: std.ArrayList(EventId) = .empty,

    pub fn init(allocator: std.mem.Allocator, id: crypto.Fingerprint) Group {
        return .{ .allocator = allocator, .id = id };
    }

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

fn isTombstoned(tombstones: []const EventId, id: EventId) bool {
    for (tombstones) |t| if (std.mem.eql(u8, &t, &id)) return true;
    return false;
}

fn makeAdd(member_byte: u8, event_byte: u8, actor_byte: u8) MembershipEvent {
    return .{ .add = .{
        .member = @splat(member_byte),
        .event_id = @splat(event_byte),
        .actor = @splat(actor_byte),
    } };
}

fn makeRemove(event_byte: u8, actor_byte: u8) MembershipEvent {
    return .{ .remove = .{
        .target_event_id = @splat(event_byte),
        .actor = @splat(actor_byte),
    } };
}

test "empty group has no members" {
    var g = Group.init(std.testing.allocator, @splat(0));
    defer g.deinit();
    const fp: crypto.Fingerprint = @splat(0xAA);
    try std.testing.expect(!g.isMember(fp));
    try std.testing.expectEqual(@as(usize, 0), g.memberCount());
}

test "apply add makes member visible" {
    var g = Group.init(std.testing.allocator, @splat(0));
    defer g.deinit();
    try g.apply(makeAdd(0xAA, 0x01, 0xFF));
    try std.testing.expect(g.isMember(@splat(0xAA)));
    try std.testing.expectEqual(@as(usize, 1), g.memberCount());
}

test "apply add with existing event_id is idempotent" {
    var g = Group.init(std.testing.allocator, @splat(0));
    defer g.deinit();
    try g.apply(makeAdd(0xAA, 0x01, 0xFF));
    try g.apply(makeAdd(0xAA, 0x01, 0xFF));
    try g.apply(makeAdd(0xAA, 0x01, 0xFF));
    try std.testing.expectEqual(@as(usize, 1), g.adds.items.len);
    try std.testing.expectEqual(@as(usize, 1), g.memberCount());
}

test "remove tombstones the matching add event" {
    var g = Group.init(std.testing.allocator, @splat(0));
    defer g.deinit();
    try g.apply(makeAdd(0xAA, 0x01, 0xFF));
    try g.apply(makeRemove(0x01, 0xFF));
    try std.testing.expect(!g.isMember(@splat(0xAA)));
    try std.testing.expectEqual(@as(usize, 0), g.memberCount());
}

test "two add events for the same member: removing one leaves the other" {
    var g = Group.init(std.testing.allocator, @splat(0));
    defer g.deinit();
    try g.apply(makeAdd(0xAA, 0x01, 0xFF));
    try g.apply(makeAdd(0xAA, 0x02, 0xFE));
    try g.apply(makeRemove(0x01, 0xFF));
    try std.testing.expect(g.isMember(@splat(0xAA)));
    try std.testing.expectEqual(@as(usize, 1), g.memberCount());
}

test "remove before add (out-of-order) still gates membership" {
    var g = Group.init(std.testing.allocator, @splat(0));
    defer g.deinit();
    try g.apply(makeRemove(0x01, 0xFF));
    try g.apply(makeAdd(0xAA, 0x01, 0xFF));
    try std.testing.expect(!g.isMember(@splat(0xAA)));
}

test "idempotent remove" {
    var g = Group.init(std.testing.allocator, @splat(0));
    defer g.deinit();
    try g.apply(makeAdd(0xAA, 0x01, 0xFF));
    try g.apply(makeRemove(0x01, 0xFF));
    try g.apply(makeRemove(0x01, 0xFF));
    try std.testing.expectEqual(@as(usize, 1), g.tombstones.items.len);
}

test "CRDT: two apply orders converge to the same state" {
    const events = [_]MembershipEvent{
        makeAdd(0xAA, 0x01, 0xFF),
        makeAdd(0xBB, 0x02, 0xFF),
        makeAdd(0xCC, 0x03, 0xFF),
        makeRemove(0x02, 0xFF),
        makeAdd(0xDD, 0x04, 0xFE),
    };

    var g1 = Group.init(std.testing.allocator, @splat(0));
    defer g1.deinit();
    for (events) |e| try g1.apply(e);

    var g2 = Group.init(std.testing.allocator, @splat(0));
    defer g2.deinit();
    // reverse order
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
    var g = Group.init(std.testing.allocator, id);
    defer g.deinit();
    try std.testing.expectEqualSlices(u8, &id, &g.id);
}

test "member not matching any add event is not a member" {
    var g = Group.init(std.testing.allocator, @splat(0));
    defer g.deinit();
    try g.apply(makeAdd(0xAA, 0x01, 0xFF));
    try std.testing.expect(!g.isMember(@splat(0xBB)));
}
