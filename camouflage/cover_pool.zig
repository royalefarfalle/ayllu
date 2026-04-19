//! Weighted pool of cover hosts for the honest-fallback reverse proxy.
//! A single cover host is a fingerprint handle: every probed IP gets routed
//! through the same address and a long-running observer can correlate. A
//! pool with rotation breaks that correlation — different probes from the
//! same /24 can legitimately traverse different cover hosts (Ubuntu mirrors,
//! Debian mirrors, Microsoft, …) without changing the daemon's identity.
//!
//! Picking is deterministic given the `picker_state` the caller passes in
//! so tests can reproduce a rotation sequence; in production the picker is
//! seeded from std.crypto.random per session.

const std = @import("std");
const reverse_proxy = @import("reverse_proxy.zig");

pub const WeightedCover = struct {
    target: reverse_proxy.CoverTarget,
    /// Rotation weight. 1.0 = uniform; higher biases toward this cover.
    /// u32 gives enough resolution while keeping the arithmetic integer-
    /// only in the hot path.
    weight: u32 = 1,
};

pub const Pool = struct {
    entries: []const WeightedCover,

    /// Precomputed total across all entries. 0 means the pool is empty;
    /// callers should treat that as "no pool configured".
    total_weight: u32,

    pub fn init(entries: []const WeightedCover) Pool {
        var total: u32 = 0;
        for (entries) |e| total += e.weight;
        return .{ .entries = entries, .total_weight = total };
    }

    pub fn isEmpty(self: Pool) bool {
        return self.total_weight == 0 or self.entries.len == 0;
    }

    /// Weighted pick from the pool. `r` is a caller-provided uniform u32 in
    /// [0, total_weight). Deterministic given `r`.
    pub fn pick(self: Pool, r: u32) ?reverse_proxy.CoverTarget {
        if (self.isEmpty()) return null;
        var acc: u32 = 0;
        for (self.entries) |e| {
            acc += e.weight;
            if (r < acc) return e.target;
        }
        // Guard against off-by-one from r == total_weight (should not happen
        // if the caller followed the contract, but pinning behavior here
        // means a bug in the caller can't misroute).
        return self.entries[self.entries.len - 1].target;
    }

    /// Convenience wrapper: pulls entropy from the Io random source.
    pub fn pickRandom(self: Pool, io: std.Io) ?reverse_proxy.CoverTarget {
        if (self.isEmpty()) return null;
        var buf: [4]u8 = undefined;
        io.random(&buf);
        const r_u32: u32 = @bitCast(buf);
        return self.pick(r_u32 % self.total_weight);
    }
};

test "Pool: empty pool picks nothing" {
    const p: Pool = Pool.init(&.{});
    try std.testing.expect(p.isEmpty());
    try std.testing.expectEqual(@as(?reverse_proxy.CoverTarget, null), p.pick(0));
}

test "Pool: single-entry pool always picks it" {
    const entries = [_]WeightedCover{
        .{ .target = .{ .host = "archive.ubuntu.com" }, .weight = 1 },
    };
    const p = Pool.init(&entries);
    const got = p.pick(0).?;
    try std.testing.expectEqualStrings("archive.ubuntu.com", got.host);
}

test "Pool: uniform weights rotate in order" {
    const entries = [_]WeightedCover{
        .{ .target = .{ .host = "a" }, .weight = 1 },
        .{ .target = .{ .host = "b" }, .weight = 1 },
        .{ .target = .{ .host = "c" }, .weight = 1 },
    };
    const p = Pool.init(&entries);
    try std.testing.expectEqualStrings("a", p.pick(0).?.host);
    try std.testing.expectEqualStrings("b", p.pick(1).?.host);
    try std.testing.expectEqualStrings("c", p.pick(2).?.host);
}

test "Pool: weights bias picks proportionally" {
    const entries = [_]WeightedCover{
        .{ .target = .{ .host = "heavy" }, .weight = 3 },
        .{ .target = .{ .host = "light" }, .weight = 1 },
    };
    const p = Pool.init(&entries);
    try std.testing.expectEqual(@as(u32, 4), p.total_weight);
    // r in [0, 3) -> heavy; r == 3 -> light.
    try std.testing.expectEqualStrings("heavy", p.pick(0).?.host);
    try std.testing.expectEqualStrings("heavy", p.pick(2).?.host);
    try std.testing.expectEqualStrings("light", p.pick(3).?.host);
}

test "Pool: out-of-range r falls back to last entry (contract-guard)" {
    const entries = [_]WeightedCover{
        .{ .target = .{ .host = "a" }, .weight = 1 },
        .{ .target = .{ .host = "b" }, .weight = 1 },
    };
    const p = Pool.init(&entries);
    try std.testing.expectEqualStrings("b", p.pick(99).?.host);
}

test "Pool: empty-weight entry is ignored" {
    const entries = [_]WeightedCover{
        .{ .target = .{ .host = "zero" }, .weight = 0 },
        .{ .target = .{ .host = "one" }, .weight = 1 },
    };
    const p = Pool.init(&entries);
    try std.testing.expectEqual(@as(u32, 1), p.total_weight);
    try std.testing.expectEqualStrings("one", p.pick(0).?.host);
}
