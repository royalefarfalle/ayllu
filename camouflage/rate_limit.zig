//! Per-source rate limit for admission failures. Without this, a single
//! adversary can enumerate the short_id space for free: every wrong-token
//! probe either gets a `fallback` response (still useful information) or
//! costs the VPS one crypto roundtrip plus a reverse-proxied HTTPS stream
//! to a cover site. After N failures from the same /24 in M seconds we
//! flip that source into "silent drop" mode for K minutes — the socket
//! simply closes before any crypto runs, indistinguishable from a random
//! TCP stall.
//!
//! Eviction is LRU so the bucket map stays bounded; running out of room
//! still "works" (oldest entries get recycled), it just makes the rate
//! limiter slightly less accurate for the long tail.

const std = @import("std");

pub const Config = struct {
    /// Max admission failures from one source before we flip to silent-drop.
    failures_per_window: u32 = 20,
    /// Window within which failures accumulate.
    window_ms: i64 = 60_000,
    /// Duration the source stays silently-dropped after tripping.
    silent_duration_ms: i64 = 300_000,
    /// Upper bound on tracked sources. LRU-evicted beyond this.
    bucket_capacity: usize = 1024,
};

/// 8 bytes is enough to hold the first 4 bytes of an IPv4 address (the rest
/// zeroed) OR the first 8 bytes of an IPv6 /64 — both are the right
/// aggregation level for "one adversary". Larger prefixes (e.g., /16)
/// would over-aggregate; smaller (e.g., /32) lets a botnet sidestep.
pub const PrefixKey = [8]u8;

pub const ipv4_zero_prefix: PrefixKey = @splat(0);

/// Produce a PrefixKey from raw IPv4 bytes (stores them in the first 4
/// bytes, zeros the rest).
pub fn prefixFromIpv4(ip4: [4]u8) PrefixKey {
    var out: PrefixKey = @splat(0);
    out[0] = ip4[0];
    out[1] = ip4[1];
    out[2] = ip4[2];
    // /24: omit the last octet so all hosts in the /24 share one bucket.
    return out;
}

/// Produce a PrefixKey from an IPv6 /64 prefix (first 8 bytes).
pub fn prefixFromIpv6(ip6: [16]u8) PrefixKey {
    return ip6[0..8].*;
}

pub const Verdict = enum { allow, drop_silently };

const Bucket = struct {
    failures_in_window: u32 = 0,
    window_start_ms: i64 = 0,
    silent_until_ms: i64 = 0,
    last_access_ms: i64 = 0,
};

/// Thread-safe rate limiter. Wrap in a mutex at the caller side if used
/// under `Io.async` on `std.Io.Threaded`; the internal map is not itself
/// locked — keep this struct behind a single mutex (like the existing
/// State.mutex in camouflage/server.zig).
pub const RateLimiter = struct {
    config: Config,
    buckets: std.AutoHashMapUnmanaged(PrefixKey, Bucket) = .empty,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, config: Config) RateLimiter {
        return .{ .config = config, .allocator = allocator };
    }

    pub fn deinit(self: *RateLimiter) void {
        self.buckets.deinit(self.allocator);
    }

    /// Before admitting: check if this source is currently silenced.
    pub fn consult(self: *RateLimiter, key: PrefixKey, now_ms: i64) Verdict {
        const bucket = self.buckets.getPtr(key) orelse return .allow;
        if (bucket.silent_until_ms > now_ms) return .drop_silently;
        return .allow;
    }

    /// Call after an admission attempt failed. May flip the source into
    /// silent-drop mode. Allocator failure here is NOT fatal — we skip
    /// the update and fall through to .allow on the next consult (fail-
    /// open under memory pressure, consistent with the rest of the
    /// anti-probing stack).
    pub fn recordFailure(self: *RateLimiter, key: PrefixKey, now_ms: i64) void {
        // Evict one LRU entry if at capacity.
        if (self.buckets.count() >= self.config.bucket_capacity) {
            self.evictOldest();
        }

        const gop = self.buckets.getOrPut(self.allocator, key) catch return;
        if (!gop.found_existing) {
            gop.value_ptr.* = .{};
        }
        const b = gop.value_ptr;
        b.last_access_ms = now_ms;

        // Rotate the window if we're past the end.
        if (now_ms - b.window_start_ms >= self.config.window_ms) {
            b.window_start_ms = now_ms;
            b.failures_in_window = 0;
        }
        b.failures_in_window += 1;

        if (b.failures_in_window >= self.config.failures_per_window) {
            b.silent_until_ms = now_ms + self.config.silent_duration_ms;
        }
    }

    /// Call after a successful admission. Clears any pending failure count
    /// for the source — legitimate traffic shouldn't be punished for a
    /// prior spray by its /24 neighbors.
    pub fn recordSuccess(self: *RateLimiter, key: PrefixKey, now_ms: i64) void {
        const b = self.buckets.getPtr(key) orelse return;
        b.last_access_ms = now_ms;
        b.failures_in_window = 0;
        b.silent_until_ms = 0;
    }

    fn evictOldest(self: *RateLimiter) void {
        var oldest_key: ?PrefixKey = null;
        var oldest_ms: i64 = std.math.maxInt(i64);
        var it = self.buckets.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.last_access_ms < oldest_ms) {
                oldest_ms = entry.value_ptr.last_access_ms;
                oldest_key = entry.key_ptr.*;
            }
        }
        if (oldest_key) |k| {
            _ = self.buckets.remove(k);
        }
    }
};

test "RateLimiter: fresh key allows" {
    var rl = RateLimiter.init(std.testing.allocator, .{});
    defer rl.deinit();
    try std.testing.expectEqual(Verdict.allow, rl.consult(prefixFromIpv4(.{ 1, 2, 3, 4 }), 0));
}

test "RateLimiter: trips to silent after N failures within window" {
    var rl = RateLimiter.init(std.testing.allocator, .{
        .failures_per_window = 3,
        .window_ms = 1000,
        .silent_duration_ms = 5_000,
    });
    defer rl.deinit();
    const key = prefixFromIpv4(.{ 1, 2, 3, 4 });

    rl.recordFailure(key, 100);
    rl.recordFailure(key, 200);
    try std.testing.expectEqual(Verdict.allow, rl.consult(key, 250));
    rl.recordFailure(key, 300); // tripper
    try std.testing.expectEqual(Verdict.drop_silently, rl.consult(key, 400));
}

test "RateLimiter: silent period expires and allows again" {
    var rl = RateLimiter.init(std.testing.allocator, .{
        .failures_per_window = 2,
        .window_ms = 1000,
        .silent_duration_ms = 1_000,
    });
    defer rl.deinit();
    const key = prefixFromIpv4(.{ 5, 6, 7, 8 });
    rl.recordFailure(key, 0);
    rl.recordFailure(key, 100); // trip
    try std.testing.expectEqual(Verdict.drop_silently, rl.consult(key, 500));
    try std.testing.expectEqual(Verdict.allow, rl.consult(key, 1_200));
}

test "RateLimiter: window rotation resets failure count" {
    var rl = RateLimiter.init(std.testing.allocator, .{
        .failures_per_window = 3,
        .window_ms = 1_000,
    });
    defer rl.deinit();
    const key = prefixFromIpv4(.{ 9, 9, 9, 9 });
    rl.recordFailure(key, 0);
    rl.recordFailure(key, 100);
    // Jump past window — should NOT trip even after one more failure.
    rl.recordFailure(key, 2_000);
    try std.testing.expectEqual(Verdict.allow, rl.consult(key, 2_100));
    rl.recordFailure(key, 2_200);
    rl.recordFailure(key, 2_300);
    try std.testing.expectEqual(Verdict.drop_silently, rl.consult(key, 2_400));
}

test "RateLimiter: success clears the failure count" {
    var rl = RateLimiter.init(std.testing.allocator, .{
        .failures_per_window = 3,
        .window_ms = 10_000,
    });
    defer rl.deinit();
    const key = prefixFromIpv4(.{ 10, 11, 12, 13 });
    rl.recordFailure(key, 100);
    rl.recordFailure(key, 200);
    rl.recordSuccess(key, 300);
    rl.recordFailure(key, 400);
    try std.testing.expectEqual(Verdict.allow, rl.consult(key, 500));
}

test "RateLimiter: /24 aggregation groups neighbors" {
    var rl = RateLimiter.init(std.testing.allocator, .{
        .failures_per_window = 2,
        .window_ms = 1_000,
    });
    defer rl.deinit();
    const a = prefixFromIpv4(.{ 1, 2, 3, 4 });
    const b = prefixFromIpv4(.{ 1, 2, 3, 200 }); // same /24
    rl.recordFailure(a, 0);
    rl.recordFailure(b, 100);
    try std.testing.expectEqual(Verdict.drop_silently, rl.consult(a, 150));
    try std.testing.expectEqual(Verdict.drop_silently, rl.consult(b, 150));
}

test "RateLimiter: LRU eviction caps memory" {
    var rl = RateLimiter.init(std.testing.allocator, .{
        .bucket_capacity = 4,
        .failures_per_window = 10,
    });
    defer rl.deinit();
    var i: u32 = 0;
    while (i < 12) : (i += 1) {
        var key: PrefixKey = @splat(0);
        key[0] = @as(u8, @intCast(i));
        rl.recordFailure(key, @as(i64, i) * 100);
    }
    try std.testing.expect(rl.buckets.count() <= 4);
}

test "RateLimiter: allocator failure during recordFailure is swallowed (fail-open)" {
    var fa = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var rl = RateLimiter.init(fa.allocator(), .{});
    defer rl.deinit();
    const key = prefixFromIpv4(.{ 1, 2, 3, 4 });
    rl.recordFailure(key, 0); // allocator fails, recordFailure must not crash
    try std.testing.expectEqual(Verdict.allow, rl.consult(key, 100));
}
