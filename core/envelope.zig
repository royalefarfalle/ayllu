//! Envelope (quipu) — атомарная единица ayllu-трафика.
//!
//! Содержит всё, что нужно любому узлу, чтобы принять решение о
//! пересылке/приёмке: версия протокола, идентификатор, отправитель,
//! получатель, срок жизни и подписанный payload. Версия и domain-тег в
//! digest'е — строгие: любое изменение формы digest'а требует bump.

const std = @import("std");
const crypto = @import("crypto.zig");
const Identity = @import("identity.zig").Identity;
const PublicIdentity = @import("identity.zig").PublicIdentity;

pub const envelope_version: u8 = 1;
pub const id_length = 16;
pub const Id = [id_length]u8;

// Domain-тег держит digest envelope'а отдельно от любого другого
// SHA-256-пространства в проекте (fingerprint, session id, будущие
// производные). Любое изменение формы digest'а → bump на v2.
const digest_domain = "ayllu.env.v1";

pub const Target = union(enum) {
    broadcast,
    fingerprint: crypto.Fingerprint,
    multicast: crypto.Fingerprint,
};

pub const VerifyError = error{
    FingerprintMismatch,
    WrongVersion,
    SignatureVerificationFailed,
} || crypto.Ed25519.Signature.VerifyError;

pub const Envelope = struct {
    version: u8 = envelope_version,
    id: Id,
    from: crypto.Fingerprint,
    to: Target,
    created_at: i64,
    expires_at: i64,
    payload: []const u8,
    signature: crypto.Ed25519.Signature,

    pub fn digest(self: Envelope) [crypto.Sha256.digest_length]u8 {
        return computeDigest(
            self.version,
            self.id,
            self.from,
            self.to,
            self.created_at,
            self.expires_at,
            self.payload,
        );
    }

    pub fn isExpired(self: Envelope, now_ms: i64) bool {
        return now_ms >= self.expires_at;
    }

    pub fn verify(self: Envelope, sender: PublicIdentity) VerifyError!void {
        if (self.version != envelope_version) return error.WrongVersion;
        if (!std.mem.eql(u8, &self.from, &sender.fingerprint())) {
            return error.FingerprintMismatch;
        }
        const d = self.digest();
        try self.signature.verify(&d, sender.ed_public_key);
    }
};

pub fn buildAndSign(
    io: std.Io,
    sender: Identity,
    to: Target,
    created_at: i64,
    expires_at: i64,
    payload: []const u8,
) !Envelope {
    var env_id: Id = undefined;
    io.random(&env_id);
    const from = sender.fingerprint();
    const d = computeDigest(envelope_version, env_id, from, to, created_at, expires_at, payload);
    const sig = try sender.sign(&d);
    return .{
        .id = env_id,
        .from = from,
        .to = to,
        .created_at = created_at,
        .expires_at = expires_at,
        .payload = payload,
        .signature = sig,
    };
}

fn computeDigest(
    version: u8,
    id: Id,
    from: crypto.Fingerprint,
    to: Target,
    created_at: i64,
    expires_at: i64,
    payload: []const u8,
) [crypto.Sha256.digest_length]u8 {
    var h = crypto.Sha256.init(.{});
    h.update(digest_domain);
    h.update(&.{version});
    h.update(&id);
    h.update(&from);
    switch (to) {
        .broadcast => h.update(&.{0}),
        .fingerprint => |fp| {
            h.update(&.{1});
            h.update(&fp);
        },
        .multicast => |fp| {
            h.update(&.{2});
            h.update(&fp);
        },
    }
    var buf: [8]u8 = undefined;
    std.mem.writeInt(i64, &buf, created_at, .little);
    h.update(&buf);
    std.mem.writeInt(i64, &buf, expires_at, .little);
    h.update(&buf);
    std.mem.writeInt(u64, &buf, payload.len, .little);
    h.update(&buf);
    h.update(payload);
    var out: [crypto.Sha256.digest_length]u8 = undefined;
    h.final(&out);
    return out;
}

fn hex32(comptime s: *const [64]u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "buildAndSign + verify — fingerprint target" {
    const io = std.testing.io;
    const alice = try Identity.fromSeed(@splat(0x01));
    const bob = try Identity.fromSeed(@splat(0x02));
    const env = try buildAndSign(
        io,
        alice,
        .{ .fingerprint = bob.fingerprint() },
        1_700_000_000_000,
        1_700_000_060_000,
        "hello, bob",
    );
    try env.verify(alice.publicView());
}

test "buildAndSign + verify — broadcast target" {
    const io = std.testing.io;
    const alice = try Identity.fromSeed(@splat(0x03));
    const env = try buildAndSign(io, alice, .broadcast, 0, 1, "broadcasting");
    try env.verify(alice.publicView());
}

test "buildAndSign + verify — multicast target" {
    const io = std.testing.io;
    const alice = try Identity.fromSeed(@splat(0x04));
    const group_id: crypto.Fingerprint = @splat(0xCC);
    const env = try buildAndSign(io, alice, .{ .multicast = group_id }, 0, 1, "to group");
    try env.verify(alice.publicView());
}

test "verify rejects tampered payload" {
    const io = std.testing.io;
    const alice = try Identity.fromSeed(@splat(0x05));
    var env = try buildAndSign(io, alice, .broadcast, 0, 1, "original payload");
    env.payload = "tampered payload";
    try std.testing.expectError(
        error.SignatureVerificationFailed,
        env.verify(alice.publicView()),
    );
}

test "verify rejects tampered timestamps" {
    const io = std.testing.io;
    const alice = try Identity.fromSeed(@splat(0x06));
    var env = try buildAndSign(io, alice, .broadcast, 1000, 2000, "p");
    env.expires_at = 999_999;
    try std.testing.expectError(
        error.SignatureVerificationFailed,
        env.verify(alice.publicView()),
    );
}

test "verify rejects fingerprint mismatch" {
    const io = std.testing.io;
    const alice = try Identity.fromSeed(@splat(0x07));
    const eve = try Identity.fromSeed(@splat(0x08));
    const env = try buildAndSign(io, alice, .broadcast, 0, 1, "p");
    try std.testing.expectError(
        error.FingerprintMismatch,
        env.verify(eve.publicView()),
    );
}

test "verify rejects wrong version" {
    const io = std.testing.io;
    const alice = try Identity.fromSeed(@splat(0x09));
    var env = try buildAndSign(io, alice, .broadcast, 0, 1, "p");
    env.version = 99;
    try std.testing.expectError(error.WrongVersion, env.verify(alice.publicView()));
}

test "isExpired semantics" {
    const io = std.testing.io;
    const alice = try Identity.fromSeed(@splat(0x0A));
    const env = try buildAndSign(io, alice, .broadcast, 1000, 2000, "p");
    try std.testing.expect(!env.isExpired(1500));
    try std.testing.expect(!env.isExpired(1999));
    try std.testing.expect(env.isExpired(2000));
    try std.testing.expect(env.isExpired(3000));
}

test "digest is deterministic for identical inputs" {
    const fp: crypto.Fingerprint = @splat(0x11);
    const id: Id = @splat(0x22);
    const d1 = computeDigest(envelope_version, id, fp, .broadcast, 100, 200, "p");
    const d2 = computeDigest(envelope_version, id, fp, .broadcast, 100, 200, "p");
    try std.testing.expectEqualSlices(u8, &d1, &d2);
}

test "digest distinguishes different Target variants" {
    const fp_a: crypto.Fingerprint = @splat(0x33);
    const fp_b: crypto.Fingerprint = @splat(0x33); // same bytes, different variant
    const id: Id = @splat(0x44);
    const d_broadcast = computeDigest(envelope_version, id, fp_a, .broadcast, 0, 0, "p");
    const d_fp = computeDigest(envelope_version, id, fp_a, .{ .fingerprint = fp_b }, 0, 0, "p");
    const d_mc = computeDigest(envelope_version, id, fp_a, .{ .multicast = fp_b }, 0, 0, "p");
    try std.testing.expect(!std.mem.eql(u8, &d_broadcast, &d_fp));
    try std.testing.expect(!std.mem.eql(u8, &d_fp, &d_mc));
    try std.testing.expect(!std.mem.eql(u8, &d_broadcast, &d_mc));
}

test "digest is domain-separated from raw SHA256 of fields" {
    const fp: crypto.Fingerprint = @splat(0);
    const id: Id = @splat(0);
    var naive: [32]u8 = undefined;
    var h = crypto.Sha256.init(.{});
    h.update(&.{envelope_version});
    h.update(&id);
    h.update(&fp);
    h.update(&.{0}); // broadcast tag
    var tsb: [8]u8 = undefined;
    std.mem.writeInt(i64, &tsb, 0, .little);
    h.update(&tsb);
    h.update(&tsb);
    std.mem.writeInt(u64, &tsb, 1, .little);
    h.update(&tsb);
    h.update("x");
    h.final(&naive);
    const tagged = computeDigest(envelope_version, id, fp, .broadcast, 0, 0, "x");
    try std.testing.expect(!std.mem.eql(u8, &naive, &tagged));
}

test "digest golden vector v1" {
    const from: crypto.Fingerprint = @splat(0xAB);
    const id: Id = @splat(0xCD);
    const d = computeDigest(envelope_version, id, from, .broadcast, 1700, 1800, "hi");
    const expected = hex32("38d26a22a82c740ece03c8522e93d22d8084e53df91583b38f4e3290be1a3f32");
    try std.testing.expectEqualSlices(u8, &expected, &d);
}

test "distinct envelope ids produce distinct digests" {
    const from: crypto.Fingerprint = @splat(0x55);
    const a = computeDigest(envelope_version, @splat(0x01), from, .broadcast, 0, 0, "p");
    const b = computeDigest(envelope_version, @splat(0x02), from, .broadcast, 0, 0, "p");
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}

test "distinct payloads produce distinct digests (length-prefixed)" {
    const from: crypto.Fingerprint = @splat(0x77);
    const id: Id = @splat(0x88);
    const a = computeDigest(envelope_version, id, from, .broadcast, 0, 0, "abc");
    const b = computeDigest(envelope_version, id, from, .broadcast, 0, 0, "abcd");
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}

test "payload-length prefix blocks ambiguous concatenation" {
    const from: crypto.Fingerprint = @splat(0x99);
    const id: Id = @splat(0xAA);
    const split = computeDigest(envelope_version, id, from, .broadcast, 0, 0, "abcdef");
    const merged = computeDigest(envelope_version, id, from, .broadcast, 0, 0, "abc" ++ "def");
    try std.testing.expectEqualSlices(u8, &split, &merged);
    const different = computeDigest(envelope_version, id, from, .broadcast, 0, 0, "ab" ++ "cdefg");
    try std.testing.expect(!std.mem.eql(u8, &split, &different));
}

test "buildAndSign includes sender fingerprint in from" {
    const io = std.testing.io;
    const alice = try Identity.fromSeed(@splat(0x12));
    const env = try buildAndSign(io, alice, .broadcast, 0, 1, "p");
    try std.testing.expectEqualSlices(u8, &alice.fingerprint(), &env.from);
}
