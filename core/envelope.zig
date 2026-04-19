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

pub const current_version: u8 = 1;
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
} || crypto.Ed25519.Signature.VerifyError;

pub const Envelope = struct {
    version: u8,
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
        if (self.version != current_version) return error.WrongVersion;
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
    const d = computeDigest(current_version, env_id, from, to, created_at, expires_at, payload);
    const sig = try sender.sign(&d);
    return .{
        .version = current_version,
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

const hex32 = @import("testing.zig").hex32;

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
    const d1 = computeDigest(current_version, id, fp, .broadcast, 100, 200, "p");
    const d2 = computeDigest(current_version, id, fp, .broadcast, 100, 200, "p");
    try std.testing.expectEqualSlices(u8, &d1, &d2);
}

test "digest distinguishes different Target variants" {
    const fp_a: crypto.Fingerprint = @splat(0x33);
    const fp_b: crypto.Fingerprint = @splat(0x33); // same bytes, different variant
    const id: Id = @splat(0x44);
    const d_broadcast = computeDigest(current_version, id, fp_a, .broadcast, 0, 0, "p");
    const d_fp = computeDigest(current_version, id, fp_a, .{ .fingerprint = fp_b }, 0, 0, "p");
    const d_mc = computeDigest(current_version, id, fp_a, .{ .multicast = fp_b }, 0, 0, "p");
    try std.testing.expect(!std.mem.eql(u8, &d_broadcast, &d_fp));
    try std.testing.expect(!std.mem.eql(u8, &d_fp, &d_mc));
    try std.testing.expect(!std.mem.eql(u8, &d_broadcast, &d_mc));
}

test "digest is domain-separated from raw SHA256 of fields" {
    const fp: crypto.Fingerprint = @splat(0);
    const id: Id = @splat(0);
    var naive: [32]u8 = undefined;
    var h = crypto.Sha256.init(.{});
    h.update(&.{current_version});
    h.update(&id);
    h.update(&fp);
    h.update(&.{0});
    var tsb: [8]u8 = undefined;
    std.mem.writeInt(i64, &tsb, 0, .little);
    h.update(&tsb);
    h.update(&tsb);
    std.mem.writeInt(u64, &tsb, 1, .little);
    h.update(&tsb);
    h.update("x");
    h.final(&naive);
    const tagged = computeDigest(current_version, id, fp, .broadcast, 0, 0, "x");
    try std.testing.expect(!std.mem.eql(u8, &naive, &tagged));
}

test "digest golden vector v1" {
    const from: crypto.Fingerprint = @splat(0xAB);
    const id: Id = @splat(0xCD);
    const d = computeDigest(current_version, id, from, .broadcast, 1700, 1800, "hi");
    const expected = hex32("38d26a22a82c740ece03c8522e93d22d8084e53df91583b38f4e3290be1a3f32");
    try std.testing.expectEqualSlices(u8, &expected, &d);
}

test "distinct envelope ids produce distinct digests" {
    const from: crypto.Fingerprint = @splat(0x55);
    const a = computeDigest(current_version, @splat(0x01), from, .broadcast, 0, 0, "p");
    const b = computeDigest(current_version, @splat(0x02), from, .broadcast, 0, 0, "p");
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}

test "distinct payloads produce distinct digests (length-prefixed)" {
    const from: crypto.Fingerprint = @splat(0x77);
    const id: Id = @splat(0x88);
    const a = computeDigest(current_version, id, from, .broadcast, 0, 0, "abc");
    const b = computeDigest(current_version, id, from, .broadcast, 0, 0, "abcd");
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}

test "digest incorporates payload length prefix" {
    const from: crypto.Fingerprint = @splat(0x99);
    const id: Id = @splat(0xAA);
    const actual = computeDigest(current_version, id, from, .broadcast, 0, 0, "payload");
    var without_len: [32]u8 = undefined;
    var h = crypto.Sha256.init(.{});
    h.update(digest_domain);
    h.update(&.{current_version});
    h.update(&id);
    h.update(&from);
    h.update(&.{0});
    var ts: [8]u8 = undefined;
    std.mem.writeInt(i64, &ts, 0, .little);
    h.update(&ts);
    h.update(&ts);
    h.update("payload");
    h.final(&without_len);
    try std.testing.expect(!std.mem.eql(u8, &actual, &without_len));
}

test "buildAndSign includes sender fingerprint in from" {
    const io = std.testing.io;
    const alice = try Identity.fromSeed(@splat(0x12));
    const env = try buildAndSign(io, alice, .broadcast, 0, 1, "p");
    try std.testing.expectEqualSlices(u8, &alice.fingerprint(), &env.from);
}

test "signature over golden digest is stable — EdDSA determinism + wire format" {
    // EdDSA with null noise is deterministic, so signing a pinned digest with a
    // pinned identity must reproduce the same 64 bytes. Catches any regression
    // that switches to hedged signing, changes noise handling, or alters the
    // sign-over-digest wiring.
    const alice = try Identity.fromSeed(@splat(0x01));
    var digest: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &digest,
        "38d26a22a82c740ece03c8522e93d22d8084e53df91583b38f4e3290be1a3f32",
    );
    const sig = try alice.sign(&digest);
    var expected: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &expected,
        "7b701a7ccc8d5b971d2c7d2a64ac33dffe54456639c76d773c52d41ccabcddc9" ++
            "a4c4552954f5d787dc23b4a2f265d93fa68a0f7908c4f5fb65bf976f4a23ab07",
    );
    try std.testing.expectEqualSlices(u8, &expected, &sig.toBytes());
}

test "verify rejects envelope with mutant PublicIdentity (Alice ed + Bob x)" {
    const io = std.testing.io;
    const alice = try Identity.fromSeed(@splat(0x20));
    const bob = try Identity.fromSeed(@splat(0x21));
    const env = try buildAndSign(io, alice, .broadcast, 0, 1, "p");
    const mutant: PublicIdentity = .{
        .ed_public_key = alice.ed25519.public_key,
        .x_public_key = bob.x25519.public_key,
    };
    try std.testing.expectError(error.FingerprintMismatch, env.verify(mutant));
}

test "verify rejects signature that isn't over this envelope's digest" {
    const io = std.testing.io;
    const alice = try Identity.fromSeed(@splat(0x30));
    var env = try buildAndSign(io, alice, .broadcast, 0, 1, "p");
    env.signature = try alice.sign("not this envelope's digest");
    try std.testing.expectError(
        error.SignatureVerificationFailed,
        env.verify(alice.publicView()),
    );
}

test "verify rejects tampered envelope id" {
    const io = std.testing.io;
    const alice = try Identity.fromSeed(@splat(0x31));
    var env = try buildAndSign(io, alice, .broadcast, 0, 1, "p");
    env.id[0] ^= 0x01;
    try std.testing.expectError(
        error.SignatureVerificationFailed,
        env.verify(alice.publicView()),
    );
}

test "verify rejects tampered from — FingerprintMismatch precedes signature check" {
    const io = std.testing.io;
    const alice = try Identity.fromSeed(@splat(0x32));
    var env = try buildAndSign(io, alice, .broadcast, 0, 1, "p");
    env.from[0] ^= 0x01;
    try std.testing.expectError(error.FingerprintMismatch, env.verify(alice.publicView()));
}

test "verify rejects multicast rewritten to fingerprint of same fp" {
    const io = std.testing.io;
    const alice = try Identity.fromSeed(@splat(0x33));
    const group_id: crypto.Fingerprint = @splat(0xCC);
    var env = try buildAndSign(io, alice, .{ .multicast = group_id }, 0, 1, "p");
    env.to = .{ .fingerprint = group_id };
    try std.testing.expectError(
        error.SignatureVerificationFailed,
        env.verify(alice.publicView()),
    );
}

test "buildAndSign + verify — empty payload" {
    const io = std.testing.io;
    const alice = try Identity.fromSeed(@splat(0x34));
    const env = try buildAndSign(io, alice, .broadcast, 0, 1, "");
    try env.verify(alice.publicView());
}

test "version = 0 is rejected" {
    const io = std.testing.io;
    const alice = try Identity.fromSeed(@splat(0x35));
    var env = try buildAndSign(io, alice, .broadcast, 0, 1, "p");
    env.version = 0;
    try std.testing.expectError(error.WrongVersion, env.verify(alice.publicView()));
}

test "isExpired — created_at == expires_at is born-expired at that instant" {
    const io = std.testing.io;
    const alice = try Identity.fromSeed(@splat(0x36));
    const env = try buildAndSign(io, alice, .broadcast, 1000, 1000, "p");
    try std.testing.expect(!env.isExpired(999));
    try std.testing.expect(env.isExpired(1000));
}

test "signature roundtrips through toBytes/fromBytes" {
    const io = std.testing.io;
    const alice = try Identity.fromSeed(@splat(0x37));
    var env = try buildAndSign(io, alice, .broadcast, 0, 1, "wire");
    const bytes = env.signature.toBytes();
    env.signature = crypto.Ed25519.Signature.fromBytes(bytes);
    try env.verify(alice.publicView());
}

test "envelope digest domain-separates from crypto.fingerprint space" {
    const ed_shape: [32]u8 = @splat(0xAA);
    const x_shape: [32]u8 = @splat(0xAA);
    const fp = crypto.fingerprint(ed_shape, x_shape);
    const env_d = computeDigest(current_version, @splat(0), ed_shape, .broadcast, 0, 0, "");
    try std.testing.expect(!std.mem.eql(u8, &fp, &env_d));
}
