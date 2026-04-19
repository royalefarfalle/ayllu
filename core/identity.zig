//! Identity (runa) — the long-lived cryptographic identity of a node.
//!
//! Holds an Ed25519 key for signatures and an X25519 key for DH, where
//! X25519 is derived from the same Ed25519 seed via `fromEd25519`. That
//! means exactly one secret source is stored, and we can't accidentally
//! end up with a mismatched pair.

const std = @import("std");
const crypto = @import("crypto.zig");

pub const PublicIdentity = struct {
    ed_public_key: crypto.Ed25519.PublicKey,
    x_public_key: [crypto.X25519.public_length]u8,

    pub fn fingerprint(self: PublicIdentity) crypto.Fingerprint {
        return crypto.fingerprint(self.ed_public_key.toBytes(), self.x_public_key);
    }
};

pub const Identity = struct {
    ed25519: crypto.Ed25519.KeyPair,
    x25519: crypto.X25519.KeyPair,

    pub fn generate(io: std.Io) !Identity {
        const ed = crypto.Ed25519.KeyPair.generate(io);
        const x = try crypto.X25519.KeyPair.fromEd25519(ed);
        return .{ .ed25519 = ed, .x25519 = x };
    }

    pub fn fromSeed(seed: [crypto.Ed25519.KeyPair.seed_length]u8) !Identity {
        const ed = try crypto.Ed25519.KeyPair.generateDeterministic(seed);
        const x = try crypto.X25519.KeyPair.fromEd25519(ed);
        return .{ .ed25519 = ed, .x25519 = x };
    }

    pub fn publicView(self: Identity) PublicIdentity {
        return .{
            .ed_public_key = self.ed25519.public_key,
            .x_public_key = self.x25519.public_key,
        };
    }

    pub fn fingerprint(self: Identity) crypto.Fingerprint {
        return crypto.fingerprint(self.ed25519.public_key.toBytes(), self.x25519.public_key);
    }

    pub fn sign(self: Identity, msg: []const u8) !crypto.Ed25519.Signature {
        return self.ed25519.sign(msg, null);
    }

    pub fn dh(
        self: Identity,
        peer_x_public_key: [crypto.X25519.public_length]u8,
    ) ![crypto.X25519.shared_length]u8 {
        return crypto.X25519.scalarmult(self.x25519.secret_key, peer_x_public_key);
    }
};

const hex32 = @import("testing.zig").hex32;

test "fromSeed is deterministic" {
    const seed: [32]u8 = @splat(0x42);
    const a = try Identity.fromSeed(seed);
    const b = try Identity.fromSeed(seed);
    try std.testing.expectEqualSlices(u8, &a.fingerprint(), &b.fingerprint());
    try std.testing.expectEqualSlices(
        u8,
        &a.ed25519.public_key.toBytes(),
        &b.ed25519.public_key.toBytes(),
    );
    try std.testing.expectEqualSlices(u8, &a.x25519.public_key, &b.x25519.public_key);
}

test "fromSeed(0x42) golden vectors — wire-format anchor" {
    const id = try Identity.fromSeed(@splat(0x42));
    try std.testing.expectEqualSlices(
        u8,
        &hex32("2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"),
        &id.ed25519.public_key.toBytes(),
    );
    try std.testing.expectEqualSlices(
        u8,
        &hex32("cc4f2cdb695dd766f34118eb67b98652fed1d8bc49c330b119bbfa8a64989378"),
        &id.x25519.public_key,
    );
    try std.testing.expectEqualSlices(
        u8,
        &hex32("c3f8511d4d5006ea17bcd8890515b9f4bc965f1386def3bf1466b3be3bff5c8a"),
        &id.fingerprint(),
    );
}

test "x25519 is derived from ed25519 — single-secret-source invariant" {
    const id = try Identity.fromSeed(@splat(0x33));
    const expected_x = try crypto.X25519.KeyPair.fromEd25519(id.ed25519);
    try std.testing.expectEqualSlices(u8, &expected_x.public_key, &id.x25519.public_key);
    try std.testing.expectEqualSlices(u8, &expected_x.secret_key, &id.x25519.secret_key);
}

test "ed_public_key and x_public_key are distinct for same seed" {
    const id = try Identity.fromSeed(@splat(0x42));
    try std.testing.expect(!std.mem.eql(u8, &id.ed25519.public_key.toBytes(), &id.x25519.public_key));
}

test "generate produces distinct identities" {
    const io = std.testing.io;
    const a = try Identity.generate(io);
    const b = try Identity.generate(io);
    try std.testing.expect(!std.mem.eql(u8, &a.fingerprint(), &b.fingerprint()));
}

test "sign and verify roundtrip" {
    const io = std.testing.io;
    const id = try Identity.generate(io);
    const msg = "hello, ayllu";
    const sig = try id.sign(msg);
    try sig.verify(msg, id.ed25519.public_key);
}

test "sign verifies through publicView.ed_public_key too" {
    const id = try Identity.fromSeed(@splat(0x55));
    const sig = try id.sign("envelope-digest-placeholder");
    try sig.verify("envelope-digest-placeholder", id.publicView().ed_public_key);
}

test "verify rejects tampered message" {
    const io = std.testing.io;
    const id = try Identity.generate(io);
    const sig = try id.sign("original");
    try std.testing.expectError(
        error.SignatureVerificationFailed,
        sig.verify("tampered", id.ed25519.public_key),
    );
}

test "sign is deterministic (EdDSA, noise = null)" {
    const id = try Identity.fromSeed(@splat(0x44));
    const a = try id.sign("determinism");
    const b = try id.sign("determinism");
    try std.testing.expectEqualSlices(u8, &a.toBytes(), &b.toBytes());
}

test "sign empty message" {
    const id = try Identity.fromSeed(@splat(0x66));
    const sig = try id.sign("");
    try sig.verify("", id.ed25519.public_key);
    try std.testing.expectError(
        error.SignatureVerificationFailed,
        sig.verify("x", id.ed25519.public_key),
    );
}

test "dh is symmetric" {
    const io = std.testing.io;
    const alice = try Identity.generate(io);
    const bob = try Identity.generate(io);
    const ss_a = try alice.dh(bob.x25519.public_key);
    const ss_b = try bob.dh(alice.x25519.public_key);
    try std.testing.expectEqualSlices(u8, &ss_a, &ss_b);
}

test "dh golden vector between seeds 0x0A and 0x0B" {
    const alice = try Identity.fromSeed(@splat(0x0A));
    const bob = try Identity.fromSeed(@splat(0x0B));
    const ss = try alice.dh(bob.x25519.public_key);
    try std.testing.expectEqualSlices(
        u8,
        &hex32("cefd70475e6e583341fc0fdaebed8bb6232cd3407f55c242fb794c7e508e5e59"),
        &ss,
    );
}

test "dh rejects all-zero peer key — fail-fast contract" {
    const id = try Identity.fromSeed(@splat(0x77));
    try std.testing.expectError(error.IdentityElement, id.dh(@splat(0)));
}

test "fingerprint derives from crypto.fingerprint(ed_pk, x_pk)" {
    const seed: [32]u8 = @splat(0x77);
    const id = try Identity.fromSeed(seed);
    const expected = crypto.fingerprint(id.ed25519.public_key.toBytes(), id.x25519.public_key);
    try std.testing.expectEqualSlices(u8, &expected, &id.fingerprint());
}

test "publicView carries the same public keys" {
    const seed: [32]u8 = @splat(0x11);
    const id = try Identity.fromSeed(seed);
    const pv = id.publicView();
    try std.testing.expectEqualSlices(
        u8,
        &id.ed25519.public_key.toBytes(),
        &pv.ed_public_key.toBytes(),
    );
    try std.testing.expectEqualSlices(u8, &id.x25519.public_key, &pv.x_public_key);
    try std.testing.expectEqualSlices(u8, &id.fingerprint(), &pv.fingerprint());
}

test "publicView is a value copy, not aliased" {
    const id = try Identity.fromSeed(@splat(0x22));
    var pv = id.publicView();
    pv.x_public_key[0] ^= 0xFF;
    try std.testing.expect(pv.x_public_key[0] != id.x25519.public_key[0]);
}

test "Identity has only two fields — catches secret-leaking additions" {
    try std.testing.expectEqual(@as(usize, 2), std.meta.fields(Identity).len);
}

test "distinct seeds produce distinct fingerprints" {
    const a = try Identity.fromSeed(@splat(0x01));
    const b = try Identity.fromSeed(@splat(0x02));
    try std.testing.expect(!std.mem.eql(u8, &a.fingerprint(), &b.fingerprint()));
}
