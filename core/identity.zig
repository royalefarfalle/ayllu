//! Identity (runa) — долгоживущая криптографическая идентичность узла.
//!
//! Состоит из Ed25519-ключа для подписей и X25519-ключа для DH, причём
//! X25519 выводится из того же Ed25519 seed через `fromEd25519` — это
//! означает, что мы храним ровно один источник секрета и не можем случайно
//! получить рассогласованную пару.

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

test "generate produces distinct identities" {
    const io = std.testing.io;
    const a = try Identity.generate(io);
    const b = try Identity.generate(io);
    try std.testing.expect(!std.mem.eql(u8, &a.fingerprint(), &b.fingerprint()));
}

test "sign and verify roundtrip" {
    const io = std.testing.io;
    const id = try Identity.generate(io);
    const msg = "привет, ayllu";
    const sig = try id.sign(msg);
    try sig.verify(msg, id.ed25519.public_key);
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

test "dh is symmetric" {
    const io = std.testing.io;
    const alice = try Identity.generate(io);
    const bob = try Identity.generate(io);
    const ss_a = try alice.dh(bob.x25519.public_key);
    const ss_b = try bob.dh(alice.x25519.public_key);
    try std.testing.expectEqualSlices(u8, &ss_a, &ss_b);
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

test "distinct seeds produce distinct fingerprints" {
    const a = try Identity.fromSeed(@splat(0x01));
    const b = try Identity.fromSeed(@splat(0x02));
    try std.testing.expect(!std.mem.eql(u8, &a.fingerprint(), &b.fingerprint()));
}
