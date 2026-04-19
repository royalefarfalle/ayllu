//! Обёртки над `std.crypto`. Единственное место, где ядро трогает std.crypto
//! напрямую — дальше по проекту все primitives импортируются отсюда, чтобы
//! замена (например, на hybrid-KEM в фазе post-quantum) была локальной.

const std = @import("std");

pub const Ed25519 = std.crypto.sign.Ed25519;
pub const X25519 = std.crypto.dh.X25519;
pub const Aes256GcmSiv = std.crypto.aead.aes_gcm_siv.Aes256GcmSiv;
pub const Sha256 = std.crypto.hash.sha2.Sha256;
pub const Blake2b256 = std.crypto.hash.blake2.Blake2b256;

pub const fingerprint_length = Sha256.digest_length;
pub const Fingerprint = [fingerprint_length]u8;

pub fn fingerprint(
    ed_public_key: [Ed25519.PublicKey.encoded_length]u8,
    x_public_key: [X25519.public_length]u8,
) Fingerprint {
    var h = Sha256.init(.{});
    h.update(&ed_public_key);
    h.update(&x_public_key);
    var out: Fingerprint = undefined;
    h.final(&out);
    return out;
}

test "fingerprint is deterministic" {
    const ed: [32]u8 = @splat(0xAA);
    const x: [32]u8 = @splat(0xBB);
    try std.testing.expectEqualSlices(u8, &fingerprint(ed, x), &fingerprint(ed, x));
}

test "fingerprint reacts to any bit flip in ed key" {
    var ed: [32]u8 = @splat(0xAA);
    const x: [32]u8 = @splat(0xBB);
    const base = fingerprint(ed, x);
    ed[0] ^= 1;
    try std.testing.expect(!std.mem.eql(u8, &base, &fingerprint(ed, x)));
}

test "fingerprint reacts to any bit flip in x key" {
    const ed: [32]u8 = @splat(0xAA);
    var x: [32]u8 = @splat(0xBB);
    const base = fingerprint(ed, x);
    x[31] ^= 0x80;
    try std.testing.expect(!std.mem.eql(u8, &base, &fingerprint(ed, x)));
}

test "fingerprint distinguishes key-role swap" {
    const a: [32]u8 = @splat(0x11);
    const b: [32]u8 = @splat(0x22);
    try std.testing.expect(!std.mem.eql(u8, &fingerprint(a, b), &fingerprint(b, a)));
}

test "fingerprint length matches sha256 digest" {
    try std.testing.expectEqual(@as(usize, 32), fingerprint_length);
    const fp: Fingerprint = fingerprint(@splat(0), @splat(0));
    try std.testing.expectEqual(@as(usize, 32), fp.len);
}

test "primitives wire through to std.crypto" {
    try std.testing.expectEqual(@as(usize, 32), Ed25519.PublicKey.encoded_length);
    try std.testing.expectEqual(@as(usize, 32), X25519.public_length);
    try std.testing.expectEqual(@as(usize, 32), Aes256GcmSiv.key_length);
}
