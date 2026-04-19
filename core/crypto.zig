//! Обёртки над `std.crypto`. Единственное место, где ядро трогает std.crypto
//! напрямую — дальше по проекту все primitives импортируются отсюда, чтобы
//! замена (например, на hybrid-KEM в фазе post-quantum) была локальной.

const std = @import("std");

pub const Ed25519 = std.crypto.sign.Ed25519;
pub const X25519 = std.crypto.dh.X25519;
pub const Sha256 = std.crypto.hash.sha2.Sha256;

pub const fingerprint_length = Sha256.digest_length;
pub const Fingerprint = [fingerprint_length]u8;

// Связывает это хэш-пространство с «peer-fingerprint v1» и отделяет его
// от любого другого SHA-256(32||32) в проекте (envelope digest, session id
// и т.п.), чтобы не возникало случайных коллизий между пространствами.
const fingerprint_domain = "ayllu.fp.v1";

pub fn fingerprint(
    ed_public_key: [Ed25519.PublicKey.encoded_length]u8,
    x_public_key: [X25519.public_length]u8,
) Fingerprint {
    var h = Sha256.init(.{});
    h.update(fingerprint_domain);
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

test "fingerprint distinguishes key-role swap" {
    const a: [32]u8 = @splat(0x11);
    const b: [32]u8 = @splat(0x22);
    try std.testing.expect(!std.mem.eql(u8, &fingerprint(a, b), &fingerprint(b, a)));
}

test "fingerprint is domain-separated from raw SHA256(ed || x)" {
    const ed: [32]u8 = @splat(0x55);
    const x: [32]u8 = @splat(0x66);
    var naive: [32]u8 = undefined;
    var h = Sha256.init(.{});
    h.update(&ed);
    h.update(&x);
    h.final(&naive);
    try std.testing.expect(!std.mem.eql(u8, &naive, &fingerprint(ed, x)));
}

test "fingerprint length matches sha256 digest" {
    try std.testing.expectEqual(@as(usize, 32), fingerprint_length);
}

test "primitives wire through to std.crypto" {
    try std.testing.expectEqual(@as(usize, 32), Ed25519.PublicKey.encoded_length);
    try std.testing.expectEqual(@as(usize, 32), X25519.public_length);
}
