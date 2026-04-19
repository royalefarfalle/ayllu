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
// от любого другого SHA-256(32||32) в проекте. Менять ТОЛЬКО вместе с
// миграцией всех существующих peer id — golden vector ниже заставит
// подумать дважды.
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

const testing_helpers = @import("testing.zig");

fn ramp(comptime start: u8) [32]u8 {
    var arr: [32]u8 = undefined;
    for (&arr, 0..) |*b, i| b.* = start +% @as(u8, @intCast(i));
    return arr;
}

test "fingerprint golden vector v1 — asymmetric inputs" {
    const ed = ramp(0x01); // 0x01..0x20
    const x = ramp(0x81); //  0x81..0xA0
    const expected = testing_helpers.hex32("9ae4f0e46d9dbf8575c5812f858a92a7f16ae57ac5a336ab165467df0cdfe776");
    try std.testing.expectEqualSlices(u8, &expected, &fingerprint(ed, x));
}

test "fingerprint golden vector v1 — zero keys" {
    const zero: [32]u8 = @splat(0);
    const expected = testing_helpers.hex32("00ea1658a9c34367d24a49b64c3b8b90fe5c99b37e49f2d3b4bd839abf73ea29");
    try std.testing.expectEqualSlices(u8, &expected, &fingerprint(zero, zero));
}

test "fingerprint is deterministic" {
    const ed = ramp(0x01);
    const x = ramp(0x81);
    try std.testing.expectEqualSlices(u8, &fingerprint(ed, x), &fingerprint(ed, x));
}

test "fingerprint distinguishes key-role swap" {
    const a = ramp(0x01);
    const b = ramp(0x81);
    try std.testing.expect(!std.mem.eql(u8, &fingerprint(a, b), &fingerprint(b, a)));
}

test "fingerprint accepts real Ed25519 + X25519 public keys" {
    const io = std.testing.io;
    const ed_kp = Ed25519.KeyPair.generate(io);
    const x_kp = try X25519.KeyPair.fromEd25519(ed_kp);
    const fp = fingerprint(ed_kp.public_key.toBytes(), x_kp.public_key);
    try std.testing.expectEqual(@as(usize, 32), fp.len);
}

test "primitives wire through to std.crypto" {
    try std.testing.expectEqual(@as(usize, 32), Ed25519.PublicKey.encoded_length);
    try std.testing.expectEqual(@as(usize, 32), X25519.public_length);
    try std.testing.expectEqual(@as(usize, 32), fingerprint_length);
}
