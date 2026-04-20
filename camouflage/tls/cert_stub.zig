//! Runtime-generated Ed25519 self-signed stub certificate for the
//! REALITY TLS 1.3 handshake.
//!
//! REALITY normally proxies the cover host's real certificate (see C6
//! cert-harvest). Until that lands, we synthesise a minimal X.509
//! certificate with a fresh Ed25519 keypair at process start and serve
//! that inside the handshake. Our cooperating client
//! (`ayllu-camouflage-client`) doesn't validate the chain, so a stub is
//! enough to exercise the wire protocol end-to-end.
//!
//! The DER layout is the absolute minimum a TLS 1.3 `Certificate`
//! message needs:
//!
//!     Certificate ::= SEQUENCE {
//!         tbsCertificate     TBSCertificate,
//!         signatureAlgorithm AlgorithmIdentifier,  -- Ed25519
//!         signatureValue     BIT STRING            -- Ed25519 over DER(tbs)
//!     }
//!     TBSCertificate ::= SEQUENCE {
//!         [0] EXPLICIT version(v3),
//!         serialNumber        INTEGER,
//!         signature           AlgorithmIdentifier, -- Ed25519
//!         issuer              Name,                -- CN = <common_name>
//!         validity            SEQUENCE { notBefore UTCTime, notAfter UTCTime },
//!         subject             Name,                -- same as issuer
//!         subjectPublicKeyInfo SubjectPublicKeyInfo
//!     }
//!
//! No extensions, no SAN, no key-usage bits. A real TLS client with
//! chain validation (e.g. `std.crypto.tls.Client` pointed at a populated
//! CA bundle) will reject this for the usual reasons; tests that need a
//! full handshake either install the stub's public key as a trust
//! anchor or bypass chain validation.

const std = @import("std");
pub const Ed25519 = std.crypto.sign.Ed25519;

/// Ed25519 OID 1.3.101.112 (RFC 8410). Emitted as the
/// `AlgorithmIdentifier` for both TBS.signature and the outer
/// signatureAlgorithm, and inside the SubjectPublicKeyInfo.
const ed25519_alg_der = [_]u8{
    0x30, 0x05, // SEQUENCE, 5 bytes
    0x06, 0x03, 0x2B, 0x65, 0x70, // OID 1.3.101.112
};

/// `commonName` OID 2.5.4.3 as a fully-formed AttributeType DER value.
const cn_oid_der = [_]u8{ 0x06, 0x03, 0x55, 0x04, 0x03 };

pub const max_common_name = 64;
pub const max_cert_der = 512;

pub const CertStub = struct {
    allocator: std.mem.Allocator,
    keypair: Ed25519.KeyPair,
    cert_der: []u8,

    /// Generate a fresh keypair and self-signed stub certificate valid
    /// from `now_unix_s` for one year. `common_name.len` must be in
    /// `1..max_common_name`.
    pub fn generate(
        allocator: std.mem.Allocator,
        io: std.Io,
        common_name: []const u8,
        now_unix_s: i64,
    ) !CertStub {
        if (common_name.len == 0 or common_name.len > max_common_name) {
            return error.InvalidCommonName;
        }
        const kp = Ed25519.KeyPair.generate(io);
        const der = try buildCert(allocator, io, kp, common_name, now_unix_s);
        return .{ .allocator = allocator, .keypair = kp, .cert_der = der };
    }

    pub fn deinit(self: *CertStub) void {
        self.allocator.free(self.cert_der);
        self.cert_der = &.{};
    }

    pub fn publicKey(self: *const CertStub) [32]u8 {
        return self.keypair.public_key.bytes;
    }

    /// Sign the TLS 1.3 `CertificateVerify` context message for the
    /// server role: 64 × 0x20 || "TLS 1.3, server CertificateVerify" || 0x00
    /// || transcript_hash. Returns the 64-byte Ed25519 signature.
    pub fn signCertificateVerify(
        self: *const CertStub,
        transcript_hash: []const u8,
    ) !([Ed25519.Signature.encoded_length]u8) {
        const prefix_len = 64 + 33 + 1;
        var msg_buf: [prefix_len + 64]u8 = undefined;
        if (transcript_hash.len > 64) return error.TranscriptTooLarge;
        @memset(msg_buf[0..64], 0x20);
        @memcpy(msg_buf[64..][0..33], "TLS 1.3, server CertificateVerify");
        msg_buf[64 + 33] = 0x00;
        @memcpy(msg_buf[prefix_len..][0..transcript_hash.len], transcript_hash);
        const sig = try self.keypair.sign(msg_buf[0 .. prefix_len + transcript_hash.len], null);
        return sig.toBytes();
    }
};

/// DER length encoding: short form for < 128, otherwise minimal long
/// form with 0x81/0x82 prefix. `std.crypto.tls` and Web PKI parsers
/// expect DER (minimal), not BER.
fn derLengthLen(len: usize) usize {
    if (len < 128) return 1;
    if (len < 256) return 2;
    return 3;
}

fn writeDerLength(buf: []u8, len: usize) usize {
    if (len < 128) {
        buf[0] = @intCast(len);
        return 1;
    }
    if (len < 256) {
        buf[0] = 0x81;
        buf[1] = @intCast(len);
        return 2;
    }
    buf[0] = 0x82;
    std.mem.writeInt(u16, buf[1..3], @intCast(len), .big);
    return 3;
}

/// Emit a complete TLV (tag || length || value) at `out[0..]`. Returns
/// bytes written. Caller guarantees `out` is large enough.
fn emitTlv(out: []u8, tag: u8, body: []const u8) usize {
    out[0] = tag;
    const len_bytes = writeDerLength(out[1..], body.len);
    @memcpy(out[1 + len_bytes ..][0..body.len], body);
    return 1 + len_bytes + body.len;
}

/// Format 13-byte UTCTime ("YYMMDDHHMMSSZ", years 2000-2049). Panics
/// on overflow (year >= 2050). For a 1-year stub validity window we
/// won't hit that until 2049.
fn utcTime(out: *[13]u8, unix_s: i64) void {
    const secs_per_day: i64 = 86_400;
    const days = @divFloor(unix_s, secs_per_day);
    const sec_of_day: u32 = @intCast(unix_s - days * secs_per_day);

    // Convert days since 1970-01-01 to y/m/d.
    // Algorithm from Howard Hinnant's date library (civil_from_days).
    const z = days + 719468;
    const era = @divFloor(z, 146097);
    const doe: u32 = @intCast(z - era * 146097);
    const yoe: u32 = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const y_i64: i64 = @as(i64, @intCast(yoe)) + era * 400;
    const doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const mp = (5 * doy + 2) / 153;
    const d = doy - (153 * mp + 2) / 5 + 1;
    const m = if (mp < 10) mp + 3 else mp - 9;
    const year_full: i64 = y_i64 + @as(i64, if (m <= 2) 1 else 0);

    if (year_full < 2000 or year_full >= 2050) @panic("cert_stub: UTCTime only covers 2000-2049");
    const yy: u32 = @intCast(year_full - 2000);

    const hh: u32 = sec_of_day / 3600;
    const mm: u32 = (sec_of_day % 3600) / 60;
    const ss: u32 = sec_of_day % 60;

    _ = std.fmt.bufPrint(out, "{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", .{
        yy, m, d, hh, mm, ss,
    }) catch unreachable;
}

/// Build `Name` SEQUENCE { SET { SEQUENCE { commonName OID, UTF8String(cn) } } }.
/// Returns total bytes; fills `out` starting at 0.
fn emitName(out: []u8, cn: []const u8) usize {
    // innermost SEQUENCE: OID(commonName) || UTF8String(cn)
    var att_body: [8 + max_common_name]u8 = undefined;
    var att_pos: usize = 0;
    @memcpy(att_body[att_pos..][0..cn_oid_der.len], &cn_oid_der);
    att_pos += cn_oid_der.len;
    att_pos += emitTlv(att_body[att_pos..], 0x0C, cn); // UTF8String

    var seq: [16 + max_common_name]u8 = undefined;
    const seq_len = emitTlv(&seq, 0x30, att_body[0..att_pos]);

    var set_out: [32 + max_common_name]u8 = undefined;
    const set_len = emitTlv(&set_out, 0x31, seq[0..seq_len]);

    return emitTlv(out, 0x30, set_out[0..set_len]);
}

fn buildCert(
    allocator: std.mem.Allocator,
    io: std.Io,
    kp: Ed25519.KeyPair,
    common_name: []const u8,
    now_unix_s: i64,
) ![]u8 {
    // --- Build TBSCertificate body into scratch ---
    var tbs_scratch: [max_cert_der]u8 = undefined;
    var tp: usize = 0;

    // [0] EXPLICIT version v3 (INTEGER 2)
    const ver_body = [_]u8{ 0x02, 0x01, 0x02 };
    tp += emitTlv(tbs_scratch[tp..], 0xA0, &ver_body);

    // serialNumber — random u64, prefix 0x00 to ensure positive (high bit may be set)
    var serial: [8]u8 = undefined;
    io.random(&serial);
    var serial_body: [9]u8 = undefined;
    serial_body[0] = 0x00;
    @memcpy(serial_body[1..9], &serial);
    tp += emitTlv(tbs_scratch[tp..], 0x02, &serial_body);

    // signature AlgorithmIdentifier (Ed25519) — full DER of the SEQUENCE, already self-tagged
    @memcpy(tbs_scratch[tp..][0..ed25519_alg_der.len], &ed25519_alg_der);
    tp += ed25519_alg_der.len;

    // issuer Name
    var name_scratch: [96]u8 = undefined;
    const name_len = emitName(&name_scratch, common_name);
    @memcpy(tbs_scratch[tp..][0..name_len], name_scratch[0..name_len]);
    tp += name_len;

    // validity
    var nb: [13]u8 = undefined;
    var na: [13]u8 = undefined;
    utcTime(&nb, now_unix_s);
    utcTime(&na, now_unix_s + 365 * 24 * 60 * 60);
    var validity_body: [32]u8 = undefined;
    var vp: usize = 0;
    vp += emitTlv(validity_body[vp..], 0x17, &nb);
    vp += emitTlv(validity_body[vp..], 0x17, &na);
    tp += emitTlv(tbs_scratch[tp..], 0x30, validity_body[0..vp]);

    // subject Name (same as issuer)
    @memcpy(tbs_scratch[tp..][0..name_len], name_scratch[0..name_len]);
    tp += name_len;

    // SubjectPublicKeyInfo: SEQUENCE { AlgId(Ed25519) || BIT STRING(pubkey) }
    var spki_body: [64]u8 = undefined;
    var sp: usize = 0;
    @memcpy(spki_body[sp..][0..ed25519_alg_der.len], &ed25519_alg_der);
    sp += ed25519_alg_der.len;
    // BIT STRING: tag 0x03, length 33 (1 unused-bits byte + 32 pubkey), unused=0
    spki_body[sp] = 0x03;
    spki_body[sp + 1] = 0x21;
    spki_body[sp + 2] = 0x00;
    @memcpy(spki_body[sp + 3 ..][0..32], &kp.public_key.bytes);
    sp += 3 + 32;
    tp += emitTlv(tbs_scratch[tp..], 0x30, spki_body[0..sp]);

    const tbs_body = tbs_scratch[0..tp];

    // Wrap TBS in outer SEQUENCE to get the exact bytes that get signed.
    var tbs_wrapped: [max_cert_der]u8 = undefined;
    const tbs_total = emitTlv(&tbs_wrapped, 0x30, tbs_body);

    // Sign the wrapped TBS.
    const sig = try kp.sign(tbs_wrapped[0..tbs_total], null);
    const sig_bytes = sig.toBytes();

    // --- Build outer Certificate ---
    // body = tbs_wrapped || ed25519_alg || BITSTRING(sig)
    const sig_bitstring_len = 1 + 1 + 1 + sig_bytes.len; // 03 41 00 <64>
    const outer_body_len = tbs_total + ed25519_alg_der.len + sig_bitstring_len;

    const total_len = 1 + derLengthLen(outer_body_len) + outer_body_len;
    const out = try allocator.alloc(u8, total_len);
    errdefer allocator.free(out);

    var op: usize = 0;
    out[op] = 0x30;
    op += 1;
    op += writeDerLength(out[op..], outer_body_len);
    @memcpy(out[op..][0..tbs_total], tbs_wrapped[0..tbs_total]);
    op += tbs_total;
    @memcpy(out[op..][0..ed25519_alg_der.len], &ed25519_alg_der);
    op += ed25519_alg_der.len;
    out[op] = 0x03; // BIT STRING
    out[op + 1] = @intCast(1 + sig_bytes.len); // len = 65
    out[op + 2] = 0x00; // unused bits
    @memcpy(out[op + 3 ..][0..sig_bytes.len], &sig_bytes);
    op += sig_bitstring_len;

    std.debug.assert(op == total_len);
    return out;
}

// -------------------- Tests --------------------

const testing = std.testing;

test "CertStub.generate produces a DER-framed cert" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var stub = try CertStub.generate(testing.allocator, io, "ayllu-reality", 1_712_000_000);
    defer stub.deinit();

    // Outer tag must be SEQUENCE.
    try testing.expectEqual(@as(u8, 0x30), stub.cert_der[0]);
    // Total length matches what's encoded in the outer TLV.
    const encoded_len = switch (stub.cert_der[1]) {
        0x82 => @as(usize, std.mem.readInt(u16, stub.cert_der[2..4], .big)),
        0x81 => @as(usize, stub.cert_der[2]),
        else => @as(usize, stub.cert_der[1]),
    };
    const hdr_len: usize = switch (stub.cert_der[1]) {
        0x82 => 4,
        0x81 => 3,
        else => 2,
    };
    try testing.expectEqual(encoded_len, stub.cert_der.len - hdr_len);
}

test "CertStub.signCertificateVerify round-trips via Ed25519 verify" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var stub = try CertStub.generate(testing.allocator, io, "ayllu-reality", 1_712_000_000);
    defer stub.deinit();

    var transcript: [32]u8 = undefined;
    io.random(&transcript);

    const sig = try stub.signCertificateVerify(&transcript);

    // Reconstruct the exact message the verifier expects.
    const prefix_len = 64 + 33 + 1;
    var msg: [prefix_len + 32]u8 = undefined;
    @memset(msg[0..64], 0x20);
    @memcpy(msg[64..][0..33], "TLS 1.3, server CertificateVerify");
    msg[64 + 33] = 0x00;
    @memcpy(msg[prefix_len..][0..32], &transcript);

    const sig_struct = Ed25519.Signature.fromBytes(sig);
    try sig_struct.verify(&msg, stub.keypair.public_key);
}

test "CertStub: bad transcript makes verify reject" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var stub = try CertStub.generate(testing.allocator, io, "ayllu-reality", 1_712_000_000);
    defer stub.deinit();

    var transcript: [32]u8 = [_]u8{0x11} ** 32;
    const sig = try stub.signCertificateVerify(&transcript);
    transcript[0] ^= 0xFF; // tamper

    const prefix_len = 64 + 33 + 1;
    var msg: [prefix_len + 32]u8 = undefined;
    @memset(msg[0..64], 0x20);
    @memcpy(msg[64..][0..33], "TLS 1.3, server CertificateVerify");
    msg[64 + 33] = 0x00;
    @memcpy(msg[prefix_len..][0..32], &transcript);

    const sig_struct = Ed25519.Signature.fromBytes(sig);
    try testing.expectError(error.SignatureVerificationFailed, sig_struct.verify(&msg, stub.keypair.public_key));
}

test "CertStub: rejects empty or oversize common names" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    try testing.expectError(
        error.InvalidCommonName,
        CertStub.generate(testing.allocator, io, "", 1_712_000_000),
    );
    const too_long: [max_common_name + 1]u8 = [_]u8{'a'} ** (max_common_name + 1);
    try testing.expectError(
        error.InvalidCommonName,
        CertStub.generate(testing.allocator, io, &too_long, 1_712_000_000),
    );
}

test "utcTime formats 2026-04-20 correctly" {
    // 2026-04-20 00:00:00 UTC = 1_776_643_200
    var out: [13]u8 = undefined;
    utcTime(&out, 1_776_643_200);
    try testing.expectEqualStrings("260420000000Z", &out);
}

test "utcTime formats epoch origin (2000-01-01) correctly" {
    var out: [13]u8 = undefined;
    utcTime(&out, 946_684_800);
    try testing.expectEqualStrings("000101000000Z", &out);
}

test "CertStub: cert_der carries the keypair's public key inside SPKI" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var stub = try CertStub.generate(testing.allocator, io, "ayllu", 1_712_000_000);
    defer stub.deinit();

    // The pubkey appears verbatim in the cert after the Ed25519 SPKI
    // preamble (30 2A 30 05 06 03 2B 65 70 03 21 00).
    const needle = [_]u8{ 0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00 };
    const idx = std.mem.indexOf(u8, stub.cert_der, &needle) orelse return error.SpkiPreambleMissing;
    const pub_start = idx + needle.len;
    try testing.expectEqualSlices(u8, &stub.keypair.public_key.bytes, stub.cert_der[pub_start..][0..32]);
}
