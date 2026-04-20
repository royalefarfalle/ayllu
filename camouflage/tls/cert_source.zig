//! CertSource abstraction: pick between a runtime-generated stub
//! (`cert_stub.CertStub`) and an operator-supplied DER file
//! (`ExternalCert`). Both variants sign CertificateVerify with our own
//! fresh Ed25519 keypair; the cert DER is cover, not a trust anchor
//! (the cooperating REALITY client doesn't validate the chain).

const std = @import("std");
const cert_stub_mod = @import("cert_stub.zig");
pub const Ed25519 = cert_stub_mod.Ed25519;

/// Upper bound on cert DER size for the stack buffers in
/// reality_transport.zig. Covers RSA-2048 (~1.3 KB), RSA-4096 (~1.8 KB),
/// long-SAN leaves (~3–4 KB), and SCT-embedded outliers (~5 KB) with
/// headroom. Tuned against observed real-world cover-host leaf certs.
pub const max_cert_der: usize = 8192;

/// Floor on file size. Rejects empty and obviously-truncated inputs
/// before they get a chance to produce confusing downstream errors.
/// An Ed25519 minimum self-signed cert is >200 B; 64 is a generous floor.
const min_cert_der: usize = 64;

pub const ExternalCert = struct {
    allocator: std.mem.Allocator,
    keypair: Ed25519.KeyPair,
    cert_der: []u8,

    pub fn loadFromFile(
        allocator: std.mem.Allocator,
        io: std.Io,
        path: []const u8,
    ) !ExternalCert {
        const raw = try std.Io.Dir.cwd().readFileAlloc(
            io,
            path,
            allocator,
            .limited(max_cert_der),
        );
        errdefer allocator.free(raw);
        if (raw.len < min_cert_der) return error.CertDerTooSmall;
        const encoded_len, const hdr_len = try parseDerSeqLen(raw);
        if (hdr_len + encoded_len != raw.len) return error.CertDerMalformed;
        const kp = Ed25519.KeyPair.generate(io);
        return .{ .allocator = allocator, .keypair = kp, .cert_der = raw };
    }

    pub fn deinit(self: *ExternalCert) void {
        self.allocator.free(self.cert_der);
        self.cert_der = &.{};
    }

    pub fn signCertificateVerify(
        self: *const ExternalCert,
        transcript_hash: []const u8,
    ) !([Ed25519.Signature.encoded_length]u8) {
        return signCertificateVerifyWithKey(self.keypair, transcript_hash);
    }
};

pub const CertSource = union(enum) {
    stub: cert_stub_mod.CertStub,
    external: ExternalCert,

    pub fn certDer(self: *const CertSource) []const u8 {
        return switch (self.*) {
            .stub => |*s| s.cert_der,
            .external => |*e| e.cert_der,
        };
    }

    pub fn signCertificateVerify(
        self: *const CertSource,
        transcript_hash: []const u8,
    ) !([Ed25519.Signature.encoded_length]u8) {
        return switch (self.*) {
            .stub => |*s| s.signCertificateVerify(transcript_hash),
            .external => |*e| e.signCertificateVerify(transcript_hash),
        };
    }

    pub fn deinit(self: *CertSource) void {
        switch (self.*) {
            .stub => |*s| s.deinit(),
            .external => |*e| e.deinit(),
        }
    }
};

/// Format the TLS 1.3 CertificateVerify context and sign it with
/// `keypair`. Shared between `ExternalCert` here and `CertStub` (which
/// keeps its own identical copy for self-containment).
fn signCertificateVerifyWithKey(
    keypair: Ed25519.KeyPair,
    transcript_hash: []const u8,
) !([Ed25519.Signature.encoded_length]u8) {
    const prefix_len = 64 + 33 + 1;
    var msg_buf: [prefix_len + 64]u8 = undefined;
    if (transcript_hash.len > 64) return error.TranscriptTooLarge;
    @memset(msg_buf[0..64], 0x20);
    @memcpy(msg_buf[64..][0..33], "TLS 1.3, server CertificateVerify");
    msg_buf[64 + 33] = 0x00;
    @memcpy(msg_buf[prefix_len..][0..transcript_hash.len], transcript_hash);
    const sig = try keypair.sign(msg_buf[0 .. prefix_len + transcript_hash.len], null);
    return sig.toBytes();
}

/// Parse the outer SEQUENCE tag + length of a DER-encoded certificate.
/// Returns `(encoded_length, header_byte_count)`. Accepts short form
/// (1-byte length < 128) and long form with 0x81/0x82 prefixes — enough
/// for any realistic leaf cert. Rejects indefinite form (0x80) and
/// lengths ≥ 2^16, which don't occur in DER-encoded X.509 leaves.
fn parseDerSeqLen(buf: []const u8) !struct { usize, usize } {
    if (buf.len < 2 or buf[0] != 0x30) return error.CertDerMalformed;
    const b1 = buf[1];
    if (b1 < 0x80) return .{ b1, 2 };
    if (b1 == 0x80) return error.CertDerMalformed; // indefinite form, BER-only
    if (b1 == 0x81) {
        if (buf.len < 3) return error.CertDerMalformed;
        return .{ buf[2], 3 };
    }
    if (b1 == 0x82) {
        if (buf.len < 4) return error.CertDerMalformed;
        return .{ std.mem.readInt(u16, buf[2..4], .big), 4 };
    }
    return error.CertDerMalformed; // lengths ≥ 2^16 not expected
}

// -------------------- Tests --------------------

const testing = std.testing;

fn fixturePath(
    allocator: std.mem.Allocator,
    tmp_sub_path: []const u8,
    file_name: []const u8,
) ![]u8 {
    return std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp_sub_path, file_name });
}

test "CertSource.stub dispatches certDer and signCertificateVerify" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var src: CertSource = .{
        .stub = try cert_stub_mod.CertStub.generate(testing.allocator, io, "ayllu-src-test", 1_712_000_000),
    };
    defer src.deinit();

    // certDer() matches the stub's own cert_der.
    try testing.expect(src.certDer().len > 0);
    try testing.expectEqual(@as(u8, 0x30), src.certDer()[0]);

    // CV sig round-trips through Ed25519 verify with the stub's key.
    var transcript: [32]u8 = undefined;
    io.random(&transcript);
    const sig = try src.signCertificateVerify(&transcript);

    const prefix_len = 64 + 33 + 1;
    var msg: [prefix_len + 32]u8 = undefined;
    @memset(msg[0..64], 0x20);
    @memcpy(msg[64..][0..33], "TLS 1.3, server CertificateVerify");
    msg[64 + 33] = 0x00;
    @memcpy(msg[prefix_len..][0..32], &transcript);

    const sig_struct = Ed25519.Signature.fromBytes(sig);
    try sig_struct.verify(&msg, src.stub.keypair.public_key);
}

test "ExternalCert.loadFromFile round-trips DER bytes" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Build a known-good DER by generating a stub cert and writing its bytes.
    var donor = try cert_stub_mod.CertStub.generate(testing.allocator, io, "donor", 1_712_000_000);
    defer donor.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "cert.der", .data = donor.cert_der });

    const path = try fixturePath(testing.allocator, tmp.sub_path[0..], "cert.der");
    defer testing.allocator.free(path);

    var ext = try ExternalCert.loadFromFile(testing.allocator, io, path);
    defer ext.deinit();

    try testing.expectEqualSlices(u8, donor.cert_der, ext.cert_der);
}

test "ExternalCert.loadFromFile rejects malformed DER" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // 128 bytes but first byte isn't 0x30 — fails the tag check in parseDerSeqLen.
    var junk: [128]u8 = [_]u8{0xAA} ** 128;
    try tmp.dir.writeFile(io, .{ .sub_path = "junk.der", .data = &junk });

    const path = try fixturePath(testing.allocator, tmp.sub_path[0..], "junk.der");
    defer testing.allocator.free(path);

    try testing.expectError(
        error.CertDerMalformed,
        ExternalCert.loadFromFile(testing.allocator, io, path),
    );
}

test "ExternalCert.loadFromFile rejects tiny files" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "tiny.der", .data = "\x30\x82\x00\x02xx" });

    const path = try fixturePath(testing.allocator, tmp.sub_path[0..], "tiny.der");
    defer testing.allocator.free(path);

    try testing.expectError(
        error.CertDerTooSmall,
        ExternalCert.loadFromFile(testing.allocator, io, path),
    );
}

test "ExternalCert.loadFromFile rejects oversize files" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // One byte past the cap trips readFileAlloc's .limited() guard.
    const oversize = try testing.allocator.alloc(u8, max_cert_der + 1);
    defer testing.allocator.free(oversize);
    @memset(oversize, 0x30);
    try tmp.dir.writeFile(io, .{ .sub_path = "big.der", .data = oversize });

    const path = try fixturePath(testing.allocator, tmp.sub_path[0..], "big.der");
    defer testing.allocator.free(path);

    try testing.expectError(
        error.StreamTooLong,
        ExternalCert.loadFromFile(testing.allocator, io, path),
    );
}

test "CertSource.external dispatches via its own keypair, not the stub's" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var donor = try cert_stub_mod.CertStub.generate(testing.allocator, io, "donor", 1_712_000_000);
    defer donor.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "cert.der", .data = donor.cert_der });

    const path = try fixturePath(testing.allocator, tmp.sub_path[0..], "cert.der");
    defer testing.allocator.free(path);

    var src: CertSource = .{
        .external = try ExternalCert.loadFromFile(testing.allocator, io, path),
    };
    defer src.deinit();

    try testing.expectEqualSlices(u8, donor.cert_der, src.certDer());

    var transcript: [32]u8 = undefined;
    io.random(&transcript);
    const sig = try src.signCertificateVerify(&transcript);

    const prefix_len = 64 + 33 + 1;
    var msg: [prefix_len + 32]u8 = undefined;
    @memset(msg[0..64], 0x20);
    @memcpy(msg[64..][0..33], "TLS 1.3, server CertificateVerify");
    msg[64 + 33] = 0x00;
    @memcpy(msg[prefix_len..][0..32], &transcript);

    const sig_struct = Ed25519.Signature.fromBytes(sig);
    // Verifies against the external's freshly-generated keypair —
    // NOT the donor stub's key.
    try sig_struct.verify(&msg, src.external.keypair.public_key);
    // And does NOT verify against the donor's key.
    try testing.expectError(
        error.SignatureVerificationFailed,
        sig_struct.verify(&msg, donor.keypair.public_key),
    );
}

test "parseDerSeqLen short form" {
    const buf = [_]u8{ 0x30, 0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE };
    const encoded_len, const hdr_len = try parseDerSeqLen(&buf);
    try testing.expectEqual(@as(usize, 5), encoded_len);
    try testing.expectEqual(@as(usize, 2), hdr_len);
}

test "parseDerSeqLen long form 0x81" {
    const buf = [_]u8{ 0x30, 0x81, 0x80 } ++ [_]u8{0} ** 0x80;
    const encoded_len, const hdr_len = try parseDerSeqLen(&buf);
    try testing.expectEqual(@as(usize, 0x80), encoded_len);
    try testing.expectEqual(@as(usize, 3), hdr_len);
}

test "parseDerSeqLen long form 0x82" {
    const buf = [_]u8{ 0x30, 0x82, 0x01, 0x23 } ++ [_]u8{0} ** 0x123;
    const encoded_len, const hdr_len = try parseDerSeqLen(&buf);
    try testing.expectEqual(@as(usize, 0x123), encoded_len);
    try testing.expectEqual(@as(usize, 4), hdr_len);
}

test "parseDerSeqLen rejects non-SEQUENCE tag and indefinite form" {
    try testing.expectError(error.CertDerMalformed, parseDerSeqLen(&[_]u8{ 0x31, 0x01, 0x00 }));
    try testing.expectError(error.CertDerMalformed, parseDerSeqLen(&[_]u8{ 0x30, 0x80, 0x00 }));
    try testing.expectError(error.CertDerMalformed, parseDerSeqLen(&[_]u8{ 0x30, 0x83, 0x00, 0x00, 0x00 }));
}
