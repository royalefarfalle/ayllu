//! TLS 1.3 key schedule (RFC 8446 §7.1). Implements the three-stage
//! Extract-then-Expand chain used to derive handshake and application
//! traffic secrets:
//!
//!     early_secret    = HKDF-Extract(0, PSK ?? 0)
//!     derived_1       = Expand-Label(early, "derived", empty_hash)
//!     handshake_secret= HKDF-Extract(derived_1, (EC)DHE_shared_secret)
//!     derived_2       = Expand-Label(handshake, "derived", empty_hash)
//!     master_secret   = HKDF-Extract(derived_2, 0)
//!
//!     c_hs_traffic    = Expand-Label(handshake, "c hs traffic", H(CH || SH))
//!     s_hs_traffic    = Expand-Label(handshake, "s hs traffic", H(CH || SH))
//!     c_ap_traffic    = Expand-Label(master,    "c ap traffic", H(...Finished))
//!     s_ap_traffic    = Expand-Label(master,    "s ap traffic", H(...Finished))
//!
//! Per-direction traffic keys:
//!
//!     key             = Expand-Label(traffic_secret, "key", "")
//!     iv              = Expand-Label(traffic_secret, "iv", "")
//!     finished_key    = Expand-Label(traffic_secret, "finished", "")
//!
//! The `Schedule` generic is parameterised on (AEAD, Hash). Pre-baked
//! aliases for the three TLS 1.3 mandatory-to-implement cipher suites
//! are at the bottom.

const std = @import("std");
const tls = std.crypto.tls;

pub fn Schedule(comptime AeadType: type, comptime HashType: type) type {
    return struct {
        const Self = @This();

        pub const Hash = HashType;
        pub const AEAD = AeadType;
        pub const Hmac = std.crypto.auth.hmac.Hmac(Hash);
        pub const Hkdf = std.crypto.kdf.hkdf.Hkdf(Hmac);

        pub const digest_length = Hash.digest_length;
        pub const key_length = AEAD.key_length;
        pub const nonce_length = AEAD.nonce_length;

        /// Secrets live across phases. Zero-initialised; each stage
        /// fills the relevant field.
        early_secret: [digest_length]u8 = [_]u8{0} ** digest_length,
        handshake_secret: [digest_length]u8 = [_]u8{0} ** digest_length,
        master_secret: [digest_length]u8 = [_]u8{0} ** digest_length,

        /// Enter the early stage. PSK is always all-zeros in REALITY's
        /// handshake (no resumption / no 0-RTT).
        pub fn initNoPsk() Self {
            const zero_salt: [digest_length]u8 = [_]u8{0} ** digest_length;
            const zero_ikm: [digest_length]u8 = [_]u8{0} ** digest_length;
            const early = Hkdf.extract(&zero_salt, &zero_ikm);
            return .{ .early_secret = early };
        }

        pub const HandshakeSecrets = struct {
            client_handshake_traffic_secret: [digest_length]u8,
            server_handshake_traffic_secret: [digest_length]u8,
        };

        /// Mix in the ECDHE shared secret + the transcript hash of
        /// ClientHello || ServerHello to produce client/server
        /// handshake traffic secrets. After this, encrypted-extensions
        /// and Certificate/CertificateVerify/Finished records use
        /// these secrets.
        pub fn enterHandshake(
            self: *Self,
            shared_secret: []const u8,
            transcript_hash: [digest_length]u8,
        ) HandshakeSecrets {
            const derived = tls.hkdfExpandLabel(
                Hkdf,
                self.early_secret,
                "derived",
                &tls.emptyHash(Hash),
                digest_length,
            );
            self.handshake_secret = Hkdf.extract(&derived, shared_secret);

            const c_hs = tls.hkdfExpandLabel(
                Hkdf,
                self.handshake_secret,
                "c hs traffic",
                &transcript_hash,
                digest_length,
            );
            const s_hs = tls.hkdfExpandLabel(
                Hkdf,
                self.handshake_secret,
                "s hs traffic",
                &transcript_hash,
                digest_length,
            );
            return .{
                .client_handshake_traffic_secret = c_hs,
                .server_handshake_traffic_secret = s_hs,
            };
        }

        pub const ApplicationSecrets = struct {
            client_application_traffic_secret: [digest_length]u8,
            server_application_traffic_secret: [digest_length]u8,
        };

        /// Mix in the transcript hash up through server Finished to
        /// produce client/server application traffic secrets. Used
        /// once the handshake is complete.
        pub fn enterApplication(
            self: *Self,
            transcript_hash: [digest_length]u8,
        ) ApplicationSecrets {
            const derived = tls.hkdfExpandLabel(
                Hkdf,
                self.handshake_secret,
                "derived",
                &tls.emptyHash(Hash),
                digest_length,
            );
            const zero_ikm: [digest_length]u8 = [_]u8{0} ** digest_length;
            self.master_secret = Hkdf.extract(&derived, &zero_ikm);

            const c_ap = tls.hkdfExpandLabel(
                Hkdf,
                self.master_secret,
                "c ap traffic",
                &transcript_hash,
                digest_length,
            );
            const s_ap = tls.hkdfExpandLabel(
                Hkdf,
                self.master_secret,
                "s ap traffic",
                &transcript_hash,
                digest_length,
            );
            return .{
                .client_application_traffic_secret = c_ap,
                .server_application_traffic_secret = s_ap,
            };
        }

        pub const TrafficKeys = struct {
            key: [key_length]u8,
            iv: [nonce_length]u8,
            finished_key: [digest_length]u8,
        };

        /// Derive per-direction write_key + write_iv + finished_key
        /// from a traffic_secret. Used for both handshake and
        /// application phases — the only difference is which secret
        /// is fed in.
        pub fn deriveTrafficKeys(traffic_secret: [digest_length]u8) TrafficKeys {
            const key = tls.hkdfExpandLabel(Hkdf, traffic_secret, "key", "", key_length);
            const iv = tls.hkdfExpandLabel(Hkdf, traffic_secret, "iv", "", nonce_length);
            const finished = tls.hkdfExpandLabel(Hkdf, traffic_secret, "finished", "", digest_length);
            return .{ .key = key, .iv = iv, .finished_key = finished };
        }
    };
}

/// TLS 1.3 AES_128_GCM_SHA256 (CipherSuite 0x1301).
pub const Aes128GcmSha256 = Schedule(
    std.crypto.aead.aes_gcm.Aes128Gcm,
    std.crypto.hash.sha2.Sha256,
);

/// TLS 1.3 AES_256_GCM_SHA384 (CipherSuite 0x1302).
pub const Aes256GcmSha384 = Schedule(
    std.crypto.aead.aes_gcm.Aes256Gcm,
    std.crypto.hash.sha2.Sha384,
);

/// TLS 1.3 CHACHA20_POLY1305_SHA256 (CipherSuite 0x1303).
pub const ChaCha20Poly1305Sha256 = Schedule(
    std.crypto.aead.chacha_poly.ChaCha20Poly1305,
    std.crypto.hash.sha2.Sha256,
);

// -------------------- Tests (RFC 8448 §3, Simple 1-RTT Handshake) --------------------

const testing = std.testing;

/// Parse a contiguous hex string at comptime.
fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "RFC 8448 §3: early secret (PSK=0) for AES_128_GCM_SHA256" {
    const s = Aes128GcmSha256.initNoPsk();
    const expected = hex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
    try testing.expectEqualSlices(u8, &expected, &s.early_secret);
}

test "RFC 8448 §3: derived = Expand-Label(early, \"derived\", empty_hash) matches PRK" {
    const s = Aes128GcmSha256.initNoPsk();
    const empty_hash = tls.emptyHash(std.crypto.hash.sha2.Sha256);
    const derived = tls.hkdfExpandLabel(
        Aes128GcmSha256.Hkdf,
        s.early_secret,
        "derived",
        &empty_hash,
        Aes128GcmSha256.digest_length,
    );
    const expected = hex("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba");
    try testing.expectEqualSlices(u8, &expected, &derived);
}

test "RFC 8448 §3: handshake_secret from known ECDHE shared_secret + derived" {
    var s = Aes128GcmSha256.initNoPsk();
    // Shared secret (ECDHE output, X25519).
    const shared = hex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    // Transcript hash after ClientHello + ServerHello (specific to the
    // CH/SH blobs pinned in the RFC; pinned here as input).
    const ch_sh_hash = hex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
    const secrets = s.enterHandshake(&shared, ch_sh_hash);

    const expected_hs_secret = hex("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac");
    try testing.expectEqualSlices(u8, &expected_hs_secret, &s.handshake_secret);

    const expected_c_hs = hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21");
    try testing.expectEqualSlices(u8, &expected_c_hs, &secrets.client_handshake_traffic_secret);

    const expected_s_hs = hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");
    try testing.expectEqualSlices(u8, &expected_s_hs, &secrets.server_handshake_traffic_secret);
}

test "RFC 8448 §3: client handshake key/iv/finished_key from c_hs_traffic" {
    const c_hs = hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21");
    const keys = Aes128GcmSha256.deriveTrafficKeys(c_hs);

    const expected_key = hex("dbfaa693d1762c5b666af5d950258d01");
    try testing.expectEqualSlices(u8, &expected_key, &keys.key);

    const expected_iv = hex("5bd3c71b836e0b76bb73265f");
    try testing.expectEqualSlices(u8, &expected_iv, &keys.iv);

    const expected_finished = hex("b80ad01015fb2f0bd65ff7d4da5d6bf83f84821d1f87fdc7d3c75b5a7b42d9c4");
    try testing.expectEqualSlices(u8, &expected_finished, &keys.finished_key);
}

test "RFC 8448 §3: server handshake key/iv/finished_key from s_hs_traffic" {
    const s_hs = hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");
    const keys = Aes128GcmSha256.deriveTrafficKeys(s_hs);

    const expected_key = hex("3fce516009c21727d0f2e4e86ee403bc");
    try testing.expectEqualSlices(u8, &expected_key, &keys.key);

    const expected_iv = hex("5d313eb2671276ee13000b30");
    try testing.expectEqualSlices(u8, &expected_iv, &keys.iv);

    const expected_finished = hex("008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8");
    try testing.expectEqualSlices(u8, &expected_finished, &keys.finished_key);
}

test "RFC 8448 §3: master_secret + application traffic secrets" {
    var s = Aes128GcmSha256.initNoPsk();
    const shared = hex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    const ch_sh_hash = hex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
    _ = s.enterHandshake(&shared, ch_sh_hash);

    // Transcript through server Finished (pinned from RFC).
    const through_sf_hash = hex("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");
    const app = s.enterApplication(through_sf_hash);

    const expected_master = hex("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919");
    try testing.expectEqualSlices(u8, &expected_master, &s.master_secret);

    const expected_c_ap = hex("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5");
    try testing.expectEqualSlices(u8, &expected_c_ap, &app.client_application_traffic_secret);

    const expected_s_ap = hex("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643");
    try testing.expectEqualSlices(u8, &expected_s_ap, &app.server_application_traffic_secret);
}

test "Aes256GcmSha384: initNoPsk produces non-trivial early secret" {
    const s = Aes256GcmSha384.initNoPsk();
    // Early secret for SHA-384: HKDF-Extract(0^48, 0^48). Different
    // constant from SHA-256's because the hash output length differs
    // and HKDF's PRK length = Hash.digest_length.
    try testing.expectEqual(@as(usize, 48), s.early_secret.len);
    // Non-zero — verifies the extract ran.
    const all_zero: [48]u8 = [_]u8{0} ** 48;
    try testing.expect(!std.mem.eql(u8, &all_zero, &s.early_secret));
}

test "ChaCha20Poly1305Sha256: deriveTrafficKeys shape" {
    // Just check the shape of the derived keys for the alt TLS 1.3 suite.
    const secret = hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21");
    const keys = ChaCha20Poly1305Sha256.deriveTrafficKeys(secret);
    try testing.expectEqual(@as(usize, 32), keys.key.len);
    try testing.expectEqual(@as(usize, 12), keys.iv.len);
    try testing.expectEqual(@as(usize, 32), keys.finished_key.len);
}

test "enterHandshake mutates handshake_secret only (early_secret unchanged)" {
    var s = Aes128GcmSha256.initNoPsk();
    const early_before = s.early_secret;
    const shared: [32]u8 = [_]u8{0x42} ** 32;
    const th: [32]u8 = [_]u8{0x11} ** 32;
    _ = s.enterHandshake(&shared, th);
    try testing.expectEqualSlices(u8, &early_before, &s.early_secret);
    const hs_all_zero: [32]u8 = [_]u8{0} ** 32;
    try testing.expect(!std.mem.eql(u8, &hs_all_zero, &s.handshake_secret));
}
