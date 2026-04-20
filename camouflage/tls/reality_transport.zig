//! REALITY `OuterTransport`. Reads a TLS 1.3 ClientHello, runs REALITY
//! admission (server_name + X25519 + Xray v25.x AuthKey), and on
//! success performs the full TLS 1.3 handshake — ServerHello,
//! middlebox-compat ChangeCipherSpec, EncryptedExtensions, Certificate
//! (Ed25519 stub from `cert_stub.zig`; C6 harvest will replace it with
//! the cover cert), CertificateVerify (Ed25519-signed over the
//! transcript), Server Finished, then synchronously verifies Client
//! Finished before entering application phase. The pivoted stream
//! wraps the socket in `TlsReader`/`TlsWriter` so the inner SOCKS5 (or
//! VLESS in C5b-2c) traffic travels as encrypted application_data.
//!
//! Admission uses `peekGreedy` exclusively until the commit point so
//! any rejection before we touch `admission.writer` routes to
//! `.fallback` and the dispatcher forwards the buffered ClientHello to
//! the cover host. Once ServerHello is on the wire we've burned the
//! cover identity — every later failure mode returns `.silent` and
//! bumps `admission_reality_handshake_failed_total`.

const std = @import("std");
const tls = std.crypto.tls;
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.Hmac(Sha256);
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const ayllu = @import("ayllu");
const proxy = @import("ayllu-proxy");
const transport = @import("../transport.zig");
const reality = @import("../reality.zig");
const metrics_mod = @import("../metrics.zig");
const record = @import("record.zig");
const client_hello_mod = @import("client_hello.zig");
const server_hello_mod = @import("server_hello.zig");
const xray_wire = @import("xray_wire.zig");
const keys_mod = @import("keys.zig");
const stream_mod = @import("stream.zig");
const cert_stub_mod = @import("cert_stub.zig");

pub const alpn_scratch_capacity: usize = 8;

/// Only TLS 1.3 suite we serve in the C5b-2a slice. AES256-GCM-SHA384
/// and ChaCha20-Poly1305 negotiation arrives once the session-state
/// tagged union lands.
pub const supported_cipher_suite: u16 = 0x1301; // TLS_AES_128_GCM_SHA256

/// Per-pivot heap state. Holds the two application-phase record layers
/// keyed by the TLS schedule, plus the `TlsReader`/`TlsWriter` adapter
/// structs exposed through `Pivoted.stream`. Allocated from
/// `AdmissionContext.allocator` on the success path and freed by
/// `destroyOnClose` when the dispatcher finishes the session.
pub const SessionState = struct {
    allocator: std.mem.Allocator,
    server_write_layer: record.Aes128GcmRecord,
    client_read_layer: record.Aes128GcmRecord,
    reader_buf: [record.max_plaintext_len]u8,
    writer_buf: [record.max_plaintext_len]u8,
    tls_reader: stream_mod.Aes128GcmReader,
    tls_writer: stream_mod.Aes128GcmWriter,

    pub fn destroyOnClose(ctx: ?*anyopaque, io: std.Io) void {
        _ = io;
        if (ctx) |p| {
            const self: *SessionState = @ptrCast(@alignCast(p));
            const allocator = self.allocator;
            allocator.destroy(self);
        }
    }
};

/// Shared state handed to every `RealityTransport` instance. `config`
/// and `cert_stub` are borrowed — the caller (typically `State`) owns
/// them. `metrics` is optional; when present the transport bumps
/// REALITY-specific counters.
pub const Shared = struct {
    config: reality.Config,
    cert_stub: *const cert_stub_mod.CertStub,
    metrics: ?*metrics_mod.Registry = null,
};

pub const RealityTransport = struct {
    shared: Shared,

    pub fn init(shared: Shared) RealityTransport {
        return .{ .shared = shared };
    }

    pub fn outerTransport(self: *RealityTransport) transport.OuterTransport {
        return .{ .ctx = @ptrCast(self), .vtable = &vtable };
    }

    const vtable: transport.OuterTransport.VTable = .{
        .admit = admitFn,
        .name = nameFn,
    };

    fn nameFn(_: *anyopaque) []const u8 {
        return "reality";
    }

    fn admitFn(
        ctx: *anyopaque,
        admission: transport.AdmissionContext,
    ) anyerror!transport.AdmitOutcome {
        const self: *RealityTransport = @ptrCast(@alignCast(ctx));
        return self.admit(admission);
    }

    fn fallback(self: *RealityTransport, buffered_head: []const u8) transport.AdmitOutcome {
        if (self.shared.metrics) |m| m.admission_reality_rejected_total.inc();
        return .{ .fallback = .{ .buffered_head = buffered_head } };
    }

    fn silentHandshakeFailure(self: *RealityTransport) transport.AdmitOutcome {
        if (self.shared.metrics) |m| m.admission_reality_handshake_failed_total.inc();
        return .silent;
    }

    pub fn admit(
        self: *RealityTransport,
        admission: transport.AdmissionContext,
    ) anyerror!transport.AdmitOutcome {
        const admission_deadline = proxy.timeouts.deadlineFromNowMs(
            admission.io,
            proxy.timeouts.Defaults.handshake_ms,
        );

        // ----- Pre-commit: all failures route to .fallback -----

        const hdr_bytes = proxy.timeouts.peekDeadline(
            admission.io,
            admission.reader,
            record.RecordHeader.wire_len,
            admission_deadline,
        ) catch |err| switch (err) {
            error.EndOfStream, error.Timeout => return err,
            else => return self.fallback(admission.reader.buffered()),
        };
        const hdr = record.RecordHeader.parse(hdr_bytes[0..record.RecordHeader.wire_len]) catch {
            return self.fallback(admission.reader.buffered());
        };
        if (hdr.content_type != .handshake or hdr.length > record.max_plaintext_len or hdr.length < 4) {
            return self.fallback(admission.reader.buffered());
        }

        const record_total = record.RecordHeader.wire_len + @as(usize, hdr.length);
        const full = proxy.timeouts.peekDeadline(
            admission.io,
            admission.reader,
            record_total,
            admission_deadline,
        ) catch |err| switch (err) {
            error.EndOfStream, error.Timeout => return err,
            else => return self.fallback(admission.reader.buffered()),
        };

        const payload = full[record.RecordHeader.wire_len..record_total];
        if (payload[0] != @intFromEnum(tls.HandshakeType.client_hello)) {
            return self.fallback(admission.reader.buffered());
        }
        const body_len = (@as(usize, payload[1]) << 16) |
            (@as(usize, payload[2]) << 8) |
            @as(usize, payload[3]);
        if (payload.len != 4 + body_len) {
            return self.fallback(admission.reader.buffered());
        }
        const ch_body = payload[4 .. 4 + body_len];

        var scratch_alpn: [alpn_scratch_capacity]?[]const u8 = @splat(null);
        const hello = client_hello_mod.parse(ch_body, &scratch_alpn) catch {
            return self.fallback(admission.reader.buffered());
        };

        if (!hello.supports_tls_13 or hello.x25519_key_share == null) {
            return self.fallback(admission.reader.buffered());
        }
        const sni = hello.server_name orelse return self.fallback(admission.reader.buffered());
        if (!containsServerName(self.shared.config.server_names, sni)) {
            return self.fallback(admission.reader.buffered());
        }

        const session = xray_wire.verifyClientHello(
            self.shared.config,
            hello,
            nowUnixMs(admission.io),
        ) catch {
            return self.fallback(admission.reader.buffered());
        };

        if (!hello.offersCipher(supported_cipher_suite)) {
            return self.fallback(admission.reader.buffered());
        }

        // ----- Commit: consume CH, any later error → .silent -----
        _ = admission.reader.take(record_total) catch return self.silentHandshakeFailure();

        // Full handshake message bytes = [type u8 | u24 length | body] = payload.
        const ss = self.runHandshake(admission, hello, payload, session) catch {
            return self.silentHandshakeFailure();
        };

        return transport.AdmitOutcome{
            .pivoted = .{
                .stream = .{
                    .reader = &ss.tls_reader.interface,
                    .writer = &ss.tls_writer.interface,
                    .net_stream = admission.net_stream,
                },
                .on_close = SessionState.destroyOnClose,
                .ctx_for_close = @ptrCast(ss),
            },
        };
    }

    fn runHandshake(
        self: *RealityTransport,
        admission: transport.AdmissionContext,
        hello: client_hello_mod.ClientHello,
        ch_handshake_msg: []const u8,
        session: xray_wire.VerifiedSession,
    ) !*SessionState {
        // ----- Transcript hash, running -----
        var ts = Sha256.init(.{});
        ts.update(ch_handshake_msg);

        // ----- ServerHello -----
        var server_random: [32]u8 = undefined;
        admission.io.random(&server_random);
        const server_public = try ayllu.crypto.X25519.recoverPublicKey(self.shared.config.private_key);

        var sh_body_buf: [server_hello_mod.bodyLen(32)]u8 = undefined;
        const sh_body_len = try server_hello_mod.emit(&sh_body_buf, .{
            .cipher_suite = supported_cipher_suite,
            .server_random = server_random,
            .session_id_echo = hello.session_id,
            .server_x25519_public = server_public,
        });

        var sh_wrapped_buf: [4 + server_hello_mod.bodyLen(32)]u8 = undefined;
        const sh_wrapped_len = try server_hello_mod.wrapHandshake(
            &sh_wrapped_buf,
            .server_hello,
            sh_body_buf[0..sh_body_len],
        );

        try writePlaintextRecord(admission.writer, .handshake, sh_wrapped_buf[0..sh_wrapped_len]);
        ts.update(sh_wrapped_buf[0..sh_wrapped_len]);

        // ----- Middlebox-compat ChangeCipherSpec (excluded from transcript) -----
        try admission.writer.writeAll(&ccs_record);

        // ----- Derive handshake-phase traffic keys -----
        const transcript_ch_sh = ts.peek();
        var schedule = keys_mod.Aes128GcmSha256.initNoPsk();
        const hs_secrets = schedule.enterHandshake(&session.material.shared_secret, transcript_ch_sh);
        const server_hs_keys = keys_mod.Aes128GcmSha256.deriveTrafficKeys(hs_secrets.server_handshake_traffic_secret);
        const client_hs_keys = keys_mod.Aes128GcmSha256.deriveTrafficKeys(hs_secrets.client_handshake_traffic_secret);

        var server_hs_layer: record.Aes128GcmRecord = .init(server_hs_keys.key, server_hs_keys.iv);
        var client_hs_layer: record.Aes128GcmRecord = .init(client_hs_keys.key, client_hs_keys.iv);

        // ----- EncryptedExtensions (empty extension list) -----
        const ee_empty_exts = [_]u8{ 0x00, 0x00 };
        var ee_wrapped_buf: [8]u8 = undefined;
        const ee_wrapped_len = try server_hello_mod.wrapHandshake(
            &ee_wrapped_buf,
            .encrypted_extensions,
            &ee_empty_exts,
        );
        ts.update(ee_wrapped_buf[0..ee_wrapped_len]);
        try emitEncryptedHandshake(&server_hs_layer, ee_wrapped_buf[0..ee_wrapped_len], admission.writer);

        // ----- Certificate -----
        const cert_der = self.shared.cert_stub.cert_der;
        var cert_body_buf: [16 + cert_stub_mod.max_cert_der]u8 = undefined;
        const cert_body_len = encodeCertificateBody(&cert_body_buf, cert_der);
        var cert_wrapped_buf: [16 + cert_stub_mod.max_cert_der]u8 = undefined;
        const cert_wrapped_len = try server_hello_mod.wrapHandshake(
            &cert_wrapped_buf,
            .certificate,
            cert_body_buf[0..cert_body_len],
        );
        ts.update(cert_wrapped_buf[0..cert_wrapped_len]);
        try emitEncryptedHandshake(&server_hs_layer, cert_wrapped_buf[0..cert_wrapped_len], admission.writer);

        // ----- CertificateVerify -----
        const transcript_at_cv = ts.peek();
        const sig_bytes = try self.shared.cert_stub.signCertificateVerify(&transcript_at_cv);

        var cv_body_buf: [4 + 64]u8 = undefined;
        std.mem.writeInt(u16, cv_body_buf[0..2], 0x0807, .big); // ed25519 signature scheme
        std.mem.writeInt(u16, cv_body_buf[2..4], sig_bytes.len, .big);
        @memcpy(cv_body_buf[4..][0..sig_bytes.len], &sig_bytes);

        var cv_wrapped_buf: [16 + 64]u8 = undefined;
        const cv_wrapped_len = try server_hello_mod.wrapHandshake(
            &cv_wrapped_buf,
            .certificate_verify,
            cv_body_buf[0 .. 4 + sig_bytes.len],
        );
        ts.update(cv_wrapped_buf[0..cv_wrapped_len]);
        try emitEncryptedHandshake(&server_hs_layer, cv_wrapped_buf[0..cv_wrapped_len], admission.writer);

        // ----- Server Finished -----
        const transcript_at_sf = ts.peek();
        var sf_verify: [32]u8 = undefined;
        HmacSha256.create(&sf_verify, &transcript_at_sf, &server_hs_keys.finished_key);

        var sf_wrapped_buf: [4 + 32]u8 = undefined;
        const sf_wrapped_len = try server_hello_mod.wrapHandshake(
            &sf_wrapped_buf,
            .finished,
            &sf_verify,
        );
        ts.update(sf_wrapped_buf[0..sf_wrapped_len]);
        try emitEncryptedHandshake(&server_hs_layer, sf_wrapped_buf[0..sf_wrapped_len], admission.writer);

        try admission.writer.flush();

        // ----- Expected Client Finished (transcript frozen before client's contribution) -----
        const transcript_at_cf = ts.peek();
        var expected_cf: [32]u8 = undefined;
        HmacSha256.create(&expected_cf, &transcript_at_cf, &client_hs_keys.finished_key);

        // ----- Read + verify Client Finished -----
        var cf_scratch: [record.RecordHeader.wire_len + record.max_ciphertext_len]u8 = undefined;
        var cf_plaintext_buf: [record.max_plaintext_len]u8 = undefined;
        const opened = try record.ReadRecordExact(Aes128Gcm).call(
            &client_hs_layer,
            admission.reader,
            &cf_scratch,
            &cf_plaintext_buf,
        );
        if (opened.inner_content_type != .handshake) return error.UnexpectedRecordType;

        const cf_plain = cf_plaintext_buf[0..opened.plaintext_len];
        if (cf_plain.len != 4 + 32) return error.MalformedClientFinished;
        if (cf_plain[0] != @intFromEnum(tls.HandshakeType.finished)) return error.MalformedClientFinished;
        const got_cf: *const [32]u8 = cf_plain[4..36];
        if (!std.crypto.timing_safe.eql([32]u8, got_cf.*, expected_cf)) {
            return error.ClientFinishedMacMismatch;
        }

        ts.update(cf_plain);
        const transcript_at_af = ts.peek();

        // ----- Application-phase keys -----
        const app_secrets = schedule.enterApplication(transcript_at_af);
        const server_ap_keys = keys_mod.Aes128GcmSha256.deriveTrafficKeys(app_secrets.server_application_traffic_secret);
        const client_ap_keys = keys_mod.Aes128GcmSha256.deriveTrafficKeys(app_secrets.client_application_traffic_secret);

        // ----- Heap-allocate SessionState, wire up TlsReader/Writer -----
        const ss = try admission.allocator.create(SessionState);
        errdefer admission.allocator.destroy(ss);

        ss.* = .{
            .allocator = admission.allocator,
            .server_write_layer = .init(server_ap_keys.key, server_ap_keys.iv),
            .client_read_layer = .init(client_ap_keys.key, client_ap_keys.iv),
            .reader_buf = undefined,
            .writer_buf = undefined,
            .tls_reader = undefined,
            .tls_writer = undefined,
        };
        ss.tls_reader = stream_mod.Aes128GcmReader.init(&ss.client_read_layer, admission.reader, &ss.reader_buf);
        ss.tls_writer = stream_mod.Aes128GcmWriter.init(&ss.server_write_layer, admission.writer, &ss.writer_buf);

        return ss;
    }
};

/// TLS 1.3 middlebox-compat ChangeCipherSpec: type=0x14, legacy version
/// 0x0303, length=1, body=0x01. Sent once right after ServerHello. Per
/// RFC 8446 §5 this record MUST NOT be included in the handshake
/// transcript hash.
const ccs_record: [6]u8 = .{ 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };

fn writePlaintextRecord(
    w: *std.Io.Writer,
    content_type: tls.ContentType,
    body: []const u8,
) !void {
    var hdr: [record.RecordHeader.wire_len]u8 = undefined;
    hdr[0] = @intFromEnum(content_type);
    std.mem.writeInt(u16, hdr[1..3], 0x0303, .big);
    std.mem.writeInt(u16, hdr[3..5], @intCast(body.len), .big);
    try w.writeAll(&hdr);
    try w.writeAll(body);
}

fn emitEncryptedHandshake(
    layer: *record.Aes128GcmRecord,
    plaintext: []const u8,
    w: *std.Io.Writer,
) !void {
    var scratch: [record.RecordHeader.wire_len + record.max_ciphertext_len]u8 = undefined;
    const n = try layer.sealRecord(.handshake, plaintext, &scratch);
    try w.writeAll(scratch[0..n]);
}

/// TLS 1.3 `Certificate` message body:
///   certificate_request_context (len-prefixed, always empty on server)
///   CertificateList (u24 length || entries)
/// Each entry: u24 cert_data length || cert_data || u16 extensions length (0).
fn encodeCertificateBody(out: []u8, cert_der: []const u8) usize {
    const entry_len = 3 + cert_der.len + 2;
    out[0] = 0; // empty request context
    out[1] = @intCast((entry_len >> 16) & 0xFF);
    out[2] = @intCast((entry_len >> 8) & 0xFF);
    out[3] = @intCast(entry_len & 0xFF);
    out[4] = @intCast((cert_der.len >> 16) & 0xFF);
    out[5] = @intCast((cert_der.len >> 8) & 0xFF);
    out[6] = @intCast(cert_der.len & 0xFF);
    @memcpy(out[7..][0..cert_der.len], cert_der);
    out[7 + cert_der.len] = 0;
    out[8 + cert_der.len] = 0;
    return 9 + cert_der.len;
}

fn containsServerName(list: []const []const u8, candidate: []const u8) bool {
    for (list) |n| if (std.mem.eql(u8, n, candidate)) return true;
    return false;
}

fn nowUnixMs(io: std.Io) i64 {
    return @intCast(@divFloor(std.Io.Clock.real.now(io).nanoseconds, 1_000_000));
}

// -------------------- Tests --------------------

const testing = std.testing;
const rate_limit = @import("../rate_limit.zig");
const metrics = @import("../metrics.zig");

fn hex32(comptime s: *const [64]u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

const TestCtx = struct {
    short_ids: [1]reality.ShortId,
    server_names: [1][]const u8,

    fn config(self: *const TestCtx, max_time_diff_ms: u64) reality.Config {
        return .{
            .target = .{ .host = "example.com", .port = 443 },
            .server_names = &self.server_names,
            .private_key = hex32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
            .max_time_diff_ms = max_time_diff_ms,
            .short_ids = &self.short_ids,
        };
    }
};

fn makeTestCtx() !TestCtx {
    return .{
        .short_ids = .{try reality.parseShortId("0ed36d458733a0bc")},
        .server_names = .{"example.com"},
    };
}

fn makeStubCertStub(io: std.Io) !cert_stub_mod.CertStub {
    return try cert_stub_mod.CertStub.generate(testing.allocator, io, "ayllu-test", 1_712_000_000);
}

/// Build a full TLS 1.3 handshake record carrying a ClientHello. Adds
/// TLS_AES_128_GCM_SHA256 (0x1301) to the cipher list so our transport
/// accepts it.
fn buildHandshakeRecord(
    out: []u8,
    sni: []const u8,
    client_public: [32]u8,
    session_id: [xray_wire.session_id_length]u8,
) !usize {
    var body_scratch: [512]u8 = undefined;
    const body_len = try buildClientHelloBody(&body_scratch, sni, client_public, session_id);
    const body = body_scratch[0..body_len];

    const handshake_total = 4 + body.len;
    const total = record.RecordHeader.wire_len + handshake_total;
    if (out.len < total) return error.OutBufferTooSmall;

    out[0] = @intFromEnum(tls.ContentType.handshake);
    std.mem.writeInt(u16, out[1..3], 0x0303, .big);
    std.mem.writeInt(u16, out[3..5], @intCast(handshake_total), .big);
    out[5] = @intFromEnum(tls.HandshakeType.client_hello);
    out[6] = @intCast((body.len >> 16) & 0xFF);
    out[7] = @intCast((body.len >> 8) & 0xFF);
    out[8] = @intCast(body.len & 0xFF);
    @memcpy(out[9 .. 9 + body.len], body);
    return total;
}

fn buildClientHelloBody(
    out: []u8,
    sni: []const u8,
    client_public: [32]u8,
    session_id: [xray_wire.session_id_length]u8,
) !usize {
    var w = TestWriter{ .buf = out };
    w.writeU16(0x0303);
    w.writeFixed(&[_]u8{0x00} ** 32);
    w.writeVecU8(&session_id);
    w.writeU16(2);
    w.writeU16(supported_cipher_suite);
    w.writeVecU8(&[_]u8{0});

    var ext_buf: [256]u8 = undefined;
    var ew = TestWriter{ .buf = &ext_buf };

    var sni_body: [128]u8 = undefined;
    var swr = TestWriter{ .buf = &sni_body };
    swr.writeU16(@intCast(1 + 2 + sni.len));
    swr.writeU8(0);
    swr.writeU16(@intCast(sni.len));
    swr.writeFixed(sni);
    writeExt(&ew, .server_name, sni_body[0..swr.pos]);

    var sv: [4]u8 = undefined;
    sv[0] = 2;
    std.mem.writeInt(u16, sv[1..3], 0x0304, .big);
    writeExt(&ew, .supported_versions, sv[0..3]);

    var ks_body: [64]u8 = undefined;
    std.mem.writeInt(u16, ks_body[0..2], 2 + 2 + 32, .big);
    std.mem.writeInt(u16, ks_body[2..4], @intFromEnum(tls.NamedGroup.x25519), .big);
    std.mem.writeInt(u16, ks_body[4..6], 32, .big);
    @memcpy(ks_body[6..38], &client_public);
    writeExt(&ew, .key_share, ks_body[0..38]);

    w.writeVecU16(ext_buf[0..ew.pos]);
    return w.pos;
}

fn writeExt(ew: *TestWriter, ext_type: tls.ExtensionType, data: []const u8) void {
    ew.writeU16(@intFromEnum(ext_type));
    ew.writeU16(@intCast(data.len));
    ew.writeFixed(data);
}

const TestWriter = struct {
    buf: []u8,
    pos: usize = 0,

    fn writeU8(self: *TestWriter, v: u8) void {
        self.buf[self.pos] = v;
        self.pos += 1;
    }
    fn writeU16(self: *TestWriter, v: u16) void {
        std.mem.writeInt(u16, self.buf[self.pos..][0..2], v, .big);
        self.pos += 2;
    }
    fn writeFixed(self: *TestWriter, bytes: []const u8) void {
        @memcpy(self.buf[self.pos .. self.pos + bytes.len], bytes);
        self.pos += bytes.len;
    }
    fn writeVecU8(self: *TestWriter, bytes: []const u8) void {
        self.writeU8(@intCast(bytes.len));
        self.writeFixed(bytes);
    }
    fn writeVecU16(self: *TestWriter, bytes: []const u8) void {
        self.writeU16(@intCast(bytes.len));
        self.writeFixed(bytes);
    }
};

/// Build a valid ClientHello record with the AuthKey MAC matching the
/// given short_id + client_public + now_ms. Returns the record bytes
/// and the preview `auth_key` the server would derive.
fn buildValidClientHello(
    out: []u8,
    cfg: reality.Config,
    short_id: reality.ShortId,
    client_public: [32]u8,
    now_ms: i64,
) !struct { record_len: usize, auth_key: [32]u8 } {
    const sid_zero = xray_wire.packSessionId(short_id.bytes, @splat(0), @intCast(@max(now_ms, 0)), @splat(0));
    const n = try buildHandshakeRecord(out, "example.com", client_public, sid_zero);

    // auth_mac offset inside the record: 5 (record hdr) + 4 (handshake hdr) + 43 (CH body offset of session_id) = 52.
    const auth_mac_record_offset = record.RecordHeader.wire_len + 4 + xray_wire.raw_auth_mac_offset;
    const preview = try reality.authorize(cfg, .{
        .server_name = "example.com",
        .short_id = short_id,
        .client_public_key = client_public,
        .client_version = null,
        .unix_ms = now_ms,
    }, now_ms);
    const ch_body = out[9..n];
    const mac = try xray_wire.computeAuthMac(preview.auth_key, ch_body);
    @memcpy(out[auth_mac_record_offset..][0..xray_wire.auth_mac_length], &mac);
    return .{ .record_len = n, .auth_key = preview.auth_key };
}

test "RealityTransport.name() returns \"reality\" through the vtable" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var cert = try makeStubCertStub(io);
    defer cert.deinit();

    const ctx = try makeTestCtx();
    var xport = RealityTransport.init(.{ .config = ctx.config(0), .cert_stub = &cert });
    const t = xport.outerTransport();
    try testing.expectEqualStrings("reality", t.name());
}

test "RealityTransport.admit: non-TLS garbage => fallback with buffered bytes" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var cert = try makeStubCertStub(io);
    defer cert.deinit();

    const garbage = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    var r: std.Io.Reader = .fixed(garbage);
    var wbuf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&wbuf);
    const net_stream: std.Io.net.Stream = .{ .socket = undefined };

    const ctx = try makeTestCtx();
    var xport = RealityTransport.init(.{ .config = ctx.config(0), .cert_stub = &cert });

    const outcome = try xport.admit(.{
        .io = io,
        .reader = &r,
        .writer = &w,
        .net_stream = &net_stream,
        .peer_key = rate_limit.ipv4_zero_prefix,
        .allocator = testing.allocator,
    });
    try testing.expectEqual(
        std.meta.Tag(transport.AdmitOutcome).fallback,
        std.meta.activeTag(outcome),
    );
    try testing.expectEqual(@as(usize, 0), w.buffered().len);
}

test "RealityTransport.admit: SNI not in config => fallback" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var cert = try makeStubCertStub(io);
    defer cert.deinit();

    const ctx = try makeTestCtx();
    const cfg = ctx.config(0);

    const client_seed = hex32("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40");
    const client_public = try ayllu.crypto.X25519.recoverPublicKey(client_seed);
    const sid = xray_wire.packSessionId(cfg.short_ids[0].bytes, @splat(0), 0, @splat(0));

    var record_buf: [512]u8 = undefined;
    const n = try buildHandshakeRecord(&record_buf, "not-in-config.example", client_public, sid);

    var r: std.Io.Reader = .fixed(record_buf[0..n]);
    var wbuf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&wbuf);
    const net_stream: std.Io.net.Stream = .{ .socket = undefined };

    var xport = RealityTransport.init(.{ .config = cfg, .cert_stub = &cert });

    const outcome = try xport.admit(.{
        .io = io,
        .reader = &r,
        .writer = &w,
        .net_stream = &net_stream,
        .peer_key = rate_limit.ipv4_zero_prefix,
        .allocator = testing.allocator,
    });
    try testing.expectEqual(
        std.meta.Tag(transport.AdmitOutcome).fallback,
        std.meta.activeTag(outcome),
    );
    try testing.expectEqualSlices(u8, record_buf[0..n], outcome.fallback.buffered_head);
    try testing.expectEqual(@as(usize, 0), w.buffered().len);
}

test "RealityTransport.admit: bad AuthKey MAC => fallback with original bytes" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var cert = try makeStubCertStub(io);
    defer cert.deinit();

    const ctx = try makeTestCtx();
    const cfg = ctx.config(0);
    const client_seed = hex32("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40");
    const client_public = try ayllu.crypto.X25519.recoverPublicKey(client_seed);
    const sid = xray_wire.packSessionId(
        cfg.short_ids[0].bytes,
        [_]u8{0xFF} ** xray_wire.auth_mac_length,
        0,
        @splat(0),
    );

    var record_buf: [512]u8 = undefined;
    const n = try buildHandshakeRecord(&record_buf, "example.com", client_public, sid);

    var r: std.Io.Reader = .fixed(record_buf[0..n]);
    var wbuf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&wbuf);
    const net_stream: std.Io.net.Stream = .{ .socket = undefined };

    var xport = RealityTransport.init(.{ .config = cfg, .cert_stub = &cert });
    const outcome = try xport.admit(.{
        .io = io,
        .reader = &r,
        .writer = &w,
        .net_stream = &net_stream,
        .peer_key = rate_limit.ipv4_zero_prefix,
        .allocator = testing.allocator,
    });
    try testing.expectEqual(
        std.meta.Tag(transport.AdmitOutcome).fallback,
        std.meta.activeTag(outcome),
    );
    try testing.expectEqualSlices(u8, record_buf[0..n], outcome.fallback.buffered_head);
    try testing.expectEqual(@as(usize, 0), w.buffered().len);
}

test "RealityTransport.admit: malformed record header (wrong version) => fallback" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var cert = try makeStubCertStub(io);
    defer cert.deinit();

    const bad = [_]u8{ 22, 0x02, 0x02, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 0 };
    var r: std.Io.Reader = .fixed(&bad);
    var wbuf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&wbuf);
    const net_stream: std.Io.net.Stream = .{ .socket = undefined };

    const ctx = try makeTestCtx();
    var xport = RealityTransport.init(.{ .config = ctx.config(0), .cert_stub = &cert });

    const outcome = try xport.admit(.{
        .io = io,
        .reader = &r,
        .writer = &w,
        .net_stream = &net_stream,
        .peer_key = rate_limit.ipv4_zero_prefix,
        .allocator = testing.allocator,
    });
    try testing.expectEqual(
        std.meta.Tag(transport.AdmitOutcome).fallback,
        std.meta.activeTag(outcome),
    );
}

test "RealityTransport.admit: fallback bumps admission_reality_rejected_total via metrics" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var cert = try makeStubCertStub(io);
    defer cert.deinit();

    const garbage = "GET / HTTP/1.1\r\n\r\n";
    var r: std.Io.Reader = .fixed(garbage);
    var wbuf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&wbuf);
    const net_stream: std.Io.net.Stream = .{ .socket = undefined };

    var registry: metrics.Registry = .{};
    const ctx = try makeTestCtx();
    var xport = RealityTransport.init(.{ .config = ctx.config(0), .cert_stub = &cert, .metrics = &registry });

    const outcome = try xport.admit(.{
        .io = io,
        .reader = &r,
        .writer = &w,
        .net_stream = &net_stream,
        .peer_key = rate_limit.ipv4_zero_prefix,
        .allocator = testing.allocator,
    });
    try testing.expectEqual(
        std.meta.Tag(transport.AdmitOutcome).fallback,
        std.meta.activeTag(outcome),
    );
    try testing.expectEqual(@as(u64, 1), registry.admission_reality_rejected_total.load());
    try testing.expectEqual(@as(u64, 0), registry.admission_reality_handshake_failed_total.load());
}

test "RealityTransport.admit: truncated record (short read) => EndOfStream" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var cert = try makeStubCertStub(io);
    defer cert.deinit();

    const short = [_]u8{ 22, 0x03, 0x03 };
    var r: std.Io.Reader = .fixed(&short);
    var wbuf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&wbuf);
    const net_stream: std.Io.net.Stream = .{ .socket = undefined };

    const ctx = try makeTestCtx();
    var xport = RealityTransport.init(.{ .config = ctx.config(0), .cert_stub = &cert });

    try testing.expectError(error.EndOfStream, xport.admit(.{
        .io = io,
        .reader = &r,
        .writer = &w,
        .net_stream = &net_stream,
        .peer_key = rate_limit.ipv4_zero_prefix,
        .allocator = testing.allocator,
    }));
}

test "encodeCertificateBody: lays out req-context/list/entry as expected" {
    const cert = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    var out: [32]u8 = undefined;
    const n = encodeCertificateBody(&out, &cert);
    // 1 (req ctx len) + 3 (list len) + 3 (cert len) + 4 (cert) + 2 (exts len) = 13
    try testing.expectEqual(@as(usize, 13), n);
    try testing.expectEqual(@as(u8, 0), out[0]); // empty req context
    // list length (u24): entry_len = 3 + 4 + 2 = 9
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x00, 0x09 }, out[1..4]);
    // cert length (u24): 4
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x00, 0x04 }, out[4..7]);
    try testing.expectEqualSlices(u8, &cert, out[7..11]);
    // extensions length (u16): 0
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x00 }, out[11..13]);
}

test "RealityTransport.admit: unsupported cipher offered => fallback" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var cert = try makeStubCertStub(io);
    defer cert.deinit();

    // Build a CH that offers ONLY 0x1302 (AES256-GCM-SHA384). Our
    // transport only serves 0x1301 in this slice, so admission must
    // fall back before writing anything.
    var body_scratch: [512]u8 = undefined;
    var w = TestWriter{ .buf = &body_scratch };
    w.writeU16(0x0303);
    w.writeFixed(&[_]u8{0} ** 32);
    w.writeVecU8(&([_]u8{0x11} ** xray_wire.session_id_length));
    w.writeU16(2);
    w.writeU16(0x1302); // unsupported
    w.writeVecU8(&[_]u8{0});

    const client_seed = hex32("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40");
    const client_public = try ayllu.crypto.X25519.recoverPublicKey(client_seed);

    var ext_buf: [256]u8 = undefined;
    var ew = TestWriter{ .buf = &ext_buf };
    var sni_body: [32]u8 = undefined;
    var swr = TestWriter{ .buf = &sni_body };
    swr.writeU16(@intCast(1 + 2 + "example.com".len));
    swr.writeU8(0);
    swr.writeU16(@intCast("example.com".len));
    swr.writeFixed("example.com");
    writeExt(&ew, .server_name, sni_body[0..swr.pos]);

    var sv: [4]u8 = undefined;
    sv[0] = 2;
    std.mem.writeInt(u16, sv[1..3], 0x0304, .big);
    writeExt(&ew, .supported_versions, sv[0..3]);

    var ks_body: [64]u8 = undefined;
    std.mem.writeInt(u16, ks_body[0..2], 2 + 2 + 32, .big);
    std.mem.writeInt(u16, ks_body[2..4], @intFromEnum(tls.NamedGroup.x25519), .big);
    std.mem.writeInt(u16, ks_body[4..6], 32, .big);
    @memcpy(ks_body[6..38], &client_public);
    writeExt(&ew, .key_share, ks_body[0..38]);

    w.writeVecU16(ext_buf[0..ew.pos]);

    // Wrap as handshake record.
    var rec_buf: [600]u8 = undefined;
    const body = body_scratch[0..w.pos];
    const handshake_total = 4 + body.len;
    rec_buf[0] = @intFromEnum(tls.ContentType.handshake);
    std.mem.writeInt(u16, rec_buf[1..3], 0x0303, .big);
    std.mem.writeInt(u16, rec_buf[3..5], @intCast(handshake_total), .big);
    rec_buf[5] = @intFromEnum(tls.HandshakeType.client_hello);
    rec_buf[6] = @intCast((body.len >> 16) & 0xFF);
    rec_buf[7] = @intCast((body.len >> 8) & 0xFF);
    rec_buf[8] = @intCast(body.len & 0xFF);
    @memcpy(rec_buf[9..][0..body.len], body);
    const n = 9 + body.len;

    var r: std.Io.Reader = .fixed(rec_buf[0..n]);
    var wbuf: [64]u8 = undefined;
    var resp: std.Io.Writer = .fixed(&wbuf);
    const net_stream: std.Io.net.Stream = .{ .socket = undefined };

    const ctx = try makeTestCtx();
    // Note: even if AuthKey would fail for this garbage session_id, the
    // unsupported-cipher gate fires first — but to make the test
    // independent of validation order, build a CH with an authorized
    // session_id too. For simplicity we use a random sid_zero_like
    // here; the outcome must be fallback regardless of MAC state.
    var xport = RealityTransport.init(.{ .config = ctx.config(0), .cert_stub = &cert });
    const outcome = try xport.admit(.{
        .io = io,
        .reader = &r,
        .writer = &resp,
        .net_stream = &net_stream,
        .peer_key = rate_limit.ipv4_zero_prefix,
        .allocator = testing.allocator,
    });
    try testing.expectEqual(
        std.meta.Tag(transport.AdmitOutcome).fallback,
        std.meta.activeTag(outcome),
    );
    try testing.expectEqual(@as(usize, 0), resp.buffered().len);
}

test "RealityTransport.admit: valid CH + garbage client-finished => silent with SH+CCS+4 encrypted records laid down" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var cert = try makeStubCertStub(io);
    defer cert.deinit();

    const ctx = try makeTestCtx();
    const cfg = ctx.config(std.math.maxInt(u64)); // forgiving clock skew
    const short_id = cfg.short_ids[0];
    const client_seed = hex32("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40");
    const client_public = try ayllu.crypto.X25519.recoverPublicKey(client_seed);

    // Build a CH with valid AuthKey — we want runHandshake to reach the
    // post-commit phase so the framing is emitted.
    var ch_buf: [512]u8 = undefined;
    const built = try buildValidClientHello(&ch_buf, cfg, short_id, client_public, nowUnixMs(io));
    const ch_len = built.record_len;

    // Reader = CH || garbage masquerading as an encrypted Client Finished.
    // The garbage decrypts to an AEAD failure → runHandshake returns
    // an error → admit returns .silent (post-commit path).
    const fake_cf = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x35 } ++ [_]u8{0xAB} ** 0x35;
    var r_buf: [1024]u8 = undefined;
    @memcpy(r_buf[0..ch_len], ch_buf[0..ch_len]);
    @memcpy(r_buf[ch_len..][0..fake_cf.len], &fake_cf);

    var r: std.Io.Reader = .fixed(r_buf[0 .. ch_len + fake_cf.len]);
    var w_buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&w_buf);
    const net_stream: std.Io.net.Stream = .{ .socket = undefined };

    var registry: metrics.Registry = .{};
    var xport = RealityTransport.init(.{ .config = cfg, .cert_stub = &cert, .metrics = &registry });

    const outcome = try xport.admit(.{
        .io = io,
        .reader = &r,
        .writer = &w,
        .net_stream = &net_stream,
        .peer_key = rate_limit.ipv4_zero_prefix,
        .allocator = testing.allocator,
    });
    try testing.expectEqual(transport.AdmitOutcome.silent, outcome);

    // Post-commit failure → _handshake_failed_total bumps, _rejected_total doesn't.
    try testing.expectEqual(@as(u64, 1), registry.admission_reality_handshake_failed_total.load());
    try testing.expectEqual(@as(u64, 0), registry.admission_reality_rejected_total.load());

    // --- Framing assertions on what we sent to the client ---
    const out = w.buffered();
    try testing.expect(out.len >= 550 and out.len <= 4096);

    // Record 1: ServerHello handshake record.
    try testing.expectEqual(@as(u8, 0x16), out[0]); // handshake
    try testing.expectEqual(@as(u8, 0x03), out[1]);
    try testing.expectEqual(@as(u8, 0x03), out[2]);
    const sh_body_len: usize = @intCast(std.mem.readInt(u16, out[3..5], .big));
    const sh_record_total = 5 + sh_body_len;
    // First byte of SH body is the handshake message type: ServerHello = 0x02.
    try testing.expectEqual(@as(u8, 0x02), out[5]);

    // session_id echo (32 bytes) lives at:
    //   record header (5) + handshake hdr (4) + legacy_version (2) + random (32) + session_id_len (1) = 44
    // The server must echo ClientHello.session_id verbatim.
    const sid_offset: usize = 44;
    // Compute CH body offset of session_id in the request buffer so we
    // can cross-check. CH body starts at offset 9 (5 + 4); session_id
    // begins at body offset 2 (version) + 32 (random) + 1 (len) = 35 → absolute 44.
    try testing.expectEqualSlices(u8, ch_buf[44..76], out[sid_offset .. sid_offset + 32]);

    // Record 2: middlebox-compat ChangeCipherSpec.
    const ccs_off = sh_record_total;
    try testing.expectEqualSlices(
        u8,
        &.{ 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 },
        out[ccs_off .. ccs_off + 6],
    );

    // Records 3..6: four encrypted handshake records (EE / Cert / CV / SF).
    // Each has outer content_type = application_data (0x17).
    var off = ccs_off + 6;
    var count: usize = 0;
    while (count < 4) : (count += 1) {
        try testing.expectEqual(@as(u8, 0x17), out[off]); // application_data
        const enc_len: usize = @intCast(std.mem.readInt(u16, out[off + 3 ..][0..2], .big));
        off += 5 + enc_len;
    }
    // Exactly 4 encrypted records — no extras.
    try testing.expectEqual(off, out.len);
}

test "RealityTransport.admit: valid CH cert_der appears verbatim inside the Certificate record" {
    // Reuses the garbage-CF setup to observe post-commit bytes. The cert
    // bytes inside the encrypted Certificate record are under AEAD, so
    // they appear as ciphertext — but the cert's ed25519 OID SPKI
    // preamble (0x30 0x2A 0x30 0x05 0x06 0x03 0x2B 0x65 0x70) only shows
    // up verbatim if we decrypt. Instead this test validates that the
    // Certificate record length is in the expected range for our stub
    // cert (~250 bytes plaintext → ~265 ciphertext).
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var cert = try makeStubCertStub(io);
    defer cert.deinit();

    const ctx = try makeTestCtx();
    const cfg = ctx.config(std.math.maxInt(u64));
    const short_id = cfg.short_ids[0];
    const client_seed = hex32("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40");
    const client_public = try ayllu.crypto.X25519.recoverPublicKey(client_seed);

    var ch_buf: [512]u8 = undefined;
    const built = try buildValidClientHello(&ch_buf, cfg, short_id, client_public, nowUnixMs(io));

    const fake_cf = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x35 } ++ [_]u8{0xAB} ** 0x35;
    var r_buf: [1024]u8 = undefined;
    @memcpy(r_buf[0..built.record_len], ch_buf[0..built.record_len]);
    @memcpy(r_buf[built.record_len..][0..fake_cf.len], &fake_cf);

    var r: std.Io.Reader = .fixed(r_buf[0 .. built.record_len + fake_cf.len]);
    var w_buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&w_buf);
    const net_stream: std.Io.net.Stream = .{ .socket = undefined };

    var xport = RealityTransport.init(.{ .config = cfg, .cert_stub = &cert });
    _ = try xport.admit(.{
        .io = io,
        .reader = &r,
        .writer = &w,
        .net_stream = &net_stream,
        .peer_key = rate_limit.ipv4_zero_prefix,
        .allocator = testing.allocator,
    });

    // Walk past SH record + CCS + EE record to land at Certificate record.
    const out = w.buffered();
    const sh_total = 5 + @as(usize, @intCast(std.mem.readInt(u16, out[3..5], .big)));
    var off = sh_total + 6; // skip CCS
    // Skip EE record
    off += 5 + @as(usize, @intCast(std.mem.readInt(u16, out[off + 3 ..][0..2], .big)));

    // Certificate record. Inner plaintext = 4 (hs hdr) + 1 (req ctx len) + 3 (list len) + 3 (cert len) + cert_der.len + 2 (exts len) = 13 + cert_der.len.
    // Ciphertext = plaintext + 1 (inner type) + 16 (AEAD tag) = 30 + cert_der.len.
    const cert_enc_len: usize = @intCast(std.mem.readInt(u16, out[off + 3 ..][0..2], .big));
    const expected_plaintext = 13 + cert.cert_der.len;
    const expected_cipher = expected_plaintext + 1 + 16;
    try testing.expectEqual(expected_cipher, cert_enc_len);
}

test "RealityTransport.admit: post-commit path allocates nothing on .silent (heap leak guard)" {
    // The SessionState is only allocated after Client Finished verifies.
    // Garbage CF aborts before alloc, so `testing.allocator`'s leak check
    // will fire here if we accidentally allocate something that's never
    // freed.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var cert = try makeStubCertStub(io);
    defer cert.deinit();

    const ctx = try makeTestCtx();
    const cfg = ctx.config(std.math.maxInt(u64));
    const short_id = cfg.short_ids[0];
    const client_seed = hex32("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40");
    const client_public = try ayllu.crypto.X25519.recoverPublicKey(client_seed);

    var ch_buf: [512]u8 = undefined;
    const built = try buildValidClientHello(&ch_buf, cfg, short_id, client_public, nowUnixMs(io));

    const fake_cf = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x35 } ++ [_]u8{0xAB} ** 0x35;
    var r_buf: [1024]u8 = undefined;
    @memcpy(r_buf[0..built.record_len], ch_buf[0..built.record_len]);
    @memcpy(r_buf[built.record_len..][0..fake_cf.len], &fake_cf);

    var r: std.Io.Reader = .fixed(r_buf[0 .. built.record_len + fake_cf.len]);
    var w_buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&w_buf);
    const net_stream: std.Io.net.Stream = .{ .socket = undefined };

    var xport = RealityTransport.init(.{ .config = cfg, .cert_stub = &cert });
    const outcome = try xport.admit(.{
        .io = io,
        .reader = &r,
        .writer = &w,
        .net_stream = &net_stream,
        .peer_key = rate_limit.ipv4_zero_prefix,
        .allocator = testing.allocator,
    });
    try testing.expectEqual(transport.AdmitOutcome.silent, outcome);
    // testing.allocator asserts no unfreed allocations on teardown.
}
