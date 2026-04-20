//! REALITY `OuterTransport`. Reads a TLS 1.3 ClientHello, runs REALITY
//! admission (server_name + X25519 + Xray v25.x AuthKey), and either
//! pivots the session or hands it off to the reverse-proxy fallback
//! path so the cover site responds byte-for-byte authentically.
//!
//! C4c scaffolding: on pivot we emit a plaintext
//! `HTTP/1.1 101 Switching Protocols` marker on the TCP stream, same
//! shape as `LegacyHttpTransport`. C5 replaces the marker with real
//! TLS records wrapped via `TlsReader` / `TlsWriter`.
//!
//! The admission path uses `peekGreedy` exclusively until it commits
//! to a pivot. Any rejection can therefore return `.fallback` with the
//! full original bytes still sitting in the reader's buffer, which the
//! dispatcher replays to the cover host.

const std = @import("std");
const tls = std.crypto.tls;
const proxy = @import("ayllu-proxy");
const transport = @import("../transport.zig");
const reality = @import("../reality.zig");
const record = @import("record.zig");
const client_hello_mod = @import("client_hello.zig");
const xray_wire = @import("xray_wire.zig");

pub const alpn_scratch_capacity: usize = 8;

/// Shared state handed to every `RealityTransport` instance. `config`
/// is borrowed — the caller (typically `State`) owns it.
pub const Shared = struct {
    config: reality.Config,
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

    pub fn admit(
        self: *RealityTransport,
        admission: transport.AdmissionContext,
    ) anyerror!transport.AdmitOutcome {
        const admission_deadline = proxy.timeouts.deadlineFromNowMs(
            admission.io,
            proxy.timeouts.Defaults.handshake_ms,
        );

        // Peek the outer record header. Any malformed bytes → fallback
        // so the cover host sees the original request.
        const hdr_bytes = proxy.timeouts.peekDeadline(
            admission.io,
            admission.reader,
            record.RecordHeader.wire_len,
            admission_deadline,
        ) catch |err| switch (err) {
            error.EndOfStream, error.Timeout => return err,
            else => return transport.AdmitOutcome{
                .fallback = .{ .buffered_head = admission.reader.buffered() },
            },
        };
        const hdr = record.RecordHeader.parse(hdr_bytes[0..record.RecordHeader.wire_len]) catch {
            return transport.AdmitOutcome{
                .fallback = .{ .buffered_head = admission.reader.buffered() },
            };
        };
        if (hdr.content_type != .handshake or hdr.length > record.max_plaintext_len or hdr.length < 4) {
            return transport.AdmitOutcome{
                .fallback = .{ .buffered_head = admission.reader.buffered() },
            };
        }

        const record_total = record.RecordHeader.wire_len + @as(usize, hdr.length);
        const full = proxy.timeouts.peekDeadline(
            admission.io,
            admission.reader,
            record_total,
            admission_deadline,
        ) catch |err| switch (err) {
            error.EndOfStream, error.Timeout => return err,
            else => return transport.AdmitOutcome{
                .fallback = .{ .buffered_head = admission.reader.buffered() },
            },
        };

        const payload = full[record.RecordHeader.wire_len..record_total];
        // Inner handshake header: [type u8 | u24 body length].
        if (payload[0] != @intFromEnum(tls.HandshakeType.client_hello)) {
            return transport.AdmitOutcome{
                .fallback = .{ .buffered_head = admission.reader.buffered() },
            };
        }
        const body_len = (@as(usize, payload[1]) << 16) |
            (@as(usize, payload[2]) << 8) |
            @as(usize, payload[3]);
        if (payload.len != 4 + body_len) {
            return transport.AdmitOutcome{
                .fallback = .{ .buffered_head = admission.reader.buffered() },
            };
        }
        const ch_body = payload[4 .. 4 + body_len];

        var scratch_alpn: [alpn_scratch_capacity]?[]const u8 = @splat(null);
        const hello = client_hello_mod.parse(ch_body, &scratch_alpn) catch {
            return transport.AdmitOutcome{
                .fallback = .{ .buffered_head = admission.reader.buffered() },
            };
        };

        // Structural gate — any miss routes to cover.
        if (!hello.supports_tls_13 or hello.x25519_key_share == null) {
            return transport.AdmitOutcome{
                .fallback = .{ .buffered_head = admission.reader.buffered() },
            };
        }
        const sni = hello.server_name orelse return transport.AdmitOutcome{
            .fallback = .{ .buffered_head = admission.reader.buffered() },
        };
        if (!containsServerName(self.shared.config.server_names, sni)) {
            return transport.AdmitOutcome{
                .fallback = .{ .buffered_head = admission.reader.buffered() },
            };
        }

        // AuthKey binding. MAC fail / version skew / unknown short_id
        // all route to cover — DPI sees the authentic upstream response.
        _ = xray_wire.verifyClientHello(
            self.shared.config,
            hello,
            nowUnixMs(admission.io),
        ) catch {
            return transport.AdmitOutcome{
                .fallback = .{ .buffered_head = admission.reader.buffered() },
            };
        };

        // Commit: consume the ClientHello record, emit the 101-Switching
        // marker, and hand the raw stream off to the dispatcher. SOCKS5
        // (or whatever the cooperating client speaks after the marker)
        // runs on the same TCP stream.
        //
        // TODO(C5): replace the plaintext marker with a real TLS
        //           ServerHello + encrypted app_data records wrapped via
        //           TlsReader / TlsWriter.
        _ = try admission.reader.take(record_total);
        try admission.writer.writeAll(
            "HTTP/1.1 101 Switching Protocols\r\n" ++
                "Connection: Upgrade\r\n" ++
                "Upgrade: ayllu-reality\r\n\r\n",
        );
        try admission.writer.flush();

        return transport.AdmitOutcome{
            .pivoted = .{
                .stream = .{
                    .reader = admission.reader,
                    .writer = admission.writer,
                    .net_stream = admission.net_stream,
                },
            },
        };
    }
};

fn containsServerName(list: []const []const u8, candidate: []const u8) bool {
    for (list) |n| if (std.mem.eql(u8, n, candidate)) return true;
    return false;
}

fn nowUnixMs(io: std.Io) i64 {
    return @intCast(@divFloor(std.Io.Clock.real.now(io).nanoseconds, 1_000_000));
}

// -------------------- Tests --------------------

const testing = std.testing;
const ayllu = @import("ayllu");
const rate_limit = @import("../rate_limit.zig");

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

/// Build a full TLS 1.3 handshake record carrying a ClientHello with
/// the given fields. Writes into `out`, returns length.
fn buildHandshakeRecord(
    out: []u8,
    sni: []const u8,
    client_public: [32]u8,
    session_id: [xray_wire.session_id_length]u8,
) !usize {
    // Build CH body first in a scratch buffer.
    var body_scratch: [512]u8 = undefined;
    const body_len = try buildClientHelloBody(&body_scratch, sni, client_public, session_id);
    const body = body_scratch[0..body_len];

    // handshake header: type=1 + u24 length.
    const handshake_total = 4 + body.len;
    // outer record header: type=handshake(22), u16 version, u16 length.
    const total = record.RecordHeader.wire_len + handshake_total;
    if (out.len < total) return error.OutBufferTooSmall;

    // Record header.
    out[0] = @intFromEnum(tls.ContentType.handshake);
    std.mem.writeInt(u16, out[1..3], 0x0303, .big);
    std.mem.writeInt(u16, out[3..5], @intCast(handshake_total), .big);

    // Handshake header.
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
    w.writeU16(0x1301);
    w.writeVecU8(&[_]u8{0});

    var ext_buf: [256]u8 = undefined;
    var ew = TestWriter{ .buf = &ext_buf };

    // server_name
    var sni_body: [128]u8 = undefined;
    var swr = TestWriter{ .buf = &sni_body };
    swr.writeU16(@intCast(1 + 2 + sni.len));
    swr.writeU8(0);
    swr.writeU16(@intCast(sni.len));
    swr.writeFixed(sni);
    writeExt(&ew, .server_name, sni_body[0..swr.pos]);

    // supported_versions
    var sv: [4]u8 = undefined;
    sv[0] = 2;
    std.mem.writeInt(u16, sv[1..3], 0x0304, .big);
    writeExt(&ew, .supported_versions, sv[0..3]);

    // key_share (X25519)
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

test "RealityTransport.name() returns \"reality\" through the vtable" {
    const ctx = try makeTestCtx();
    var xport = RealityTransport.init(.{ .config = ctx.config(0) });
    const t = xport.outerTransport();
    try testing.expectEqualStrings("reality", t.name());
}

test "RealityTransport.admit: non-TLS garbage => fallback with buffered bytes" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const garbage = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    var r: std.Io.Reader = .fixed(garbage);
    var wbuf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&wbuf);
    const net_stream: std.Io.net.Stream = .{ .socket = undefined };

    const ctx = try makeTestCtx();
    var xport = RealityTransport.init(.{ .config = ctx.config(0) });

    const outcome = try xport.admit(.{
        .io = io,
        .reader = &r,
        .writer = &w,
        .net_stream = &net_stream,
        .peer_key = rate_limit.ipv4_zero_prefix,
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

    const ctx = try makeTestCtx();
    const cfg = ctx.config(0);

    const client_seed = hex32("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40");
    const client_public = try ayllu.crypto.X25519.recoverPublicKey(client_seed);
    const sid = xray_wire.packSessionId(
        cfg.short_ids[0].bytes,
        @splat(0),
        0,
        @splat(0),
    );

    var record_buf: [512]u8 = undefined;
    const n = try buildHandshakeRecord(&record_buf, "not-in-config.example", client_public, sid);

    var r: std.Io.Reader = .fixed(record_buf[0..n]);
    var wbuf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&wbuf);
    const net_stream: std.Io.net.Stream = .{ .socket = undefined };

    var xport = RealityTransport.init(.{ .config = cfg });

    const outcome = try xport.admit(.{
        .io = io,
        .reader = &r,
        .writer = &w,
        .net_stream = &net_stream,
        .peer_key = rate_limit.ipv4_zero_prefix,
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

    const ctx = try makeTestCtx();
    const cfg = ctx.config(0);
    const client_seed = hex32("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40");
    const client_public = try ayllu.crypto.X25519.recoverPublicKey(client_seed);
    // Deliberately wrong auth_mac (all 0xFF).
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

    var xport = RealityTransport.init(.{ .config = cfg });
    const outcome = try xport.admit(.{
        .io = io,
        .reader = &r,
        .writer = &w,
        .net_stream = &net_stream,
        .peer_key = rate_limit.ipv4_zero_prefix,
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

    // 22 = handshake, but version bytes 0x02 0x02 are invalid.
    const bad = [_]u8{ 22, 0x02, 0x02, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 0 };
    var r: std.Io.Reader = .fixed(&bad);
    var wbuf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&wbuf);
    const net_stream: std.Io.net.Stream = .{ .socket = undefined };

    const ctx = try makeTestCtx();
    var xport = RealityTransport.init(.{ .config = ctx.config(0) });

    const outcome = try xport.admit(.{
        .io = io,
        .reader = &r,
        .writer = &w,
        .net_stream = &net_stream,
        .peer_key = rate_limit.ipv4_zero_prefix,
    });
    try testing.expectEqual(
        std.meta.Tag(transport.AdmitOutcome).fallback,
        std.meta.activeTag(outcome),
    );
}

test "RealityTransport.admit: happy path writes 101 marker and returns pivoted" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const ctx = try makeTestCtx();
    const cfg = ctx.config(0);
    const short_id = cfg.short_ids[0];
    const client_seed = hex32("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40");
    const client_public = try ayllu.crypto.X25519.recoverPublicKey(client_seed);

    // Preview the auth_key the server will see.
    const preview = try reality.authorize(cfg, .{
        .server_name = "example.com",
        .short_id = short_id,
        .client_public_key = client_public,
        .client_version = null,
        .unix_ms = 0,
    }, 0);

    // Build CH with zero auth_mac, MAC it, patch the slot.
    const sid_zero = xray_wire.packSessionId(short_id.bytes, @splat(0), 0, @splat(0));
    var record_buf: [512]u8 = undefined;
    const n = try buildHandshakeRecord(&record_buf, "example.com", client_public, sid_zero);

    // auth_mac offset inside the record: 5 (record header) + 4 (handshake header) + 43 (CH body) = 52.
    const auth_mac_record_offset = record.RecordHeader.wire_len + 4 + xray_wire.raw_auth_mac_offset;
    // Reconstruct the CH body that was MAC'd: the bytes from offset 9..n
    // are the CH body starting with legacy_version. Pass that to computeAuthMac.
    const ch_body = record_buf[9..n];
    const mac = try xray_wire.computeAuthMac(preview.auth_key, ch_body);
    @memcpy(record_buf[auth_mac_record_offset..][0..xray_wire.auth_mac_length], &mac);

    var r: std.Io.Reader = .fixed(record_buf[0..n]);
    var wbuf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&wbuf);
    const net_stream: std.Io.net.Stream = .{ .socket = undefined };

    // Bump cfg.max_time_diff_ms so current-wall-clock doesn't skew out.
    var cfg_forgiving = cfg;
    cfg_forgiving.max_time_diff_ms = std.math.maxInt(u64);
    var xport = RealityTransport.init(.{ .config = cfg_forgiving });

    const outcome = try xport.admit(.{
        .io = io,
        .reader = &r,
        .writer = &w,
        .net_stream = &net_stream,
        .peer_key = rate_limit.ipv4_zero_prefix,
    });
    try testing.expectEqual(
        std.meta.Tag(transport.AdmitOutcome).pivoted,
        std.meta.activeTag(outcome),
    );
    // 101 marker written.
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "101 Switching Protocols") != null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Upgrade: ayllu-reality") != null);
    // ClientHello record fully consumed — reader has no bytes left.
    try testing.expectEqual(@as(usize, 0), r.buffered().len);
}

test "RealityTransport.admit: truncated record (short read) => EndOfStream" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Only 3 bytes of a record header — peekDeadline will return EndOfStream.
    const short = [_]u8{ 22, 0x03, 0x03 };
    var r: std.Io.Reader = .fixed(&short);
    var wbuf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&wbuf);
    const net_stream: std.Io.net.Stream = .{ .socket = undefined };

    const ctx = try makeTestCtx();
    var xport = RealityTransport.init(.{ .config = ctx.config(0) });

    try testing.expectError(error.EndOfStream, xport.admit(.{
        .io = io,
        .reader = &r,
        .writer = &w,
        .net_stream = &net_stream,
        .peer_key = rate_limit.ipv4_zero_prefix,
    }));
}
