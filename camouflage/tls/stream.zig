//! `std.Io.Reader` / `std.Io.Writer` wrappers that drive a continuous
//! stream of TLS 1.3 application_data records on top of a `RecordLayer`.
//!
//! TlsReader reads encrypted records from an inner reader, decrypts
//! them via the layer, and exposes the plaintext through the
//! `interface` reader so callers can `take`/`peek`/etc. without
//! knowing records are underneath.
//!
//! TlsWriter buffers plaintext in its `interface` writer and on drain
//! or flush seals one or more records (each ≤ `max_plaintext_len`
//! bytes of plaintext) into the inner writer.
//!
//! Buffer-size constraints:
//!
//!   * TlsReader's plaintext buffer must be at least
//!     `record.max_plaintext_len` (16 384) bytes, so a single decrypted
//!     record always fits. The reader rebases when space runs low.
//!   * TlsWriter's plaintext buffer must be at most
//!     `record.max_plaintext_len`, so a single flush emits exactly one
//!     record. A zero-length buffer is legal (unbuffered mode).
//!
//! Out of scope for this slice:
//!   * Post-handshake non-application-data records (NewSessionTicket,
//!     KeyUpdate, CloseNotify). The reader treats any inner
//!     content_type other than `application_data` as `ReadFailed`.
//!   * Concurrent access: each wrapper is single-threaded.

const std = @import("std");
const tls = std.crypto.tls;
const record = @import("record.zig");

pub fn TlsReader(comptime AeadType: type) type {
    const Layer = record.RecordLayer(AeadType);
    return struct {
        const Self = @This();

        interface: std.Io.Reader,
        layer: *Layer,
        inner: *std.Io.Reader,
        record_scratch: [record.RecordHeader.wire_len + record.max_ciphertext_len]u8 = undefined,

        pub fn init(layer: *Layer, inner: *std.Io.Reader, plaintext_buffer: []u8) Self {
            std.debug.assert(plaintext_buffer.len >= record.max_plaintext_len);
            return .{
                .interface = .{
                    .vtable = &.{
                        .stream = streamFn,
                        .readVec = readVecFn,
                    },
                    .buffer = plaintext_buffer,
                    .seek = 0,
                    .end = 0,
                },
                .layer = layer,
                .inner = inner,
            };
        }

        fn streamFn(
            io_r: *std.Io.Reader,
            io_w: *std.Io.Writer,
            limit: std.Io.Limit,
        ) std.Io.Reader.StreamError!usize {
            _ = io_w;
            _ = limit;
            // Populate io_r.buffer with one more record; the outer
            // `Reader.stream` wrapper will drain the buffer to the
            // writer on the next iteration.
            var empty: [0][]u8 = .{};
            _ = try readVecFn(io_r, &empty);
            return 0;
        }

        fn readVecFn(io_r: *std.Io.Reader, data: [][]u8) std.Io.Reader.Error!usize {
            _ = data; // We always populate io_r.buffer directly.
            const self: *Self = @alignCast(@fieldParentPtr("interface", io_r));

            // Rebase if there's not enough room for a full plaintext record.
            if (io_r.buffer.len - io_r.end < record.max_plaintext_len) {
                const unread = io_r.end - io_r.seek;
                if (unread > 0) {
                    std.mem.copyForwards(u8, io_r.buffer[0..unread], io_r.buffer[io_r.seek..io_r.end]);
                }
                io_r.seek = 0;
                io_r.end = unread;
            }

            const dest = io_r.buffer[io_r.end..];
            const opened = record.ReadRecordExact(AeadType).call(
                self.layer,
                self.inner,
                &self.record_scratch,
                dest,
            ) catch |err| switch (err) {
                error.EndOfStream => return error.EndOfStream,
                error.ReadFailed => return error.ReadFailed,
                else => return error.ReadFailed,
            };

            if (opened.inner_content_type != .application_data) {
                return error.ReadFailed;
            }
            io_r.end += opened.plaintext_len;
            return 0;
        }
    };
}

pub fn TlsWriter(comptime AeadType: type) type {
    const Layer = record.RecordLayer(AeadType);
    return struct {
        const Self = @This();

        interface: std.Io.Writer,
        layer: *Layer,
        inner: *std.Io.Writer,
        record_scratch: [record.RecordHeader.wire_len + record.max_ciphertext_len]u8 = undefined,

        pub fn init(layer: *Layer, inner: *std.Io.Writer, plaintext_buffer: []u8) Self {
            std.debug.assert(plaintext_buffer.len <= record.max_plaintext_len);
            return .{
                .interface = .{
                    .vtable = &.{ .drain = drainFn },
                    .buffer = plaintext_buffer,
                    .end = 0,
                },
                .layer = layer,
                .inner = inner,
            };
        }

        fn drainFn(
            io_w: *std.Io.Writer,
            data: []const []const u8,
            splat: usize,
        ) std.Io.Writer.Error!usize {
            const self: *Self = @alignCast(@fieldParentPtr("interface", io_w));

            // Emit whatever was buffered first; this clears io_w.end so
            // the default flush loop terminates.
            if (io_w.end > 0) {
                try self.emitRecord(io_w.buffer[0..io_w.end]);
                io_w.end = 0;
            }

            // Find the first non-empty chunk in data[0..len-1] and emit it.
            // This keeps writeAll(small bytes) working on an unbuffered writer
            // (buffer.len == 0): drain gets data = [user_bytes] and emits one
            // record per call.
            for (data[0 .. data.len - 1]) |chunk| {
                if (chunk.len == 0) continue;
                const take_n = @min(chunk.len, record.max_plaintext_len);
                try self.emitRecord(chunk[0..take_n]);
                return take_n;
            }

            // Last element is repeated `splat` times. For our callers splat=1
            // so we emit `pattern` once.
            const pattern = data[data.len - 1];
            if (pattern.len > 0 and splat > 0) {
                const take_n = @min(pattern.len, record.max_plaintext_len);
                try self.emitRecord(pattern[0..take_n]);
                return take_n;
            }
            return 0;
        }

        fn emitRecord(self: *Self, plaintext: []const u8) std.Io.Writer.Error!void {
            if (plaintext.len == 0) return;
            const n = self.layer.sealRecord(.application_data, plaintext, &self.record_scratch) catch {
                return error.WriteFailed;
            };
            try self.inner.writeAll(self.record_scratch[0..n]);
        }
    };
}

pub const Aes128GcmReader = TlsReader(std.crypto.aead.aes_gcm.Aes128Gcm);
pub const Aes128GcmWriter = TlsWriter(std.crypto.aead.aes_gcm.Aes128Gcm);
pub const Aes256GcmReader = TlsReader(std.crypto.aead.aes_gcm.Aes256Gcm);
pub const Aes256GcmWriter = TlsWriter(std.crypto.aead.aes_gcm.Aes256Gcm);
pub const ChaCha20Poly1305Reader = TlsReader(std.crypto.aead.chacha_poly.ChaCha20Poly1305);
pub const ChaCha20Poly1305Writer = TlsWriter(std.crypto.aead.chacha_poly.ChaCha20Poly1305);

// -------------------- Tests --------------------

const testing = std.testing;

fn makePair(
    comptime Aead: type,
    send_layer: *record.RecordLayer(Aead),
    recv_layer: *record.RecordLayer(Aead),
) struct {
    enc_storage: [65536]u8,
} {
    _ = send_layer;
    _ = recv_layer;
    return .{ .enc_storage = undefined };
}

test "TlsReader + TlsWriter: round-trip a short app_data message" {
    const Aead = std.crypto.aead.aes_gcm.Aes128Gcm;
    const key: [16]u8 = [_]u8{0xAA} ** 16;
    const iv: [12]u8 = [_]u8{0x55} ** 12;

    var send_layer: record.Aes128GcmRecord = .init(key, iv);
    var recv_layer: record.Aes128GcmRecord = .init(key, iv);

    var enc_storage: [4096]u8 = undefined;
    var enc_writer: std.Io.Writer = .fixed(&enc_storage);
    var tls_w_buf: [record.max_plaintext_len]u8 = undefined;
    var tls_w = TlsWriter(Aead).init(&send_layer, &enc_writer, &tls_w_buf);
    try tls_w.interface.writeAll("hello world");
    try tls_w.interface.flush();

    const ciphertext = enc_writer.buffered();
    try testing.expect(ciphertext.len > "hello world".len);
    try testing.expectEqual(@as(u64, 1), send_layer.seq);

    var enc_reader: std.Io.Reader = .fixed(ciphertext);
    var tls_r_buf: [record.max_plaintext_len]u8 = undefined;
    var tls_r = TlsReader(Aead).init(&recv_layer, &enc_reader, &tls_r_buf);
    const got = try tls_r.interface.take("hello world".len);
    try testing.expectEqualStrings("hello world", got);
    try testing.expectEqual(@as(u64, 1), recv_layer.seq);
}

test "TlsReader + TlsWriter: large plaintext (30 KiB) splits across two records" {
    const Aead = std.crypto.aead.aes_gcm.Aes128Gcm;
    const key: [16]u8 = [_]u8{0x42} ** 16;
    const iv: [12]u8 = [_]u8{0x13} ** 12;

    var send_layer: record.Aes128GcmRecord = .init(key, iv);
    var recv_layer: record.Aes128GcmRecord = .init(key, iv);

    var payload: [30 * 1024]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @intCast(i & 0xFF);

    var enc_storage: [64 * 1024]u8 = undefined;
    var enc_writer: std.Io.Writer = .fixed(&enc_storage);
    var tls_w_buf: [record.max_plaintext_len]u8 = undefined;
    var tls_w = TlsWriter(Aead).init(&send_layer, &enc_writer, &tls_w_buf);
    try tls_w.interface.writeAll(&payload);
    try tls_w.interface.flush();

    // sealRecord increments seq once per record. 30 KiB > 16 KiB cap
    // so we expect at least two records.
    try testing.expect(send_layer.seq >= 2);

    var enc_reader: std.Io.Reader = .fixed(enc_writer.buffered());
    var tls_r_buf: [record.max_plaintext_len * 2]u8 = undefined;
    var tls_r = TlsReader(Aead).init(&recv_layer, &enc_reader, &tls_r_buf);

    // Read the whole payload back in chunks smaller than the record
    // boundary to exercise rebasing.
    var got: [30 * 1024]u8 = undefined;
    var read_off: usize = 0;
    while (read_off < got.len) {
        const chunk_size = @min(1024, got.len - read_off);
        const chunk = try tls_r.interface.take(chunk_size);
        @memcpy(got[read_off..][0..chunk_size], chunk);
        read_off += chunk_size;
    }
    try testing.expectEqualSlices(u8, &payload, &got);
}

test "TlsWriter: unbuffered (zero-length buffer) emits one record per writeAll" {
    const Aead = std.crypto.aead.aes_gcm.Aes128Gcm;
    const key: [16]u8 = [_]u8{0x77} ** 16;
    const iv: [12]u8 = [_]u8{0x33} ** 12;

    var send_layer: record.Aes128GcmRecord = .init(key, iv);
    var enc_storage: [1024]u8 = undefined;
    var enc_writer: std.Io.Writer = .fixed(&enc_storage);
    var empty_buf: [0]u8 = undefined;
    var tls_w = TlsWriter(Aead).init(&send_layer, &enc_writer, &empty_buf);
    try tls_w.interface.writeAll("abc");
    try tls_w.interface.writeAll("defg");
    try tls_w.interface.flush();
    // Two writeAll => two records (unbuffered).
    try testing.expectEqual(@as(u64, 2), send_layer.seq);
}

test "TlsReader: tag tampered ciphertext => ReadFailed" {
    const Aead = std.crypto.aead.aes_gcm.Aes128Gcm;
    const key: [16]u8 = [_]u8{0x88} ** 16;
    const iv: [12]u8 = [_]u8{0x99} ** 12;

    var send_layer: record.Aes128GcmRecord = .init(key, iv);
    var enc_storage: [64]u8 = undefined;
    var enc_writer: std.Io.Writer = .fixed(&enc_storage);
    var tls_w_buf: [record.max_plaintext_len]u8 = undefined;
    var tls_w = TlsWriter(Aead).init(&send_layer, &enc_writer, &tls_w_buf);
    try tls_w.interface.writeAll("payload");
    try tls_w.interface.flush();

    // Flip a byte in the tag.
    const n = enc_writer.buffered().len;
    enc_storage[n - 1] ^= 0xFF;

    var recv_layer: record.Aes128GcmRecord = .init(key, iv);
    var enc_reader: std.Io.Reader = .fixed(enc_storage[0..n]);
    var tls_r_buf: [record.max_plaintext_len]u8 = undefined;
    var tls_r = TlsReader(Aead).init(&recv_layer, &enc_reader, &tls_r_buf);
    try testing.expectError(error.ReadFailed, tls_r.interface.take(7));
}

test "TlsReader: EOF on inner stream surfaces as EndOfStream" {
    const Aead = std.crypto.aead.aes_gcm.Aes128Gcm;
    var recv_layer: record.Aes128GcmRecord = .init([_]u8{0} ** 16, [_]u8{0} ** 12);

    var enc_reader: std.Io.Reader = .fixed("");
    var tls_r_buf: [record.max_plaintext_len]u8 = undefined;
    var tls_r = TlsReader(Aead).init(&recv_layer, &enc_reader, &tls_r_buf);
    try testing.expectError(error.EndOfStream, tls_r.interface.take(1));
}

test "TlsWriter + TlsReader: 1000 records in sequence (nonce monotonic)" {
    const Aead = std.crypto.aead.aes_gcm.Aes128Gcm;
    const key: [16]u8 = [_]u8{0x5A} ** 16;
    const iv: [12]u8 = [_]u8{0xA5} ** 12;

    var send_layer: record.Aes128GcmRecord = .init(key, iv);
    var recv_layer: record.Aes128GcmRecord = .init(key, iv);

    // Each record is 8 bytes plaintext; 1000 records = ~33 KiB ciphertext.
    var enc_storage: [64 * 1024]u8 = undefined;
    var enc_writer: std.Io.Writer = .fixed(&enc_storage);
    var empty_buf: [0]u8 = undefined;
    var tls_w = TlsWriter(Aead).init(&send_layer, &enc_writer, &empty_buf);

    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        var pl: [8]u8 = undefined;
        std.mem.writeInt(u64, &pl, i, .big);
        try tls_w.interface.writeAll(&pl);
    }
    try tls_w.interface.flush();
    try testing.expectEqual(@as(u64, 1000), send_layer.seq);

    var enc_reader: std.Io.Reader = .fixed(enc_writer.buffered());
    var tls_r_buf: [record.max_plaintext_len]u8 = undefined;
    var tls_r = TlsReader(Aead).init(&recv_layer, &enc_reader, &tls_r_buf);

    i = 0;
    while (i < 1000) : (i += 1) {
        const bytes = try tls_r.interface.take(8);
        const got = std.mem.readInt(u64, bytes[0..8], .big);
        try testing.expectEqual(@as(u64, i), got);
    }
    try testing.expectEqual(@as(u64, 1000), recv_layer.seq);
}

test "TlsReader + TlsWriter: ChaCha20-Poly1305 round-trip" {
    const Aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
    const key: [32]u8 = [_]u8{0xCC} ** 32;
    const iv: [12]u8 = [_]u8{0xDD} ** 12;

    var send_layer: record.ChaCha20Poly1305Record = .init(key, iv);
    var recv_layer: record.ChaCha20Poly1305Record = .init(key, iv);

    var enc_storage: [256]u8 = undefined;
    var enc_writer: std.Io.Writer = .fixed(&enc_storage);
    var tls_w_buf: [record.max_plaintext_len]u8 = undefined;
    var tls_w = TlsWriter(Aead).init(&send_layer, &enc_writer, &tls_w_buf);
    try tls_w.interface.writeAll("chacha20 over tls");
    try tls_w.interface.flush();

    var enc_reader: std.Io.Reader = .fixed(enc_writer.buffered());
    var tls_r_buf: [record.max_plaintext_len]u8 = undefined;
    var tls_r = TlsReader(Aead).init(&recv_layer, &enc_reader, &tls_r_buf);
    const got = try tls_r.interface.take("chacha20 over tls".len);
    try testing.expectEqualStrings("chacha20 over tls", got);
}

test "TlsReader: wrong key rejects with ReadFailed" {
    const Aead = std.crypto.aead.aes_gcm.Aes128Gcm;
    var send_layer: record.Aes128GcmRecord = .init([_]u8{0x01} ** 16, [_]u8{0x02} ** 12);
    var enc_storage: [64]u8 = undefined;
    var enc_writer: std.Io.Writer = .fixed(&enc_storage);
    var tls_w_buf: [record.max_plaintext_len]u8 = undefined;
    var tls_w = TlsWriter(Aead).init(&send_layer, &enc_writer, &tls_w_buf);
    try tls_w.interface.writeAll("payload");
    try tls_w.interface.flush();

    // Receiver with a different key.
    var recv_layer: record.Aes128GcmRecord = .init([_]u8{0x99} ** 16, [_]u8{0x02} ** 12);
    var enc_reader: std.Io.Reader = .fixed(enc_writer.buffered());
    var tls_r_buf: [record.max_plaintext_len]u8 = undefined;
    var tls_r = TlsReader(Aead).init(&recv_layer, &enc_reader, &tls_r_buf);
    try testing.expectError(error.ReadFailed, tls_r.interface.take(7));
}

test "TlsReader: non-application-data inner content_type => ReadFailed" {
    const Aead = std.crypto.aead.aes_gcm.Aes128Gcm;
    const key: [16]u8 = [_]u8{0x24} ** 16;
    const iv: [12]u8 = [_]u8{0x42} ** 12;

    // Seal a record with inner type=handshake.
    var send_layer: record.Aes128GcmRecord = .init(key, iv);
    var enc_storage: [64]u8 = undefined;
    const n = try send_layer.sealRecord(.handshake, "fake NSTicket", &enc_storage);

    var recv_layer: record.Aes128GcmRecord = .init(key, iv);
    var enc_reader: std.Io.Reader = .fixed(enc_storage[0..n]);
    var tls_r_buf: [record.max_plaintext_len]u8 = undefined;
    var tls_r = TlsReader(Aead).init(&recv_layer, &enc_reader, &tls_r_buf);
    try testing.expectError(error.ReadFailed, tls_r.interface.take(1));
}

test "TlsReader: small takes across a single record exercise buffered path" {
    const Aead = std.crypto.aead.aes_gcm.Aes128Gcm;
    const key: [16]u8 = [_]u8{0x11} ** 16;
    const iv: [12]u8 = [_]u8{0x22} ** 12;

    var send_layer: record.Aes128GcmRecord = .init(key, iv);
    var recv_layer: record.Aes128GcmRecord = .init(key, iv);

    var enc_storage: [128]u8 = undefined;
    var enc_writer: std.Io.Writer = .fixed(&enc_storage);
    var tls_w_buf: [record.max_plaintext_len]u8 = undefined;
    var tls_w = TlsWriter(Aead).init(&send_layer, &enc_writer, &tls_w_buf);
    try tls_w.interface.writeAll("abcdefghijklmnop");
    try tls_w.interface.flush();

    var enc_reader: std.Io.Reader = .fixed(enc_writer.buffered());
    var tls_r_buf: [record.max_plaintext_len]u8 = undefined;
    var tls_r = TlsReader(Aead).init(&recv_layer, &enc_reader, &tls_r_buf);

    const a = try tls_r.interface.take(4);
    try testing.expectEqualStrings("abcd", a);
    const b = try tls_r.interface.take(4);
    try testing.expectEqualStrings("efgh", b);
    const rest = try tls_r.interface.take(8);
    try testing.expectEqualStrings("ijklmnop", rest);
    // Sender sealed once; receiver decrypted once.
    try testing.expectEqual(@as(u64, 1), recv_layer.seq);
}
