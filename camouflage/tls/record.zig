//! TLS 1.3 record layer (RFC 8446 §5).
//!
//! Wire format (plaintext record, pre-handshake):
//!
//!     +-- 1 byte: ContentType
//!     |  +-- 2 bytes: legacy_record_version = 0x0303
//!     |  |  +-- 2 bytes: length (u16 BE, = payload.len, ≤ 2^14)
//!     |  |  |  +-- N bytes: payload
//!     v  v  v  v
//!     22 03 03 LL LL pp pp ...
//!
//! Wire format (encrypted record, TLSCiphertext):
//!
//!     +-- 1 byte: opaque_type = 23 (application_data)
//!     |  +-- 2 bytes: legacy_record_version = 0x0303
//!     |  |  +-- 2 bytes: length = inner_plaintext.len + 1 + tag_len (+ padding)
//!     |  |  |  +-- N bytes: ciphertext (seal(inner_plaintext || inner_type || pad))
//!     |  |  |  +-- 16 bytes: auth tag
//!     v  v  v  v
//!     17 03 03 LL LL cc cc ... tt tt ...
//!
//! AEAD nonce = write_iv XOR seq_u64_be_in_last_8_bytes.
//! AEAD AAD   = the 5-byte record header (verbatim).
//!
//! Padding (zero bytes between inner_type and the AEAD tag) is allowed
//! by the spec but REALITY never uses it — the forged ServerHello and
//! all subsequent records emit padding_len = 0. We still accept
//! arbitrary padding on `openRecord` for interop.

const std = @import("std");
const tls = std.crypto.tls;

/// TLS 1.3 plaintext records cap at 2^14 = 16384 payload bytes.
pub const max_plaintext_len: usize = 16384;

/// Worst-case ciphertext length (plaintext + inner_type byte + 255
/// bytes of padding + 16-byte tag). We won't emit anything this big.
pub const max_ciphertext_len: usize = max_plaintext_len + 1 + 255 + 16;

pub const legacy_record_version: u16 = 0x0303;

pub const RecordHeader = struct {
    content_type: tls.ContentType,
    length: u16,

    pub const wire_len: usize = 5;

    pub fn writeInto(self: RecordHeader, buf: *[wire_len]u8) void {
        buf[0] = @intFromEnum(self.content_type);
        std.mem.writeInt(u16, buf[1..3], legacy_record_version, .big);
        std.mem.writeInt(u16, buf[3..5], self.length, .big);
    }

    pub fn parse(bytes: []const u8) error{ShortBuffer, InvalidVersion}!RecordHeader {
        if (bytes.len < wire_len) return error.ShortBuffer;
        const ver = std.mem.readInt(u16, bytes[1..3], .big);
        // TLS 1.0 (0x0301) appears in ClientHello's legacy_record_version per
        // RFC 8446 §D.4 (middlebox compat). Accept 0x0301-0x0303.
        if (ver != 0x0303 and ver != 0x0301) return error.InvalidVersion;
        return .{
            .content_type = @enumFromInt(bytes[0]),
            .length = std.mem.readInt(u16, bytes[3..5], .big),
        };
    }
};

/// Write a plaintext record header + payload to `writer`. Used for
/// pre-handshake records (ClientHello / ServerHello / Alert / CCS)
/// before any key material is available.
pub fn writePlaintextRecord(
    writer: *std.Io.Writer,
    content_type: tls.ContentType,
    payload: []const u8,
) !void {
    if (payload.len > max_plaintext_len) return error.RecordTooLarge;
    var hdr_buf: [RecordHeader.wire_len]u8 = undefined;
    const hdr: RecordHeader = .{
        .content_type = content_type,
        .length = @intCast(payload.len),
    };
    hdr.writeInto(&hdr_buf);
    try writer.writeAll(&hdr_buf);
    try writer.writeAll(payload);
}

pub const ReadRecord = struct {
    content_type: tls.ContentType,
    /// Slice owned by the reader's ring; valid until next `take` /
    /// `peek` consumes the buffer.
    payload: []const u8,
};

/// Read a plaintext record header and return it plus the payload
/// slice. On a short/invalid record returns the parse error from
/// `RecordHeader.parse`.
pub fn readPlaintextRecord(reader: *std.Io.Reader) !ReadRecord {
    const hdr_bytes = try reader.take(RecordHeader.wire_len);
    const hdr = try RecordHeader.parse(hdr_bytes);
    if (hdr.length > max_plaintext_len) return error.RecordTooLarge;
    const payload = try reader.take(hdr.length);
    return .{ .content_type = hdr.content_type, .payload = payload };
}

/// Directional AEAD state: key + base iv + monotonically increasing
/// sequence counter. One instance per direction (client-read /
/// client-write / server-read / server-write — REALITY uses four:
/// handshake-receive, handshake-send, application-receive,
/// application-send).
pub fn RecordLayer(comptime AeadType: type) type {
    return struct {
        const Self = @This();

        pub const AEAD = AeadType;
        pub const key_length = AEAD.key_length;
        pub const nonce_length = AEAD.nonce_length;
        pub const tag_length = AEAD.tag_length;

        key: [key_length]u8,
        iv: [nonce_length]u8,
        seq: u64 = 0,

        pub fn init(key: [key_length]u8, iv: [nonce_length]u8) Self {
            return .{ .key = key, .iv = iv };
        }

        /// XOR the 64-bit sequence counter (big-endian) into the last
        /// 8 bytes of the base IV. Spec: RFC 8446 §5.3.
        pub fn deriveNonce(self: Self) [nonce_length]u8 {
            var nonce = self.iv;
            var seq_be: [8]u8 = undefined;
            std.mem.writeInt(u64, &seq_be, self.seq, .big);
            const off = nonce_length - 8;
            inline for (0..8) |i| nonce[off + i] ^= seq_be[i];
            return nonce;
        }

        /// Encrypt inner plaintext + append inner content type byte,
        /// prepend a 5-byte record header, emit header||ciphertext||tag
        /// into `out`. Returns the number of bytes written.
        pub fn sealRecord(
            self: *Self,
            inner_content_type: tls.ContentType,
            plaintext: []const u8,
            out: []u8,
        ) !usize {
            if (plaintext.len > max_plaintext_len) return error.RecordTooLarge;
            const inner_len = plaintext.len + 1;
            const encrypted_len = inner_len + tag_length;
            if (encrypted_len > std.math.maxInt(u16)) return error.RecordTooLarge;
            const total = RecordHeader.wire_len + encrypted_len;
            if (out.len < total) return error.ShortBuffer;

            // Header first (becomes the AEAD AAD).
            const hdr: RecordHeader = .{
                .content_type = .application_data,
                .length = @intCast(encrypted_len),
            };
            hdr.writeInto(out[0..RecordHeader.wire_len]);

            // Build inner plaintext in a scratch buffer: plaintext || type.
            // We do this in `out`'s ciphertext region to avoid a copy, then
            // encrypt in place.
            const ct_start = RecordHeader.wire_len;
            const ct_region = out[ct_start .. ct_start + inner_len];
            @memcpy(ct_region[0..plaintext.len], plaintext);
            ct_region[plaintext.len] = @intFromEnum(inner_content_type);

            const nonce = self.deriveNonce();
            const tag_dest = out[ct_start + inner_len ..][0..tag_length];
            AEAD.encrypt(
                ct_region,
                tag_dest,
                ct_region,
                out[0..RecordHeader.wire_len],
                nonce,
                self.key,
            );

            self.seq +%= 1;
            return total;
        }

        pub const OpenedRecord = struct {
            inner_content_type: tls.ContentType,
            /// Length of inner plaintext (not including the trailing
            /// content-type byte or padding).
            plaintext_len: usize,
        };

        /// Decrypt a full TLSCiphertext record in `input` (header +
        /// ciphertext + tag). Writes inner plaintext to `out[0..plaintext_len]`;
        /// strips trailing zero padding and the inner content type byte.
        pub fn openRecord(self: *Self, input: []const u8, out: []u8) !OpenedRecord {
            if (input.len < RecordHeader.wire_len + tag_length) return error.ShortBuffer;
            const hdr = try RecordHeader.parse(input[0..RecordHeader.wire_len]);
            if (hdr.content_type != .application_data) return error.NotApplicationData;
            if (hdr.length < tag_length or hdr.length > max_ciphertext_len) return error.InvalidLength;
            const record_end = RecordHeader.wire_len + @as(usize, hdr.length);
            if (input.len < record_end) return error.ShortBuffer;

            const ciphertext_len = @as(usize, hdr.length) - tag_length;
            if (out.len < ciphertext_len) return error.ShortBuffer;

            const ct = input[RecordHeader.wire_len .. RecordHeader.wire_len + ciphertext_len];
            const tag_bytes = input[RecordHeader.wire_len + ciphertext_len ..][0..tag_length];
            const nonce = self.deriveNonce();

            // Decrypt into `out[0..ciphertext_len]`.
            const plain = out[0..ciphertext_len];
            try AEAD.decrypt(
                plain,
                ct,
                tag_bytes.*,
                input[0..RecordHeader.wire_len],
                nonce,
                self.key,
            );

            // Strip trailing zero padding, then the content type byte.
            var end: usize = ciphertext_len;
            while (end > 0 and plain[end - 1] == 0) : (end -= 1) {}
            if (end == 0) return error.MissingContentType;
            const inner_ct: tls.ContentType = @enumFromInt(plain[end - 1]);
            const plaintext_len = end - 1;

            self.seq +%= 1;
            return .{ .inner_content_type = inner_ct, .plaintext_len = plaintext_len };
        }
    };
}

pub const Aes128GcmRecord = RecordLayer(std.crypto.aead.aes_gcm.Aes128Gcm);
pub const Aes256GcmRecord = RecordLayer(std.crypto.aead.aes_gcm.Aes256Gcm);
pub const ChaCha20Poly1305Record = RecordLayer(std.crypto.aead.chacha_poly.ChaCha20Poly1305);

/// Read a full encrypted TLSCiphertext record (5-byte header +
/// ciphertext + tag) from `reader` into `scratch`, then decrypt into
/// `plaintext_out`. Returns an `OpenedRecord` describing the inner
/// content type and plaintext length.
///
/// `scratch` must be at least `RecordHeader.wire_len + max_ciphertext_len`
/// (5 + 16671 = 16676) bytes. `plaintext_out` must be at least
/// `max_plaintext_len` (16384) bytes to fit any conformant record.
///
/// On any wire-level malformation (short header, wrong version, bad
/// length) returns the underlying error. On AEAD failure returns
/// `error.AuthenticationFailed`. EOF mid-record returns
/// `error.EndOfStream`.
pub fn ReadRecordExact(comptime AeadType: type) type {
    const Layer = RecordLayer(AeadType);
    return struct {
        pub fn call(
            layer: *Layer,
            reader: *std.Io.Reader,
            scratch: []u8,
            plaintext_out: []u8,
        ) !Layer.OpenedRecord {
            if (scratch.len < RecordHeader.wire_len) return error.ShortBuffer;

            // Read the 5-byte record header.
            const hdr_bytes = try reader.take(RecordHeader.wire_len);
            const hdr = try RecordHeader.parse(hdr_bytes[0..RecordHeader.wire_len]);
            if (hdr.content_type != .application_data) return error.NotApplicationData;
            if (hdr.length < Layer.tag_length + 1) return error.InvalidLength;
            if (hdr.length > max_ciphertext_len) return error.RecordTooLarge;

            const total = RecordHeader.wire_len + @as(usize, hdr.length);
            if (scratch.len < total) return error.ShortBuffer;

            // Copy header into scratch; read ciphertext+tag directly adjacent.
            @memcpy(scratch[0..RecordHeader.wire_len], hdr_bytes[0..RecordHeader.wire_len]);
            const ct_with_tag = try reader.take(hdr.length);
            @memcpy(scratch[RecordHeader.wire_len..total], ct_with_tag);

            return layer.openRecord(scratch[0..total], plaintext_out);
        }
    };
}

// -------------------- Tests --------------------

const testing = std.testing;

test "RecordHeader.writeInto/parse round-trip" {
    const hdr: RecordHeader = .{ .content_type = .handshake, .length = 260 };
    var buf: [RecordHeader.wire_len]u8 = undefined;
    hdr.writeInto(&buf);
    try testing.expectEqual(@as(u8, 22), buf[0]);
    try testing.expectEqualSlices(u8, &.{ 0x03, 0x03 }, buf[1..3]);
    try testing.expectEqual(@as(u16, 260), std.mem.readInt(u16, buf[3..5], .big));

    const parsed = try RecordHeader.parse(&buf);
    try testing.expectEqual(tls.ContentType.handshake, parsed.content_type);
    try testing.expectEqual(@as(u16, 260), parsed.length);
}

test "RecordHeader.parse accepts legacy TLS 1.0 version byte in ClientHello records" {
    const buf = [_]u8{ 0x16, 0x03, 0x01, 0x00, 0x10 };
    const parsed = try RecordHeader.parse(&buf);
    try testing.expectEqual(tls.ContentType.handshake, parsed.content_type);
    try testing.expectEqual(@as(u16, 16), parsed.length);
}

test "RecordHeader.parse rejects short buffer and wrong version" {
    try testing.expectError(error.ShortBuffer, RecordHeader.parse(&.{ 0x17, 0x03 }));
    const bad = [_]u8{ 0x17, 0x02, 0x00, 0x00, 0x10 };
    try testing.expectError(error.InvalidVersion, RecordHeader.parse(&bad));
}

test "writePlaintextRecord writes header + payload and enforces max length" {
    var buf: [32]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const payload = "hello";
    try writePlaintextRecord(&w, .application_data, payload);
    try testing.expectEqualSlices(u8, &.{ 0x17, 0x03, 0x03, 0x00, 0x05 }, w.buffered()[0..5]);
    try testing.expectEqualSlices(u8, payload, w.buffered()[5..10]);
}

test "writePlaintextRecord rejects oversize payloads" {
    var sink_buf: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&sink_buf);
    var huge_buf: [max_plaintext_len + 1]u8 = undefined;
    try testing.expectError(
        error.RecordTooLarge,
        writePlaintextRecord(&w, .application_data, &huge_buf),
    );
}

test "readPlaintextRecord round-trips with writePlaintextRecord" {
    var wire: [32]u8 = undefined;
    var w: std.Io.Writer = .fixed(&wire);
    try writePlaintextRecord(&w, .alert, &.{ 0x02, 0x32 });
    var r: std.Io.Reader = .fixed(w.buffered());
    const rec = try readPlaintextRecord(&r);
    try testing.expectEqual(tls.ContentType.alert, rec.content_type);
    try testing.expectEqualSlices(u8, &.{ 0x02, 0x32 }, rec.payload);
}

test "RecordLayer.deriveNonce XORs seq into the last 8 iv bytes" {
    const R = Aes128GcmRecord;
    const iv: [12]u8 = .{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C };
    var layer: R = .init([_]u8{0xAA} ** 16, iv);

    const n0 = layer.deriveNonce();
    try testing.expectEqualSlices(u8, &iv, &n0);

    layer.seq = 1;
    const n1 = layer.deriveNonce();
    const expected_n1: [12]u8 = .{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0D };
    try testing.expectEqualSlices(u8, &expected_n1, &n1);

    layer.seq = 0x0123456789ABCDEF;
    const n2 = layer.deriveNonce();
    // Last 8 bytes XOR'd with 01 23 45 67 89 AB CD EF.
    const expected_n2: [12]u8 = .{ 0x01, 0x02, 0x03, 0x04, 0x04, 0x25, 0x42, 0x6F, 0x80, 0xA1, 0xC6, 0xE3 };
    try testing.expectEqualSlices(u8, &expected_n2, &n2);
}

test "sealRecord + openRecord round-trip (AES-128-GCM)" {
    const R = Aes128GcmRecord;
    const key: [16]u8 = .{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00 };
    const iv: [12]u8 = .{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C };

    var sender: R = .init(key, iv);
    var receiver: R = .init(key, iv);

    const plaintext = "ping one two three";
    var wire: [64]u8 = undefined;
    const n = try sender.sealRecord(.handshake, plaintext, &wire);
    try testing.expectEqual(RecordHeader.wire_len + plaintext.len + 1 + 16, n);
    try testing.expectEqual(@as(u64, 1), sender.seq);
    // Outer type is app_data regardless of inner type.
    try testing.expectEqual(@as(u8, 23), wire[0]);

    var out: [64]u8 = undefined;
    const opened = try receiver.openRecord(wire[0..n], &out);
    try testing.expectEqual(tls.ContentType.handshake, opened.inner_content_type);
    try testing.expectEqualSlices(u8, plaintext, out[0..opened.plaintext_len]);
    try testing.expectEqual(@as(u64, 1), receiver.seq);
}

test "sealRecord + openRecord round-trip (ChaCha20-Poly1305)" {
    const R = ChaCha20Poly1305Record;
    const key: [32]u8 = [_]u8{0x42} ** 32;
    const iv: [12]u8 = [_]u8{0x07} ** 12;

    var sender: R = .init(key, iv);
    var receiver: R = .init(key, iv);

    const plaintext = "chacha20 test";
    var wire: [64]u8 = undefined;
    const n = try sender.sealRecord(.application_data, plaintext, &wire);

    var out: [64]u8 = undefined;
    const opened = try receiver.openRecord(wire[0..n], &out);
    try testing.expectEqual(tls.ContentType.application_data, opened.inner_content_type);
    try testing.expectEqualSlices(u8, plaintext, out[0..opened.plaintext_len]);
}

test "sealRecord: successive records use distinct nonces (seq increments)" {
    const R = Aes128GcmRecord;
    const key: [16]u8 = [_]u8{0x33} ** 16;
    const iv: [12]u8 = [_]u8{0x55} ** 12;

    var sender: R = .init(key, iv);
    const plaintext = "same";
    var wire_a: [32]u8 = undefined;
    var wire_b: [32]u8 = undefined;

    const na = try sender.sealRecord(.application_data, plaintext, &wire_a);
    const nb = try sender.sealRecord(.application_data, plaintext, &wire_b);
    try testing.expectEqual(na, nb);
    // Same plaintext, different seq -> different ciphertext.
    try testing.expect(!std.mem.eql(u8, wire_a[0..na], wire_b[0..nb]));
    try testing.expectEqual(@as(u64, 2), sender.seq);
}

test "openRecord: tag tamper is rejected" {
    const R = Aes128GcmRecord;
    const key: [16]u8 = [_]u8{0x11} ** 16;
    const iv: [12]u8 = [_]u8{0x22} ** 12;

    var sender: R = .init(key, iv);
    var receiver: R = .init(key, iv);

    var wire: [48]u8 = undefined;
    const n = try sender.sealRecord(.handshake, "payload", &wire);
    // Flip a tag bit.
    wire[n - 1] ^= 0x01;

    var out: [48]u8 = undefined;
    try testing.expectError(error.AuthenticationFailed, receiver.openRecord(wire[0..n], &out));
}

test "openRecord: wrong key is rejected" {
    const R = Aes128GcmRecord;
    const iv: [12]u8 = [_]u8{0x22} ** 12;

    var sender: R = .init([_]u8{0x11} ** 16, iv);
    var receiver: R = .init([_]u8{0x99} ** 16, iv);

    var wire: [48]u8 = undefined;
    const n = try sender.sealRecord(.handshake, "payload", &wire);
    var out: [48]u8 = undefined;
    try testing.expectError(error.AuthenticationFailed, receiver.openRecord(wire[0..n], &out));
}

test "openRecord: short buffer is rejected" {
    var layer: Aes128GcmRecord = .init([_]u8{0} ** 16, [_]u8{0} ** 12);
    var out: [32]u8 = undefined;
    try testing.expectError(error.ShortBuffer, layer.openRecord(&.{ 0x17, 0x03, 0x03 }, &out));
}

test "ReadRecordExact: round-trip with sealRecord over a fixed reader" {
    const R = Aes128GcmRecord;
    const key: [16]u8 = [_]u8{0x11} ** 16;
    const iv: [12]u8 = [_]u8{0x22} ** 12;

    var sender: R = .init(key, iv);
    var wire: [64]u8 = undefined;
    const n = try sender.sealRecord(.handshake, "round-trip", &wire);

    var receiver: R = .init(key, iv);
    var reader: std.Io.Reader = .fixed(wire[0..n]);
    var scratch: [max_ciphertext_len + RecordHeader.wire_len]u8 = undefined;
    var plaintext: [max_plaintext_len]u8 = undefined;
    const opened = try ReadRecordExact(std.crypto.aead.aes_gcm.Aes128Gcm).call(
        &receiver,
        &reader,
        &scratch,
        &plaintext,
    );
    try testing.expectEqual(tls.ContentType.handshake, opened.inner_content_type);
    try testing.expectEqualSlices(u8, "round-trip", plaintext[0..opened.plaintext_len]);
    try testing.expectEqual(@as(u64, 1), receiver.seq);
}

test "ReadRecordExact: two successive records track sequence counter" {
    const R = Aes128GcmRecord;
    const key: [16]u8 = [_]u8{0x33} ** 16;
    const iv: [12]u8 = [_]u8{0x44} ** 12;

    var sender: R = .init(key, iv);
    var wire: [128]u8 = undefined;
    const n1 = try sender.sealRecord(.application_data, "first", &wire);
    const n2 = try sender.sealRecord(.application_data, "second", wire[n1..]);

    var receiver: R = .init(key, iv);
    var reader: std.Io.Reader = .fixed(wire[0 .. n1 + n2]);
    var scratch: [RecordHeader.wire_len + max_ciphertext_len]u8 = undefined;
    var plaintext: [max_plaintext_len]u8 = undefined;

    const o1 = try ReadRecordExact(std.crypto.aead.aes_gcm.Aes128Gcm).call(
        &receiver,
        &reader,
        &scratch,
        &plaintext,
    );
    try testing.expectEqualSlices(u8, "first", plaintext[0..o1.plaintext_len]);

    const o2 = try ReadRecordExact(std.crypto.aead.aes_gcm.Aes128Gcm).call(
        &receiver,
        &reader,
        &scratch,
        &plaintext,
    );
    try testing.expectEqualSlices(u8, "second", plaintext[0..o2.plaintext_len]);
    try testing.expectEqual(@as(u64, 2), receiver.seq);
}

test "ReadRecordExact: outer type != application_data => NotApplicationData" {
    const R = Aes128GcmRecord;
    var receiver: R = .init([_]u8{0} ** 16, [_]u8{0} ** 12);
    // Forge a handshake-typed record header with a small payload.
    const wire = [_]u8{ 0x16, 0x03, 0x03, 0x00, 0x11 } ++ [_]u8{0x00} ** 17;
    var reader: std.Io.Reader = .fixed(&wire);
    var scratch: [RecordHeader.wire_len + max_ciphertext_len]u8 = undefined;
    var plaintext: [max_plaintext_len]u8 = undefined;
    try testing.expectError(error.NotApplicationData, ReadRecordExact(std.crypto.aead.aes_gcm.Aes128Gcm).call(
        &receiver,
        &reader,
        &scratch,
        &plaintext,
    ));
}

test "ReadRecordExact: tag tamper is rejected as AuthenticationFailed" {
    const R = Aes128GcmRecord;
    const key: [16]u8 = [_]u8{0x55} ** 16;
    const iv: [12]u8 = [_]u8{0x66} ** 12;

    var sender: R = .init(key, iv);
    var wire: [64]u8 = undefined;
    const n = try sender.sealRecord(.application_data, "payload", &wire);
    wire[n - 1] ^= 0xFF;

    var receiver: R = .init(key, iv);
    var reader: std.Io.Reader = .fixed(wire[0..n]);
    var scratch: [RecordHeader.wire_len + max_ciphertext_len]u8 = undefined;
    var plaintext: [max_plaintext_len]u8 = undefined;
    try testing.expectError(error.AuthenticationFailed, ReadRecordExact(std.crypto.aead.aes_gcm.Aes128Gcm).call(
        &receiver,
        &reader,
        &scratch,
        &plaintext,
    ));
}

test "ReadRecordExact: truncated wire returns EndOfStream" {
    const R = Aes128GcmRecord;
    var receiver: R = .init([_]u8{0} ** 16, [_]u8{0} ** 12);
    // Only 3 bytes — header needs 5.
    const truncated = [_]u8{ 0x17, 0x03, 0x03 };
    var reader: std.Io.Reader = .fixed(&truncated);
    var scratch: [RecordHeader.wire_len + max_ciphertext_len]u8 = undefined;
    var plaintext: [max_plaintext_len]u8 = undefined;
    try testing.expectError(error.EndOfStream, ReadRecordExact(std.crypto.aead.aes_gcm.Aes128Gcm).call(
        &receiver,
        &reader,
        &scratch,
        &plaintext,
    ));
}

test "openRecord: inner content type reflects what sealRecord tagged" {
    const R = Aes128GcmRecord;
    const key: [16]u8 = [_]u8{0xA5} ** 16;
    const iv: [12]u8 = [_]u8{0x5A} ** 12;

    var sender: R = .init(key, iv);
    var receiver: R = .init(key, iv);

    var wire: [48]u8 = undefined;
    const n = try sender.sealRecord(.alert, &.{ 0x02, 0x28 }, &wire);
    var out: [48]u8 = undefined;
    const opened = try receiver.openRecord(wire[0..n], &out);
    try testing.expectEqual(tls.ContentType.alert, opened.inner_content_type);
    try testing.expectEqualSlices(u8, &.{ 0x02, 0x28 }, out[0..opened.plaintext_len]);
}
