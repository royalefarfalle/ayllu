//! TLS 1.3 primitives for the REALITY transport. Wraps std.crypto.tls
//! with REALITY-specific bits: record layer ready to feed AEAD from a
//! TLS 1.3 key schedule, full schedule (early/handshake/master
//! secrets + traffic keys), and — in later slices — ClientHello
//! parse, ForgedServerHello synth, and Xray v25.x session_id binding.

pub const record = @import("record.zig");
pub const keys = @import("keys.zig");
pub const client_hello = @import("client_hello.zig");

test {
    _ = record;
    _ = keys;
    _ = client_hello;
}
