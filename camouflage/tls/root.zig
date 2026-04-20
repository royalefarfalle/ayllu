//! TLS 1.3 primitives for the REALITY transport. Wraps std.crypto.tls
//! with REALITY-specific bits: record layer ready to feed AEAD from a
//! TLS 1.3 key schedule, full schedule (early/handshake/master
//! secrets + traffic keys), and — in later slices — ClientHello
//! parse, ForgedServerHello synth, and Xray v25.x session_id binding.

pub const record = @import("record.zig");
pub const keys = @import("keys.zig");
pub const client_hello = @import("client_hello.zig");
pub const server_hello = @import("server_hello.zig");
pub const xray_wire = @import("xray_wire.zig");
pub const reality_transport = @import("reality_transport.zig");
pub const stream = @import("stream.zig");

test {
    _ = record;
    _ = keys;
    _ = client_hello;
    _ = server_hello;
    _ = xray_wire;
    _ = reality_transport;
    _ = stream;
    _ = @import("xray_v25_vectors.zig");
}
