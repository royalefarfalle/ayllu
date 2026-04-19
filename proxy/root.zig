//! ayllu-proxy — proxy transport layer.
//!
//! Phase-3 ships SOCKS5 (RFC 1928): no-auth + CONNECT, covering
//! Telegram/WhatsApp/YouTube-in-browser. Phase-5 adds MTProto, phase-7
//! WireGuard-over-Ayllu, phase-10 Shadowsocks. Phase-4 Reality adds
//! DPI camouflage on top of any of them.

pub const socks5 = @import("socks5.zig");
pub const relay = @import("relay.zig");
pub const auth = @import("auth.zig");
pub const timeouts = @import("timeouts.zig");
pub const daemon = @import("daemon.zig");

test {
    _ = socks5;
    _ = relay;
    _ = auth;
    _ = timeouts;
    _ = daemon;
}

test "proxy public surface exposes socks5.decodeGreeting + decodeRequest" {
    const std = @import("std");
    const g = try socks5.decodeGreeting(&[_]u8{ 0x05, 0x01, 0x00 });
    try std.testing.expect(g.offersNoAuth());
    const r = try socks5.decodeRequest(&[_]u8{ 0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 80 });
    try std.testing.expectEqual(socks5.Command.connect, r.command);
}
