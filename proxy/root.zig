//! ayllu-proxy — транспортный слой прокси.
//!
//! Phase-3 поставляет SOCKS5 (RFC 1928): no-auth + CONNECT, покрывает
//! Telegram/WhatsApp/YouTube-в-браузере. Phase-5 добавит MTProto, phase-7
//! WireGuard-over-Ayllu, phase-10 Shadowsocks. Phase-4 Reality даст
//! DPI-маскировку поверх любого из них.

pub const socks5 = @import("socks5.zig");

test {
    _ = socks5;
}

test "proxy public surface exposes socks5.decodeGreeting + decodeRequest" {
    const std = @import("std");
    const g = try socks5.decodeGreeting(&[_]u8{ 0x05, 0x01, 0x00 });
    try std.testing.expect(g.offersNoAuth());
    const r = try socks5.decodeRequest(&[_]u8{ 0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 80 });
    try std.testing.expectEqual(socks5.Command.connect, r.command);
}
