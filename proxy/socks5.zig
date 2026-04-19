//! SOCKS5 protocol (RFC 1928). Pure parsers/encoders — не трогает сеть.
//! Phase-3 scope: no-auth greeting + CONNECT request, IPv4/IPv6/domain.
//! BIND и UDP ASSOCIATE не реализованы (не нужны для Telegram/HTTP).

const std = @import("std");

pub const version: u8 = 5;
