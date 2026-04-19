//! ayllu — протокол устойчивой связи. Публичный модуль ядра.

pub const crypto = @import("crypto.zig");
pub const identity = @import("identity.zig");
pub const envelope = @import("envelope.zig");
pub const transport = @import("transport.zig");

pub const phase: u8 = 1;

test {
    _ = crypto;
    _ = identity;
    _ = envelope;
    _ = transport;
}
