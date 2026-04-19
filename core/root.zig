//! ayllu — протокол устойчивой связи. Публичный модуль ядра.

pub const crypto = @import("crypto.zig");
pub const identity = @import("identity.zig");

pub const phase: u8 = 1;

test {
    _ = crypto;
    _ = identity;
}
