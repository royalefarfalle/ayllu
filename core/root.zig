//! ayllu — протокол устойчивой связи. Публичный модуль ядра.

pub const crypto = @import("crypto.zig");
pub const Identity = @import("identity.zig").Identity;
pub const PublicIdentity = @import("identity.zig").PublicIdentity;

pub const phase: u8 = 1;

test {
    _ = crypto;
    _ = @import("identity.zig");
}
