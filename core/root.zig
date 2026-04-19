//! ayllu — протокол устойчивой связи.
//!
//! Публичный модуль ядра. Re-exports подсистем core/.
//! Именование следует спецификации (core/): crypto, Identity, Envelope,
//! transport, registry. Терминология: quipu = envelope, runa = identity,
//! tambo = узел, ayllu = сеть.

const std = @import("std");

pub const version = "0.0.1";
pub const phase: u8 = 1;

test {
    _ = @import("std");
}
