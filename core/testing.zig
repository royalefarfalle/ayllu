//! Shared test helpers for ayllu core modules. Not re-exported from root —
//! this file is only referenced by sibling `test` blocks.

const std = @import("std");

pub fn hex32(comptime s: *const [64]u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}
