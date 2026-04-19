const std = @import("std");
const Io = std.Io;
const ayllu = @import("ayllu");

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    var stdout_buffer: [512]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const out = &stdout_file_writer.interface;

    try out.print("ayllu phase {d}\n", .{ayllu.phase});
    try out.flush();
}

test "cli links against ayllu module" {
    try std.testing.expect(ayllu.phase >= 1);
}

test "ayllu public surface exposes crypto.fingerprint" {
    const zero: [32]u8 = @splat(0);
    const fp = ayllu.crypto.fingerprint(zero, zero);
    try std.testing.expectEqual(@as(usize, 32), fp.len);
}

test "ayllu public surface exposes identity.Identity" {
    const id = try ayllu.identity.Identity.fromSeed(@splat(0));
    _ = id.fingerprint();
}

test "ayllu public surface exposes envelope.buildAndSign" {
    const id = try ayllu.identity.Identity.fromSeed(@splat(0));
    const env = try ayllu.envelope.buildAndSign(std.testing.io, id, .broadcast, 0, 1, "p");
    try env.verify(id.publicView());
}

test "ayllu public surface: end-to-end send + recv + verify via transport" {
    var t: ayllu.transport.InMemoryTransport = .{ .allocator = std.testing.allocator };
    defer t.deinit();
    const id = try ayllu.identity.Identity.fromSeed(@splat(0));
    const env = try ayllu.envelope.buildAndSign(std.testing.io, id, .broadcast, 0, 1, "end2end");
    try t.transport().send(&env);
    const got = (try t.transport().recv()).?;
    try got.verify(id.publicView());
}

test "ayllu public surface exposes registry.Group" {
    var g: ayllu.registry.Group = .{ .allocator = std.testing.allocator, .id = @splat(0) };
    defer g.deinit();
    try g.apply(.{ .add = .{ .member = @splat(0xAA), .event_id = @splat(0x01) } });
    try std.testing.expectEqual(@as(usize, 1), g.memberCount());
}
