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
