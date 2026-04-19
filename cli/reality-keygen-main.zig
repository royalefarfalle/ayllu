const std = @import("std");
const ayllu_camouflage = @import("ayllu-camouflage");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);

    var short_id_bytes: u8 = ayllu_camouflage.reality.max_short_id_length;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--short-id-bytes")) {
            i += 1;
            if (i >= args.len) return error.MissingShortIdBytesValue;
            short_id_bytes = std.fmt.parseInt(u8, args[i], 10) catch return error.BadShortIdBytesValue;
            if (short_id_bytes == 0 or short_id_bytes > ayllu_camouflage.reality.max_short_id_length) {
                return error.BadShortIdBytesValue;
            }
        } else if (std.mem.eql(u8, args[i], "--help") or std.mem.eql(u8, args[i], "-h")) {
            try printUsage(io);
            return;
        } else {
            try printUsage(io);
            return error.UnknownArg;
        }
    }

    const kp = ayllu_camouflage.reality.generateKeyPair(io);
    var private_key_buf: [ayllu_camouflage.reality.encoded_key_length]u8 = undefined;
    var public_key_buf: [ayllu_camouflage.reality.encoded_key_length]u8 = undefined;
    const private_key = try ayllu_camouflage.reality.encodeKey(&private_key_buf, kp.secret_key);
    const public_key = try ayllu_camouflage.reality.encodeKey(&public_key_buf, kp.public_key);

    var short_id: ayllu_camouflage.reality.ShortId = .{ .len = short_id_bytes };
    io.random(short_id.bytes[0..short_id_bytes]);
    var short_id_buf: [ayllu_camouflage.reality.max_short_id_length * 2]u8 = undefined;
    const short_id_text = try ayllu_camouflage.reality.formatShortId(&short_id_buf, short_id);

    var stdout_buffer: [512]u8 = undefined;
    var stdout_writer: std.Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    try stdout_writer.interface.print(
        "Private key: {s}\nPublic key:  {s}\nShort id:    {s}\n",
        .{ private_key, public_key, short_id_text },
    );
    try stdout_writer.interface.flush();
}

fn printUsage(io: std.Io) !void {
    var buf: [512]u8 = undefined;
    var w: std.Io.File.Writer = .init(.stdout(), io, &buf);
    try w.interface.writeAll(
        \\ayllu-reality-keygen — generate base64url X25519 keys and a short id
        \\
        \\Usage: ayllu-reality-keygen [--short-id-bytes N]
        \\
        \\Options:
        \\  --short-id-bytes N  short id size in bytes, 1..8 (default 8)
        \\  --help              show this help
        \\
    );
    try w.interface.flush();
}
