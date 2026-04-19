//! Private-proxy access control helpers.
//!
//! Phase-3 scope: one username/password credential loaded from a local file.

const std = @import("std");

pub const Config = union(enum) {
    none,
    username_password: Credentials,

    pub fn requiresUsernamePassword(self: Config) bool {
        return self == .username_password;
    }

    pub fn deinit(self: *Config, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .none => {},
            .username_password => |*creds| creds.deinit(allocator),
        }
        self.* = .none;
    }
};

pub const Credentials = struct {
    username: []const u8,
    password: []const u8,
    backing: ?[]u8 = null,

    pub fn matches(self: Credentials, username: []const u8, password: []const u8) bool {
        return secretEql(self.username, username) and secretEql(self.password, password);
    }

    pub fn deinit(self: *Credentials, allocator: std.mem.Allocator) void {
        if (self.backing) |backing| allocator.free(backing);
        self.* = .{
            .username = "",
            .password = "",
            .backing = null,
        };
    }
};

pub const LoadError = error{
    InvalidAuthFile,
    EmptyUsername,
    EmptyPassword,
    UsernameTooLong,
    PasswordTooLong,
} || std.Io.Dir.ReadFileAllocError;

pub fn loadFromFile(io: std.Io, allocator: std.mem.Allocator, path: []const u8) LoadError!Config {
    const raw = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(4096));
    errdefer allocator.free(raw);
    const trimmed = trimTrailingWhitespace(raw);
    const colon = std.mem.indexOfScalar(u8, trimmed, ':') orelse return error.InvalidAuthFile;
    const username = trimmed[0..colon];
    const password = trimmed[colon + 1 ..];

    if (username.len == 0) return error.EmptyUsername;
    if (password.len == 0) return error.EmptyPassword;
    if (username.len > 255) return error.UsernameTooLong;
    if (password.len > 255) return error.PasswordTooLong;

    return .{
        .username_password = .{
            .username = username,
            .password = password,
            .backing = raw,
        },
    };
}

fn secretEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, 0..) |byte, i| diff |= byte ^ b[i];
    return diff == 0;
}

fn trimTrailingWhitespace(bytes: []const u8) []const u8 {
    var end = bytes.len;
    while (end > 0) {
        switch (bytes[end - 1]) {
            ' ', '\t', '\r', '\n' => end -= 1,
            else => break,
        }
    }
    return bytes[0..end];
}

test "loadFromFile parses username:password line" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try authFixturePath(std.testing.allocator, tmp.sub_path[0..], "auth.txt");
    defer std.testing.allocator.free(path);
    try tmp.dir.writeFile(io, .{ .sub_path = "auth.txt", .data = "alice:secret\n" });
    var cfg = try loadFromFile(io, std.testing.allocator, path);
    defer cfg.deinit(std.testing.allocator);
    try std.testing.expect(cfg.requiresUsernamePassword());
    try std.testing.expectEqualStrings("alice", cfg.username_password.username);
    try std.testing.expectEqualStrings("secret", cfg.username_password.password);
}

test "loadFromFile rejects malformed and empty credentials" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const bad_path = try authFixturePath(std.testing.allocator, tmp.sub_path[0..], "bad.txt");
    defer std.testing.allocator.free(bad_path);
    try tmp.dir.writeFile(io, .{ .sub_path = "bad.txt", .data = "alice-only" });
    try std.testing.expectError(error.InvalidAuthFile, loadFromFile(io, std.testing.allocator, bad_path));

    const empty_user_path = try authFixturePath(std.testing.allocator, tmp.sub_path[0..], "empty-user.txt");
    defer std.testing.allocator.free(empty_user_path);
    try tmp.dir.writeFile(io, .{ .sub_path = "empty-user.txt", .data = ":secret" });
    try std.testing.expectError(error.EmptyUsername, loadFromFile(io, std.testing.allocator, empty_user_path));

    const empty_pass_path = try authFixturePath(std.testing.allocator, tmp.sub_path[0..], "empty-pass.txt");
    defer std.testing.allocator.free(empty_pass_path);
    try tmp.dir.writeFile(io, .{ .sub_path = "empty-pass.txt", .data = "alice:" });
    try std.testing.expectError(error.EmptyPassword, loadFromFile(io, std.testing.allocator, empty_pass_path));
}

test "credentials match exact username/password only" {
    const creds: Credentials = .{ .username = "alice", .password = "secret" };
    try std.testing.expect(creds.matches("alice", "secret"));
    try std.testing.expect(!creds.matches("alice", "SECRET"));
    try std.testing.expect(!creds.matches("bob", "secret"));
}

fn authFixturePath(allocator: std.mem.Allocator, tmp_sub_path: []const u8, file_name: []const u8) ![]u8 {
    return std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp_sub_path, file_name });
}
