const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const ayllu_mod = b.addModule("ayllu", .{
        .root_source_file = b.path("core/root.zig"),
        .target = target,
    });

    const proxy_mod = b.addModule("ayllu-proxy", .{
        .root_source_file = b.path("proxy/root.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "ayllu", .module = ayllu_mod },
        },
    });

    const exe = b.addExecutable(.{
        .name = "ayllu",
        .root_module = b.createModule(.{
            .root_source_file = b.path("cli/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ayllu", .module = ayllu_mod },
            },
        }),
    });
    b.installArtifact(exe);

    const proxy_exe = b.addExecutable(.{
        .name = "ayllu-proxy",
        .root_module = b.createModule(.{
            .root_source_file = b.path("cli/proxy-main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ayllu-proxy", .module = proxy_mod },
                .{ .name = "ayllu", .module = ayllu_mod },
            },
        }),
    });
    b.installArtifact(proxy_exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);

    const run_step = b.step("run", "Run the ayllu CLI");
    run_step.dependOn(&run_cmd.step);

    const run_proxy = b.addRunArtifact(proxy_exe);
    run_proxy.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_proxy.addArgs(args);

    const run_proxy_step = b.step("run-proxy", "Run the ayllu-proxy SOCKS5 daemon");
    run_proxy_step.dependOn(&run_proxy.step);

    const mod_tests = b.addTest(.{ .root_module = ayllu_mod });
    const run_mod_tests = b.addRunArtifact(mod_tests);

    const proxy_tests = b.addTest(.{ .root_module = proxy_mod });
    const run_proxy_tests = b.addRunArtifact(proxy_tests);

    const exe_tests = b.addTest(.{ .root_module = exe.root_module });
    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_proxy_tests.step);
    test_step.dependOn(&run_exe_tests.step);
}
