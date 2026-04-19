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

    const camouflage_mod = b.addModule("ayllu-camouflage", .{
        .root_source_file = b.path("camouflage/root.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "ayllu", .module = ayllu_mod },
            .{ .name = "ayllu-proxy", .module = proxy_mod },
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

    const camouflage_proxy_exe = b.addExecutable(.{
        .name = "ayllu-camouflage-proxy",
        .root_module = b.createModule(.{
            .root_source_file = b.path("cli/camouflage-proxy-main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ayllu-camouflage", .module = camouflage_mod },
                .{ .name = "ayllu-proxy", .module = proxy_mod },
                .{ .name = "ayllu", .module = ayllu_mod },
            },
        }),
    });
    b.installArtifact(camouflage_proxy_exe);

    const reality_keygen_exe = b.addExecutable(.{
        .name = "ayllu-reality-keygen",
        .root_module = b.createModule(.{
            .root_source_file = b.path("cli/reality-keygen-main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ayllu-camouflage", .module = camouflage_mod },
                .{ .name = "ayllu", .module = ayllu_mod },
            },
        }),
    });
    b.installArtifact(reality_keygen_exe);

    const camouflage_client_exe = b.addExecutable(.{
        .name = "ayllu-camouflage-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("cli/camouflage-client-main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ayllu-camouflage", .module = camouflage_mod },
                .{ .name = "ayllu", .module = ayllu_mod },
            },
        }),
    });
    b.installArtifact(camouflage_client_exe);

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

    const run_camouflage_proxy = b.addRunArtifact(camouflage_proxy_exe);
    run_camouflage_proxy.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_camouflage_proxy.addArgs(args);

    const run_camouflage_proxy_step = b.step("run-camouflage-proxy", "Run the ayllu camouflage proxy daemon");
    run_camouflage_proxy_step.dependOn(&run_camouflage_proxy.step);

    const run_camouflage_client = b.addRunArtifact(camouflage_client_exe);
    run_camouflage_client.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_camouflage_client.addArgs(args);

    const run_camouflage_client_step = b.step("run-camouflage-client", "Run the ayllu camouflage local client bridge");
    run_camouflage_client_step.dependOn(&run_camouflage_client.step);

    const mod_tests = b.addTest(.{ .root_module = ayllu_mod });
    const run_mod_tests = b.addRunArtifact(mod_tests);

    const proxy_tests = b.addTest(.{ .root_module = proxy_mod });
    const run_proxy_tests = b.addRunArtifact(proxy_tests);

    const camouflage_tests = b.addTest(.{ .root_module = camouflage_mod });
    const run_camouflage_tests = b.addRunArtifact(camouflage_tests);

    const exe_tests = b.addTest(.{ .root_module = exe.root_module });
    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_proxy_tests.step);
    test_step.dependOn(&run_camouflage_tests.step);
    test_step.dependOn(&run_exe_tests.step);
}
