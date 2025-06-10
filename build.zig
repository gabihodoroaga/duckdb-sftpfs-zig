const std = @import("std");
const duckdb = @import("build.duckdb.zig");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const name = "sftpfs";
    const lib = b.addSharedLibrary(.{
        .name = name,
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // duckdb headers
    lib.addIncludePath(b.path("duckdb/src/include"));

    // our c bridge
    lib.addIncludePath(b.path("src/include"));
    // our c++ bridge
    lib.addCSourceFile(.{ .file = b.path("src/bridge.cpp") });

    lib.linkSystemLibrary("libssh2");
    lib.linkLibC();
    lib.linkSystemLibrary("c++");

    lib.linkSystemLibrary("duckdb");
    lib.addLibraryPath(b.path("duckdb/build/release/src"));

    // create the extenstion metadata
    b.getInstallStep().dependOn(&duckdb.appendMetadata(
        b,
        b.addInstallArtifact(
            lib,
            .{
                .dest_sub_path = name ++ ".duckdb_extension",
            },
        ),
        .{ .platform = "osx_amd64" }, // osx_arm64
    ).step);

    // Creates a step for unit testing. This only builds the test executable
    // but does not run it.
    const main_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // duckdb headers
    main_tests.addIncludePath(b.path("duckdb/src/include"));

    // our c bridge
    main_tests.addIncludePath(b.path("src/include"));

    // our c++ bridge
    main_tests.addCSourceFile(.{ .file = b.path("src/bridge.cpp") });

    main_tests.linkSystemLibrary("libssh2");
    main_tests.linkLibC();
    main_tests.linkSystemLibrary("c++");

    main_tests.linkSystemLibrary("duckdb");
    main_tests.addLibraryPath(b.path("lib"));

    const run_main_tests = b.addRunArtifact(main_tests);

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build test`
    // This will evaluate the `test` step rather than the default, which is "install".
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);
}
