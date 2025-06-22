// Copyright (c) 2024 Doug Tangren

// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:

// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

const std = @import("std");

/// Appends DuckDb extension metadata to library artifact
pub fn appendMetadata(
    owner: *std.Build,
    installArtifact: *std.Build.Step.InstallArtifact,
    options: AppendMetadata.Options,
) *AppendMetadata {
    var append = AppendMetadata.create(
        owner,
        installArtifact,
        options,
    );
    append.step.dependOn(&installArtifact.step);
    return append;
}

pub const AppendMetadata = struct {
    step: std.Build.Step,
    installArtifact: *std.Build.Step.InstallArtifact,
    options: Options,

    pub const Options = struct {
        duckDbVersion: []const u8 = "v1.3.1",
        platform: []const u8,
        extVersion: ?[]const u8 = null,
    };

    pub fn create(owner: *std.Build, installArtifact: *std.Build.Step.InstallArtifact, options: Options) *AppendMetadata {
        const self = owner.allocator.create(AppendMetadata) catch @panic("OOM");
        self.* = .{
            .options = options,
            .installArtifact = installArtifact,
            .step = std.Build.Step.init(.{
                .id = .custom,
                .name = "append-metadata",
                .owner = owner,
                .makeFn = make,
            }),
        };
        return self;
    }

    fn make(step: *std.Build.Step, _: std.Build.Step.MakeOptions) !void {
        const self: *AppendMetadata = @fieldParentPtr("step", step);
        const path = self.installArtifact.artifact.installed_path.?;
        var payload = std.mem.zeroes([512]u8);
        const segments = [_][]const u8{
            "",                                                        "",                         "",                    "",
            self.options.extVersion orelse self.options.duckDbVersion, self.options.duckDbVersion, self.options.platform, "4",
        };
        for (segments, 0..) |segment, i| {
            const start = 32 * i;
            const end = start + segments[i].len;
            @memcpy(payload[start..end], segment);
        }
        var file = try std.fs.cwd().openFile(path, .{ .mode = .read_write });
        try file.seekTo(try file.getEndPos());
        try file.writer().writeAll(&payload);
    }
};
