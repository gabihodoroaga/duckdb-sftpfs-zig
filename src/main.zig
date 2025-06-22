const std = @import("std");
const Allocator = std.mem.Allocator;
const Stream = std.net.Stream;
const lists = @import("lists.zig");

const c = @cImport({
    @cInclude("libssh2.h");
    @cInclude("libssh2_sftp.h");
    @cInclude("bridge.h");
});

const main_allocator: Allocator = std.heap.c_allocator;
const EmptyStr: []u8 = &.{};

const SftpParams = struct {
    user: []const u8 = EmptyStr,
    pass: []const u8 = EmptyStr,

    identity_file: []const u8 = EmptyStr,
    private_key: []const u8 = EmptyStr,
    private_key_password: []const u8 = EmptyStr,

    host: []const u8 = EmptyStr,
    port: u16 = 22,

    path: []const u8 = EmptyStr,
};

const SftpFileHandle = struct {
    arena: std.heap.ArenaAllocator,
    url: []u8,
    params: ?SftpParams,
    stream: ?Stream,
    session: ?*c.LIBSSH2_SESSION,
    sftp_session: ?*c.LIBSSH2_SFTP,
    sftp_handle: ?*c.LIBSSH2_SFTP_HANDLE,
    offset: u64,
    size: u64,
    mtime: u32,

    pub fn deinit(self: *SftpFileHandle) void {

        // close all resources used by this sftp handle
        if (self.sftp_handle) |sftp_handle| {
            _ = c.libssh2_sftp_close_handle(sftp_handle);
        }

        if (self.sftp_session) |sftp_session| {
            _ = c.libssh2_sftp_shutdown(sftp_session);
        }

        if (self.session) |session| {
            _ = c.libssh2_session_free(session);
        }

        if (self.stream) |stream| {
            stream.close();
        }

        var arena = self.arena;
        arena.deinit();
    }

    pub fn updateSettings(self: *SftpFileHandle, settings: *c.duckdb_settings) !void {
        if (self.params) |*params| {
            if (params.user.len == 0) {
                params.user = try self.arena.allocator().dupe(u8, std.mem.span(settings.sftp_username));
            }
            if (params.pass.len == 0) {
                params.pass = try self.arena.allocator().dupe(u8, std.mem.span(settings.sftp_password));
            }
            params.identity_file = try self.arena.allocator().dupe(u8, std.mem.span(settings.sftp_identity_file));
            params.private_key = try self.arena.allocator().dupe(u8, std.mem.span(settings.sftp_private_key));
            params.private_key_password = try self.arena.allocator().dupe(u8, std.mem.span(settings.sftp_private_key_password));
        } else unreachable;
    }
};

fn GetSftpHandle(allocator: Allocator) !*SftpFileHandle {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();

    const result = try arena.allocator().create(SftpFileHandle);
    result.* = SftpFileHandle{
        .arena = arena,
        .url = EmptyStr,
        .params = null,
        .stream = null,
        .session = null,
        .sftp_session = null,
        .sftp_handle = null,
        .offset = 0,
        .size = 0,
        .mtime = 0,
    };

    return result;
}

const CacheNode = lists.LinkedList(*FileCacheEntry).Node;

const FileCacheEntry = struct {
    key: []const u8,
    size: u64,
    fill_offset: u64,
    mtime: u32,
    data: ?[]u8,
    lru_node: ?*CacheNode,
};

const FileCache = struct {
    allocator: Allocator,
    cache: std.StringHashMap(FileCacheEntry),
    total_size: u64,
    max_size: u64,
    lru_list: lists.LinkedList(*FileCacheEntry),

    const Self = @This();

    pub fn init(allocator: Allocator) FileCache {
        return FileCache{
            .allocator = allocator,
            .cache = std.StringHashMap(FileCacheEntry).init(allocator),
            .total_size = 0,
            .max_size = 1024 * 1024 * 1024, // 1GB
            .lru_list = lists.LinkedList(*FileCacheEntry).init(),
        };
    }

    pub fn get(self: *Self, key: []const u8) ?*FileCacheEntry {
        if (self.cache.getPtr(key)) |v| {
            if (v.lru_node) |n| {
                self.lru_list.promote(n);
            }
            self.stats();
            return v;
        }
        return null;
    }

    pub fn put(self: *Self, key: []const u8, size: u64, mtime: u32) !*FileCacheEntry {
        const fc_key = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(fc_key);
        const data = try self.allocator.alloc(u8, size);
        errdefer self.allocator.free(data);

        try self.cache.put(fc_key, FileCacheEntry{ .key = fc_key, .size = size, .fill_offset = 0, .mtime = mtime, .data = data, .lru_node = null });
        if (self.cache.getPtr(key)) |v| {

            // first, check if the file can fit into the cache max size and release if necessary
            while (self.total_size + size > self.max_size) {
                const lru_node = self.lru_list.del();
                if (lru_node) |n| {
                    self.total_size -= n.value.size;

                    const lru_key = n.value.key;
                    const lru_data = n.value.data;

                    _ = self.cache.remove(lru_key);
                    if (lru_data) |d| {
                        self.allocator.free(d);
                    }
                    self.allocator.free(lru_key);
                    self.allocator.destroy(n);
                } else {
                    unreachable;
                }
            }

            const node = try self.allocator.create(CacheNode);
            node.* = .{ .value = v };
            self.lru_list.add(node);
            v.lru_node = node;

            self.total_size += size;
            self.stats();
            return v;
        } else unreachable;
    }

    pub fn remove(self: *Self, key: []const u8) void {
        if (self.cache.get(key)) |v| {
            self.allocator.free(v.data);
            self.allocator.free(v.key);
            self.cache.remove(key);
        }
    }

    pub fn stats(self: *Self) void {
        std.log.debug("cache stats: items: {}, size: {}, max: {}", .{ self.lru_list.size, self.total_size, self.max_size });
    }
};

var cache: FileCache = FileCache.init(main_allocator);

/// Initialize all the extension dependencies: libssh2
export fn sftpfs_init_ext(err_msg: *[*:0]const u8) bool {
    std.log.debug("Initializing sftpfs extension", .{});

    // Initialize libssh2
    if (c.libssh2_init(0) != 0) {
        std.log.debug("failed to initialize libssh2", .{});
        err_msg.* = "failed to initialize libssh2";
        return false;
    }

    return true;
}

/// Creates an sftp file handle.
/// This function parse the path, validates the params, connects to the server,
/// create the ssh session and the sftp session and the sftp file handle.
export fn file_handle_create(path: [*:0]const u8, settings: *anyopaque, err_msg: *[*:0]const u8) usize {
    std.log.debug("open file {s}", .{path});

    const sftp_handle = GetSftpHandle(main_allocator) catch |err| {
        std.log.err("failed to alloc sftp handle for path {s}: {any}", .{ path, err });
        err_msg.* = @errorName(err);
        return 0;
    };

    const sfh = @intFromPtr(sftp_handle);
    std.log.debug("[{}] file handle for file {s}", .{ sfh, path });
    var has_error = false;
    defer {
        // this is hack because I cannot use errdefer for c functions
        if (has_error) {
            sftp_handle.deinit();
            std.log.debug("[{}] file handle close", .{sfh});
        }
    }

    // the path is received from c++ and the lifetime is unknown it is safer to copy it
    const url: []const u8 = std.mem.span(path);
    sftp_handle.url = sftp_handle.arena.allocator().dupe(u8, url) catch |err| {
        std.log.debug("[{}] failed to set url: {any}", .{ sfh, err });
        err_msg.* = @errorName(err);
        return 0;
    };

    sftp_handle.params = parseSftpUrl(sftp_handle.url) catch |err| {
        std.log.debug("[{}] failed to parse sftp url: {any}", .{ sfh, err });
        err_msg.* = @errorName(err);
        return 0;
    };

    //std.log.debug("user name is {s}", .{std.mem.span(username)});
    const db_settings: *c.duckdb_settings = @ptrCast(@alignCast(settings));
    sftp_handle.updateSettings(db_settings) catch |err| {
        std.log.debug("[{}] failed to read duckdb setting: {any}", .{ sfh, err });
        err_msg.* = @errorName(err);
        return 0;
    };

    sftp_handle.stream = openTcpConnection(sftp_handle.arena.allocator(), sftp_handle.params.?) catch |err| {
        std.log.debug("[{}] failed to connect: {any}", .{ sfh, err });
        err_msg.* = @errorName(err);
        has_error = true;
        return 0;
    };

    sftp_handle.session = c.libssh2_session_init_ex(null, null, null, null);
    if (sftp_handle.session == null) {
        std.log.debug("[{}] failed to initialize SSH session", .{sfh});
        err_msg.* = "Failed to initialize SSH session";
        has_error = true;
    }

    _ = c.libssh2_trace(sftp_handle.session, c.LIBSSH2_TRACE_SFTP);

    // set the session to be blocking in order to read data from it
    c.libssh2_session_set_blocking(sftp_handle.session, 1);

    var libssh_err_code: c_int = 0;
    var libssh_err_msg: [*c]u8 = null;
    var libssh_err_len: c_int = 0;

    libssh_err_code = c.libssh2_session_handshake(sftp_handle.session, @intCast(sftp_handle.stream.?.handle));

    if (libssh_err_code != 0) {
        _ = c.libssh2_session_last_error(sftp_handle.session, &libssh_err_msg, &libssh_err_len, 0);
        std.log.debug("[{}] ssh handshake failed: ({}) {s}", .{ sfh, libssh_err_code, libssh_err_msg });
        err_msg.* = libssh_err_msg;
        has_error = true;
        return 0;
    }

    if (sftp_handle.params.?.private_key.len > 0) {
        std.log.debug("[{}] session auth (private key)", .{sfh});
        libssh_err_code = c.libssh2_userauth_publickey_frommemory(sftp_handle.session, //
            sftp_handle.params.?.user.ptr, @intCast(sftp_handle.params.?.user.len), null, 0, //
            sftp_handle.params.?.private_key.ptr, @intCast(sftp_handle.params.?.private_key.len), //
            if (sftp_handle.params.?.private_key_password.len == 0) null else sftp_handle.params.?.private_key_password.ptr);

        if (libssh_err_code != 0) {
            _ = c.libssh2_session_last_error(sftp_handle.session, &libssh_err_msg, &libssh_err_len, 0);
            std.log.debug("[{}] ssh session auth (private key) failed: ({}) {s}", .{ sfh, libssh_err_code, libssh_err_msg });
            err_msg.* = libssh_err_msg;
            has_error = true;
            return 0;
        }
    } else if (sftp_handle.params.?.identity_file.len > 0) {
        std.log.debug("[{}] session auth (identity file), {s}", .{ sfh, sftp_handle.params.?.identity_file });
        libssh_err_code = c.libssh2_userauth_publickey_fromfile_ex(sftp_handle.session, //
            sftp_handle.params.?.user.ptr, @intCast(sftp_handle.params.?.user.len), //
            null, sftp_handle.params.?.identity_file.ptr, //
            if (sftp_handle.params.?.private_key_password.len == 0) null else sftp_handle.params.?.private_key_password.ptr);

        if (libssh_err_code != 0) {
            _ = c.libssh2_session_last_error(sftp_handle.session, &libssh_err_msg, &libssh_err_len, 0);
            std.log.debug("[{}] ssh session auth (identity file) failed: ({}) {s}", .{ sfh, libssh_err_code, libssh_err_msg });
            err_msg.* = libssh_err_msg;
            has_error = true;
            return 0;
        }
    } else {
        std.log.debug("[{}] session auth (username/password)", .{sfh});
        libssh_err_code = c.libssh2_userauth_password_ex(sftp_handle.session, sftp_handle.params.?.user.ptr, //
            @intCast(sftp_handle.params.?.user.len), sftp_handle.params.?.pass.ptr, @intCast(sftp_handle.params.?.pass.len), null);

        if (libssh_err_code != 0) {
            _ = c.libssh2_session_last_error(sftp_handle.session, &libssh_err_msg, &libssh_err_len, 0);
            std.log.debug("[{}] ssh session auth (password) failed: ({}) {s}", .{ sfh, libssh_err_code, libssh_err_msg });
            err_msg.* = libssh_err_msg;
            has_error = true;
            return 0;
        }
    }

    sftp_handle.sftp_session = c.libssh2_sftp_init(sftp_handle.session) orelse {
        _ = c.libssh2_session_last_error(sftp_handle.session, &libssh_err_msg, &libssh_err_len, 0);
        std.log.debug("[{}] sftp init failed: ({}) {s}", .{ sfh, libssh_err_code, libssh_err_msg });
        err_msg.* = libssh_err_msg;
        has_error = true;
        return 0;
    };

    sftp_handle.sftp_handle = c.libssh2_sftp_open_ex(sftp_handle.sftp_session, sftp_handle.params.?.path.ptr, //
        @intCast(sftp_handle.params.?.path.len), c.LIBSSH2_FXF_READ, 0, c.LIBSSH2_SFTP_OPENFILE) orelse {
        _ = c.libssh2_session_last_error(sftp_handle.session, &libssh_err_msg, &libssh_err_len, 0);
        std.log.debug("[{}] sftp open failed: ({}) {s}", .{ sfh, libssh_err_code, libssh_err_msg });
        err_msg.* = libssh_err_msg;
        has_error = true;
        return 0;
    };

    std.log.debug("[{}] file handle initialized", .{sfh});
    return sfh;
}

export fn file_handle_close(handle: usize) void {
    std.log.debug("[{}] file handle close", .{handle});
    const sfh = @as(*SftpFileHandle, @ptrFromInt(handle));
    sfh.deinit();
}

export fn file_handle_seek(handle: usize, location: c_ulonglong) void {
    std.log.debug("[{}] file handle seek location {}", .{ handle, location });
    const sfh: *SftpFileHandle = @ptrFromInt(handle);
    c.libssh2_sftp_seek64(sfh.sftp_handle, location);
    sfh.offset = @intCast(location);
}

export fn file_handle_seek_position(handle: usize) c_ulonglong {
    std.log.debug("[{}] file handle seek position", .{handle});
    const sfh: *SftpFileHandle = @ptrFromInt(handle);
    return @intCast(sfh.offset);
}

export fn file_handle_get_file_size(handle: usize, file_size: *c_longlong, err_msg: *[*:0]const u8) bool {
    std.log.debug("[{}] file handle get file size", .{handle});
    const sfh: *SftpFileHandle = @ptrFromInt(handle);

    if (sfh.size > 0 and sfh.mtime > 0) {
        file_size.* = @intCast(sfh.size);
        return true;
    }

    var attrs: c.LIBSSH2_SFTP_ATTRIBUTES = undefined;
    const fstat_err_code = c.libssh2_sftp_fstat_ex(sfh.sftp_handle, &attrs, 0);
    if (fstat_err_code != 0) {
        var libssh_err_code: c_int = 0;
        var libssh_err_msg: [*c]u8 = null;
        var libssh_err_len: c_int = 0;
        libssh_err_code = c.libssh2_session_last_error(sfh.session, &libssh_err_msg, &libssh_err_len, 0);
        std.log.debug("[{}] sftp fstat failed: ({}) {s}\n", .{ sfh, libssh_err_code, libssh_err_msg });
        err_msg.* = libssh_err_msg;
        return false;
    }
    sfh.size = @intCast(attrs.filesize);
    sfh.mtime = @intCast(attrs.mtime);
    file_size.* = @intCast(sfh.size);
    return true;
}

export fn file_handle_get_last_modified(handle: usize, last_modified: *c_long, err_msg: *[*:0]const u8) bool {
    std.log.debug("[{}] file handle get last modified", .{handle});
    const sfh: *SftpFileHandle = @ptrFromInt(handle);

    if (sfh.size > 0 and sfh.mtime > 0) {
        last_modified.* = @intCast(sfh.mtime);
        return true;
    }

    var attrs: c.LIBSSH2_SFTP_ATTRIBUTES = undefined;
    const fstat_err_code = c.libssh2_sftp_fstat_ex(sfh.sftp_handle, &attrs, 0);
    if (fstat_err_code != 0) {
        var libssh_err_code: c_int = 0;
        var libssh_err_msg: [*c]u8 = null;
        var libssh_err_len: c_int = 0;
        libssh_err_code = c.libssh2_session_last_error(sfh.session, &libssh_err_msg, &libssh_err_len, 0);
        std.log.debug("[{}] sftp fstat failed: ({}) {s}\n", .{ sfh, libssh_err_code, libssh_err_msg });
        err_msg.* = libssh_err_msg;
        return false;
    }
    sfh.size = @intCast(attrs.filesize);
    sfh.mtime = @intCast(attrs.mtime);
    last_modified.* = @intCast(sfh.mtime);
    return true;
}

export fn file_handle_read_location(handle: usize, buffer: [*c]u8, nr_bytes: c_longlong, location: c_ulonglong, n_read: *c_longlong, err_msg: *[*:0]const u8) bool {
    std.log.debug("[{}] read location: nr_bytes = {}, location = {}", .{ handle, nr_bytes, location });
    const sfh: *SftpFileHandle = @ptrFromInt(handle);

    file_handle_seek(handle, location);

    var buffer_available: u64 = @intCast(nr_bytes);
    var buffer_offset: u64 = 0;

    while (buffer_available > 0) {
        // copy file content to the cache
        const read = c.libssh2_sftp_read(sfh.sftp_handle, buffer + buffer_offset, buffer_available);
        if (read < 0) {
            var libssh_err_code: c_int = 0;
            var libssh_err_msg: [*c]u8 = null;
            var libssh_err_len: c_int = 0;
            libssh_err_code = c.libssh2_session_last_error(sfh.session, &libssh_err_msg, &libssh_err_len, 0);
            std.log.debug("[{}] sftp read failed: ({}) {s}\n", .{ handle, libssh_err_code, libssh_err_msg });
            err_msg.* = libssh_err_msg;
            return false;
        }
        if (read == 0) {
            break;
        }
        const copy_bytes: u64 = @intCast(read);
        buffer_available -= copy_bytes;
        buffer_offset += copy_bytes;
    }

    file_handle_seek(handle, location);
    n_read.* = @intCast(buffer_offset);
    std.log.debug("[{}] read location n_read {}", .{ handle, buffer_offset });
    return true;
}

export fn file_handle_read(handle: usize, buffer: [*c]u8, nr_bytes: c_longlong, n_read: *c_longlong, err_msg: *[*:0]const u8) bool {
    std.log.debug("[{}] read: nr_bytes = {}", .{ handle, nr_bytes });
    const sfh: *SftpFileHandle = @ptrFromInt(handle);

    if (sfh.size - sfh.offset <= 0) {
        n_read.* = 0;
        std.log.debug("[{}] read bytes 0", .{handle});
        return true;
    }

    const file_cache = if (cache.get(sfh.url)) |v| blk: {
        std.log.debug("[{}] file found in cache {s}, size={},mtime={}", .{ handle, sfh.url, v.size, v.mtime });
        break :blk v;
    } else blk: {
        std.log.debug("[{}] file not found in cache {s}", .{ handle, sfh.url });
        break :blk cache.put(sfh.url, sfh.size, sfh.mtime) catch |err| {
            std.log.debug("[{}] failed to put in cache: {any}\n", .{ handle, err });
            err_msg.* = @errorName(err);
            return false;
        };
    };

    var buffer_available: u64 = @intCast(nr_bytes);
    var buffer_offset: u64 = 0;

    if (file_cache.fill_offset < file_cache.size) {
        std.log.debug("[{}] read file from remote; buffer_available={},buffer_offset={},sfh.offset={},sfh.size={}", .{ handle, buffer_available, buffer_offset, sfh.offset, sfh.size });

        while (buffer_available > 0) {
            // copy file content to the cache
            const read = c.libssh2_sftp_read(sfh.sftp_handle, file_cache.data.?.ptr + file_cache.fill_offset, buffer_available);
            if (read < 0) {
                var libssh_err_code: c_int = 0;
                var libssh_err_msg: [*c]u8 = null;
                var libssh_err_len: c_int = 0;
                libssh_err_code = c.libssh2_session_last_error(sfh.session, &libssh_err_msg, &libssh_err_len, 0);
                std.log.debug("[{}] sftp read failed: ({}) {s}\n", .{ handle, libssh_err_code, libssh_err_msg });
                err_msg.* = libssh_err_msg;
                return false;
            }
            if (read == 0) {
                break;
            }
            const copy_bytes: u64 = @intCast(read);
            file_cache.fill_offset += copy_bytes;

            // copy from cache to the output buffer
            for (buffer[buffer_offset..(buffer_offset + copy_bytes)], file_cache.data.?[sfh.offset..(sfh.offset + copy_bytes)]) |*d, s| d.* = s;

            // update all the counters
            sfh.offset += copy_bytes;
            buffer_available -= copy_bytes;
            buffer_offset += copy_bytes;
        }
    } else {
        std.log.debug("[{}] read file from cache; buffer_available={},buffer_offset={},sfh.offset={},sfh.size={}", .{ handle, buffer_available, buffer_offset, sfh.offset, sfh.size });
        const copy_bytes = @min(sfh.size - sfh.offset, buffer_available);
        for (buffer[buffer_offset..(buffer_offset + copy_bytes)], file_cache.data.?[sfh.offset..(sfh.offset + copy_bytes)]) |*d, s| d.* = s;
        sfh.offset += copy_bytes;
        buffer_available -= copy_bytes; // this might not be require
        buffer_offset += copy_bytes;
    }

    n_read.* = @intCast(buffer_offset);
    std.log.debug("[{}] read: n_read {}", .{ handle, buffer_offset });
    return true;
}

// Private function section

/// Parse and validate the sftp url
fn parseSftpUrl(url: []const u8) !SftpParams {
    var parsed_params = SftpParams{};

    const uri = try std.Uri.parse(url);
    if (!std.mem.eql(u8, uri.scheme, "sftp"))
        return error.OnlySftpSchemeAllowed;

    if (uri.user) |user|
        parsed_params.user = switch (user) {
            .percent_encoded, .raw => |v| v,
        };
    if (uri.password) |password|
        parsed_params.pass = switch (password) {
            .percent_encoded, .raw => |v| v,
        };

    if (uri.host) |host|
        parsed_params.host = switch (host) {
            .percent_encoded, .raw => |v| v,
        };

    if (uri.port) |port|
        parsed_params.port = port;

    parsed_params.path = switch (uri.path) {
        .percent_encoded, .raw => |v| v,
    };

    if (parsed_params.host.len == 0 or parsed_params.path.len == 0) {
        return error.SftpUriNotValid;
    }

    return parsed_params;
}

test "SFTP parse url" {
    const TestCase = struct {
        desc: []const u8,
        url: []const u8,
        expected: SftpParams,
    };

    const test_cases = [_]TestCase{
        .{
            .desc = "all",
            .url = "sftp://testuser:testpass@localhost:2222/config/data/data.csv", //
            .expected = SftpParams{ .user = "testuser", .pass = "testpass", .host = "localhost", .port = 2222, .path = "/config/data/data.csv" },
        },
        .{
            .desc = "all except, pass",
            .url = "sftp://testuser@localhost:2222/config/data/data.csv", //
            .expected = SftpParams{ .user = "testuser", .pass = EmptyStr, .host = "localhost", .port = 2222, .path = "/config/data/data.csv" },
        },
        .{
            .desc = "all except, user, pass, port",
            .url = "sftp://localhost:2222/config/data/data.csv", //
            .expected = SftpParams{ .user = EmptyStr, .pass = EmptyStr, .host = "localhost", .port = 2222, .path = "/config/data/data.csv" },
        },
        .{
            .desc = "all, except port",
            .url = "sftp://testuser:testpass@localhost/config/data/data.csv", //
            .expected = SftpParams{ .user = "testuser", .pass = "testpass", .host = "localhost", .port = 22, .path = "/config/data/data.csv" },
        },
        .{
            .desc = "all except, user and pass",
            .url = "sftp://localhost:2222/config/data/data.csv", //
            .expected = SftpParams{ .user = EmptyStr, .pass = EmptyStr, .host = "localhost", .port = 2222, .path = "/config/data/data.csv" },
        },
    };

    for (test_cases) |test_case| {
        const parsed = try parseSftpUrl(test_case.url);
        std.testing.expectEqualDeep(test_case.expected, parsed) catch |err| {
            std.log.debug("Test case: {s}, parsed.pass={s}\n", .{ test_case.desc, parsed.pass });
            std.log.debug("url is '{s}', parsed.pass={s}\n", .{ test_case.url, parsed.pass });
            return err;
        };
    }
}

fn openTcpConnection(allocator: Allocator, sftp: SftpParams) !Stream {
    const addresses = try std.net.getAddressList(allocator, sftp.host, sftp.port);
    defer addresses.deinit();

    var conn_err: anyerror = undefined;
    const valid_stream: ?std.net.Stream = for (addresses.addrs) |addr| {
        const stream = std.net.tcpConnectToAddress(addr) catch |err| {
            conn_err = err;
            continue;
        };
        break stream;
    } else null;
    if (valid_stream) |stream| {
        return stream;
    }
    return conn_err;
}
