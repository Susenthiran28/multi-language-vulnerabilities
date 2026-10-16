// File:    vulnerable.zig
// Purpose: SAST fixture (Zig). Child process spawning, C interop, unvalidated
//          outbound HTTP.
// Author:  Vigilnz Security Engineering
// Date:    2026-10-16
// Expected rules: zig-process-child, zig-c-import, zig-http-client

const std = @import("std");

// CWE-676: unchecked C interop surface
const c = @cImport({
    @cInclude("stdlib.h");
});

// CWE-78: command injection
pub fn ping(allocator: std.mem.Allocator, host: []const u8) !void {
    const cmd = try std.fmt.allocPrint(allocator, "ping -c 1 {s}", .{host});
    defer allocator.free(cmd);

    var child = std.process.Child.init(&[_][]const u8{ "sh", "-c", cmd }, allocator);
    _ = try child.spawnAndWait();
}

// CWE-918: SSRF
pub fn proxy(allocator: std.mem.Allocator, url: []const u8) !void {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const uri = try std.Uri.parse(url);
    var req = try client.open(.GET, uri, .{ .server_header_buffer = &[_]u8{} });
    defer req.deinit();
    try req.send();
}
