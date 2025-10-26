const std = @import("std");
const builtin = @import("builtin");
const interop = @import("interop.zig");
const Doom = @import("animations/Doom.zig");
const TerminalBuffer = @import("tui/TerminalBuffer.zig");
const Text = @import("tui/components/Text.zig");

const fb = if (builtin.os.tag == .linux)
    @cImport({
        @cInclude("linux/fb.h");
    })
else
    struct {};

const termbox = interop.termbox;

const Colors = struct {
    pub const fg: u32 = 0x00FFFFFF;
    pub const bg: u32 = 0x00000000;
    pub const border: u32 = 0x00FFFFFF;
    pub const error: u32 = 0x01FF0000;
};

const Hint = struct {
    key: []const u8,
    description: []const u8,
};

const hints = [_]Hint{
    .{ .key = "F1", .description = "shutdown" },
    .{ .key = "F2", .description = "restart" },
    .{ .key = "F3", .description = "suspend" },
    .{ .key = "F5", .description = "brightness-" },
    .{ .key = "F6", .description = "brightness+" },
};

const SHUTDOWN_CMD = "/sbin/shutdown -a now";
const RESTART_CMD = "/sbin/shutdown -r now";
const SUSPEND_CMD: ?[]const u8 = "/bin/systemctl suspend";
const BRIGHTNESS_DOWN_CMD = "brightnessctl -q -n s 10%-";
const BRIGHTNESS_UP_CMD = "brightnessctl -q -n s +10%";

const default_message = "Enter password to unlock";
const unlocking_message = "Unlocking...";
const spawn_error_message = "Failed to run unlocker";
const unlock_failed_message = "Unlock failed";
const suspend_failed_message = "Suspend command failed";
const brightness_failed_message = "Brightness command failed";
const input_error_message = "Input error";
const empty_password_message = "Password required";

pub fn main() !void {
    var stderr_buffer: [128]u8 = undefined;
    var stderr_writer = std.fs.File.stderr().writer(&stderr_buffer);
    var stderr = &stderr_writer.interface;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const init_result = termbox.tb_init();
    if (init_result != 0) {
        try stderr.writeAll("failed to initialize termbox2\n");
        return error.TermboxInitFailed;
    }
    defer redrawSplashOnExit();
    defer {
        _ = termbox.tb_shutdown();
    }

    _ = termbox.tb_set_output_mode(termbox.TB_OUTPUT_TRUECOLOR);
    _ = termbox.tb_clear();
    try ttyClearScreen();

    var seed: u64 = undefined;
    std.crypto.random.bytes(std.mem.asBytes(&seed));
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();

    const labels_max_length = TerminalBuffer.strWidth("Password") catch 8;
    const buffer_options = TerminalBuffer.InitOptions{
        .fg = Colors.fg,
        .bg = Colors.bg,
        .border_fg = Colors.border,
        .margin_box_h = 2,
        .margin_box_v = 1,
        .input_len = 34,
    };
    var buffer = TerminalBuffer.init(buffer_options, labels_max_length, random);

    var doom = try Doom.init(allocator, &buffer, 0x00FF0000, 0x00FFFF00, 0x00FFFFFF, 6, 2);
    var animation = doom.animation();
    defer animation.deinit();

    var password = Text.init(allocator, &buffer, true, '*');
    defer {
        wipePassword(&password);
        password.deinit();
    }

    var message_text: []const u8 = default_message;
    var message_fg: u32 = Colors.fg;
    var message_bg: u32 = Colors.bg;
    var pending_action: ?[]const u8 = null;
    var pending_unlock = false;
    var unlock_buffer: ?[]u8 = null;

    var event: termbox.tb_event = undefined;
    var running = true;

    while (running) {
        animation.draw();

        buffer.drawBoxCenter(true, true);
        drawHints(&buffer);

        const coordinates = buffer.calculateComponentCoordinates();
        const message_y = coordinates.y;
        const input_y = coordinates.y + 2;

        clearLine(&buffer, coordinates.start_x, message_y, coordinates.full_visible_length);
        drawMessage(message_text, message_fg, message_bg, &buffer, coordinates.start_x, message_y, coordinates.full_visible_length);

        clearLine(&buffer, coordinates.start_x, input_y, coordinates.full_visible_length);
        buffer.drawLabel("Password", coordinates.start_x, input_y);
        password.position(coordinates.x, input_y, coordinates.visible_length);
        password.draw();
        password.handle(null, true) catch {
            message_text = input_error_message;
            message_fg = Colors.error;
            message_bg = Colors.bg;
        };

        _ = termbox.tb_present();

        if (pending_unlock) {
            if (unlock_buffer) |slice| {
                const unlock_ok = runUnlock(allocator, slice) catch {
                    message_text = spawn_error_message;
                    message_fg = Colors.error;
                    message_bg = Colors.bg;
                    wipeSecret(slice);
                    allocator.free(slice);
                    unlock_buffer = null;
                    pending_unlock = false;
                    continue;
                };

                if (unlock_ok) {
                    wipeSecret(slice);
                    allocator.free(slice);
                    return;
                }

                message_text = unlock_failed_message;
                message_fg = Colors.error;
                message_bg = Colors.bg;

                wipeSecret(slice);
                allocator.free(slice);
                unlock_buffer = null;
            }

            pending_unlock = false;
            continue;
        }

        const event_result = termbox.tb_peek_event(&event, 50);
        if (event_result == 0) continue;
        if (event_result < 0) continue;

        if (event.type == termbox.TB_EVENT_RESIZE) {
            buffer = TerminalBuffer.init(buffer_options, labels_max_length, random);
            animation.realloc() catch {};
            continue;
        }

        if (event.type != termbox.TB_EVENT_KEY) continue;

        var handled = false;
        switch (event.key) {
            termbox.TB_KEY_CTRL_C => {
                handled = true;
                running = false;
            },
            termbox.TB_KEY_F1 => {
                handled = true;
                pending_action = SHUTDOWN_CMD;
                running = false;
            },
            termbox.TB_KEY_F2 => {
                handled = true;
                pending_action = RESTART_CMD;
                running = false;
            },
            termbox.TB_KEY_F3 => {
                handled = true;
                if (SUSPEND_CMD) |cmd| {
                    runCommand(cmd) catch {
                        message_text = suspend_failed_message;
                        message_fg = Colors.error;
                        message_bg = Colors.bg;
                    };
                }
            },
            termbox.TB_KEY_F5 => {
                handled = true;
                adjustBrightness(allocator, BRIGHTNESS_DOWN_CMD) catch {
                    message_text = brightness_failed_message;
                    message_fg = Colors.error;
                    message_bg = Colors.bg;
                };
            },
            termbox.TB_KEY_F6 => {
                handled = true;
                adjustBrightness(allocator, BRIGHTNESS_UP_CMD) catch {
                    message_text = brightness_failed_message;
                    message_fg = Colors.error;
                    message_bg = Colors.bg;
                };
            },
            termbox.TB_KEY_CTRL_U => {
                handled = true;
                wipePassword(&password);
            },
            termbox.TB_KEY_ENTER => {
                handled = true;
                const slice = password.text.items[0..password.end];
                if (slice.len == 0) {
                    message_text = empty_password_message;
                    message_fg = Colors.error;
                    message_bg = Colors.bg;
                    continue;
                }

                unlock_buffer = allocator.dupe(u8, slice) catch {
                    message_text = spawn_error_message;
                    message_fg = Colors.error;
                    message_bg = Colors.bg;
                    continue;
                };
                message_text = unlocking_message;
                message_fg = Colors.fg;
                message_bg = Colors.bg;
                pending_unlock = true;
                wipePassword(&password);
                continue;
            },
            else => {},
        }

        if (!handled) {
            password.handle(&event, true) catch {
                message_text = input_error_message;
                message_fg = Colors.error;
                message_bg = Colors.bg;
            };
        }
    }

    if (pending_action) |cmd| {
        const argv = [_][]const u8{ "/bin/sh", "-c", cmd };
        std.process.execv(std.heap.page_allocator, &argv) catch |err| {
            stderr.print("failed to run {s}: {s}\n", .{ cmd, @errorName(err) }) catch {};
        };
    }
}

fn drawMessage(text: []const u8, fg: u32, bg: u32, buffer: *TerminalBuffer, x: usize, y: usize, max_width: usize) void {
    if (text.len == 0 or max_width == 0) return;
    const width = TerminalBuffer.strWidth(text) catch 0;
    if (width == 0) return;
    if (width >= max_width) {
        buffer.drawConfinedLabel(text, x, y, max_width);
        return;
    }
    const offset = (max_width - width) / 2;
    TerminalBuffer.drawColorLabel(text, x + offset, y, fg, bg);
}

fn drawHints(buffer: *TerminalBuffer) void {
    if (buffer.width == 0) return;
    clearLine(buffer, 0, 0, buffer.width);
    var x: usize = 0;
    for (hints) |hint| {
        if (hint.key.len == 0 or hint.description.len == 0) continue;
        if (x + hint.key.len >= buffer.width) break;
        buffer.drawLabel(hint.key, x, 0);
        x += hint.key.len + 1;
        if (x + hint.description.len >= buffer.width) break;
        buffer.drawLabel(hint.description, x, 0);
        x += hint.description.len + 2;
    }
}

fn clearLine(buffer: *TerminalBuffer, x: usize, y: usize, width: usize) void {
    if (width == 0) return;
    buffer.drawCharMultiple(' ', x, y, width);
}

fn wipePassword(password: *Text) void {
    wipeSecret(password.text.items);
    password.clear();
}

fn wipeSecret(secret: []u8) void {
    if (secret.len == 0) return;
    @memset(secret, 0);
}

fn runUnlock(allocator: std.mem.Allocator, password: []const u8) !bool {
    var child = std.process.Child.init(&[_][]const u8{ "/bin/opal-unlocker" }, allocator);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;

    try child.spawn();

    if (child.stdin) |*stdin_file| {
        var writer = stdin_file.writer();
        try writer.writeAll(password);
        try writer.writeByte('\n');
        try stdin_file.close();
        child.stdin = null;
    }

    const result = try child.wait();
    return switch (result) {
        .Exited => |code| code == 0,
        else => false,
    };
}

fn runCommand(cmd: []const u8) !void {
    var child = std.process.Child.init(&[_][]const u8{ "/bin/sh", "-c", cmd }, std.heap.page_allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;

    const result = try child.spawnAndWait();
    switch (result) {
        .Exited => |code| if (code != 0) return error.CommandFailed,
        else => return error.CommandFailed,
    }
}

fn adjustBrightness(allocator: std.mem.Allocator, cmd: []const u8) !void {
    var brightness = std.process.Child.init(&[_][]const u8{ "/bin/sh", "-c", cmd }, allocator);
    brightness.stdout_behavior = .Ignore;
    brightness.stderr_behavior = .Ignore;

    const process_result = brightness.spawnAndWait() catch return error.BrightnessChangeFailed;
    switch (process_result) {
        .Exited => |code| if (code != 0) return error.BrightnessChangeFailed,
        else => return error.BrightnessChangeFailed,
    }
}

fn ttyClearScreen() !void {
    const capability = termbox.global.caps[termbox.TB_CAP_CLEAR_SCREEN];
    const capability_slice = std.mem.span(capability);
    _ = try std.posix.write(termbox.global.ttyfd, capability_slice);
}

fn redrawSplashOnExit() void {
    if (builtin.os.tag != .linux) return;
    redrawSplashLinux(std.heap.page_allocator) catch {};
}

fn redrawSplashLinux(allocator: std.mem.Allocator) !void {
    comptime if (builtin.os.tag != .linux) {
        return;
    }

    var splash_file = std.fs.openFileAbsolute("/splash.bmp", .{}) catch return;
    defer splash_file.close();

    var header: [54]u8 = undefined;
    const header_read = try splash_file.readAll(&header);
    if (header_read < header.len) return error.InvalidBmpHeader;
    if (header[0] != 'B' or header[1] != 'M') return error.InvalidBmpHeader;

    const data_offset = std.mem.readIntLittle(u32, header[10..14]);
    const dib_header = std.mem.readIntLittle(u32, header[14..18]);
    if (dib_header < 40) return error.UnsupportedBmpFormat;

    const width_raw = std.mem.readIntLittle(i32, header[18..22]);
    const height_raw = std.mem.readIntLittle(i32, header[22..26]);
    const planes = std.mem.readIntLittle(u16, header[26..28]);
    const bits_per_pixel = std.mem.readIntLittle(u16, header[28..30]);

    if (planes != 1) return error.UnsupportedBmpFormat;
    if (bits_per_pixel != 24 and bits_per_pixel != 32) return error.UnsupportedBmpFormat;

    const bmp_width = @as(usize, @intCast(@abs(width_raw)));
    const bmp_height = @as(usize, @intCast(@abs(height_raw)));
    if (bmp_width == 0 or bmp_height == 0) return error.UnsupportedBmpFormat;

    const top_down = height_raw < 0;
    const bytes_per_pixel = bits_per_pixel / 8;
    const row_size = try std.math.mul(usize, bmp_width, bytes_per_pixel);
    const row_padded = (row_size + 3) & ~@as(usize, 3);
    const data_size = try std.math.mul(usize, row_padded, bmp_height);

    try splash_file.seekTo(data_offset);
    var pixel_data = try allocator.alloc(u8, data_size);
    defer allocator.free(pixel_data);
    const data_read = try splash_file.readAll(pixel_data);
    if (data_read < data_size) return error.InvalidBmpData;

    var fb_file = std.fs.openFileAbsolute("/dev/fb0", .{ .mode = .read_write }) catch return;
    defer fb_file.close();

    const fd = fb_file.handle;

    var fix_info: fb.fb_fix_screeninfo = undefined;
    if (std.posix.ioctl(fd, fb.FBIOGET_FSCREENINFO, @intFromPtr(&fix_info)) != 0) return error.FramebufferInfoFailed;

    var var_info: fb.fb_var_screeninfo = undefined;
    if (std.posix.ioctl(fd, fb.FBIOGET_VSCREENINFO, @intFromPtr(&var_info)) != 0) return error.FramebufferInfoFailed;

    if (var_info.bits_per_pixel == 0) return error.FramebufferInfoFailed;
    const fb_bytes_per_pixel = @as(usize, @intCast(var_info.bits_per_pixel / 8));
    if (fb_bytes_per_pixel == 0) return error.FramebufferInfoFailed;

    const screen_width = @as(usize, @intCast(var_info.xres));
    const screen_height = @as(usize, @intCast(var_info.yres));
    const line_length = @as(usize, @intCast(fix_info.line_length));
    if (screen_width == 0 or screen_height == 0 or line_length == 0) return error.FramebufferInfoFailed;

    const dest_width = std.math.min(screen_width, bmp_width);
    const dest_height = std.math.min(screen_height, bmp_height);
    if (dest_width == 0 or dest_height == 0) return;

    const x_offset = (screen_width - dest_width) / 2;
    const y_offset = (screen_height - dest_height) / 2;
    const src_x_offset = (bmp_width - dest_width) / 2;
    const src_y_offset = (bmp_height - dest_height) / 2;

    var zero_row = try allocator.alloc(u8, line_length);
    defer allocator.free(zero_row);
    @memset(zero_row, 0);

    var y: usize = 0;
    while (y < screen_height) : (y += 1) {
        const offset = try std.math.mul(usize, y, line_length);
        try fb_file.pwriteAll(zero_row, offset);
    }

    const dest_row_bytes = try std.math.mul(usize, dest_width, fb_bytes_per_pixel);
    var dest_row_buffer = try allocator.alloc(u8, dest_row_bytes);
    defer allocator.free(dest_row_buffer);

    var dest_row: usize = 0;
    while (dest_row < dest_height) : (dest_row += 1) {
        const src_row_index = src_y_offset + dest_row;
        const adjusted_row = if (top_down) src_row_index else (bmp_height - 1 - src_row_index);
        const base_row_offset = try std.math.mul(usize, adjusted_row, row_padded);
        const src_pixel_offset = try std.math.mul(usize, src_x_offset, bytes_per_pixel);
        const row_start = base_row_offset + src_pixel_offset;
        const row_length = try std.math.mul(usize, dest_width, bytes_per_pixel);
        const row_slice = pixel_data[row_start .. row_start + row_length];

        var dest_col: usize = 0;
        while (dest_col < dest_width) : (dest_col += 1) {
            const src_index = dest_col * bytes_per_pixel;
            const b = row_slice[src_index];
            const g = row_slice[src_index + 1];
            const r = row_slice[src_index + 2];
            const a: u8 = if (bytes_per_pixel == 4) row_slice[src_index + 3] else 0xFF;

            const pixel_value = packFramebufferPixel(var_info, fb_bytes_per_pixel, r, g, b, a);
            const dest_index = dest_col * fb_bytes_per_pixel;

            var byte_index: usize = 0;
            while (byte_index < fb_bytes_per_pixel) : (byte_index += 1) {
                dest_row_buffer[dest_index + byte_index] = @as(u8, @truncate(pixel_value >> (byte_index * 8)));
            }
        }

        const dest_line_offset = try std.math.mul(usize, y_offset + dest_row, line_length);
        const dest_pixel_offset = try std.math.mul(usize, x_offset, fb_bytes_per_pixel);
        const dest_offset = dest_line_offset + dest_pixel_offset;
        try fb_file.pwriteAll(dest_row_buffer, dest_offset);
    }
}

fn packFramebufferPixel(info: fb.fb_var_screeninfo, bytes_per_pixel: usize, r: u8, g: u8, b: u8, a: u8) u64 {
    comptime if (builtin.os.tag != .linux) {
        return 0;
    }

    const red_offset: u6 = @intCast(std.math.min(u32, info.red.offset, 63));
    const green_offset: u6 = @intCast(std.math.min(u32, info.green.offset, 63));
    const blue_offset: u6 = @intCast(std.math.min(u32, info.blue.offset, 63));
    const alpha_offset: u6 = @intCast(std.math.min(u32, info.transp.offset, 63));

    const red = scaleComponent(r, info.red.length) << red_offset;
    const green = scaleComponent(g, info.green.length) << green_offset;
    const blue = scaleComponent(b, info.blue.length) << blue_offset;
    const alpha = scaleComponent(a, info.transp.length) << alpha_offset;

    var pixel: u64 = red | green | blue | alpha;
    if (bytes_per_pixel <= 4) {
        const bits: u6 = @intCast(std.math.min(usize, bytes_per_pixel * 8, 64));
        const mask = if (bits == 64) std.math.maxInt(u64) else (@as(u64, 1) << bits) - 1;
        return pixel & mask;
    }
    return pixel;
}

fn scaleComponent(value: u8, length: u32) u64 {
    if (length == 0) return 0;
    const bits: u6 = @intCast(std.math.min(u32, length, 63));
    const max_value: u64 = (@as(u64, 1) << bits) - 1;
    return (max_value * value + 127) / 255;
}
