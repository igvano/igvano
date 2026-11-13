//! Frontend supervision of an attached exec, including the caller's terminal.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const fd_t = std.posix.fd_t;

const watched = signals: {
    var result: [linux.NSIG]linux.SIG = undefined;
    var used = 0;
    for (1..linux.NSIG) |number| {
        const signal: linux.SIG = @enumFromInt(number);
        if (signal == .KILL or signal == .STOP or signal == .URG) continue;
        // std.Io.Threaded uses SIGIO (also SIGPOLL) for cancellation;
        // forwarding it would kill the container process.
        if (signal == .IO) continue;
        // Preserve local job control; catching TTIN/TTOU makes terminal I/O retry EINTR forever.
        if (signal == .TSTP or signal == .TTIN or signal == .TTOU) continue;
        // Keep fault handlers intact; returning from notify would repeat a real fault.
        if (signal == .SEGV or signal == .BUS or signal == .ILL or signal == .FPE or signal == .TRAP or signal == .SYS) continue;
        result[used] = signal;
        used += 1;
    }
    break :signals result[0..used].*;
};
var signal_writer: std.atomic.Value(fd_t) = .init(-1);
var pending_signals: [linux.sigemptyset().len]std.atomic.Value(c_ulong) = @splat(.init(0));

fn notify(signal: linux.SIG) callconv(.c) void {
    const bit = @intFromEnum(signal) - 1;
    _ = pending_signals[bit / @bitSizeOf(c_ulong)].fetchOr(@as(c_ulong, 1) << @intCast(bit % @bitSizeOf(c_ulong)), .monotonic);
    const fd = signal_writer.load(.monotonic);
    if (fd < 0) return;
    const byte = [_]u8{1};
    // Only async-signal-safe, nonblocking work. The bitset retains signals even
    // when the wakeup pipe fills, or multiple threads enter the handler.
    while (linux.errno(linux.write(fd, &byte, 1)) == .INTR) {}
}

pub const Signals = struct {
    pipe: [2]fd_t,
    previous: [watched.len]linux.Sigaction = undefined,
    installed: usize = 0,

    pub fn init() !Signals {
        if (comptime builtin.os.tag != .linux) return error.NotImplemented;
        var self: Signals = .{ .pipe = undefined };
        if (linux.errno(linux.pipe2(&self.pipe, .{ .CLOEXEC = true, .NONBLOCK = true })) != .SUCCESS)
            return error.SignalSetupFailed;
        errdefer self.deinit();
        for (&pending_signals) |*pending| pending.store(0, .monotonic);
        signal_writer.store(self.pipe[1], .monotonic);
        var mask = linux.sigemptyset();
        for (watched) |signal| linux.sigaddset(&mask, signal);
        const action: linux.Sigaction = .{ .handler = .{ .handler = notify }, .mask = mask, .flags = 0 };
        for (watched, &self.previous) |signal, *previous| {
            if (linux.errno(linux.sigaction(signal, &action, previous)) != .SUCCESS)
                return error.SignalSetupFailed;
            self.installed += 1;
        }
        return self;
    }

    pub fn deinit(self: *Signals) void {
        if (comptime builtin.os.tag != .linux) return;
        for (watched[0..self.installed], self.previous[0..self.installed]) |signal, *previous|
            _ = linux.sigaction(signal, previous, null);
        signal_writer.store(-1, .monotonic);
        for (self.pipe) |fd| _ = linux.close(fd);
    }

    fn forward(self: *Signals, pid: ?i32, controller: ?fd_t, input: fd_t) !void {
        var bytes: [128]u8 = undefined;
        while (true) {
            const count = linux.read(self.pipe[0], &bytes, bytes.len);
            switch (linux.errno(count)) {
                .SUCCESS => if (count == 0) return error.SignalReadFailed,
                .INTR => continue,
                .AGAIN => break,
                else => return error.SignalReadFailed,
            }
        }
        var pending: linux.sigset_t = undefined;
        for (&pending_signals, &pending) |*word, *bits| bits.* = word.swap(0, .acq_rel);
        const child = pid orelse return;
        for (watched) |signal| {
            if (!linux.sigismember(&pending, signal)) continue;
            switch (signal) {
                .CHLD => {},
                .WINCH => if (controller) |fd| resize(input, fd),
                else => {
                    // Non-TTY exec shares the caller's foreground process group:
                    // terminal Ctrl-C arrives directly and by forwarding, as in runc.
                    _ = linux.kill(child, signal);
                },
            }
        }
    }
};

/// Like runc's recvtty, keep "\n" as "\n" in output copied to a pipe or file.
/// A terminal output is put in raw mode, so it still needs the PTY's "\r\n".
pub fn clearOnlcr(controller: fd_t, output: fd_t) void {
    var term: linux.termios = undefined;
    if (linux.errno(linux.ioctl(output, linux.T.CGETS, @intFromPtr(&term))) == .SUCCESS) return;
    if (linux.errno(linux.ioctl(controller, linux.T.CGETS, @intFromPtr(&term))) != .SUCCESS) return;
    term.oflag.ONLCR = false;
    _ = linux.ioctl(controller, linux.T.CSETS, @intFromPtr(&term));
}

fn resize(input: fd_t, controller: fd_t) void {
    var size: std.posix.winsize = undefined;
    if (linux.errno(linux.ioctl(input, linux.T.IOCGWINSZ, @intFromPtr(&size))) == .SUCCESS)
        _ = linux.ioctl(controller, linux.T.IOCSWINSZ, @intFromPtr(&size));
}

fn makeRaw(input: fd_t) !?linux.termios {
    var original: linux.termios = undefined;
    while (true) {
        switch (linux.errno(linux.ioctl(input, linux.T.CGETS, @intFromPtr(&original)))) {
            .SUCCESS => break,
            .INTR => continue,
            .NOTTY, .BADF => return null,
            else => return error.ConsoleFailed,
        }
    }
    var raw = original;
    inline for (.{ "IGNBRK", "BRKINT", "PARMRK", "ISTRIP", "INLCR", "IGNCR", "ICRNL", "IXON" }) |field|
        @field(raw.iflag, field) = false;
    raw.oflag.OPOST = false;
    inline for (.{ "ECHO", "ECHONL", "ICANON", "ISIG", "IEXTEN" }) |field|
        @field(raw.lflag, field) = false;
    raw.cflag.CSIZE = .CS8;
    raw.cflag.PARENB = false;
    raw.cc[@intFromEnum(linux.V.MIN)] = 1;
    raw.cc[@intFromEnum(linux.V.TIME)] = 0;
    while (true) {
        switch (linux.errno(linux.ioctl(input, linux.T.CSETS, @intFromPtr(&raw)))) {
            .SUCCESS => break,
            .INTR => continue,
            .NOTTY, .BADF => return null,
            else => return error.ConsoleFailed,
        }
    }
    return original;
}

fn nonblocking(fd: fd_t) !usize {
    const flags = linux.fcntl(fd, linux.F.GETFL, 0);
    if (linux.errno(flags) != .SUCCESS) return error.ConsoleFailed;
    const nonblock = @as(u32, @bitCast(linux.O{ .NONBLOCK = true }));
    if (linux.errno(linux.fcntl(fd, linux.F.SETFL, flags | nonblock)) != .SUCCESS) return error.ConsoleFailed;
    return flags;
}

const Buffer = struct {
    bytes: [4096]u8 = undefined,
    used: usize = 0,
    offset: usize = 0,

    fn read(self: *Buffer, fd: fd_t) !bool {
        const count = linux.read(fd, &self.bytes, self.bytes.len);
        switch (linux.errno(count)) {
            .SUCCESS => {
                self.used = count;
                self.offset = 0;
                return count == 0;
            },
            .INTR, .AGAIN => return false,
            .IO => return true, // A PTY controller returns EIO after the replica closes.
            else => return error.ConsoleReadFailed,
        }
    }

    fn write(self: *Buffer, fd: fd_t) !void {
        const count = linux.write(fd, self.bytes[self.offset..].ptr, self.used - self.offset);
        switch (linux.errno(count)) {
            .SUCCESS => {
                if (count == 0) return error.ConsoleWriteFailed;
                self.offset += count;
                if (self.offset == self.used) self.used = 0;
            },
            .INTR, .AGAIN => {},
            else => return error.ConsoleWriteFailed,
        }
    }
};

fn reap(pid: i32, exit_status: *?u8, reaped: *bool) !void {
    while (true) {
        var status: u32 = undefined;
        const result = linux.waitpid(-1, &status, linux.W.NOHANG);
        switch (linux.errno(result)) {
            .SUCCESS => {
                if (result == 0) return;
                if (result == @as(u32, @intCast(pid))) {
                    reaped.* = true;
                    const signal = status & 0x7f;
                    exit_status.* = @intCast(if (signal == 0) (status >> 8) & 0xff else 128 + signal);
                }
            },
            .INTR => continue,
            .CHILD => if (exit_status.* != null) return else return error.WaitFailed,
            else => return error.WaitFailed,
        }
    }
}

/// The caller keeps child subreaping enabled until return. Set reaped as soon as
/// waitpid collects pid, including when subsequent console draining fails.
pub fn wait(pid: i32, reaped: *bool, signals: *Signals, controller: ?fd_t, input: fd_t, output: fd_t) !u8 {
    if (comptime builtin.os.tag != .linux) return error.NotImplemented;
    // Raw mode and the first resize deliberately follow container.exec, matching runc.
    const original = if (controller != null) try makeRaw(input) else null;
    defer restoreTerminal(input, original);
    const controller_flags = if (controller) |fd| try nonblocking(fd) else null;
    defer restoreControllerFlags(controller, controller_flags);
    // stdin/stdout share their open file descriptions with the caller's shell.
    // Leave their flags alone; poll gates the blocking reads and writes.
    if (controller) |fd| {
        clearOnlcr(fd, output);
        resize(input, fd);
    }
    var terminal: AttachedIo = .{ .controller = controller, .input = input, .output = output, .input_open = controller != null, .console_open = controller != null };
    var exit_status: ?u8 = null;
    while (true) {
        try supervise(pid, reaped, signals, controller, input, &exit_status);
        if (controller == null) {
            if (exit_status) |status| return status;
        }
        var fds = terminal.pollFds(signals.pipe[0], exit_status);
        // After exit, drain available PTY output without waiting for descendants
        // that may have inherited the replica. Pending stdout still gets flushed.
        const timeout: i32 = if (exit_status != null and terminal.from_console.used == 0) 0 else -1;
        _ = try std.posix.poll(&fds, timeout);
        if (fds[0].revents != 0) try supervise(pid, reaped, signals, controller, input, &exit_status);
        try terminal.copyOutput(&fds);
        try terminal.copyInput(&fds);
        try terminal.readOutput(&fds);
        if (exit_status) |status| {
            if (terminal.drained(fds[2])) return status;
        }
    }
}

fn restoreTerminal(input: fd_t, original: ?linux.termios) void {
    if (original) |term| {
        var saved = term;
        while (linux.errno(linux.ioctl(input, linux.T.CSETS, @intFromPtr(&saved))) == .INTR) {}
    }
}

fn restoreControllerFlags(controller: ?fd_t, controller_flags: ?usize) void {
    if (controller) |fd| {
        if (controller_flags) |flags| _ = linux.fcntl(fd, linux.F.SETFL, flags);
    }
}

fn supervise(pid: i32, reaped: *bool, signals: *Signals, controller: ?fd_t, input: fd_t, exit_status: *?u8) !void {
    try reap(pid, exit_status, reaped);
    try signals.forward(if (reaped.*) null else pid, controller, input);
}

const AttachedIo = struct {
    controller: ?fd_t,
    input: fd_t,
    output: fd_t,
    to_console: Buffer = .{},
    from_console: Buffer = .{},
    input_open: bool,
    console_open: bool,

    fn pollFds(self: *const AttachedIo, signal_fd: fd_t, exit_status: ?u8) [4]linux.pollfd {
        return [_]linux.pollfd{
            .{ .fd = signal_fd, .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = self.inputFd(exit_status), .events = linux.POLL.IN, .revents = 0 },
            // HUP is reported even with events=0; stop watching while output is buffered.
            .{ .fd = if (self.console_open and self.from_console.used == 0) self.controller.? else -1, .events = linux.POLL.IN | @as(i16, if (self.to_console.used > 0 and exit_status == null) linux.POLL.OUT else 0), .revents = 0 },
            .{ .fd = if (self.from_console.used > 0) self.output else -1, .events = linux.POLL.OUT, .revents = 0 },
        };
    }

    fn inputFd(self: *const AttachedIo, exit_status: ?u8) fd_t {
        return if (self.input_open and exit_status == null and self.to_console.used == 0) self.input else -1;
    }

    fn copyOutput(self: *AttachedIo, fds: *const [4]linux.pollfd) !void {
        if (fds[3].revents != 0) try self.from_console.write(self.output);
    }

    fn copyInput(self: *AttachedIo, fds: *const [4]linux.pollfd) !void {
        if (fds[1].revents & linux.POLL.NVAL != 0)
            self.input_open = false
        else if (fds[1].revents != 0)
            self.input_open = !try self.to_console.read(self.input);
        if (fds[2].revents & linux.POLL.OUT != 0 and self.to_console.used > 0)
            try self.to_console.write(self.controller.?);
    }

    fn readOutput(self: *AttachedIo, fds: *const [4]linux.pollfd) !void {
        if (fds[2].revents & (linux.POLL.IN | linux.POLL.HUP | linux.POLL.ERR) != 0 and self.from_console.used == 0)
            self.console_open = !try self.from_console.read(self.controller.?);
    }

    fn drained(self: *const AttachedIo, controller_fd: linux.pollfd) bool {
        return self.from_console.used == 0 and (!self.console_open or (controller_fd.fd >= 0 and controller_fd.revents == 0));
    }
};

test "raw mode ignores closed or non-terminal stdin" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try std.testing.expect(try makeRaw(-1) == null);
    var pipe: [2]fd_t = undefined;
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.pipe2(&pipe, .{ .CLOEXEC = true })));
    defer for (pipe) |fd| {
        _ = linux.close(fd);
    };
    try std.testing.expect(try makeRaw(pipe[0]) == null);
}

test "WINCH only resizes and other signals forward only to unreaped processes" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var signals = try Signals.init();
    defer signals.deinit();
    const pid: i32 = @intCast(linux.getpid());
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.kill(pid, .WINCH)));
    try signals.forward(pid, null, -1);
    // Forwarding to ourselves would run notify again and leave a pending bit.
    for (&pending_signals) |*pending| try std.testing.expectEqual(@as(c_ulong, 0), pending.load(.monotonic));
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.kill(pid, .TERM)));
    try signals.forward(null, null, -1);
    for (&pending_signals) |*pending| try std.testing.expectEqual(@as(c_ulong, 0), pending.load(.monotonic));
    for ([_]linux.SIG{ .PIPE, .ALRM, @enumFromInt(linux.NSIG - 1) }) |signal| {
        try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.kill(pid, signal)));
        try signals.forward(pid, null, -1);
        const bit = @intFromEnum(signal) - 1;
        try std.testing.expect(pending_signals[bit / @bitSizeOf(c_ulong)].swap(0, .monotonic) != 0);
    }
}
