#!/usr/bin/env python3
"""Run a TUI in a pty, mirror its output, press F3 and quit when a pid exits.

Used by the demo recording: asciinema records our stdout, and this script plays
the keyboard for `talosctl dashboard` (F3 = Containers screen).
"""
import argparse
import os
import pty
import select
import signal
import sys
import time

F3 = b"\x1bOR"
CTRL_C = b"\x03"


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pidfile", required=True, help="quit once this pid has exited")
    ap.add_argument("--min-seconds", type=float, default=20)
    ap.add_argument("--max-seconds", type=float, default=1800)
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    args = ap.parse_args()
    cmd = args.cmd[1:] if args.cmd and args.cmd[0] == "--" else args.cmd

    with open(args.pidfile) as f:
        watched = int(f.read().strip())

    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(cmd[0], cmd)

    # same size as our own terminal (asciinema's virtual one)
    try:
        import fcntl, struct, termios
        size = fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, b"\0" * 8)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, size)
    except OSError:
        pass

    start = time.monotonic()
    pressed = False
    quit_at = None

    while True:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try:
                data = os.read(fd, 65536)
            except OSError:
                break
            if not data:
                break
            os.write(sys.stdout.fileno(), data)

        now = time.monotonic() - start
        if not pressed and now > 3:
            os.write(fd, F3)
            pressed = True
        if quit_at is None and now > args.min_seconds and not alive(watched):
            quit_at = now + 6  # show the final state for a moment
        if (quit_at is not None and now > quit_at) or now > args.max_seconds:
            os.write(fd, CTRL_C)
            time.sleep(1)
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
            break

    os.waitpid(pid, 0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
