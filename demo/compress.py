#!/usr/bin/env python3
"""Shorten pauses in an asciinema v2/v3 recording.

- every gap between events is capped at --max-gap seconds;
- between the demo-fast-on/off markers (see record.sh) time runs --fast times
  faster, so image pulls and the dashboard watching don't take minutes;
- output events that are only progress dots are squeezed to --dot-gap;
- --segment N=F gives the Nth fast segment its own speed (e.g. the dashboard);
- --end-hold keeps the last frame on screen for a while.
"""
import argparse
import json
import re
import sys

ON, OFF = "\x1b]1337;demo-fast-on\x07", "\x1b]1337;demo-fast-off\x07"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("dst")
    ap.add_argument("--max-gap", type=float, default=1.5)
    ap.add_argument("--fast", type=float, default=12)
    ap.add_argument("--dot-gap", type=float, default=0.05)
    ap.add_argument("--segment", action="append", default=[], help="N=F: speed factor F for the Nth fast segment")
    ap.add_argument("--end-hold", type=float, default=5)
    args = ap.parse_args()

    with open(args.src) as f:
        lines = f.read().splitlines()

    header = json.loads(lines[0])
    v3 = header.get("version") == 3
    speeds = {int(n): float(f) for n, f in (x.split("=") for x in args.segment)}
    out, fast, t_abs, t_new, seg = [json.dumps(header)], False, 0.0, 0.0, 0

    for line in lines[1:]:
        if not line.strip() or line.startswith("#"):
            continue
        ev = json.loads(line)
        t, kind, data = ev[0], ev[1], ev[2]
        # v3 stores intervals, v2 absolute times
        gap = t if v3 else t - t_abs
        t_abs = t if not v3 else t_abs + t

        if kind == "o":
            if ON in data:
                fast = True
                seg += 1
            if OFF in data:
                fast = False
            data = data.replace(ON, "").replace(OFF, "")
            if fast:
                gap /= speeds.get(seg, args.fast)
            if re.fullmatch(r"[.\s]*", data) and data.strip():
                gap = min(gap, args.dot_gap)
        gap = min(gap, args.max_gap)
        t_new += gap

        if kind == "o" and data == "":
            continue
        out.append(json.dumps([round(gap if v3 else t_new, 6), kind, data]))

    # hold the last frame (cursor-show is a no-op for the picture)
    out.append(json.dumps([round(args.end_hold if v3 else t_new + args.end_hold, 6), "o", "\u001b[?25h"]))
    t_new += args.end_hold

    with open(args.dst, "w") as f:
        f.write("\n".join(out) + "\n")

    print(f"{t_abs:.0f}s -> {t_new:.0f}s", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
