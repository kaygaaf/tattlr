#!/usr/bin/env python3
"""Record docs/scan.svg, an animated terminal recording of tattlr scan.

    go build -o /tmp/tattlr ./cmd/tattlr
    python3 scripts/scan-svg.py /tmp/tattlr > docs/scan.svg

No dependencies. It runs tattlr against the fixture logs in testdata/home,
turns the colored output into SVG text and fades it in line by line, so the
README gets a demo that stays sharp and weighs a few KB instead of a GIF.
"""
import html
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOME = os.path.join(ROOT, "testdata", "home")

FONT = 14
CW = 8.43  # monospace advance at 14px
LH = 18
PAD = 20
BAR = 34
COLS = 100

BG, FG = "#1e1e2e", "#cdd6f4"
BASIC = {30: "#45475a", 31: "#f38ba8", 32: "#a6e3a1", 33: "#f9e2af", 34: "#89b4fa",
         35: "#f5c2e7", 36: "#94e2d5", 37: "#bac2de"}

# (prompt command, args, pause before typing in seconds)
STEPS = [
    ("tattlr scan", ["scan"], 0.6),
    ("tattlr scan --since 30d --fail-on high > /dev/null; echo \"exit $?\"",
     ["scan", "--since", "30d", "--fail-on", "high"], 1.6),
]


def xterm256(n):
    if n < 16:
        base = ["#000000", "#cd3131", "#0dbc79", "#e5e510", "#2472c8", "#bc3fbc", "#11a8cd", "#e5e5e5",
                "#666666", "#f14c4c", "#23d18b", "#f5f543", "#3b8eea", "#d670d6", "#29b8db", "#ffffff"]
        return base[n]
    if n < 232:
        n -= 16
        steps = [0, 95, 135, 175, 215, 255]
        return "#%02x%02x%02x" % (steps[n // 36], steps[(n // 6) % 6], steps[n % 6])
    v = 8 + (n - 232) * 10
    return "#%02x%02x%02x" % (v, v, v)


SGR = re.compile(r"\x1b\[([0-9;]*)m")


def spans(line):
    """Split one line of ANSI text into (text, style) pieces."""
    out, st, pos = [], {}, 0
    for m in SGR.finditer(line):
        if m.start() > pos:
            out.append((line[pos:m.start()], dict(st)))
        codes = [int(c) for c in m.group(1).split(";") if c] or [0]
        i = 0
        while i < len(codes):
            c = codes[i]
            if c == 0:
                st = {}
            elif c == 1:
                st["bold"] = True
            elif c == 2:
                st["dim"] = True
            elif c in BASIC:
                st["fg"] = BASIC[c]
            elif c in (38, 48) and i + 2 < len(codes) and codes[i + 1] == 5:
                st["fg" if c == 38 else "bg"] = xterm256(codes[i + 2])
                i += 2
            i += 1
        pos = m.end()
    if pos < len(line):
        out.append((line[pos:], dict(st)))
    return out


def run(args):
    env = dict(os.environ, FORCE_COLOR="1", TZ="Europe/Amsterdam")
    env.pop("NO_COLOR", None)
    p = subprocess.run([sys.argv[1]] + args + ["--home", HOME], capture_output=True, text=True, env=env)
    return p.stdout, p.returncode


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    lines = []  # (kind, payload, start time)
    t = 0.0
    for cmd, args, pause in STEPS:
        t += pause
        lines.append(("cmd", cmd, t))
        t += len(cmd) * 0.045 + 0.4
        if "echo" in cmd:
            _, code = run(args)
            lines.append(("out", "exit %d" % code, t))
            t += 0.1
            continue
        out, _ = run(args)
        for l in out.rstrip("\n").split("\n"):
            lines.append(("out", l, t))
            t += 0.06
        lines.append(("out", "", t))
    lines.append(("cmd", "", t + 0.5))
    total = t + 6.0  # hold the last frame, then loop

    h = BAR + PAD * 2 + LH * len(lines)
    w = PAD * 2 + int(CW * COLS)
    css = [
        "text{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace;font-size:%dpx;fill:%s;white-space:pre}" % (FONT, FG),
        ".b{font-weight:bold}.d{opacity:.55}.p{fill:#a6e3a1}",
        ".l{opacity:0;animation:%.2fs linear infinite}" % total,
    ]
    body = []
    for i, (kind, payload, start) in enumerate(lines):
        y = BAR + PAD + LH * (i + 1) - 4
        a = start / total * 100
        css.append("@keyframes k%d{0%%,%.3f%%{opacity:0}%.3f%%,99%%{opacity:1}100%%{opacity:0}}" % (i, a, min(a + 0.01, 99)))
        css.append("#l%d{animation-name:k%d}" % (i, i))
        if kind == "cmd":
            n = len(payload)
            typ = n * 0.045 / total * 100
            body.append('<g id="l%d" class="l"><text x="%d" y="%d"><tspan class="p">$ </tspan></text>' % (i, PAD, y))
            if n:
                cid = "c%d" % i
                body.append('<clipPath id="%s"><rect x="%.1f" y="%d" height="%d" width="0" class="w%d"/></clipPath>'
                            % (cid, PAD + 2 * CW, y - FONT, LH, i))
                css.append("@keyframes t%d{0%%,%.3f%%{width:0}%.3f%%,100%%{width:%.1fpx}}" % (i, a, a + typ, n * CW + 2))
                css.append(".w%d{animation:t%d %.2fs steps(%d) infinite;animation-timing-function:linear}" % (i, i, total, max(n, 1)))
                body.append('<text x="%.1f" y="%d" clip-path="url(#%s)">%s</text>' % (PAD + 2 * CW, y, cid, html.escape(payload)))
            body.append("</g>")
            continue
        segs = []
        x = PAD
        for text, st in spans(payload):
            if st.get("bg"):
                body.append('<rect class="l" id="r%d_%d" x="%.1f" y="%d" width="%.1f" height="%d" fill="%s"/>'
                            % (i, len(segs), x, y - FONT + 1, CW * len(text), LH - 1, st["bg"]))
                css.append("#r%d_%d{animation-name:k%d}" % (i, len(segs), i))
            cls = " ".join(c for c, k in (("b", "bold"), ("d", "dim")) if st.get(k))
            attrs = (' class="%s"' % cls if cls else "") + (' style="fill:%s"' % st["fg"] if st.get("fg") else "")
            segs.append("<tspan%s>%s</tspan>" % (attrs, html.escape(text)) if attrs else html.escape(text))
            x += CW * len(text)
        body.append('<text id="l%d" class="l" x="%d" y="%d">%s</text>' % (i, PAD, y, "".join(segs)))

    print('<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-label="tattlr scan output">' % (w, h, w, h))
    print("<title>tattlr scan finding risky agent tool calls, then failing a CI check with --fail-on</title>")
    print("<style>%s</style>" % "".join(css))
    print('<rect width="100%%" height="100%%" rx="10" fill="%s"/>' % BG)
    for k, c in enumerate(("#f38ba8", "#f9e2af", "#a6e3a1")):
        print('<circle cx="%d" cy="17" r="6" fill="%s"/>' % (PAD + 4 + k * 20, c))
    print('<text x="%d" y="22" style="fill:#7f849c;font-size:12px" text-anchor="middle">~/code</text>' % (w // 2))
    print("\n".join(body))
    print("</svg>")


if __name__ == "__main__":
    main()
