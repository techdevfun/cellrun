#!/usr/bin/env python3
"""Render demo/demo.gif from demo/transcript.txt (real recorded output).

Layout: 1080x620, DejaVuSansMono, dark terminal. One screen per command:
the command is typed (2 chars/frame, blinking block cursor), the real
output then appears, and the screen holds before clearing for the next.
Title and end cards are static. Frames are 70 ms.

Usage: python3 scripts/make-gif.py
Prints frame count and total duration; target is ~30 s.
"""
import os
import sys
import textwrap

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRANSCRIPT = os.path.join(ROOT, "demo", "transcript.txt")
OUT = os.path.join(ROOT, "demo", "demo.gif")

W, H = 1280, 720
FRAME_MS = 70
MARGIN = 24
BG = (13, 17, 23)
FG = (230, 237, 243)
PROMPT = (63, 185, 80)
OUTPUT_FG = (139, 148, 158)
DIM = (110, 118, 128)
TITLE_FG = (230, 237, 243)
ACCENT = (63, 185, 80)

MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONO_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
SANS = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
SANS_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"

BODY_SIZE = 18
WRAP_WIDTH = 114
CMD_WRAP_WIDTH = 112
LINE_H = 26
HOLD_FRAMES = 20
TITLE_FRAMES = 28
END_FRAMES = 28


def load_font(path, size):
    try:
        return ImageFont.truetype(path, size)
    except OSError:
        return ImageFont.load_default()


def parse_transcript(path):
    """Return a list of screens: ('title', text) | ('cmd', cmd, [lines]) | ('end', text)."""
    screens = []
    current = None
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n")
            if line.startswith("### TITLE: "):
                screens.append(("title", line[len("### TITLE: "):]))
                current = None
            elif line.startswith("### END: "):
                screens.append(("end", line[len("### END: "):]))
                current = None
            elif line.startswith("$ "):
                current = ("cmd", line[2:], [])
                screens.append(current)
            elif line == "" and current is None:
                continue
            elif current is not None:
                current[2].append(line)
            # stray blank lines between screens are ignored
    # Drop trailing empty output lines per screen.
    for s in screens:
        if s[0] == "cmd":
            while s[2] and s[2][-1] == "":
                s[2].pop()
    return screens


def wrap_lines(lines):
    out = []
    for line in lines:
        if len(line) <= WRAP_WIDTH:
            out.append(line)
        else:
            out.extend(
                textwrap.wrap(
                    line,
                    width=WRAP_WIDTH,
                    replace_whitespace=False,
                    drop_whitespace=False,
                    subsequent_indent="    ",
                )
                or [""]
            )
    return out


def blank_frame():
    return Image.new("RGB", (W, H), BG)


def draw_title(draw, text, subtitle=None):
    title_font = load_font(SANS_BOLD, 46)
    sub_font = load_font(SANS, 22)
    bbox = draw.textbbox((0, 0), text, font=title_font)
    tw = bbox[2] - bbox[0]
    draw.text(((W - tw) / 2, H / 2 - 60), text, font=title_font, fill=TITLE_FG)
    if subtitle:
        sb = draw.textbbox((0, 0), subtitle, font=sub_font)
        sw = sb[2] - sb[0]
        draw.text(((W - sw) / 2, H / 2 + 20), subtitle, font=sub_font, fill=DIM)


def wrap_cmd(typed):
    """Wrap the (possibly partial) typed command for display.

    textwrap is greedy left-to-right, so wrapping a typed prefix gives
    the same line breaks as wrapping the full command up to that point
    (prefix-stable) - the typed text never jumps lines mid-animation.
    """
    if not typed:
        return [""]
    return textwrap.wrap(
        typed,
        width=CMD_WRAP_WIDTH,
        replace_whitespace=False,
        drop_whitespace=False,
        break_long_words=False,
        break_on_hyphens=False,
        subsequent_indent="    ",
    ) or [""]


def draw_cmd_screen(draw, cmd_typed, output_lines, show_cursor, cursor_visible):
    font = load_font(MONO, BODY_SIZE)
    bold = load_font(MONO_BOLD, BODY_SIZE)
    y = MARGIN
    prompt = "$ "
    cmd_lines = wrap_cmd(cmd_typed)
    # First line carries the prompt; continuations are indented.
    draw.text((MARGIN, y), prompt, font=bold, fill=PROMPT)
    x = MARGIN + draw.textlength(prompt, font=bold)
    draw.text((x, y), cmd_lines[0], font=font, fill=FG)
    y += LINE_H
    for line in cmd_lines[1:]:
        draw.text((MARGIN, y), line, font=font, fill=FG)
        y += LINE_H
    if show_cursor:
        last = cmd_lines[-1]
        cx = (MARGIN + draw.textlength(prompt, font=bold) + draw.textlength(last, font=font)) if len(cmd_lines) == 1 else (MARGIN + draw.textlength(last, font=font))
        cy = MARGIN + (len(cmd_lines) - 1) * LINE_H
        if cursor_visible:
            draw.rectangle([cx + 2, cy + 2, cx + 12, cy + BODY_SIZE], fill=FG)
    for line in output_lines:
        draw.text((MARGIN, y), line, font=font, fill=OUTPUT_FG)
        y += LINE_H


def main():
    screens = parse_transcript(TRANSCRIPT)
    if not screens:
        print("no screens in transcript", file=sys.stderr)
        sys.exit(1)

    frames = []
    for screen in screens:
        if screen[0] == "title":
            for _ in range(TITLE_FRAMES):
                img = blank_frame()
                draw = ImageDraw.Draw(img)
                draw_title(draw, screen[1], "fresh cell per task - network off - sanitize before context")
                frames.append(img)
        elif screen[0] == "end":
            for _ in range(END_FRAMES):
                img = blank_frame()
                draw = ImageDraw.Draw(img)
                draw_title(draw, "cellrun 0.1.0", "MIT - github.com/techdevfun/cellrun")
                frames.append(img)
        else:
            _, cmd, output = screen
            wrapped = wrap_lines(output)
            # Typing phase: 2 chars per frame, blinking cursor.
            typed = 0
            frame_no = 0
            while typed < len(cmd):
                typed = min(len(cmd), typed + 2)
                img = blank_frame()
                draw = ImageDraw.Draw(img)
                draw_cmd_screen(draw, cmd[:typed], [], True, frame_no % 2 == 0)
                frames.append(img)
                frame_no += 1
            # Output reveal: 2 lines per frame.
            shown = 0
            while shown < len(wrapped):
                shown = min(len(wrapped), shown + 2)
                img = blank_frame()
                draw = ImageDraw.Draw(img)
                draw_cmd_screen(draw, cmd, wrapped[:shown], False, False)
                frames.append(img)
            # Hold.
            for _ in range(HOLD_FRAMES):
                img = blank_frame()
                draw = ImageDraw.Draw(img)
                draw_cmd_screen(draw, cmd, wrapped, False, False)
                frames.append(img)

    frames[0].save(
        OUT,
        save_all=True,
        append_images=frames[1:],
        duration=FRAME_MS,
        loop=0,
        optimize=True,
    )
    duration = len(frames) * FRAME_MS / 1000
    print(f"wrote {OUT}: {len(frames)} frames, {duration:.1f}s, {len(screens)} screens")


if __name__ == "__main__":
    main()
