"""Field detectors that only need to compare values across samples."""

import math
import time

from .core import Finding, raw, ints

UNITS = (1, 2, 4, 8, 16, 512, 1024, 2048, 4096)
EPOCH_LO = 946684800  # 2000-01-01


def _endians(width):
    return ("le", "be") if width > 1 else ("",)


def _fit(vals, sizes):
    """Solve size = k * value + c from the first pair that differs."""
    j = next((i for i in range(1, len(vals)) if vals[i] != vals[0]), None)
    if j is None:
        return None
    dv = vals[j] - vals[0]
    ds = sizes[j] - sizes[0]
    if ds % dv:
        return None
    k = ds // dv
    if k not in UNITS:
        return None
    c = sizes[0] - k * vals[0]
    if c < 0:
        return None
    for v, sz in zip(vals, sizes):
        if k * v + c != sz:
            return None
    return k, c


def _length_note(frame, off, width, k, c):
    if k == 1:
        if c == 0:
            return "file size"
        if frame == "start" and c == off + width:
            return "bytes following this field"
        if frame == "start" and c == off:
            return "bytes from this field to EOF"
        return "file size - 0x%x" % c
    if c:
        return "(file size - 0x%x) / %d" % (c, k)
    return "file size / %d" % k


def lengths(samples, where):
    sizes = [s.size for s in samples]
    nsz = len(set(sizes))
    spread = max(sizes) - min(sizes)
    out = []
    for frame, off in where:
        for width in (2, 4, 8):
            chunks = raw(samples, frame, off, width)
            if chunks is None:
                continue
            for en in _endians(width):
                vals = ints(chunks, en)
                if min(vals) <= 0:
                    continue
                if nsz > 1:
                    hit = _fit(vals, sizes)
                    if not hit:
                        continue
                    k, c = hit
                    bits = (nsz - 1) * min(8 * width, math.log2(spread + 1))
                    bits -= math.log2(len(UNITS))
                else:
                    # one size only: accept just the obvious relations
                    k, c = 1, sizes[0] - vals[0]
                    ok = {0, off, off + width} | set(range(4, 68, 4))
                    if len(set(vals)) != 1 or c not in ok:
                        continue
                    bits = min(8 * width, math.log2(sizes[0])) - 4.5
                out.append(Finding("length", frame, off, width, en, min(bits, 99.0),
                                   _length_note(frame, off, width, k, c),
                                   {"unit": k, "slack": c}))
    return out


def pointers(samples, where):
    """Values that vary per sample but always land on the same 4 bytes."""
    if len(samples) < 2:
        return []
    out = []
    for frame, off in where:
        for width in (2, 4, 8):
            chunks = raw(samples, frame, off, width)
            if chunks is None or len(set(chunks)) < 2:
                continue
            for en in _endians(width):
                vals = ints(chunks, en)
                for base in ("file", "field", "after"):
                    targets = []
                    for s, v in zip(samples, vals):
                        t = v
                        if base != "file":
                            t += s.pos(frame, off) + (width if base == "after" else 0)
                        if t < 0 or t + 4 > s.size:
                            break
                        targets.append(t)
                    else:
                        marks = {s.data[t:t + 4] for s, t in zip(samples, targets)}
                        if len(marks) != 1:
                            continue
                        mark = marks.pop()
                        if len(set(mark)) < 3:
                            continue
                        n = len(set(targets))
                        if n < 2:
                            continue
                        rel = {"file": "file offset", "field": "offset from this field",
                               "after": "offset from end of this field"}[base]
                        out.append(Finding("pointer", frame, off, width, en,
                                           min(99.0, (n - 1) * 32 - 3),
                                           "%s, target always starts %s" % (rel, mark.hex(" ")),
                                           {"base": base, "mark": mark.hex()}))
    return out


def timestamps(samples, where):
    hi = int(time.time()) + 30 * 86400
    out = []
    for frame, off in where:
        if frame == "start" and off % 4:
            continue
        chunks = raw(samples, frame, off, 4)
        if chunks is None:
            continue
        n = len(set(chunks))
        if len(samples) > 1 and n < 2:
            continue
        for en in ("le", "be"):
            vals = ints(chunks, en)
            if min(vals) < EPOCH_LO or max(vals) > hi:
                continue
            fmt = lambda t: time.strftime("%Y-%m-%d", time.gmtime(t))
            a, b = fmt(min(vals)), fmt(max(vals))
            note = "unix time, " + (a if a == b else "%s .. %s" % (a, b))
            # roughly a 1 in 5 chance for a random u32 to fall in range
            out.append(Finding("time", frame, off, 4, en, 2.3 * n, note))
    return out


def _printable(b):
    return all(0x20 <= c < 0x7f for c in b)


def pstrings(samples, where):
    out = []
    for frame, off in where:
        if frame != "start":
            continue
        for width in (1, 2, 4):
            chunks = raw(samples, frame, off, width)
            if chunks is None:
                continue
            for en in _endians(width):
                vals = ints(chunks, en)
                if min(vals) < 3 or max(vals) > 255:
                    continue
                texts = []
                open_ended = True
                for s, v in zip(samples, vals):
                    p = off + width
                    t = s.data[p:p + v]
                    if len(t) != v or not _printable(t):
                        break
                    nxt = s.data[p + v:p + v + 1]
                    if not nxt or not _printable(nxt):
                        open_ended = False
                    texts.append(t)
                else:
                    if open_ended:
                        continue
                    uniq = set(texts)
                    if len(samples) > 1 and len(uniq) < 2:
                        continue
                    bits = min(64.0, sum(1.4 * len(t) for t in uniq) - 6)
                    eg = sorted(uniq)[0].decode("ascii")
                    out.append(Finding("string", frame, off, width, en, bits,
                                       'length-prefixed string, e.g. "%s"' % eg,
                                       {"maxlen": max(vals), "len0": vals[0]}))
    return out


def constants(samples, where):
    """Runs of bytes that are identical in every sample."""
    if len(samples) < 2:
        return []
    out = []
    run = None

    def flush():
        nonlocal run
        if run and len(run[2]) >= 2:
            frame, off, data = run
            if any(data):
                kind = "magic" if frame == "start" and off == 0 else "const"
            else:
                kind = "zero"
            bits = min(99.0, 8.0 * len(data) * (len(samples) - 1))
            out.append(Finding(kind, frame, off, len(data), "", bits, "", {"bytes": bytes(data).hex()}))
        run = None

    for frame, off in where:
        col = raw(samples, frame, off, 1)
        same = col is not None and len(set(col)) == 1
        if not same:
            flush()
            continue
        if run and run[0] == frame and run[1] + len(run[2]) == off:
            run[2].append(col[0][0])
        else:
            flush()
            run = (frame, off, bytearray(col[0]))
    flush()
    return out
