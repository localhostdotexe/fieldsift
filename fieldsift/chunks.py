"""Look for a tag/length chunk stream (PNG, RIFF, TLV blobs and friends).

Brute force over a small family of layouts. A layout counts as a hit if
hopping from chunk to chunk lands exactly on EOF in every sample.
"""

import math
import zlib
from collections import namedtuple

Layout = namedtuple("Layout", "order tag len endian counts trail align")

MAX_START = 64
SEARCH_BITS = 14
MIN_BITS = 20


def layouts():
    for ln in (4, 2, 1):
        for en in (("be", "le") if ln > 1 else ("",)):
            for tag in ((4, 2, 1, 0) if ln > 1 else (2, 1, 0)):
                for order in (("TL", "LT") if tag else ("L",)):
                    for counts in ("data", "total"):
                        for trail in (0, 4):
                            for align in (1, 2, 4):
                                if ln == 1 and (trail or align > 1):
                                    continue
                                yield Layout(order, tag, ln, en, counts, trail, align)


def walk(data, start, lay, limit=20000):
    """Hop chunk to chunk from start. Returns [(offset, data length)] or None."""
    size = len(data)
    width, trail, align = lay.len, lay.trail, lay.align
    hdr = lay.tag + width
    lo = lay.tag if lay.order == "TL" else 0
    bo = "big" if lay.endian == "be" else "little"
    extra = hdr + trail
    whole = lay.counts == "total"
    if width == 1:
        # one byte lengths hop through anything, don't follow them forever
        limit = 1024
    last = size - hdr
    pos = start
    out = []
    empty = 0
    while pos < size:
        if pos > last:
            return None
        n = int.from_bytes(data[pos + lo:pos + lo + width], bo)
        if whole:
            n -= extra
            if n < 0:
                return None
        end = pos + n + extra
        if end > size:
            return None
        if n:
            empty = 0
        else:
            empty += 1
            if empty > 8:
                return None
        if len(out) >= limit:
            return None
        out.append((pos, n))
        if align > 1:
            end = min(size, -(-end // align) * align)
        pos = end
    return out


def tag_of(data, pos, lay):
    o = pos + (0 if lay.order == "TL" else lay.len)
    return data[o:o + lay.tag]


def texty(tag):
    return all(c == 0x20 or c == 0x5F or 0x30 <= c <= 0x39 or 0x41 <= c <= 0x5A or 0x61 <= c <= 0x7A
               for c in tag)


def _named(data, lay, chunks):
    return lay.tag >= 2 and all(texty(tag_of(data, p, lay)) for p, _ in chunks)


def _score(data, lay, chunks):
    size = len(data)
    bits = 0.0
    for pos, n in chunks:
        if n:
            bits += min(6.0, max(0.0, 8 * lay.len - math.log2(size - pos + 1)))
        if lay.tag >= 2 and texty(tag_of(data, pos, lay)):
            bits += 2.2 * lay.tag
    # landing exactly on EOF is about a 1 in (average chunk size) fluke
    span = (size - chunks[0][0]) / len(chunks)
    return bits + math.log2(span + 1)


def _trailer(samples, start, lay, walks):
    """If chunks end in 4 spare bytes, see whether they are a CRC of the chunk."""
    hdr = lay.tag + lay.len
    tests = {
        "crc32(tag+data)": lambda d, p, n: zlib.crc32(tag_of(d, p, lay) + d[p + hdr:p + hdr + n]),
        "crc32(data)": lambda d, p, n: zlib.crc32(d[p + hdr:p + hdr + n]),
        "crc32(header+data)": lambda d, p, n: zlib.crc32(d[p:p + hdr + n]),
        "adler32(data)": lambda d, p, n: zlib.adler32(d[p + hdr:p + hdr + n]),
    }
    for name, fn in tests.items():
        for bo in ("big", "little"):
            ok = True
            for s, chunks in zip(samples, walks):
                for p, n in chunks:
                    t = p + hdr + n
                    if int.from_bytes(s.data[t:t + 4], bo) != fn(s.data, p, n):
                        ok = False
                        break
                if not ok:
                    break
            if ok:
                return name, "be" if bo == "big" else "le"
    return None


def describe(lay, trailer=None):
    ln = "u8" if lay.len == 1 else "u%d%s" % (lay.len * 8, lay.endian)
    ln = "len:%s" % ln
    if lay.counts == "total":
        ln += " (whole chunk)"
    parts = [ln]
    if lay.tag:
        tag = "tag[%d]" % lay.tag
        parts = [tag, ln] if lay.order == "TL" else [ln, tag]
    parts.append("data")
    if lay.trail:
        parts.append(trailer[0] if trailer else "trailer[4]")
    text = " | ".join(parts)
    if lay.align > 1:
        text += ", padded to %d" % lay.align
    return text


def search(samples):
    order = sorted(samples, key=lambda s: s.size)
    small = order[0]
    best = None
    for lay in layouts():
        top = min(MAX_START, small.size - 1)
        if lay.len == 1:
            top = min(top, 16)
        for start in range(top + 1):
            res = walk(small.data, start, lay)
            if res is None or len(res) < 2:
                continue
            total = 0.0
            walks = {}
            most = 0
            for s in order:
                r = res if s is small else walk(s.data, start, lay)
                if r is None or len(r) < 2:
                    break
                walks[id(s)] = r
                most = max(most, len(r))
                total += _score(s.data, lay, r)
            else:
                total -= SEARCH_BITS
                if total < MIN_BITS:
                    continue
                if most < 3 and not _named(small.data, lay, res):
                    # two chunks is thin, only take it with readable tags
                    continue
                if best is None or total > best["bits"]:
                    best = {"bits": total, "start": start, "layout": lay,
                            "walks": [walks[id(s)] for s in samples]}
    if best is None:
        return None
    lay = best["layout"]
    best["trailer"] = _trailer(samples, best["start"], lay, best["walks"]) if lay.trail else None
    tags = []
    if lay.tag:
        for s, chunks in zip(samples, best["walks"]):
            for p, _ in chunks:
                t = tag_of(s.data, p, lay)
                if t not in tags:
                    tags.append(t)
    best["tags"] = tags
    best["bits"] = min(99.0, best["bits"])
    return best
