"""Work out which checksum or digest sits in a field, and over which bytes.

The search runs on the smallest sample. Anything that matches there is
then replayed on the other samples, so a wrong guess has to survive
several files of different sizes before it gets reported.
"""

import array
import binascii
import hashlib
import sys
import zlib
from collections import defaultdict
from functools import lru_cache

from .core import Finding, raw

FIXED = (4, 8, 12, 16, 20, 24, 28, 32, 40, 48, 56, 64, 128, 256, 512, 1024, 2048, 4096)
TRAIL = (0, 4, 8, 12, 16, 20, 32)
WIDTHS = (1, 2, 4, 16, 20, 32)
DIGESTS = {16: "md5", 20: "sha1", 32: "sha256"}
MINLEN = 8
SEARCH_BITS = 12  # log2 of roughly how many (range, algorithm) pairs get tried

FIELD = ("field",)
AFTER = ("after",)


def _xor(seg):
    # fold the buffer in half until one byte is left
    n = len(seg)
    x = int.from_bytes(seg, "big")
    while n > 1:
        h = (n + 1) // 2
        x = (x >> (h * 8)) ^ (x & ((1 << (h * 8)) - 1))
        n = h
    return x


def _mul16(a, b):
    """Multiply two polynomials mod the CCITT one (0x1021)."""
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
        if a & 0x10000:
            a ^= 0x11021
    return r


@lru_cache(maxsize=None)
def _xpow(nbytes):
    """x^(8 * nbytes) mod the CCITT polynomial."""
    r, base = 1, 0x100
    while nbytes:
        if nbytes & 1:
            r = _mul16(r, base)
        base = _mul16(base, base)
        nbytes >>= 1
    return r


def _wordsums(seg):
    a = array.array("I")
    a.frombytes(seg)
    native = sum(a)
    a.byteswap()
    other = sum(a)
    return (native, other) if sys.byteorder == "little" else (other, native)


class Running:
    """The CRCs and digests, fed piece by piece so ranges can share work."""

    def __init__(self, need=WIDTHS):
        self.need = set(need)
        self.crc = 0
        self.adler = 1
        self.x0 = 0
        self.shift = 1
        self.hashes = {w: hashlib.new(name) for w, name in DIGESTS.items() if w in self.need}

    def copy(self, need=None):
        c = Running(())
        c.__dict__.update(self.__dict__)
        c.need = set(need) if need else set(self.need)
        c.hashes = {w: h.copy() for w, h in self.hashes.items() if w in c.need}
        return c

    def feed(self, seg):
        if not len(seg):
            return
        if 4 in self.need:
            self.crc = zlib.crc32(seg, self.crc)
            self.adler = zlib.adler32(seg, self.adler)
        if 2 in self.need:
            self.x0 = binascii.crc_hqx(seg, self.x0)
            self.shift = _mul16(self.shift, _xpow(len(seg)))
        for h in self.hashes.values():
            h.update(seg)

    def table(self):
        t = {}
        if 2 in self.need:
            # crc_hqx is the slowest primitive here, so run it once with
            # init 0 and get the init 0xffff variant from linearity:
            # crc(init, m) = crc(0, m) ^ init * x^(8 * len(m))
            ccitt = self.x0 ^ _mul16(0xFFFF, self.shift)
            t[2] = [("crc16/xmodem", self.x0), ("crc16/ccitt-false", ccitt)]
        if 4 in self.need:
            t[4] = [("crc32", self.crc), ("crc32/jamcrc", ~self.crc & 0xFFFFFFFF),
                    ("adler32", self.adler)]
        for w, h in self.hashes.items():
            t[w] = [(DIGESTS[w], h.digest())]
        return t


def _plain(name):
    return name.startswith("sum")


def _additive(need, bsum, xor, words):
    """Table entries for the plain sums, from totals over some range."""
    t = {}
    if 1 in need:
        t[1] = [("sum8", bsum & 0xFF), ("-sum8", -bsum & 0xFF), ("xor8", xor)]
    if 2 in need:
        t[2] = [("sum16", bsum & 0xFFFF), ("-sum16", -bsum & 0xFFFF), ("~sum16", ~bsum & 0xFFFF)]
    if 4 in need:
        m = 0xFFFFFFFF
        t[4] = [("sum32", bsum & m), ("-sum32", -bsum & m)]
        if words:
            le, be = words
            t[4] += [("sum of u32le words", le & m), ("-(sum of u32le words)", -le & m),
                     ("sum of u32be words", be & m), ("-(sum of u32be words)", -be & m)]
    return t


class Prefix:
    """Byte sums, xor and word sums up to a set of offsets.

    These are the slow ones in pure Python, but they are all additive, so
    one pass over the file is enough to answer any range between two of
    the offsets.
    """

    def __init__(self, data, points):
        d = memoryview(data)
        pts = sorted(set(points) | {0})
        self.bsum = {0: 0}
        self.xor = {0: 0}
        self.words = {0: (0, 0)}
        total = x = 0
        for a, b in zip(pts, pts[1:]):
            total += sum(d[a:b])
            x ^= _xor(d[a:b])
            self.bsum[b] = total
            self.xor[b] = x
        grid = [p for p in pts if p % 4 == 0]
        le = be = 0
        for a, b in zip(grid, grid[1:]):
            l, r = _wordsums(d[a:b])
            le += l
            be += r
            self.words[b] = (le, be)

    def table(self, need, a, b, hole=None):
        """hole is the (bytes, offset) of a field to count as zero."""
        bsum = self.bsum[b] - self.bsum[a]
        xor = self.xor[b] ^ self.xor[a]
        words = None
        if a % 4 == 0 and b % 4 == 0:
            wa, wb = self.words[a], self.words[b]
            words = (wb[0] - wa[0], wb[1] - wa[1])
        if hole:
            gone, p = hole
            bsum -= sum(gone)
            xor ^= _xor(gone)
            if words and len(gone) == 4 and p % 4 == 0:
                words = (words[0] - int.from_bytes(gone, "little"),
                         words[1] - int.from_bytes(gone, "big"))
            else:
                words = None
        return _additive(need, bsum, xor, words)


def _candidates(samples, where, min_bits):
    n = len(samples)
    out = []
    for frame, off in where:
        for w in WIDTHS:
            if frame == "start" and off % min(w, 4):
                continue
            chunks = raw(samples, frame, off, w)
            if chunks is None:
                continue
            distinct = len(set(chunks))
            if n > 1 and distinct < 2:
                continue
            if n == 1 and chunks[0] in (bytes(w), b"\xff" * w):
                continue
            if 8 * w * distinct - SEARCH_BITS < min_bits:
                continue
            out.append((frame, off, w))
    return out


def _ends(a, size, marks=()):
    e = defaultdict(set)
    for k in TRAIL:
        if size - k > a:
            e[size - k].add(("eof", k))
    for f in FIXED:
        if a < f < size:
            e[f].add(("abs", f))
    for i, m in marks:
        if a < m <= size:
            e[m].add(("ref", i))
    return e


def _discover(base, cands, refs, single):
    d = memoryview(base.data)
    size = base.size
    marks = [(i, r["at"][id(base)]) for i, r in enumerate(refs)]
    need = {c[2] for c in cands}
    where = {c: base.pos(c[0], c[1]) for c in cands}
    byval = defaultdict(list)
    for c in cands:
        w = c[2]
        b = base.data[where[c]:where[c] + w]
        if w > 8:
            byval[(w, b)].append((c, ""))
            continue
        le, be = int.from_bytes(b, "little"), int.from_bytes(b, "big")
        byval[(w, le)].append((c, "le" if w > 1 else ""))
        if be != le:
            byval[(w, be)].append((c, "be"))

    points = {0, size} | {m for _, m in marks if m <= size}
    points |= {f for f in FIXED if f < size} | {size - k for k in TRAIL if k < size}
    for c in cands:
        points |= {where[c], where[c] + c[2]}
    prefix = Prefix(base.data, points) if need & {1, 2, 4} else None

    hyps = defaultdict(list)

    def probe(st, a, b, sspec, especs, mode, only=None):
        if b - a < MINLEN:
            return
        tables = [st.table()]
        if prefix and mode != "skip":
            hole = None
            if mode:
                (c,) = only
                hole = (base.data[where[c]:where[c] + c[2]], where[c])
            tables.append(prefix.table(st.need, a, b, hole))
        for t in tables:
            for w, vals in t.items():
                for algo, val in vals:
                    for c, en in byval.get((w, val), ()):
                        if only is not None and c not in only:
                            continue
                        p = where[c]
                        if mode is None and not (p + w <= a or p >= b):
                            continue
                        if _plain(algo) and (b - a < 16 or base.data.find(base.data[p:p + w], a, b) >= 0):
                            # a copy of the value sitting in the range "sums" to itself
                            continue
                        for espec in especs:
                            if espec == FIELD and p != b:
                                continue
                            hyps[c + (en,)].append((algo, sspec, espec, mode))

    def inside_ok(c):
        p, w = where[c], c[2]
        return (p <= 64 and p % min(w, 4) == 0) or size - p <= 4096

    snap = {}
    want_snap = {where[c] for c in cands if inside_ok(c)}

    # ranges that start at a fixed offset or at a pointer target
    starts = [(a, ("abs", a)) for a in (0,) + FIXED if a < size]
    starts += [(m, ("ref", i)) for i, m in marks if m < size]
    for a, sspec in starts:
        stops = _ends(a, size, marks)
        for c in cands:
            if where[c] > a:
                stops[where[c]].add(FIELD)
        st = Running(need)
        cur = a
        if a == 0 and 0 in want_snap:
            snap[0] = st.copy()
        for b in sorted(stops):
            st.feed(d[cur:b])
            cur = b
            probe(st, a, b, sspec, stops[b], None)
            if sspec == ("abs", 0) and b in want_snap:
                snap[b] = st.copy()

    # ranges that start right behind the field
    afters = defaultdict(set)
    for c in cands:
        q = where[c] + c[2]
        near = size - q <= 4096
        if single:
            ok = near or (q % 4 == 0 and q <= 128)
        else:
            ok = near or q % 4 == 0 or q <= 64
        if ok:
            afters[q].add(c)
    for q, cs in afters.items():
        if q >= size:
            continue
        stops = _ends(q, size, marks)
        st = Running({c[2] for c in cs})
        cur = q
        for b in sorted(stops):
            st.feed(d[cur:b])
            cur = b
            probe(st, q, b, AFTER, stops[b], None, cs)

    # ranges from 0 that run over the field itself (zeroed out or left out)
    for c in cands:
        p, w = where[c], c[2]
        if p not in snap or not inside_ok(c):
            continue
        stops = _ends(p + w - 1, size, marks)
        for mode in ("zero", "skip"):
            st = snap[p].copy({w})
            if mode == "zero":
                st.feed(bytes(w))
            cur = p + w
            for b in sorted(stops):
                st.feed(d[cur:b])
                cur = b
                probe(st, 0, b, ("abs", 0), stops[b], mode, {c})
    return hyps


def _bounds(s, p, w, hyp, refs):
    _, ss, es, mode = hyp
    if ss[0] == "abs":
        a = ss[1]
    elif ss[0] == "ref":
        a = refs[ss[1]]["at"][id(s)]
    else:
        a = p + w
    if es[0] == "eof":
        b = s.size - es[1]
    elif es[0] == "abs":
        b = es[1]
    elif es[0] == "ref":
        b = refs[es[1]]["at"][id(s)]
    else:
        b = p
    if a < 0 or b > s.size or b - a < MINLEN:
        return None
    if mode is None:
        if not (p + w <= a or p >= b):
            return None
    elif not (a <= p and p + w <= b):
        return None
    return a, b


def _replay(s, fields, refs):
    """Check every surviving guess against one more sample.

    fields maps (frame, off, width, endian) to its list of guesses and is
    pruned in place.
    """
    todo = []
    points = set()
    for key, hl in fields.items():
        frame, off, w, en = key
        p = s.pos(frame, off)
        for h in hl:
            ab = _bounds(s, p, w, h, refs) if 0 <= p <= s.size - w else None
            todo.append((key, h, p, ab))
            if ab and w <= 4 and h[3] != "skip":
                points.update(ab)
    prefix = Prefix(s.data, points) if points else None
    d = memoryview(s.data)
    cache = {}
    keep = defaultdict(list)
    for key, h, p, ab in todo:
        if ab is None:
            continue
        w, en = key[2], key[3]
        a, b = ab
        algo, mode = h[0], h[3]
        ck = (a, b, w, mode, p if mode else None)
        if ck not in cache:
            st = Running({w})
            if mode:
                st.feed(d[a:p])
                if mode == "zero":
                    st.feed(bytes(w))
                st.feed(d[p + w:b])
            else:
                st.feed(d[a:b])
            t = dict(st.table().get(w, ()))
            if prefix and w <= 4 and mode != "skip":
                hole = (s.data[p:p + w], p) if mode else None
                t.update(prefix.table({w}, a, b, hole).get(w, ()))
            cache[ck] = t
        want = cache[ck].get(algo)
        have = s.data[p:p + w]
        if w <= 8:
            have = int.from_bytes(have, "big" if en == "be" else "little")
        if have == want:
            keep[key].append(h)
    fields.clear()
    fields.update(keep)


def _rank(hyp):
    _, ss, es, mode = hyp
    m = {None: 0, "zero": 1, "skip": 2}[mode]
    if ss == AFTER or ss[0] == "ref":
        s = 1
    else:
        s = 0 if ss[1] == 0 else 2
    if es == ("eof", 0):
        e = 0
    elif es == FIELD or es[0] == "ref":
        e = 1
    elif es[0] == "eof":
        e = 2
    else:
        e = 3
    return (m, s + e, s, e)


def describe(hyp, refs=()):
    algo, ss, es, mode = hyp
    if ss == AFTER:
        a = "end of field"
    elif ss[0] == "ref":
        a = refs[ss[1]]["name"]
    else:
        a = "0x%x" % ss[1]
    if es == FIELD:
        b = "this field"
    elif es[0] == "ref":
        b = refs[es[1]]["name"]
    elif es[0] == "abs":
        b = "0x%x" % es[1]
    else:
        b = "EOF-%d" % es[1] if es[1] else "EOF"
    text = "%s of %s .. %s" % (algo, a, b)
    if mode == "zero":
        text += ", field zeroed"
    elif mode == "skip":
        text += ", field left out"
    return text


def search(samples, where, min_bits=12.0, refs=()):
    """refs are extra range boundaries that move per file, e.g. pointer targets."""
    cands = _candidates(samples, where, min_bits)
    if not cands:
        return []
    order = sorted(samples, key=lambda s: s.size)
    hyps = _discover(order[0], cands, refs, len(samples) == 1)
    fields = {k: list(dict.fromkeys(v)) for k, v in hyps.items()}
    for s in order[1:]:
        if not fields:
            break
        _replay(s, fields, refs)
    out = []
    for (frame, off, w, en), alive in fields.items():
        best = min(alive, key=_rank)
        distinct = len(set(raw(samples, frame, off, w)))
        bits = min(99.0, 8 * min(w, 12) * distinct - SEARCH_BITS)
        kind = "digest" if w > 8 else "checksum"
        out.append(Finding(kind, frame, off, w, en, bits, describe(best, refs),
                           {"algo": best[0], "start": list(best[1]), "end": list(best[2]),
                            "mode": best[3], "alternatives": len(alive) - 1}))
    return out
