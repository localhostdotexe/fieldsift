from . import chunks, detect, sums
from .core import HEAD, TAIL, spots

# on a tie the 4 byte reading is usually the right one
WIDTH_PREF = {4: 0, 2: 1, 8: 2, 1: 3}
FILLER = ("magic", "const", "zero")


class Result:
    def __init__(self, samples):
        self.samples = samples
        self.fields = []
        self.rejected = []
        self.chunks = None


def _span(f, base):
    lo = base.pos(f.frame, f.off)
    return lo, lo + f.width


def _settle(found, base):
    """Pick a non-overlapping set of fields, strongest evidence first."""
    typed = [f for f in found if f.kind not in FILLER]
    typed.sort(key=lambda f: (-f.bits, WIDTH_PREF.get(f.width, 4), f.kind != "pointer"))
    taken = []
    keep, drop = [], []
    for f in typed:
        lo, hi = _span(f, base)
        if any(lo < b and a < hi for a, b in taken):
            drop.append(f)
        else:
            taken.append((lo, hi))
            keep.append(f)

    # constant runs only get whatever the typed fields left over
    for f in found:
        if f.kind not in FILLER:
            continue
        lo, hi = _span(f, base)
        data = bytes.fromhex(f.info["bytes"])
        start = lo
        cuts = sorted((a, b) for a, b in taken if a < hi and lo < b)
        pieces = []
        for a, b in cuts:
            if a > start:
                pieces.append((start, a))
            start = max(start, b)
        if start < hi:
            pieces.append((start, hi))
        for a, b in pieces:
            part = data[a - lo:b - lo]
            if len(part) < 2:
                continue
            kind = f.kind if any(part) else "zero"
            if kind == "magic" and a != lo:
                kind = "const"
            g = type(f)(kind, f.frame, f.off + (a - lo), b - a, "", f.bits, "", {"bytes": part.hex()})
            keep.append(g)
    keep.sort(key=lambda f: (f.frame != "start", f.off))
    return keep, drop


def _weigh(found):
    """Mark down fields that go against the file's byte order or alignment.

    A little-endian value with a zero byte next to it reads just as well
    big-endian one byte over, so without this the two readings tie.
    """
    votes = {"le": 0.0, "be": 0.0}
    for f in found:
        if f.endian and f.kind not in FILLER and f.off % min(f.width, 4) == 0:
            votes[f.endian] += f.bits
    major = None
    if votes["le"] > 2 * votes["be"]:
        major = "le"
    elif votes["be"] > 2 * votes["le"]:
        major = "be"
    for f in found:
        if f.kind in FILLER or f.width > 8:
            continue
        odd = f.frame == "start" and f.off % min(f.width, 4) != 0
        if odd:
            f.bits *= 0.8
        if major and f.endian and f.endian != major:
            f.bits *= 0.5 if not odd else 0.1


def _refs(samples, ptrs, min_bits):
    """Pointer targets double as range boundaries for the checksum search."""
    refs = []
    seen = set()
    for f in sorted(ptrs, key=lambda f: (-f.bits, WIDTH_PREF.get(f.width, 4))):
        if f.bits < min_bits:
            continue
        at = {}
        for s in samples:
            p = s.pos(f.frame, f.off)
            v = int.from_bytes(s.data[p:p + f.width], "big" if f.endian == "be" else "little")
            if f.info["base"] != "file":
                v += p + (f.width if f.info["base"] == "after" else 0)
            at[id(s)] = v
        key = tuple(at[id(s)] for s in samples)
        if key in seen:
            continue
        seen.add(key)
        where = "0x%x" % f.off if f.frame == "start" else "EOF-%d" % -f.off
        refs.append({"name": "target(%s)" % where, "at": at})
    return refs[:8]


def analyze(samples, head=HEAD, tail=TAIL, min_bits=12.0, do_sums=True, do_chunks=True):
    res = Result(samples)
    where = spots(samples, head, tail)
    found = []
    found += detect.constants(samples, where)
    found += detect.lengths(samples, where)
    ptrs = detect.pointers(samples, where)
    found += ptrs
    found += detect.timestamps(samples, where)
    found += detect.pstrings(samples, where)
    if do_sums:
        found += sums.search(samples, where, min_bits, _refs(samples, ptrs, min_bits))
    _weigh(found)
    strong = [f for f in found if f.kind in FILLER or f.bits >= min_bits]
    res.fields, res.rejected = _settle(strong, samples[0])
    if do_chunks:
        res.chunks = chunks.search(samples)
    return res
