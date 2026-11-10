import os
from dataclasses import dataclass, field

HEAD = 256
TAIL = 64

BYTEORDER = {"le": "little", "be": "big", "": "little"}


class Sample:
    def __init__(self, path, data=None):
        self.path = path
        self.name = os.path.basename(path)
        if data is None:
            with open(path, "rb") as fh:
                data = fh.read()
        self.data = data
        self.size = len(data)

    def pos(self, frame, off):
        # "end" offsets are negative, counted back from EOF
        return off if frame == "start" else self.size + off


@dataclass
class Finding:
    kind: str
    frame: str
    off: int
    width: int
    endian: str = ""
    bits: float = 0.0
    note: str = ""
    info: dict = field(default_factory=dict)

    @property
    def type(self):
        if self.kind == "digest":
            return self.info.get("algo", "bytes")
        if self.kind in ("const", "magic", "zero"):
            return "bytes"
        if self.width == 1:
            return "u8"
        return "u%d%s" % (self.width * 8, self.endian)


def load(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            for name in sorted(os.listdir(p)):
                full = os.path.join(p, name)
                if os.path.isfile(full):
                    files.append(full)
        else:
            files.append(p)
    out = []
    for f in files:
        s = Sample(f)
        if s.size:
            out.append(s)
    return out


def spots(samples, head=HEAD, tail=TAIL):
    """Offsets worth looking at: the first `head` bytes and the last `tail`.

    If every sample has the same size there is no difference between
    counting from the front or the back, so everything is reported from
    the start.
    """
    lo = min(s.size for s in samples)
    out = [("start", o) for o in range(min(head, lo))]
    same = len({s.size for s in samples}) == 1
    for o in range(-min(tail, lo), 0):
        if same:
            if lo + o >= head:
                out.append(("start", lo + o))
        else:
            out.append(("end", o))
    return out


def raw(samples, frame, off, width):
    out = []
    for s in samples:
        p = s.pos(frame, off)
        if p < 0 or p + width > s.size:
            return None
        out.append(s.data[p:p + width])
    return out


def ints(chunks, endian):
    bo = BYTEORDER[endian]
    return [int.from_bytes(c, bo) for c in chunks]
