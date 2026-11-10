import json

from . import chunks as chunkmod

LETTER = {"magic": "M", "const": "c", "zero": "0", "length": "L", "pointer": "P",
          "checksum": "S", "digest": "S", "time": "T", "string": "A"}


def _size(n):
    for unit in ("", "K", "M", "G"):
        if n < 1024 or unit == "G":
            return ("%d%s" % (n, unit)) if unit == "" else ("%.1f%s" % (n, unit))
        n /= 1024.0


def _ascii(b):
    return "".join(chr(c) if 0x20 <= c < 0x7F else "." for c in b)


def _off(f):
    return "0x%04x" % f.off if f.frame == "start" else "-0x%02x" % -f.off


def _row(f):
    if f.kind in ("magic", "const", "zero"):
        data = bytes.fromhex(f.info["bytes"])
        shown = data[:12].hex(" ") + (" .." if len(data) > 12 else "")
        note = shown if f.kind == "zero" else '%s  "%s"' % (shown, _ascii(data[:24]))
        return "  %-7s %3d  %-7s %-9s %s" % (_off(f), f.width, "", f.kind, note)
    return "  %-7s %3d  %-7s %-9s %-52s %4.0f bits" % (_off(f), f.width, f.type, f.kind, f.note, f.bits)


def hexmap(res, rows=None):
    base = res.samples[0]
    marks = {}
    for f in res.fields:
        lo = base.pos(f.frame, f.off)
        for i in range(lo, lo + f.width):
            marks[i] = LETTER.get(f.kind, "?")
        if f.kind == "string":
            for i in range(lo + f.width, lo + f.width + f.info["len0"]):
                marks.setdefault(i, "a")
    shown = sorted(marks)
    if not shown:
        return []
    last = max(i for i in shown if i < 4096) if any(i < 4096 for i in shown) else 0
    out = []
    for line in range(0, last + 1, 16):
        if rows is not None and line // 16 >= rows:
            break
        row = base.data[line:line + 16]
        hx = " ".join("%02x" % b for b in row)
        cls = "".join(marks.get(line + i, ".") for i in range(len(row)))
        out.append("  %04x  %-47s  %s" % (line, hx, cls))
    return out


def text(res, show_map=True, verbose=False):
    ss = res.samples
    sizes = [s.size for s in ss]
    lines = []
    span = _size(min(sizes)) if min(sizes) == max(sizes) else "%s .. %s" % (_size(min(sizes)), _size(max(sizes)))
    lines.append("%d sample%s, %s" % (len(ss), "" if len(ss) == 1 else "s", span))
    if len(ss) == 1:
        lines.append("only one sample: nothing to compare against, expect thin results")
    elif min(sizes) == max(sizes):
        lines.append("all samples are the same size, so length fields can't be confirmed")
    lines.append("")

    for frame, title in (("start", "from start of file"), ("end", "from end of file")):
        rows = [f for f in res.fields if f.frame == frame and f.kind != "zero"]
        if not rows:
            continue
        lines.append(title)
        lines += [_row(f) for f in rows]
        lines.append("")

    ch = res.chunks
    if ch:
        lay = ch["layout"]
        counts = [len(w) for w in ch["walks"]]
        n = str(counts[0]) if min(counts) == max(counts) else "%d-%d" % (min(counts), max(counts))
        lines.append("chunk stream from 0x%x  (%.0f bits)" % (ch["start"], ch["bits"]))
        lines.append("  " + chunkmod.describe(lay, ch["trailer"]))
        lines.append("  %s chunks per file" % n)
        if ch["tags"]:
            tags = ch["tags"]
            if all(chunkmod._texty(t) for t in tags):
                shown = " ".join(t.decode("ascii") for t in tags[:16])
            else:
                shown = " ".join(t.hex() for t in tags[:16])
            lines.append("  tags: %s%s" % (shown, " .." if len(tags) > 16 else ""))
        lines.append("")

    if not res.fields and not ch:
        lines.append("nothing stood out. more samples (with different sizes) usually help.")
        lines.append("")

    if verbose and res.rejected:
        lines.append("also matched, but overlaps a stronger field")
        lines += [_row(f) for f in sorted(res.rejected, key=lambda f: (f.frame != "start", f.off))]
        lines.append("")

    if show_map:
        m = hexmap(res, rows=None if verbose else 16)
        if m:
            lines.append("map of %s" % ss[0].name)
            lines += m
            lines.append("  M magic  c const  0 zero  L length  P pointer  S checksum  T time  Aa string")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def as_json(res):
    doc = {
        "samples": [{"name": s.name, "size": s.size} for s in res.samples],
        "fields": [],
        "chunks": None,
    }
    for f in res.fields:
        doc["fields"].append({
            "kind": f.kind, "frame": f.frame, "offset": f.off, "width": f.width,
            "type": f.type, "bits": round(f.bits, 1), "note": f.note, "info": f.info,
        })
    ch = res.chunks
    if ch:
        doc["chunks"] = {
            "start": ch["start"], "bits": round(ch["bits"], 1),
            "layout": ch["layout"]._asdict(),
            "trailer": list(ch["trailer"]) if ch["trailer"] else None,
            "tags": [t.hex() for t in ch["tags"]],
            "counts": [len(w) for w in ch["walks"]],
        }
    return json.dumps(doc, indent=2)
