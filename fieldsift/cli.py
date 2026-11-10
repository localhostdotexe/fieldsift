import argparse
import sys

from . import __version__, hexpat, report
from .analyze import analyze
from .core import HEAD, TAIL, load


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="fieldsift",
        description="Compare samples of an unknown binary format and point out "
                    "the length fields, offsets, checksums and chunk structure.")
    ap.add_argument("files", nargs="+", help="sample files, or a directory of them")
    ap.add_argument("--head", type=int, default=HEAD, metavar="N",
                    help="bytes to examine at the start of each file (default %(default)s)")
    ap.add_argument("--tail", type=int, default=TAIL, metavar="N",
                    help="bytes to examine at the end of each file (default %(default)s)")
    ap.add_argument("--min-bits", type=float, default=12.0, metavar="B",
                    help="drop findings with less evidence than this (default %(default)s)")
    ap.add_argument("--no-sums", action="store_true", help="skip the checksum search")
    ap.add_argument("--no-chunks", action="store_true", help="skip the chunk stream search")
    ap.add_argument("--no-map", action="store_true", help="leave out the annotated hexdump")
    ap.add_argument("--json", action="store_true", help="machine readable output")
    ap.add_argument("--hexpat", metavar="FILE", help="also write an ImHex pattern skeleton")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="show matches that lost out to an overlapping field")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)

    try:
        samples = load(args.files)
    except OSError as e:
        print("fieldsift: %s" % e, file=sys.stderr)
        return 2
    if not samples:
        print("fieldsift: no usable input", file=sys.stderr)
        return 2

    res = analyze(samples, args.head, args.tail, args.min_bits,
                  do_sums=not args.no_sums, do_chunks=not args.no_chunks)
    if args.json:
        print(report.as_json(res))
    else:
        sys.stdout.write(report.text(res, show_map=not args.no_map, verbose=args.verbose))
    if args.hexpat:
        with open(args.hexpat, "w") as fh:
            fh.write(hexpat.render(res))
    return 0
