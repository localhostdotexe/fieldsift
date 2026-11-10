#!/usr/bin/env python3
"""Write a few fake firmware images to try fieldsift on.

The layout is made up, but it has the usual suspects:

    00  "NVFW"
    04  u16 header version
    06  u16 flags
    08  u32 image size (whole file)
    0c  u32 build time
    10  u32 offset of the payload
    14  u32 crc32 of everything behind the header
    18  u8 name length, then the board name
    ..  padding to 4
    ..  "PAYL" + payload
   end  sha256 of everything before it
"""

import hashlib
import os
import random
import struct
import sys
import zlib

BOARDS = ["rtr-ac1200", "cam-dome-v2", "nvr8", "sw-24p-poe", "ap-outdoor-lr", "gw-lte"]


def build(rng, board):
    name = board.encode()
    payload = b"PAYL" + rng.randbytes(rng.randrange(900, 40000))
    hdr_len = 0x18 + 1 + len(name)
    hdr_len += -hdr_len % 4
    total = hdr_len + len(payload) + 32
    when = 1650000000 + rng.randrange(0, 60000000)

    hdr = bytearray(hdr_len)
    hdr[0:4] = b"NVFW"
    struct.pack_into("<HHIII", hdr, 4, 2, rng.choice([0, 1, 5]), total, when, hdr_len)
    hdr[0x18] = len(name)
    hdr[0x19:0x19 + len(name)] = name
    struct.pack_into("<I", hdr, 0x14, zlib.crc32(payload))

    body = bytes(hdr) + payload
    return body + hashlib.sha256(body).digest()


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "fw"
    os.makedirs(out, exist_ok=True)
    rng = random.Random(7)
    for board in BOARDS:
        path = os.path.join(out, board + ".bin")
        with open(path, "wb") as fh:
            fh.write(build(rng, board))
        print(path)


if __name__ == "__main__":
    main()
