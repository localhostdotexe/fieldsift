"""Small in-memory file formats to run the detectors against."""

import binascii
import hashlib
import struct
import zlib

from fieldsift.core import Sample


def samples(blobs):
    return [Sample("s%d.bin" % i, b) for i, b in enumerate(blobs)]


def png(rng, w, h, comment=False):
    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))

    rows = b"".join(b"\0" + rng.randbytes(w * 3) for _ in range(h))
    idat = zlib.compress(rows)
    out = [chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))]
    if comment:
        out.append(chunk(b"tEXt", b"Comment\0hello"))
    out += [chunk(b"IDAT", idat), chunk(b"IEND", b"")]
    return b"\x89PNG\r\n\x1a\n" + b"".join(out)


def riff(rng, n):
    fmt = b"fmt " + struct.pack("<IHHIIHH", 16, 1, 1, 8000, 16000, 2, 16)
    data = rng.randbytes(n + (n & 1))
    lst = b"LIST" + struct.pack("<I", 12) + b"INFOabcdefgh"
    body = b"WAVE" + fmt + lst + b"data" + struct.pack("<I", len(data)) + data
    return b"RIFF" + struct.pack("<I", len(body)) + body


def firmware(rng, name):
    """Header with size, payload offset, payload crc and a sha256 trailer."""
    payload = b"PAYL" + rng.randbytes(rng.randrange(600, 9000))
    hlen = 0x18 + 1 + len(name)
    hlen += -hlen % 4
    hdr = bytearray(hlen)
    hdr[0:4] = b"NVFW"
    total = hlen + len(payload) + 32
    struct.pack_into("<HHIII", hdr, 4, 2, 0, total, 1650000000 + rng.randrange(50000000), hlen)
    struct.pack_into("<I", hdr, 0x14, zlib.crc32(payload))
    hdr[0x18] = len(name)
    hdr[0x19:0x19 + len(name)] = name
    body = bytes(hdr) + payload
    return body + hashlib.sha256(body).digest()


def be_header(rng):
    """Big-endian header whose crc covers the header with the crc zeroed."""
    body = rng.randbytes(rng.randrange(300, 5000))
    hdr = bytearray(32)
    hdr[0:4] = b"\xcaBEh"
    struct.pack_into(">I", hdr, 4, len(body))
    struct.pack_into(">H", hdr, 8, rng.randrange(1, 9))
    hdr[12:20] = rng.randbytes(8)
    struct.pack_into(">I", hdr, 28, zlib.crc32(bytes(hdr)))
    return bytes(hdr) + body


def summed(rng):
    """Record that ends in a one byte two's complement checksum."""
    body = b"\x02REC" + rng.randbytes(rng.randrange(40, 400))
    return body + bytes([-sum(body) & 0xFF])


def crc16_frame(rng):
    """Magic, crc16/ccitt-false of the payload, then the payload."""
    body = rng.randbytes(rng.randrange(60, 3000))
    return b"\x7eFRM" + struct.pack(">H", binascii.crc_hqx(body, 0xFFFF)) + b"\0\0" + body


def tlv(rng):
    out = b"TLV1"
    for _ in range(rng.randrange(5, 12)):
        data = rng.randbytes(rng.randrange(1, 300))
        out += bytes([rng.randrange(1, 9)]) + struct.pack(">H", len(data)) + data
    return out
