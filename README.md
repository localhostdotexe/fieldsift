# fieldsift

You have a handful of files in some format nobody documented: firmware
images off a vendor's download page, save files, config blobs pulled from a
device. Before you can do anything with them you need the boring answers.
Which field is the length? Where does the payload start? What is that
4 byte thing that changes every time, and if it's a checksum, over which
bytes?

fieldsift answers those by comparing the samples against each other. It
doesn't know any formats. It looks for relations that hold in every file
you give it:

- bytes that never change (magic, version, padding)
- integers that track the file size (`size`, `size - 0x20`, `size / 512`, ...)
- integers that point at the same marker in every file, even though the
  marker moves
- checksums and digests, including the range they cover
- unix timestamps and length-prefixed strings
- tag/length chunk streams (the PNG / RIFF / TLV family)

and can write the result out as an [ImHex](https://github.com/WerWolv/ImHex)
pattern to keep working from.

Pure Python, standard library only.

## Install

    pip install git+https://github.com/localhostdotexe/project

or clone it and run `python -m fieldsift` from the checkout.

## Example

`examples/mkfw.py` writes six fake firmware images with a made up header.
Running fieldsift on them:

    $ python examples/mkfw.py fw
    $ fieldsift fw/
    6 samples, 14.8K .. 35.7K

    from start of file
      0x0000    6          magic     4e 56 46 57 02 00  "NVFW.."
      0x0008    4  u32le   length    file size                                              69 bits
      0x000c    4  u32le   time      unix time, 2022-07-26 .. 2023-12-05                    14 bits
      0x0010    4  u32le   pointer   file offset, target always starts 50 41 59 4c          61 bits
      0x0014    4  u32le   checksum  crc32 of target(0x10) .. EOF-32                        99 bits
      0x0018    1  u8      string    length-prefixed string, e.g. "ap-outdoor-lr"           64 bits

    from end of file
      -0x20    32  sha256  digest    sha256 of 0x0 .. this field                            99 bits

    map of ap-outdoor-lr.bin
      0000  4e 56 46 57 02 00 00 00 a9 8e 00 00 36 a8 6f 65  MMMMMM..LLLLTTTT
      0010  28 00 00 00 d0 da 64 04 0d 61 70 2d 6f 75 74 64  PPPPSSSSAaaaaaaa
      0020  6f 6f 72 2d 6c 72 00 00 50 41 59 4c e0 f1 f5 06  aaaaaa..........
      M magic  c const  0 zero  L length  P pointer  S checksum  T time  Aa string

The line worth a second look is the crc at 0x14. The header in these files
is variable length (the board name is in it), so the checksummed range
doesn't start at a fixed offset. fieldsift found the pointer at 0x10 first
and then tried its target as a range boundary: the crc covers everything
from where 0x10 points up to the 32 byte digest at the end.

A set of PNGs gives you the container instead:

    chunk stream from 0x8  (99 bits)
      len:u32be | tag[4] | data | crc32(tag+data)
      4-5 chunks per file
      tags: IHDR tEXt IDAT IEND

## Usage

    fieldsift [options] FILE [FILE ...]

Arguments can be files or a directory of samples.

| option | |
|---|---|
| `--head N` | bytes examined at the start of each file (default 256) |
| `--tail N` | bytes examined at the end (default 64) |
| `--min-bits B` | evidence needed before a field is reported (default 12) |
| `--hexpat FILE` | write an ImHex pattern skeleton |
| `--json` | machine readable output |
| `--no-sums`, `--no-chunks` | skip the checksum / chunk stream search |
| `-v` | also list matches that lost to an overlapping field |

Offsets are tracked from both ends of the file, so trailers show up with
negative offsets (`-0x20` is 32 bytes before EOF).

### Picking samples

This matters more than any option.

- Three to six files is usually plenty. One file works, but only chunk
  streams and 32 bit or wider checksums can be confirmed from a single
  sample.
- Different sizes. If every file is the same size, nothing can be tied to
  the file size.
- Same format version. A header that grew a field between v1 and v2 will
  blur everything behind that field.

## How it decides

Every finding carries a score in bits: roughly, how unlikely it is that
the relation holds by accident. A u32 that equals the file size in one
file is weak. The same field tracking the size across five files of
different sizes is not a coincidence. Scores are discounted for how many
alternatives were tried, since the checksum search goes through a few
thousand (algorithm, range) pairs per field and something will always
match an 8 bit sum if you try enough ranges. That is why a one byte
checksum needs at least three samples before it is reported and a CRC32
needs one.

When two readings overlap (a u16 and a u32 at the same offset, or the
same bytes read in either byte order) the higher score wins and the loser
is listed under `-v`.

Checksums searched: crc32, jamcrc, adler32, crc16 (xmodem and
ccitt-false), byte sums in 8/16/32 bits with their negated forms, xor8,
sums of 32 bit words, md5, sha1, sha256. Ranges may start at 0, at a
handful of fixed offsets, right after the field, or at a pointer target,
and end at EOF, a few bytes short of EOF, at the field or at a pointer
target. Ranges that include the field itself are tried with the field
zeroed and with it left out.

## Limits

- Fields are only looked for near the start and end of the file. A field
  that sits behind variable length data is found only if a chunk stream
  leads to it.
- No CRC parameter search. If the vendor used a custom polynomial you get
  nothing here; [delsum](https://github.com/8051Enthusiast/delsum) and
  CRC RevEng are the tools for that, and knowing the field and the likely
  range from fieldsift makes them much quicker to drive.
- Compressed or encrypted containers show their outer header and nothing
  else.
- Chunk streams have to run to EOF exactly. A stream followed by a
  trailer isn't recognised.
- Timestamps need about six samples with different times to clear the
  default threshold. Lower `--min-bits` if you have fewer.
- The checksum search costs a second or two per MB of the smallest sample.
  For big images use `--no-sums` first, or cut the files down.
- The ImHex output is a skeleton. Expect to rename things.

## Related work

Format inference has a long history on the network side:
[Netzob](https://github.com/netzob/netzob) and the BinaryInferno paper
(NDSS 2023) both infer field boundaries and types from captured protocol
messages. fieldsift is aimed at files instead: it works from both ends of
the file, ties checksums to the exact byte range, follows pointers, and
hands off to a hex editor.

## Tests

    python -m unittest

## License

MIT
