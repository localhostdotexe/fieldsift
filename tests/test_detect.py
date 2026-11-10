import random
import unittest

from fieldsift.analyze import analyze
from fieldsift.core import Sample

from . import formats


def by_off(res, frame="start"):
    return {f.off: f for f in res.fields if f.frame == frame}


class Firmware(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rng = random.Random(11)
        names = [b"alpha", b"router-x2", b"cam", b"switch24", b"gw-lte-b", b"nvr"]
        cls.res = analyze(formats.samples([formats.firmware(rng, n) for n in names]))
        cls.f = by_off(cls.res)

    def test_magic(self):
        self.assertEqual(self.f[0].kind, "magic")
        self.assertTrue(bytes.fromhex(self.f[0].info["bytes"]).startswith(b"NVFW"))

    def test_file_size(self):
        f = self.f[8]
        self.assertEqual((f.kind, f.type, f.note), ("length", "u32le", "file size"))

    def test_timestamp(self):
        self.assertEqual(self.f[0xC].kind, "time")

    def test_payload_pointer(self):
        f = self.f[0x10]
        self.assertEqual(f.kind, "pointer")
        self.assertEqual(f.info["mark"], b"PAYL".hex())

    def test_crc_starts_at_pointer_target(self):
        f = self.f[0x14]
        self.assertEqual(f.kind, "checksum")
        self.assertEqual(f.info["algo"], "crc32")
        self.assertEqual(f.info["start"][0], "ref")
        self.assertEqual(f.info["end"], ["eof", 32])

    def test_name(self):
        self.assertEqual(self.f[0x18].kind, "string")

    def test_trailer_digest(self):
        f = by_off(self.res, "end")[-32]
        self.assertEqual((f.kind, f.type), ("digest", "sha256"))
        self.assertEqual(f.info["start"], ["abs", 0])
        self.assertEqual(f.info["end"], ["field"])


class Checksums(unittest.TestCase):
    def test_header_crc_with_field_zeroed(self):
        rng = random.Random(5)
        res = analyze(formats.samples([formats.be_header(rng) for _ in range(4)]))
        f = by_off(res)
        self.assertEqual(f[4].kind, "length")
        self.assertEqual(f[4].type, "u32be")
        self.assertEqual(f[4].info["slack"], 32)
        crc = f[28]
        self.assertEqual((crc.info["algo"], crc.endian, crc.info["mode"]), ("crc32", "be", "zero"))
        self.assertEqual(crc.info["end"], ["abs", 32])

    def test_one_byte_sum_needs_several_samples(self):
        rng = random.Random(9)
        blobs = [formats.summed(rng) for _ in range(8)]
        res = analyze(formats.samples(blobs))
        f = by_off(res, "end")[-1]
        self.assertEqual(f.info["algo"], "-sum8")
        # two samples can't tell an 8 bit checksum from luck
        res = analyze(formats.samples(blobs[:2]))
        self.assertNotIn(-1, by_off(res, "end"))

    def test_single_sample_crc(self):
        rng = random.Random(2)
        res = analyze(formats.samples([formats.be_header(rng)]))
        self.assertEqual(by_off(res)[28].info["algo"], "crc32")


class Chunks(unittest.TestCase):
    def test_png(self):
        rng = random.Random(1)
        blobs = [formats.png(rng, rng.randrange(4, 60), rng.randrange(4, 60), i % 2 == 0) for i in range(4)]
        ch = analyze(formats.samples(blobs)).chunks
        lay = ch["layout"]
        self.assertEqual(ch["start"], 8)
        self.assertEqual((lay.order, lay.tag, lay.len, lay.endian, lay.trail), ("LT", 4, 4, "be", 4))
        self.assertEqual(ch["trailer"], ("crc32(tag+data)", "be"))
        self.assertIn(b"IDAT", ch["tags"])

    def test_png_from_one_file(self):
        rng = random.Random(4)
        ch = analyze(formats.samples([formats.png(rng, 40, 30, True)])).chunks
        self.assertEqual(ch["start"], 8)

    def test_riff(self):
        rng = random.Random(3)
        res = analyze(formats.samples([formats.riff(rng, rng.randrange(100, 6000)) for _ in range(4)]))
        lay = res.chunks["layout"]
        self.assertEqual(res.chunks["start"], 12)
        self.assertEqual((lay.order, lay.tag, lay.len, lay.endian), ("TL", 4, 4, "le"))
        self.assertEqual(by_off(res)[4].note, "bytes following this field")

    def test_binary_tlv(self):
        rng = random.Random(8)
        ch = analyze(formats.samples([formats.tlv(rng) for _ in range(4)])).chunks
        lay = ch["layout"]
        self.assertEqual(ch["start"], 4)
        self.assertEqual((lay.order, lay.tag, lay.len, lay.endian, lay.counts), ("TL", 1, 2, "be", "data"))


class Quiet(unittest.TestCase):
    """Things that should come back empty."""

    def check(self, blobs):
        res = analyze(formats.samples(blobs))
        loud = [f for f in res.fields if f.kind not in ("magic", "const", "zero")]
        self.assertEqual(loud, [])
        self.assertIsNone(res.chunks)

    def test_random(self):
        rng = random.Random(21)
        self.check([rng.randbytes(rng.randrange(500, 20000)) for _ in range(6)])

    def test_random_single(self):
        self.check([random.Random(22).randbytes(30000)])

    def test_text(self):
        rng = random.Random(23)
        words = ["packet", "len", "of", "the", "header", "x", "crc"]
        self.check([" ".join(rng.choice(words) for _ in range(rng.randrange(200, 3000))).encode()
                    for _ in range(6)])

    def test_zeros(self):
        self.check([bytes(n) for n in (512, 4096, 10000)])

    def test_tiny(self):
        self.check([b"a", b"bc", b"def"])


class Output(unittest.TestCase):
    def test_report_and_exports_run(self):
        import json
        from fieldsift import hexpat, report
        rng = random.Random(1)
        for blobs in ([formats.png(rng, 20, 20) for _ in range(3)],
                      [formats.firmware(rng, n) for n in (b"abc", b"defgh", b"ijklmno")]):
            res = analyze(formats.samples(blobs))
            self.assertIn("sample", report.text(res, verbose=True))
            json.loads(report.as_json(res))
            self.assertIn("@", hexpat.render(res))


if __name__ == "__main__":
    unittest.main()
