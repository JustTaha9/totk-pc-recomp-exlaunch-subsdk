"""Replay captured state on synthetic NSOs without game or mod files."""

import struct
import sys
import tempfile
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
sys.path[:0] = [str(TESTS), str(TESTS.parent / 'tools')]
from exefs_patches_test import reloc_module  # noqa: E402
from materialize_exlaunch import Nso, reconstructed_image, write_nso  # noqa: E402


BASE = 0x7005e00000


def write(offset, before, after):
    return {'offset': offset, 'before': before.hex(), 'after': after.hex()}


class ReplayTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / 'subsdk1'
        self.path.write_bytes(reloc_module())
        self.nso = Nso(self.path)

    def test_persist_bss_and_update_relative_addend(self):
        state = [write(0x2100, struct.pack('<Q', BASE + 8), struct.pack('<Q', BASE + 0x2300)),
                 write(0x2300, bytes(4), b'test')]
        image = reconstructed_image(self.nso, {'state': state}, BASE)
        out = self.path.with_name('rebuilt')
        write_nso(out, self.path, self.nso, image)
        rebuilt = Nso(out)
        self.assertEqual(rebuilt.image[0x2300:0x2304], b'test')
        self.assertEqual(rebuilt.relocs[0], (0x2100, 1027, 0, 0x2300))
        self.assertEqual(rebuilt.relocs[1:], self.nso.relocs[1:])
        self.assertEqual(rebuilt.size, self.nso.size)

    def test_reject_mismatched_initial_bytes(self):
        with self.assertRaisesRegex(ValueError, 'captured input does not match'):
            reconstructed_image(self.nso, {'state': [write(0x2300, b'a', b'b')]}, BASE)

    def test_reject_unhandled_relocation(self):
        with self.assertRaisesRegex(ValueError, 'unsupported relocation'):
            reconstructed_image(self.nso, {'state': [write(0x2108, b'\0', b'a')]}, BASE)

    def test_reject_overlap_and_rodata(self):
        state = [write(0x2300, bytes(2), b'ab'), write(0x2301, b'\0', b'c')]
        with self.assertRaisesRegex(ValueError, 'overlapping'):
            reconstructed_image(self.nso, {'state': state}, BASE)
        with self.assertRaisesRegex(ValueError, 'unsupported captured write'):
            reconstructed_image(self.nso, {'state': [write(0x1000, b'c', b'd')]}, BASE)


if __name__ == '__main__':
    unittest.main()
