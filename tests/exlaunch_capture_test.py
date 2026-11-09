"""Synthetic NSOs exercise the capture harness without game or mod assets."""

from pathlib import Path
import struct
import tempfile
import unittest

from exlaunch_capture import (
    ALIGN, FIRST_BASE, INFO, PAGE, CaptureError, Module, Snapshot, Trace, branch_target, reconcile, region_metadata,
    trampoline_matches,
)


ENTRY = 0x80
RET = 0xd65f03c0
ALIAS = 0x2000010000


def mov64(reg, value):
    words = [0xd2800000 | (value & 0xffff) << 5 | reg]
    for part in range(1, 4):
        half = value >> (16 * part) & 0xffff
        if half:
            words.append(0xf2800000 | part << 21 | half << 5 | reg)
    return words


def svc(number):
    return 0xd4000001 | number << 5


def nso(path, instructions=()):
    raw = bytearray(0x100 + 3 * PAGE)
    raw[:4] = b'NSO0'
    for i in range(3):
        struct.pack_into('<III', raw, 0x10 + 16 * i, 0x100 + i * PAGE, i * PAGE, PAGE)
        struct.pack_into('<I', raw, 0x60 + 4 * i, PAGE)
    mod = 0x40
    struct.pack_into('<I', raw, 0x104, mod)
    struct.pack_into('<4s6i', raw, 0x100 + mod, b'MOD0', PAGE - mod, 3 * PAGE - mod, 3 * PAGE - mod, 0, 0, 0)
    if instructions:
        struct.pack_into('<4Q', raw, 0x100 + PAGE, 12, ENTRY, 0, 0)
        struct.pack_into(f'<{len(instructions)}I', raw, 0x100 + ENTRY, *instructions)
    path.write_bytes(raw)
    return path


def patcher(site, target):
    branch = 0x14000000 | ((target - site) // 4 & 0x03ffffff)
    source = site & -PAGE
    alias_site = ALIAS + site - source
    return [*mov64(0, ALIAS), *mov64(1, 1), *mov64(2, source), *mov64(3, PAGE), svc(0x74),
            *mov64(0, alias_site), *mov64(3, branch), 0xb9000003,
            *mov64(0, ALIAS), *mov64(1, 1), *mov64(2, source), *mov64(3, PAGE), svc(0x75), RET]


class CaptureTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.game = self.root / 'exefs'
        self.game.mkdir()
        for name in ('rtld', 'main', 'sdk'):
            nso(self.game / name)

    def trace(self, *plugins):
        return list(Trace(self.game, plugins, 'synthetic', 0x10000, 1000).run())

    def plugin(self, index, site):
        return nso(self.root / f'subsdk{index + 1}', patcher(site, FIRST_BASE + ALIGN * (2 + index) + ENTRY))

    def test_two_initializers_write_through_real_aliases(self):
        results = self.trace(self.plugin(0, FIRST_BASE + 0x200), self.plugin(1, FIRST_BASE + 0x204))
        for index, result in enumerate(results):
            write, = result.info['writes']
            self.assertEqual(write['offset'], 0x200 + 4 * index)
            self.assertEqual(write['original'], 0)
            self.assertEqual(write['kind'], 'branch-candidate')
            self.assertEqual(branch_target(FIRST_BASE + write['offset'], write['word']),
                             FIRST_BASE + ALIGN * (2 + index) + ENTRY)
            self.assertEqual(result.info['svcs'], {'0x74': 1, '0x75': 1})
            self.assertFalse(result.info['aliases'][-1]['live'])

    def test_conflicting_main_write_fails(self):
        with self.assertRaisesRegex(CaptureError, 'overlapping main patch'):
            self.trace(self.plugin(0, FIRST_BASE + 0x200), self.plugin(1, FIRST_BASE + 0x200))

    def test_data_write_fails(self):
        with self.assertRaisesRegex(CaptureError, 'non-instruction write'):
            self.trace(self.plugin(0, FIRST_BASE + PAGE * 2))

    def test_unknown_svc_fails(self):
        plugin = nso(self.root / 'subsdk1', [svc(0x99), RET])
        with self.assertRaisesRegex(CaptureError, 'unsupported SVC 0x99'):
            self.trace(plugin)

    def test_bad_return_does_not_outlive_budget(self):
        plugin = nso(self.root / 'subsdk1', [0x14000000])
        with self.assertRaisesRegex(CaptureError, 'exceeded the instruction limit'):
            self.trace(plugin)

    def test_trampoline_branch_relocates_from_its_own_pc(self):
        path = nso(self.root / 'subsdk1')
        base = FIRST_BASE + ALIGN * 2
        plugin = Module.load('subsdk1', path, base)
        site = FIRST_BASE + 0x200
        trampoline = base + ENTRY
        callee = site - 0x100
        def branch(op, src, dst):
            return op | (dst - src) // 4 & 0x03ffffff
        original = branch(0x94000000, site, callee)
        copy = branch(0x94000000, trampoline, callee)
        resume = branch(0x14000000, trampoline + 4, site + 4)
        struct.pack_into('<II', plugin.image, ENTRY, copy, resume)
        self.assertTrue(trampoline_matches(plugin, original, site, trampoline))
        struct.pack_into('<II', plugin.image, ENTRY, original, resume)
        self.assertFalse(trampoline_matches(plugin, original, site, trampoline))

    def test_reconcile_explains_only_same_source_aliases(self):
        initial = bytes(24)
        def snapshot(alias, value, canonical):
            data = bytes(16) + struct.pack('<Q', value)
            info = {'rodata': (8, 8), 'data': (16, 8), 'writes': [],
                    'aliases': [{'start': alias, 'source': canonical, 'size': PAGE}]}
            return Snapshot(info, initial, data)
        a = snapshot(0x5000, 0x6000, 0x2000)
        b = snapshot(0x7000, 0x8000, 0x2000)
        info, image = reconcile(a, b)
        self.assertEqual(image, initial[:16] + struct.pack('<Q', 0x3000))
        self.assertEqual(info['normalized_aliases'], [{'offset': 16, 'size': 8, 'canonical': 0x3000}])
        self.assertEqual(info['state'], [{'segment': 'data', 'offset': 17, 'before': '00', 'after': '30'}])
        info, image = reconcile(a, snapshot(0x7000, 0x8000, 0x3000))
        self.assertIsNone(image)
        self.assertEqual(info['unexplained_words'], [16])
        _, image = reconcile(a, a)
        self.assertEqual(image, initial[:16] + struct.pack('<Q', 0x3000))

    def test_rebased_regions_check_size_and_end(self):
        base, size = INFO[2], INFO[3]
        before = bytes(32)
        after = struct.pack('<4Q', base, size, base, base + size)
        self.assertEqual([row['extent'] for row in region_metadata(before, after, 0)], ['size', 'end'])
        invalid = struct.pack('<4Q', base, 1, base, base + size)
        with self.assertRaisesRegex(CaptureError, 'unrecognized emulated region extent'):
            region_metadata(before, invalid, 0)


if __name__ == '__main__':
    unittest.main()
