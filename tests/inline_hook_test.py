"""Generate and run synthetic NSO code hooks on the host. Requires the lifter dependencies and Clang."""
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT / 'recomp'))
from exefs_patches_test import nso  # noqa: E402
import patches  # noqa: E402
from layout import layout  # noqa: E402

RET = 0xD65F03C0


def module(*words, entries=(0x8,)):
    # RELATIVE relocation targets seed discovery. The plugin wrappers at +0xc still need hook seeds.
    text = struct.pack('<' + 'I' * (len(words) + 2), 0x14000002, 0x1100, *words)
    ro = bytes(0x100) + b'MOD0' + struct.pack('<6i', 0xF00, 0, 0, -0x1100, -0x1100, 0)
    relocs = b''.join(struct.pack('<QQq', 0x2040 + i * 8, 1027, entry) for i, entry in enumerate(entries))
    ro += bytes(4) + relocs
    data = struct.pack('<6Q', 7, 0x1120, 8, len(relocs), 0, 0) + bytes(0x10 + 8 * len(entries))
    return nso(text, ro, data)


class InlineHook(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.work = Path(work.name)
        self.exefs = self.work / 'exefs'
        self.exefs.mkdir()
        (self.exefs / 'main').write_bytes(module(
            0xF100003F,     # cmp x1, #0
            0x91000E73,     # add x19, x19, #3 (hook1)
            0x10007F85,     # adr x5, .rodata (hook2)
            0x54000060,     # b.eq +0xc
            0x91001660,     # add x0, x19, #5
            RET,
            0x91002660,     # add x0, x19, #9
            RET,
            0xD2800100,     # mov x0, #8 (replacement hook)
            RET,
            entries=(0x8, 0x28),
        ))
        (self.exefs / 'subsdk1').write_bytes(module(
            RET, 0x91001E73, 0xAA1E03E4, 0xD53B4207, RET,  # add x19, x19, #7; mov x4, x30; mrs x7, nzcv
            0xAA1E03E0, RET,  # replacement: mov x0, x30
        ))
        (self.exefs / 'subsdk2').write_bytes(module(
            RET, 0xD2800546, 0xD61F0120, RET,  # mov x6, #42; br x9
            0xD2800C68, RET,  # indirect target: mov x8, #99
        ))
        self.mods = layout(self.exefs)
        self.main, self.first, self.second = (base for _, base, _ in self.mods)
        self.table = self.work / 'patches.txt'
        self.table.write_text(self.table_text(), encoding='ascii')

    def table_text(self):
        return (f'set first TEST_FIRST 0\nset second TEST_SECOND 0\nset replace TEST_REPLACE 0\n'
                f'site first main c 91000e73 @hook:{self.first + 0xC:x}\n'
                f'site second main 10 10007f85 @hook:{self.second + 0xC:x}\n'
                f'site replace main 28 d2800100 @replace:{self.first + 0x1C:x}\n'
                'seed subsdk2 18\n')

    def test_reject_mixed_replacement_and_collisions(self):
        for text, reason in (
            (self.table_text().replace(f'@hook:{self.first + 0xC:x}', f'@hook:{self.first + 0xC:x} d503201f'),
             'single aligned target'),
            (self.table_text() + 'site second main c 91000e73 d503201f\n', 'with another patch'),
            (self.table_text() + 'spin main 8 c\n', 'spin wait back-edge'),
            (self.table_text().replace(f'{self.first + 0xC:x}', f'{self.main + 0xC:x}'), 'in another module'),
            (self.table_text().replace(f'{self.first + 0xC:x}', f'{self.first + 0xD:x}'), 'aligned target'),
            (self.table_text().replace('seed subsdk2 18', 'seed subsdk2 19'), 'aligned offset'),
        ):
            with self.subTest(reason=reason):
                self.table.write_text(text, encoding='ascii')
                with self.assertRaisesRegex(patches.PatchError, reason):
                    patches.load(self.table, self.mods)

    def lift(self, modules):
        return subprocess.run(
            [sys.executable, str(ROOT / 'recomp' / 'gen.py'), '--exefs', str(self.exefs), '--out',
             str(self.work / 'gen'), '--modules', modules, '--patches', str(self.table), '--jobs', '1'],
            capture_output=True, text=True,
        )

    def test_target_must_be_emitted_code(self):
        run = self.lift('main,subsdk2')
        self.assertNotEqual(run.returncode, 0)
        self.assertIn('outside --modules', run.stderr)
        self.table.write_text(self.table_text().replace(f'{self.first + 0xC:x}', f'{self.first + 0x1000:x}'),
                              encoding='ascii')
        run = self.lift('main,subsdk1,subsdk2')
        self.assertNotEqual(run.returncode, 0)
        self.assertIn('outside .text', run.stderr)

    def test_replacement_must_start_a_discovered_function(self):
        self.table.write_text(self.table_text().replace('main 28 d2800100', 'main 18 91001660'), encoding='ascii')
        run = self.lift('main,subsdk1,subsdk2')
        self.assertNotEqual(run.returncode, 0)
        self.assertIn('replacement hook requires a discovered function entry', run.stderr)

    def test_native_hooks(self):
        clang = shutil.which('clang')
        if not clang:
            clang = Path(r'C:\msys64\ucrt64\bin\clang.exe')
            if not clang.is_file():
                self.skipTest('Clang is required to run the lifted functions')
        run = self.lift('main,subsdk1,subsdk2')
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        entry = f'f_{self.main + 8:x}'
        replacement_site = f'f_{self.main + 0x28:x}'
        replacement_target = f'f_{self.first + 0x1C:x}'
        indirect_target = f'f_{self.second + 0x18:x}'
        harness = self.work / 'harness.c'
        harness.write_text(f'''#include "cpu.h"
#include <assert.h>
#include <stdlib.h>

extern void {entry}(Cpu *c);
extern void {replacement_site}(Cpu *c);
extern void {replacement_target}(Cpu *c);
extern void {indirect_target}(Cpu *c);
uint8_t rt_patch_on[3];
uint8_t rt_hook_trace_enabled;
volatile int g_fnprof;
static unsigned traced;

void fnprof_hit(uint64_t addr, uint64_t lr, uint64_t x0) {{}}
void rt_udf(Cpu *c, uint64_t pc) {{ abort(); }}
void rt_hook_trace_log(uint64_t site, uint64_t target, const char *kind) {{
    unsigned bit;
    switch (site) {{
        case {self.main + 0xC:#x}ull:
            bit = 1;
            assert(target == {self.first + 0xC:#x}ull && !strcmp(kind, "inline"));
            break;
        case {self.main + 0x10:#x}ull:
            bit = 2;
            assert(target == {self.second + 0xC:#x}ull && !strcmp(kind, "inline"));
            break;
        case {self.main + 0x28:#x}ull:
            bit = 4;
            assert(target == {self.first + 0x1C:#x}ull && !strcmp(kind, "replacement"));
            break;
        default: abort();
    }}
    assert(!(traced & bit));
    traced |= bit;
}}
void rt_dispatch(Cpu *c) {{
    switch (c->pc) {{
        case {self.first + 0x1C:#x}ull: {replacement_target}(c); return;
        case {self.second + 0x18:#x}ull: {indirect_target}(c); return;
        default: abort();
    }}
}}

int main(void) {{
    for (int mask = 0; mask < 4; ++mask) {{
        for (int arg = 0; arg < 2; ++arg) {{
            Cpu c = {{0}};
            rt_patch_on[0] = mask & 1;
            rt_patch_on[1] = mask & 2;
            c.x[1] = arg;
            c.x[9] = {self.second + 0x18:#x}ull;
            c.x[19] = 2;
            c.x[30] = 0x12345678;
            c.nzcv = 0x80000000;
            {entry}(&c);
            assert(c.x[19] == 5 + ((mask & 1) ? 7 : 0));
            assert(c.x[0] == c.x[19] + (arg ? 5 : 9));
            assert(c.x[4] == ((mask & 1) ? c.x[30] : 0));
            assert(c.x[5] == {self.main + 0x1000:#x}ull);
            assert(c.x[6] == ((mask & 2) ? 42 : 0));
            assert(c.x[7] == ((mask & 1) ? (arg ? 0x20000000 : 0x60000000) : 0));
            assert(c.x[8] == ((mask & 2) ? 99 : 0));
            assert(c.x[30] == 0x12345678);
            assert(c.nzcv == 0x80000000);
        }}
    }}
    Cpu c = {{0}};
    c.x[30] = 0x87654321;
    {replacement_site}(&c);
    assert(c.x[0] == 8);
    rt_patch_on[2] = 1;
    {replacement_site}(&c);
    assert(c.x[0] == 0x87654321 && c.x[30] == c.x[0]);
    assert(!traced);
    rt_hook_trace_enabled = 1;
    c.x[9] = {self.second + 0x18:#x}ull;
    for (int n = 0; n < 2; ++n) {{
        {entry}(&c);
        {replacement_site}(&c);
    }}
    assert(traced == 7);
    return 0;
}}
''', encoding='ascii')
        exe = self.work / ('inline-hook.exe' if os.name == 'nt' else 'inline-hook')
        chunks = sorted((self.work / 'gen').glob('*/*_0000.c'))
        self.assertEqual(len(chunks), 3)
        run = subprocess.run([str(clang), '-std=gnu11', '-O2', '-I', str(ROOT / 'runtime'), str(harness),
                              *map(str, chunks), '-o', str(exe)], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        run = subprocess.run([str(exe)], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)


if __name__ == '__main__':
    unittest.main()
