"""Development-only Unicorn capture of an Exlaunch DT_INIT on private NSOs."""

import argparse
from collections import Counter
from dataclasses import dataclass
import ctypes
import hashlib
import json
from pathlib import Path
import struct
import sys

from unicorn import (
    UC_ARCH_ARM64, UC_HOOK_BLOCK, UC_HOOK_INTR, UC_HOOK_MEM_WRITE, UC_MODE_ARM,
    Uc, UcError,
)
from unicorn import arm64_const as arm64

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'recomp'))
from layout import ADDRESS_LIMIT, ALIGN, FIRST_BASE, ORDER, layout
from nso import Nso, R_AARCH64_ABS64, R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT, R_AARCH64_RELATIVE

PAGE = 0x1000
STACK_TOP, STACK_SIZE = 0x1000100000, 0x100000
RETURN = 0x100000
PROCESS_HANDLE = 1
INFO = {
    2: 0x2000000000, 3: 0x800000000,              # alias
    4: 0x4000000000, 5: 0x800000000,              # heap
    12: 0x8000000, 13: ADDRESS_LIMIT - 0x8000000, # ASLR
    14: STACK_TOP - STACK_SIZE, 15: STACK_SIZE,  # stack
    65001: PROCESS_HANDLE,
}
REG = [getattr(arm64, f'UC_ARM64_REG_X{i}') for i in range(31)]
VECTOR = [getattr(arm64, f'UC_ARM64_REG_Q{i}') for i in range(32)]
SNPRINTF = '_ZN2nn4util8SNPrintfEPcmPKcz'
DISPLAY_VERSION = '_ZN2nn2oe17GetDisplayVersionEPNS0_14DisplayVersionE'
UNAVAILABLE_LOOKUP = '_ZN2nn2ro6detail35g_LookupGlobalManualFunctionPointerE'


class CaptureError(ValueError):
    """The trace cannot faithfully represent this initializer."""


@dataclass
class Region:
    start: int
    end: int
    state: int
    perm: int
    module: str = ''
    source: int = 0


@dataclass(eq=False)
class Module:
    name: str
    path: Path
    base: int
    nso: Nso
    image: bytearray

    @classmethod
    def load(cls, name, path, base):
        nso = Nso(path)
        return cls(name, path, base, nso, bytearray(nso.image))

    def in_text(self, address):
        start, size = self.nso.text
        return self.base + start <= address < self.base + start + size

    def regions(self):
        # NSO segments occupy consecutive page ranges with Horizon states.
        lo, ro, rw, end = (self.base + self.nso.text[0], self.base + self.nso.rodata[0],
                          self.base + self.nso.data[0], self.base + self.nso.size)
        if not (lo == self.base and lo < ro < rw < end and (lo | ro | rw | end) % PAGE == 0):
            raise CaptureError(f'{self.name}: invalid NSO page ranges')
        return (Region(lo, ro, 3, 5, self.name), Region(ro, rw, 3, 1, self.name),
                Region(rw, end, 4, 3, self.name))


@dataclass
class Snapshot:
    info: dict
    initial: bytes
    image: bytes


def branch_target(pc, word, op=0x14000000):
    if word & 0xfc000000 != op:
        return None
    offset = word & 0x03ffffff
    if offset & 0x02000000:
        offset -= 0x04000000
    return pc + offset * 4


def inline_hook(plugin, site, target):
    """Describe the known entry stub. A separate step must verify its trampoline."""
    if not plugin.in_text(target + 23):
        return None
    save, call, load, jump, callback = struct.unpack_from('<IIIIQ', plugin.image, target - plugin.base)
    wrapper = branch_target(target + 4, call, 0x94000000)
    trampoline = branch_target(target + 12, jump)
    if (save, load) != (0xf81f03fe, 0xf85f03fe) or wrapper is None or trampoline is None:
        return None
    if not all(plugin.in_text(a) and a % 4 == 0 for a in (wrapper, trampoline, callback)):
        return None
    wrappers = {plugin.base + value: name for name, _, _, value, _ in plugin.nso.exports()
                if name in ('exl_inline_hook_impl', 'exl_inline_hook_with_fp_impl')}
    if wrapper not in wrappers:
        return None
    return {'kind': 'inline-candidate', 'wrapper': wrapper, 'wrapper_symbol': wrappers[wrapper],
            'trampoline': trampoline, 'callback': callback, 'resume': site + 4}


def trampoline_matches(plugin, original, site, trampoline):
    if not plugin.in_text(trampoline + 7):
        return False
    copy, resume = struct.unpack_from('<II', plugin.image, trampoline - plugin.base)
    if branch_target(trampoline + 4, resume) != site + 4:
        return False
    for op in (0x14000000, 0x94000000):
        target = branch_target(site, original, op)
        if target is not None:
            return branch_target(trampoline, copy, op) == target
    # Other PC-relative instructions require their own validation rule.
    pc_relative = ((0x1f000000, 0x10000000), (0x3b000000, 0x18000000),
                   (0xff000000, 0x54000000), (0x7e000000, 0x34000000),
                   (0x7e000000, 0x36000000))
    return copy == original and not any(original & mask == op for mask, op in pc_relative)


class Trace:
    def __init__(self, exefs, plugin_paths, version, tick, step_limit):
        if step_limit <= 0:
            raise CaptureError('the instruction limit must be positive')
        paths = {path.name: path for path in plugin_paths}
        if (not paths or len(paths) != len(plugin_paths) or any(name not in ORDER[3:] for name in paths)
                or any(not path.is_file() for path in paths.values())):
            raise CaptureError('expected distinct existing plugin paths named subsdk1 through subsdk9')
        game_layout = layout(exefs, paths)
        self.layout = [{'name': name, 'base': base, 'size': size} for name, base, size in game_layout]
        names = {name for name, _, _ in game_layout}
        if not {'main', 'sdk'} <= names or not (exefs / 'rtld').is_file():
            raise CaptureError('expected the game ExeFS with main, sdk and rtld')
        if names.intersection(ORDER[3:]) != paths.keys():
            raise CaptureError('layout contains plugins that were not explicitly selected')
        # rtld is required for Exlaunch discovery during capture only. Native
        # recomp links the game itself and does not load this module.
        modules = [Module.load('rtld', exefs / 'rtld', FIRST_BASE - ALIGN)]
        modules += [Module.load(name, paths.get(name, exefs / name), base) for name, base, _ in game_layout]
        self.plugins = [module for module in modules if module.name in paths]
        self.modules = {m.name: m for m in modules}
        self.main = self.modules['main']
        self.version, self.tick, self.step_limit = version, tick, step_limit
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.regions = []
        self.aliases = []
        self.imports = {plugin.name: {} for plugin in self.plugins}
        self.unavailable_imports = {plugin.name: [] for plugin in self.plugins}
        self.plugin = None
        self.svcs, self.calls, self.debug_formats = Counter(), Counter(), Counter()
        self.main_writes = {}
        self.previous_sites = set()

        exports = {}
        for module in modules:
            for name, _, section, value, _ in module.nso.exports():
                exports.setdefault(name, value if section == 0xfff1 else module.base + value)
        for module in modules:
            self.relocate(module, exports)
            for region in module.regions():
                self.map_module(region, module, region.start)
        self.uc.mem_map(STACK_TOP - STACK_SIZE, STACK_SIZE, 3)
        self.regions.append(Region(STACK_TOP - STACK_SIZE, STACK_TOP, 0xb, 3))
        self.uc.hook_add(UC_HOOK_INTR, self.interrupt)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self.write)

    def relocate(self, module, exports):
        for off, kind, symbol, addend in module.nso.relocs:
            if kind == R_AARCH64_RELATIVE:
                value = module.base + addend
            elif kind in (R_AARCH64_ABS64, R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT):
                name, info, section, symbol_value, _ = module.nso.syms[symbol]
                if section:
                    value = symbol_value if section == 0xfff1 else module.base + symbol_value
                else:
                    value = exports.get(name, 0)
                    if not value and module in self.plugins:
                        if name == UNAVAILABLE_LOOKUP and kind == R_AARCH64_GLOB_DAT:
                            # This spelling is absent from the v121 SDK. A
                            # dereference must fault, even if its address is
                            # copied into another variable during setup.
                            value = ADDRESS_LIMIT
                            self.unavailable_imports[module.name].append({'symbol': name, 'offset': off, 'value': value})
                        elif info >> 4 != 2:
                            raise CaptureError(f'{module.name}: unresolved import {name}')
                    if value and module in self.plugins and kind == R_AARCH64_JUMP_SLOT:
                        self.imports[module.name][value] = name
                value += addend
            else:
                raise CaptureError(f'{module.name}: unsupported relocation type {kind}')
            struct.pack_into('<Q', module.image, off, value)

    def map_module(self, region, module, source):
        pointer = ctypes.addressof(ctypes.c_char.from_buffer(module.image, source - module.base))
        self.uc.mem_map_ptr(region.start, region.end - region.start, region.perm, pointer)
        self.regions.append(region)

    def query(self, address):
        if address >= ADDRESS_LIMIT:
            return Region(ADDRESS_LIMIT, 1 << 64, 0x10, 0)
        start, end = 0, ADDRESS_LIMIT
        for region in self.regions:
            if region.start <= address < region.end:
                return region
            if region.end <= address:
                start = max(start, region.end)
            if region.start > address:
                end = min(end, region.start)
        return Region(start, end, 0, 0)

    def svc_write(self, address, data):
        region = self.query(address)
        if (region.perm != 3 or region.source or region.module not in ('', self.plugin.name)
                or address + len(data) > region.end):
            raise CaptureError(f'kernel model output outside plugin or stack at {address:#x}')
        self.uc.mem_write(address, data)

    def get(self, n):
        return self.uc.reg_read(REG[n])

    def set(self, n, value):
        self.uc.reg_write(REG[n], value)

    def block(self, uc, address, _size, _data):
        name = self.imports[self.plugin.name].get(address, '')
        if name == DISPLAY_VERSION:
            self.svc_write(self.get(0), self.version.encode('ascii').ljust(16, b'\0'))
        elif name == SNPRINTF:
            self.format_message()
        else:
            raise CaptureError(f'{self.plugin.name}: unsupported call to {name or hex(address)}')
        self.calls[name] += 1
        uc.reg_write(arm64.UC_ARM64_REG_PC, self.get(30))

    def format_message(self):
        # Support the diagnostic subset observed in the initializers. Fail on
        # an unsupported format rather than returning an approximate result.
        fmt = bytearray()
        for i in range(512):
            c = self.uc.mem_read(self.get(2) + i, 1)[0]
            if not c:
                break
            fmt.append(c)
        else:
            raise CaptureError('SNPrintf format exceeds diagnostic bound')
        fmt = bytes(fmt)
        if b'%' not in fmt:
            message = fmt
        elif fmt.count(b'%') == 1 and b'%d' in fmt:
            value = ctypes.c_int32(self.get(3)).value
            message = fmt.replace(b'%d', str(value).encode('ascii'))
        else:
            raise CaptureError('unsupported SNPrintf format')
        self.debug_formats[fmt.decode('ascii')] += 1
        size = self.get(1)
        if size:
            self.svc_write(self.get(0), message[:size - 1] + b'\0')
        self.set(0, len(message))


    def interrupt(self, uc, _, _data):
        pc = uc.reg_read(arm64.UC_ARM64_REG_PC) - 4
        word, = struct.unpack('<I', uc.mem_read(pc, 4))
        if word & 0xffe0001f != 0xd4000001:
            raise CaptureError(f'{self.plugin.name}: non-SVC exception at {pc - self.plugin.base:#x}')
        imm = word >> 5 & 0xffff
        self.svcs[imm] += 1
        x0, x1, x2, x3 = (self.get(i) for i in range(4))
        if imm == 6:  # QueryMemory
            r = self.query(x2)
            self.svc_write(x0, struct.pack('<QQIIIIII', r.start, r.end - r.start, r.state, 0, r.perm, 0, 0, 0))
            self.set(1, 0)
        elif imm == 0x1e:  # GetSystemTick returns its value in x0.
            self.set(0, self.tick)
            self.tick += 0x177b
            return
        elif imm == 0x27:  # OutputDebugString
            if x1 > 65536:
                raise CaptureError('oversize OutputDebugString')
            uc.mem_read(x0, x1)
        elif imm == 0x29:  # GetInfo
            if x1 not in INFO or x3:
                raise CaptureError(f'unsupported GetInfo {x1:#x}, subtype {x3:#x}')
            self.set(1, INFO[x1])
        elif imm == 0x74:  # MapProcessMemory
            region = self.query(x2)
            dest = self.query(x0)
            if (x1 != PROCESS_HANDLE or (x0 | x2 | x3) % PAGE or not x3 or not region.module
                    or region.source or x2 + x3 > region.end or dest.state or x0 + x3 > dest.end):
                raise CaptureError('unsupported MapProcessMemory range or handle')
            alias = Region(x0, x0 + x3, 0xe, 3, region.module, x2)
            self.map_module(alias, self.modules[region.module], x2)
            self.aliases.append(alias)
        elif imm == 0x75:  # UnmapProcessMemory
            alias = self.query(x0)
            if (x1 != PROCESS_HANDLE or not alias.source or alias.start != x0 or alias.source != x2
                    or alias.end != x0 + x3):
                raise CaptureError('UnmapProcessMemory does not match a live alias')
            uc.mem_unmap(alias.start, x3)
            self.regions.remove(alias)
        else:
            raise CaptureError(f'{self.plugin.name}: unsupported SVC {imm:#x} at {pc - self.plugin.base:#x}')
        self.set(0, 0)

    def write(self, _uc, _access, address, size, value, _data):
        region = self.query(address)
        canonical = address if not region.source else region.source + address - region.start
        if (not region.state or region.perm != 3 or address + size > region.end
                or region.module not in ('', 'main', self.plugin.name)):
            raise CaptureError(f'{self.plugin.name}: unexpected write at {address:#x}')
        if region.module == 'main':
            if size != 4 or canonical % 4 or not self.main.in_text(canonical):
                raise CaptureError(f'{self.plugin.name}: non-instruction write at main+{canonical - self.main.base:#x}')
            if canonical in self.previous_sites:
                raise CaptureError(f'{self.plugin.name}: overlapping main patch at {canonical - self.main.base:#x}')
            self.main_writes[canonical] = value & 0xffffffff

    def run(self):
        for plugin in self.plugins:
            self.plugin = plugin
            self.svcs.clear()
            self.calls.clear()
            self.debug_formats.clear()
            self.main_writes.clear()
            initial = bytes(plugin.image)
            # Independent rtld calls with previous initializers' changes.
            self.uc.mem_write(STACK_TOP - STACK_SIZE, bytes(STACK_SIZE))
            self.uc.reg_write(arm64.UC_ARM64_REG_SP, STACK_TOP)
            for reg in (*REG, *VECTOR, arm64.UC_ARM64_REG_NZCV, arm64.UC_ARM64_REG_FPCR, arm64.UC_ARM64_REG_FPSR):
                self.uc.reg_write(reg, 0)
            self.set(30, RETURN)
            entry = plugin.base + plugin.nso.dyn.get(12, 0)
            if 12 not in plugin.nso.dyn or not plugin.in_text(entry):
                raise CaptureError(f'{plugin.name}: no valid DT_INIT')
            text_start, text_size = plugin.nso.text
            hooks = [self.uc.hook_add(UC_HOOK_BLOCK, self.block, begin=start, end=end)
                     for start, end in ((1, plugin.base + text_start - 1),
                                        (plugin.base + text_start + text_size, ADDRESS_LIMIT - 1))]
            try:
                self.uc.emu_start(entry, RETURN, count=self.step_limit)
            except UcError as exc:
                pc = self.uc.reg_read(arm64.UC_ARM64_REG_PC)
                raise CaptureError(f'{plugin.name}: Unicorn failed at {pc - plugin.base:#x}: {exc}') from exc
            finally:
                for hook in hooks:
                    self.uc.hook_del(hook)
            if self.uc.reg_read(arm64.UC_ARM64_REG_PC) != RETURN:
                pc = self.uc.reg_read(arm64.UC_ARM64_REG_PC)
                raise CaptureError(f'{plugin.name}: DT_INIT exceeded the instruction limit at {pc - plugin.base:#x}; '
                                   f'SVC counts {dict(self.svcs)}, imports {dict(self.calls)}')
            self.previous_sites.update(self.main_writes)
            yield self.result(plugin, initial)

    def result(self, plugin, initial):
        writes = []
        for address, word in sorted(self.main_writes.items()):
            offset = address - self.main.base
            if struct.unpack_from('<I', self.main.image, offset)[0] != word:
                raise CaptureError(f'{plugin.name}: main write did not reach canonical mapping')
            target = branch_target(address, word)
            record = {'offset': offset, 'original': self.main.nso.u32(offset), 'word': word}
            if target is not None and plugin.in_text(target):
                record['target'] = target
                record.update(inline_hook(plugin, address, target) or {'kind': 'branch-candidate'})
                if record['kind'] == 'inline-candidate':
                    record['trampoline_verified'] = trampoline_matches(plugin, record['original'], address,
                                                                        record['trampoline'])
            else:
                record['kind'] = 'instruction-write'
            writes.append(record)
        image = bytes(plugin.image)
        return Snapshot({'name': plugin.name, 'source': plugin.path.name,
                 'source_sha256': hashlib.sha256(plugin.path.read_bytes()).hexdigest(),
                 'base': plugin.base,
                 'text': plugin.nso.text, 'rodata': plugin.nso.rodata, 'data': plugin.nso.data,
                 'bss_size': plugin.nso.bss_size, 'writes': writes,
                 'svcs': {hex(k): v for k, v in sorted(self.svcs.items())},
                 'imports': dict(self.calls), 'unavailable_imports': self.unavailable_imports[plugin.name],
                 'aliases': [{'start': r.start, 'size': r.end - r.start, 'module': r.module,
                              'source': r.source, 'live': r in self.regions} for r in self.aliases],
                 'diagnostic_formats': dict(self.debug_formats)}, initial, image)


def alias_targets(value, aliases):
    # The allocator stores both start and one-past-end. Some ranges have
    # already been unmapped by the time DT_INIT returns.
    return {r['source'] + value - r['start'] for r in aliases
            if r['start'] <= value <= r['start'] + r['size']}


def changed_ranges(before, after, info):
    ranges = []
    boundaries = (0, info['rodata'][0], info['data'][0], len(after))
    for segment, lo, hi in zip(('text', 'rodata', 'data'), boundaries, boundaries[1:]):
        off = lo
        while off < hi:
            if before[off] == after[off]:
                off += 1
                continue
            start = off
            off += 1
            while off < hi and before[off] != after[off]:
                off += 1
            ranges.append({'segment': segment, 'offset': start, 'before': before[start:off].hex(),
                           'after': after[start:off].hex()})
    return ranges


def region_metadata(before, after, data_start):
    memory_info = {INFO[key]: key for key in (2, 4, 12, 14)}
    metadata = []
    for off in range(data_start, len(after) - 8, 8):
        base, extent = struct.unpack_from('<QQ', after, off)
        if base not in memory_info or before[off:off + 8] == after[off:off + 8]:
            continue
        info_type = memory_info[base]
        if extent == INFO[info_type + 1]:
            form = 'size'
        elif extent == base + INFO[info_type + 1]:
            form = 'end'
        else:
            raise CaptureError(f'unrecognized emulated region extent at +{off:#x}')
        metadata.append({'offset': off, 'info_type': info_type, 'value': base, 'extent': form})
    return metadata


def reconcile(first, second):
    """Accept tick-dependent bytes only when both alias histories explain them."""
    info = dict(first.info)
    info['raw_image_sha256'] = hashlib.sha256(first.image).hexdigest()
    info['different_image_bytes'] = sum(a != b for a, b in zip(first.image, second.image, strict=True))
    info['different_write_manifest'] = first.info['writes'] != second.info['writes']
    info['normalized_aliases'] = []
    info['unexplained_words'] = []
    after = bytearray(first.image)
    for off in range(0, len(first.image), 8):
        a, = struct.unpack_from('<Q', first.image, off)
        b, = struct.unpack_from('<Q', second.image, off)
        if a == b and (off < info['data'][0] or first.initial[off:off + 8] == first.image[off:off + 8]):
            continue
        a_targets = alias_targets(a, first.info['aliases'])
        b_targets = alias_targets(b, second.info['aliases'])
        if a == b and not (a_targets or b_targets):
            continue
        targets = a_targets & b_targets
        if off < info['data'][0] or len(targets) != 1:
            info['unexplained_words'].append(off)
            continue
        target, = targets
        struct.pack_into('<Q', after, off, target)
        info['normalized_aliases'].append({'offset': off, 'size': 8, 'canonical': target})
    info['deterministic'] = (not info['unexplained_words'] and not info['different_write_manifest']
                             and first.initial == second.initial)
    if not info['deterministic']:
        return info, None
    # Literal sandbox addresses can be stored as Exlaunch region metadata even
    # when they are stable across both runs. Keep them visible in the manifest.
    info['emulated_region_values'] = region_metadata(first.initial, after, info['data'][0])
    info['state'] = changed_ranges(first.initial, after, info)
    info['image_sha256'] = hashlib.sha256(after).hexdigest()
    return info, bytes(after)


def verify_game_version(exefs, version):
    expected_path = ROOT / 'tools' / 'data' / f'expected-v{version}.json'
    if not expected_path.is_file():
        raise CaptureError('unknown game version')
    expected = json.loads(expected_path.read_text(encoding='utf-8'))['exefs_sha256']
    for path in (exefs / name for name in expected):
        with path.open('rb') as source:
            digest = hashlib.file_digest(source, 'sha256').hexdigest()
        if digest != expected[path.name]:
            raise CaptureError(f'{path.name}: incorrect SHA-256 for game {version}')
    return expected['main']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exefs', type=Path, required=True)
    parser.add_argument('--plugin', type=Path, action='append', required=True, help='selected subsdk path')
    parser.add_argument('--version', default='1.2.1', choices=('1.1.0', '1.2.1', '1.4.3'))
    parser.add_argument('--step-limit', type=int, default=100_000_000)
    parser.add_argument('--private-output', type=Path, help='empty directory outside this checkout for private results')
    parser.add_argument('--keep-unstable', action='store_true', help='save both private trials if they differ')
    args = parser.parse_args()
    try:
        main_digest = verify_game_version(args.exefs, args.version)
        trials = []
        for tick in (0x123456, 0x76543210):
            trace = Trace(args.exefs, args.plugin, args.version, tick, args.step_limit)
            trials.append(list(trace.run()))
        reconciled = [reconcile(first, second) for first, second in zip(*trials, strict=True)]
        manifest = {'format': 2, 'game_version': args.version, 'main_sha256': main_digest,
                    'main_base': FIRST_BASE, 'layout': trace.layout,
                    'deterministic': all(image is not None for _, image in reconciled),
                    'plugins': [info for info, _ in reconciled]}
        rendered = json.dumps(manifest, indent=2)
        if args.private_output and (manifest['deterministic'] or args.keep_unstable):
            out = args.private_output.resolve()
            if out.is_relative_to(ROOT):
                raise CaptureError('private output must be outside the source checkout')
            out.mkdir(parents=True, exist_ok=True)
            if any(out.iterdir()):
                raise CaptureError('private output directory must be empty')
            for info, image in reconciled:
                if image is not None:
                    (out / (info['name'] + '.img')).write_bytes(image)
            if args.keep_unstable:
                for n, trial in enumerate(trials, 1):
                    for snapshot in trial:
                        (out / f'{snapshot.info["name"]}-raw-{n}.img').write_bytes(snapshot.image)
            (out / 'capture.json').write_text(rendered + '\n', encoding='utf-8')
            print(f'capture: wrote diagnostic artifacts to {out}')
        else:
            print(rendered)
        if not manifest['deterministic']:
            raise CaptureError('initializer capture differed across system tick seeds')
    except (ValueError, OSError, UcError) as exc:
        parser.exit(1, f'capture: {exc}\n')


if __name__ == '__main__':
    main()
