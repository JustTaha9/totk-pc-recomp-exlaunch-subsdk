"""Turn a verified initializer capture into private, statically liftable plugin images and patch sites."""

import argparse
import hashlib
import json
import shutil
import struct
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / 'recomp'), str(ROOT / 'tools')]
from check_content import GENERATED_MARKER  # noqa: E402
from layout import layout  # noqa: E402
from nso import DT_RELA, DT_RELASZ, Nso, R_AARCH64_RELATIVE  # noqa: E402
from patches import branch_target  # noqa: E402
from stage_exlaunch import PLUGIN_NAMES, sha256  # noqa: E402

RET = 0xd65f03c0


def reconstructed_image(nso, capture, base):
    """Replay only changes made by the initializer, preserving ordinary runtime relocations."""
    image = bytearray(nso.image)
    spans = [(row['offset'], bytes.fromhex(row['before']), bytes.fromhex(row['after'])) for row in capture['state']]
    offsets = set()
    for off, before, after in spans:
        text = nso.text[0] <= off and off + len(after) <= sum(nso.text)
        data = nso.data[0] <= off and off + len(after) <= sum(nso.data) + nso.bss_size
        if not before or len(before) != len(after) or not (text or data):
            raise ValueError(f'unsupported captured write at +{off:#x}')
        changed = set(range(off, off + len(after)))
        if offsets & changed:
            raise ValueError(f'overlapping captured write at +{off:#x}')
        offsets.update(changed)

    relas = range(nso.dyn.get(DT_RELA, 0), nso.dyn.get(DT_RELA, 0) + nso.dyn.get(DT_RELASZ, 0), 24)
    addends = {nso.u64(p): p + 16 for p in relas if nso.u32(p + 8) == R_AARCH64_RELATIVE}
    touched = []
    for off, kind, _, addend in nso.relocs:
        if offsets.isdisjoint(range(off, off + 8)):
            continue
        if kind != R_AARCH64_RELATIVE or off not in addends or not offsets.isdisjoint(range(addends[off], addends[off] + 8)):
            raise ValueError(f'captured write overlaps unsupported relocation at +{off:#x}')
        struct.pack_into('<Q', image, off, base + addend)
        touched.append(off)
    for off, before, after in spans:
        if image[off:off + len(before)] != before:
            raise ValueError(f'captured input does not match at +{off:#x}')
        image[off:off + len(after)] = after
    for off in touched:
        destination = struct.unpack_from('<Q', image, off)[0] - base
        if not 0 <= destination < nso.size:
            raise ValueError(f'initializer changed +{off:#x} to an external relocation')
        struct.pack_into('<q', image, addends[off], destination)
        image[off:off + 8] = nso.image[off:off + 8]
    return image


def write_nso(path, source, nso, image):
    """Keep guest segment starts and make the initialized part of BSS file-backed."""
    header = bytearray(source.read_bytes()[:0x100])
    flags = struct.unpack_from('<I', header, 0x0c)[0]
    struct.pack_into('<I', header, 0x0c, flags & ~7)
    data_end = sum(nso.data) + nso.bss_size
    segments = [nso.text, nso.rodata, (nso.data[0], data_end - nso.data[0])]
    contents = bytearray()
    for i, (off, size) in enumerate(segments):
        payload = image[off:off + size]
        struct.pack_into('<III', header, 0x10 + 16 * i, 0x100 + len(contents), off, size)
        struct.pack_into('<I', header, 0x60 + i * 4, size)
        header[0xa0 + i * 32:0xc0 + i * 32] = hashlib.sha256(payload).digest()
        contents.extend(payload)
    struct.pack_into('<I', header, 0x3c, 0)
    path.write_bytes(header + contents)
    written = Nso(path)
    if written.size != nso.size or written.image != image:
        raise ValueError(f'{source.name}: rebuilt NSO does not round trip')


def plugin_patches(nso, image, base, main, main_base, name, capture):
    for row in capture['writes']:
        off, original, target = row['offset'], row['original'], row['target']
        site = main_base + off
        relative = target - base
        if (off % 4 or not main.text[0] <= off <= sum(main.text) - 4 or main.u32(off) != original
                or target % 4 or not nso.text[0] <= relative <= sum(nso.text) - 4
                or branch_target(row['word'], site) != target):
            raise ValueError(f'{name}: invalid captured branch at main+{off:#x}')
        if row['kind'] == 'inline-candidate' and row.get('trampoline_verified') is True:
            if (relative + 24 > sum(nso.text) or row['resume'] != site + 4
                    or struct.unpack_from('<Q', image, relative + 16)[0] != row['callback']
                    or branch_target(struct.unpack_from('<I', image, relative + 12)[0], target + 12) != row['trampoline']):
                raise ValueError(f'{name}: captured inline stub changed')
            struct.pack_into('<I', image, relative + 12, RET)
            yield f'seed {name} {row["callback"] - base:x}'
            kind = 'hook'
        elif row['kind'] == 'branch-candidate':
            kind = 'replace'
        else:
            raise ValueError(f'{name}: unsupported captured branch at main+{off:#x}')
        yield f'site exlaunch main {off:x} {original:08x} @{kind}:{target:x}'


def materialize(staged, capture, patches, out):
    if out.resolve().is_relative_to(ROOT):
        raise ValueError('private output must be outside the source checkout')
    if out.exists():
        raise ValueError(f'output already exists: {out}')
    if capture.get('format') != 2 or capture.get('deterministic') is not True:
        raise ValueError('expected a deterministic format-2 Exlaunch capture')
    manifest = json.loads((staged / 'expected.json').read_text(encoding='utf-8'))
    hashes = manifest['exefs_sha256']
    game = staged / 'exefs'
    version = manifest['display_version']
    official = json.loads((ROOT / 'tools' / 'data' / f'expected-v{version}.json').read_text(encoding='utf-8'))
    if capture['game_version'] != version or capture['main_sha256'] != official['exefs_sha256']['main']:
        raise ValueError('capture game version does not match staged game')
    if any(sha256(game / n) != h for n, h in (hashes | official['exefs_sha256']).items()):
        raise ValueError('staged ExeFS does not match its expected SHA-256 hashes')
    bases = {name: base for name, base, _ in layout(game)}
    main = Nso(game / 'main')
    names = [name for name in bases if name in PLUGIN_NAMES]
    if not names or len(names) != len(capture['plugins']) or bases['main'] != capture['main_base']:
        raise ValueError('capture layout does not match staged modules')
    rows = ['set exlaunch TOTK_EXLAUNCH 1']
    memory_info = []
    out.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix='.exlaunch-build-', dir=out.parent) as temporary:
        dest = Path(temporary) / 'output'
        exefs = dest / 'exefs'
        shutil.copytree(game, exefs)
        for name, plugin in zip(names, capture['plugins'], strict=True):
            source, base = game / name, bases[name]
            if plugin['base'] != base or plugin['source_sha256'] != hashes[name]:
                raise ValueError(f'{name}: capture does not match staged plugin')
            nso = Nso(source)
            image = reconstructed_image(nso, plugin, base)
            rows.extend(plugin_patches(nso, image, base, main, bases['main'], name, plugin))
            memory_info.extend([name, entry['offset'], entry['info_type'], entry['extent']]
                               for entry in plugin['emulated_region_values'])
            write_nso(exefs / name, source, nso, image)
            hashes[name] = sha256(exefs / name)
        manifest.update(preinitialized_plugins=names, plugin_memory_info=memory_info)
        (dest / 'expected.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
        (dest / 'patches.txt').write_text(f'# {GENERATED_MARKER}\n' + patches.rstrip() + '\n\n'
                                          + '\n'.join(rows) + '\n', encoding='utf-8')
        dest.rename(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--staged', type=Path, required=True, help='output from stage_exlaunch.py')
    parser.add_argument('--capture', type=Path, required=True, help='verified private capture.json')
    parser.add_argument('--patches', type=Path, required=True, help='vanilla and IPS patch table to extend')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    try:
        materialize(args.staged, json.loads(args.capture.read_text(encoding='utf-8')),
                    args.patches.read_text(encoding='utf-8'), args.out)
    except (OSError, ValueError) as exc:
        sys.exit(f'materialize_exlaunch: {exc}')
    print(f'Materialized private Exlaunch inputs in {args.out}')


if __name__ == '__main__':
    main()
