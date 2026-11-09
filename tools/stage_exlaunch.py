"""Stage verified game NSOs and explicitly selected plugins for a private experimental build.

The generated hash manifest is suitable for build_game.py --expected. Staging leaves IPS and NPDM changes from the
mod outside the image. Plugin initialization, hook capture and the choice of RomFS overlay are separate steps.
"""

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parent.parent
PLUGIN_NAMES = tuple(f'subsdk{i}' for i in range(1, 10))


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def stage(game, plugins, output, expected):
    """Copy a checked vanilla ExeFS plus the selected NSOs to a new output directory."""
    if output.resolve().is_relative_to(ROOT):
        raise ValueError('private output must be outside the source checkout')
    if output.exists():
        raise ValueError(f'output already exists: {output}')
    if not plugins:
        raise ValueError('select at least one subsdk plugin')
    names = [p.name for p in plugins]
    if len(set(names)) != len(names) or any(n not in PLUGIN_NAMES for n in names):
        raise ValueError('plugins must have distinct ExeFS names subsdk1 through subsdk9')

    hashes = expected['exefs_sha256']
    output.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix='.exlaunch-', dir=output.parent) as temporary:
        staging = Path(temporary) / 'output'
        exefs = staging / 'exefs'
        exefs.mkdir(parents=True)
        for name, wanted in hashes.items():
            copy = exefs / name
            shutil.copyfile(game / name, copy)
            if sha256(copy) != wanted:
                raise ValueError(f'{name} does not match the expected game ExeFS SHA-256')
        plugin_hashes = {}
        for plugin in plugins:
            copy = exefs / plugin.name
            shutil.copyfile(plugin, copy)
            with copy.open('rb') as stream:
                if not stream.read(0x100).startswith(b'NSO0') or copy.stat().st_size <= 0x100:
                    raise ValueError(f'{plugin.name} is not a Switch NSO')
            plugin_hashes[plugin.name] = sha256(copy)
        manifest = {'display_version': expected['display_version'], 'exefs_sha256': hashes | plugin_hashes}
        (staging / 'expected.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
        staging.rename(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--version', default='1.2.1', choices=('1.1.0', '1.2.1', '1.4.3'))
    parser.add_argument('--game-exefs', type=Path, required=True)
    parser.add_argument('--plugin', type=Path, action='append', required=True)
    parser.add_argument('--out', type=Path, required=True, help='new private staging directory')
    args = parser.parse_args()
    expected = json.loads((ROOT / 'tools' / 'data' / f'expected-v{args.version}.json').read_text(encoding='utf-8'))
    try:
        stage(args.game_exefs, args.plugin, args.out, expected)
    except (OSError, ValueError) as exc:
        sys.exit(f'stage_exlaunch: {exc}')
    print(f'Staged {len(args.plugin)} plugin NSOs with game {args.version} in {args.out}')


if __name__ == '__main__':
    main()
