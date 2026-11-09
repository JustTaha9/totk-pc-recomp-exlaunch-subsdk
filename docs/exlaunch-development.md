# Experimental Exlaunch build

This development path runs supported plugin initializers during preparation and recompiles the captured hooks into the Windows executable. The Windows runtime loads the prepared images at their captured guest addresses. The original plugin packages and all game-derived files stay in a private work folder outside the checkout.

## Inputs

- A clean 1.2.1 extraction with ExeFS and RomFS from `tools/extract.py`.
- A TKMM merge for 1.2.1. The selected plugin modules must have the final merged names `subsdk1`, `subsdk2`, and so on.
- Python and the native toolchain from [Building from source](building.md). The initializer capture also uses Unicorn from `tools/requirements.txt`. The compiled runtime has no Unicorn dependency.

The commands below use PowerShell from the source checkout. Set `$python` and `$toolchain` for your installation. `$private` is an absolute path to a private work folder outside the checkout. `$game` points to its `extracted/v121` directory and `$merge` points to the 1.2.1 TKMM output. Use an empty destination for the capture and new directories for staging and preparation.

```powershell
& $python tools/stage_exlaunch.py --game-exefs "$game/exefs" `
    --plugin "$merge/exefs/subsdk1" --plugin "$merge/exefs/subsdk2" `
    --out "$private/staged"
& $python tests/exlaunch_capture.py --exefs "$game/exefs" `
    --plugin "$merge/exefs/subsdk1" --plugin "$merge/exefs/subsdk2" `
    --private-output "$private/capture"
```

In `$private/run/mods/SixMods`, put the matching merged `romfs` directory or a directory junction to it. Copy the matching `.ips` files into `$private/run/mods/SixMods/exefs`. The prepared plugins load from the build's ExeFS path. The base extraction supplies the native runtime's `main.npdm`.

If the merged RomFS includes `UI/LayoutArchive/Common.Product.110.Nin_NX_NVN.blarc.zs`, apply the quick-menu frame-rate fix to that archive. Use `tools/make_romfs_patches.py --version v121 --romfs "$game/romfs" --layout-archive <merged archive> --out "$private/layout-60fps"`. Copy just the generated archive to the same RomFS path inside a separate `00-native-layout-60fps` mod ordered above `SixMods`. The script validates the visibility tracks and handles the renamed shortcut capture pane in the selected pack.

```powershell
& $python tools/exefs_patches.py --exefs "$game/exefs" --mods "$private/run/mods" `
    --patches recomp/patches-v121.txt --out "$private/ips-patches.txt" `
    --status "$private/run/build-cache/exefs.status" --data "$private/run/build-cache/exefs.data"
& $python tools/materialize_exlaunch.py --staged "$private/staged" `
    --capture "$private/capture/capture.json" --patches "$private/ips-patches.txt" --out "$private/prepared"
& $python recomp/gen.py --exefs "$private/prepared/exefs" --out "$private/generated" `
    --modules main,subsdk0,sdk,subsdk1,subsdk2 --patches "$private/prepared/patches.txt"
& $python tools/exefs_patches.py --exefs "$game/exefs" --folded "$private/generated/main/folded.txt" `
    --status "$private/run/build-cache/exefs.status" --data "$private/run/build-cache/exefs.data"
& $python tools/build_game.py --version v121 --gen "$private/generated" --out "$private/run" `
    --exefs "$private/prepared/exefs" --expected "$private/prepared/expected.json" `
    --romfs "$game/romfs" --profile "$private/run/profile"
```

For LLVM-MinGW, supply the `--toolchain`, `--deps` and `--ninja` paths described in [Building from source](building.md). The runtime must be compiled from this source tree for the prepared layout. When using the 0.3.13 installer toolchain, copy `SDL3.dll`, `libopus-0.dll`, `totk_xlate.exe` and `totk_xlate.id` from its `bin` directory next to the executable. Keep the merged mod enabled and use the isolated `run/profile` directory for gameplay tests.

```powershell
$env:TOTK_HOOK_TRACE = '1'
& "$private/run/totk.exe" --selftest
& "$private/run/totk.exe" --boot
& "$private/run/totk.exe"
```

The trace logs the first execution of each captured hook or replacement. The capture rejects unsupported initializer calls, overlapping code writes and unexplained differences across trials. Prepared images can only replay the captured startup state and supported hook forms. Validate gameplay and save/load with the specific merged resources and versions before reusing an existing save.

The 1.2.1 runtime supplies an empty guest pointer cell for the older Exlaunch wrappers' missing manual lookup callback import. The primary lookup still runs first. After a miss, the wrapper checks the empty cell and reports that it found no symbol. This binding applies only to the known zero-addend data relocation in a prepared 1.2.1 module.
