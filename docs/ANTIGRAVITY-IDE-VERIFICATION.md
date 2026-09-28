# Antigravity IDE — Install & Headless Verification Record

Environment: Freebuff Cloud workspace sandbox (Ubuntu 22.04, linux-x64, root, no GPU, no display server).

## Install

`scripts/install-antigravity-ide.sh` installs Antigravity IDE v1.107.0 (Google's
agentic VS Code/Electron fork):

- Download: 229.7 MB release tarball from `edgedl.me.gvt1.com` (Google Edge Cache)
- Integrity: SHA-256 verified against the pin in the script
  (`0c5233b297d2b3aebb61af49f8944012c2953d361a5ebb16978490636917f831`)
- Install location: `/opt/Antigravity IDE` (~764 MB extracted, 18,629 archive entries)
- CLI: `antigravity-ide` symlinked onto PATH (the bundled `bin/antigravity-ide`
  wrapper resolves the app dir through the symlink)
- Desktop entry: `/usr/share/applications/antigravity-ide.desktop`

All shared libraries resolve (`ldd` clean). The headless CLI path
(`antigravity-ide --list-extensions`) exits 0.

## Headless GUI verification (Xvfb)

The sandbox has no display server, so the GUI was exercised against a virtual
display:

```
Xvfb :99 -screen 0 1440x900x24 &
DISPLAY=:99 antigravity-ide --no-sandbox --disable-gpu \
  --enable-unsafe-swiftshader --user-data-dir=/tmp/ag-ui-proof &
```

Run twice independently (with and without the software-WebGL flag); both times
the main process stayed alive for 45+ seconds and the main-process log showed a
normal boot: update check → `update#setState idle`, artifact-review lifecycle,
pty-host supervision.

The captured frame is committed at
`docs/assets/antigravity-ide-headless-launch.png`. Pixel analysis of the
1440×900 capture:

| Metric | Value |
|---|---|
| Unique colors | 3,624 (a blank X display would have exactly 1) |
| Pixels differing from background | 26.4% |
| Dominant background | `#1F1F1F` — VS Code "Dark Modern" editor background |
| Secondary chrome | `#181818` activity bar / `#232323`, `#242424` panel greys |
| Capture-to-capture delta (t+30s vs t+45s) | 0 changed pixels (static, fully settled frame) |

Conclusion: the IDE's UI genuinely painted the virtual display; the process is
stable under software rendering.

## Limitations (honest caveats)

- Rendered with `--disable-gpu --enable-unsafe-swiftshader` because the sandbox
  has no GPU; the palette that painted is mostly monochrome dark. Accent-color
  widgets (welcome badge, syntax-colored sample) were not confirmed to have
  drawn. On real hardware with a GPU, rendering takes the normal path.
- The X window-manager tree did not list the Electron window at sampling time,
  so pixel analysis is the primary evidence; `xdotool` results were
  inconclusive.
- A headless sandbox cannot serve an interactive GUI session; interactive use
  requires a machine with a display
  (`sh scripts/install-antigravity-ide.sh && antigravity-ide`).
