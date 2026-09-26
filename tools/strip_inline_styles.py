"""One-shot codemod: strip the remaining inline style="" attributes from
web/index.html so the CSP can drop style-src 'unsafe-inline'.

Two kinds of sites exist:

  * council-bar-{vol,rec,pay} and adv-t{0..4}-bar are progress bars whose
    width is driven by app.js at runtime (element.style.width). Their markup
    seeds are either 0% (honest) or STALE FABRICATED MEASUREMENTS
    (91.7% / 83.3% / 91.5% baked into the HTML). Honest seed: w-0, "-".
  * "width: 100%" on fill containers (the parent track divs) becomes w-full.

Why it matters: with zero inline styles, the CSP can ship
`style-src 'self'` -- the last 'unsafe-inline' leaves the policy, and an
injected style attribute can no longer reflow the deck.

Idempotent: re-running matches nothing and exits 0 without writing.
The tailwind build MUST be re-run after this (build_web.bat) so the
utility classes exist in the compiled app.css.
"""
import os
import re

WEB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "web", "index.html")

# Any percentage the codemod may convert. New percentage styles added later
# will NOT be auto-migrated; the architecture test fails loudly instead.
_WIDTHS = ("0%", "100%", "91.7%", "83.3%", "91.5%")

# Inline style attributes that must never be silently removed: name the
# elements here and extend this codemod deliberately.
_PRESERVE = set()


def _replace_style_attr(tag: str) -> str:
    m = re.search(r'\sstyle="width:\s*([0-9.]+%)"', tag)
    if not m:
        return tag
    width = m.group(1)
    if width not in _WIDTHS or width in _PRESERVE:
        return tag
    cls = re.search(r'\sclass="([^"]*)"', tag)
    if not cls:
        # No class attribute: create one (Tailwind needs the class form).
        return tag[:m.start()] + ' class="w-full"' + tag[m.end():]
    classes = cls.group(1)
    tailwind = "w-full" if width == "100%" else "w-0"
    if tailwind in classes:
        new_classes = classes
    else:
        new_classes = classes + " " + tailwind
    tag = tag[:cls.start(1)] + new_classes + tag[cls.end(1):]
    # Re-locate the style attr (indices shifted by the class edit).
    m = re.search(r'\sstyle="width:\s*[0-9.]+%"', tag)
    return tag[:m.start()] + tag[m.end():]


def main() -> int:
    with open(WEB, "r", encoding="utf-8") as f:
        src = f.read()

    before = src.count('style="')
    src = re.sub(r'<[a-zA-Z][^>]*>', lambda m: _replace_style_attr(m.group(0)), src)
    after = src.count('style="')

    if before == after:
        print("No inline style attributes matched (already migrated).")
        return 0

    with open(WEB, "w", encoding="utf-8", newline="\n") as f:
        f.write(src)
    print(f"Removed {before - after} inline style attributes; {after} remain in markup.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
