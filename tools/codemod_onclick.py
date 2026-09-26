"""
One-shot codemod: migrate the inline onclick= handlers to data-action /
data-arg attributes consumed by one delegated listener in app.js.

Why: inline event handlers execute under the page's global scope, which forces
the CSP to carry script-src 'unsafe-inline' -- the loophole that makes an
injected attribute enough to run script in an XSS scenario. With data-action
attributes and a single addEventListener, the CSP can drop 'unsafe-inline' for
scripts entirely: no inline script can exist, so injected markup stays inert.

Migration rules:
  1. Every handler is extracted VERBATIM (mechanical refactor, no retuning).
  2. data-action is the lowercased callee name (always a valid JS
     identifier); a single literal string argument moves to data-arg and is
     read from the element at click time, so duplicate callees (switchDeck
     x4, triggerSimulatedAttack x9, opsJob x3) share one closure safely.
  3. Buttons keep the `id=` and `disabled` state the UI toggles manipulate.
  4. app.js's dynamically-rendered unban button moves to data-action too.
  5. The index.html <script src> loses `defer` -- the listener must be live
     before first paint so no early click is lost. app.js runs init on
     window.onload.
  6. Atomic transform with assertions; on any failure nothing is written.

Run from the project root:
    python tools/codemod_onclick.py
"""

import os
import re
import shutil
import sys

WEB = "web"
HTML_PATH = os.path.join(WEB, "index.html")
JS_PATH = os.path.join(WEB, "js", "app.js")

DECL_RE = re.compile(r"(?m)^(    )((?:async )?function\s+([A-Za-z_$][\w$]*)\s*\()")

HANDLER_RE = re.compile(r"\sonclick=\"([^\"]*)\"")

Q1 = chr(39)  # single quote
Q2 = chr(34)  # double quote

# Callees allowed to carry a single string-literal argument.
SINGLE_ARG_OK = {"switchDeck", "triggerSimulatedAttack", "opsJob"}

# The post-migration assertion expects exactly these action keys.
EXPECTED_KEYS = {
    "toggledefensemode", "togglelivecapture", "toggleaudio", "switchdeck",
    "runadversarystresstest", "triggerevolutionburst", "triggerdirectedsurgery",
    "togglecontinuousloop", "injectcontinuousbatch",
    "clearcontinuousauditconsole", "opsrollingstart", "opsrollingstop",
    "opsinstallschedule", "triggersimulatedattack", "opsjob", "unban ip",
}


def action_spec(handler: str, fn_names: set):
    """(action_key, callee, quoted_arg_or_None, bare_arg_or_None)."""
    h = handler.strip()
    m = re.match(r"^([A-Za-z_$][\w$]*)\s*\((.*)\)$", h, re.S)
    if not m:
        raise AssertionError(f"unexpected handler shape: {h!r}")
    fname, args = m.group(1), m.group(2).strip()
    if fname not in fn_names:
        raise AssertionError(f"handler references unknown function: {fname!r}")
    key = fname.lower()
    if not args:
        return key, fname, None, None
    if fname not in SINGLE_ARG_OK:
        raise AssertionError(f"unexpected argument on {fname}: {args!r}")
    quoted = (args[0] == Q1 and args[-1] == Q1) or (args[0] == Q2 and args[-1] == Q2)
    if not quoted or Q1 in args[1:-1] or Q2 in args[1:-1]:
        raise AssertionError(f"non-literal argument on {fname}: {args!r}")
    inner = args[1:-1]
    if not re.fullmatch(r"[A-Za-z0-9_\-]+", inner):
        raise AssertionError(f"unsafe arg token on {fname}: {inner!r}")
    return key, fname, args, inner


def main() -> int:
    with open(HTML_PATH, "r", encoding="utf-8") as f:
        html = f.read()
    with open(JS_PATH, "r", encoding="utf-8") as f:
        js = f.read()

    # 1. Collect function declarations and dedent them to top level.
    decls = {}
    js_new = DECL_RE.sub(
        lambda m: m.group(2) if m.group(1) == "    " else m.group(0), js)
    for m in DECL_RE.finditer(js):
        decls[m.group(3)] = m.group(2).strip()
    fn_names = set(decls)
    print(f"functions dedented: {len(decls)}")

    # 2. Rewrite inline handlers in place: onclick="f('x')" ->
    #    data-action="f" data-arg="x". Single pass, document order preserved.
    specs = []

    def _repl(m):
        key, fname, quoted, inner = action_spec(m.group(1), fn_names)
        specs.append((key, fname, quoted, inner))
        attr = f' data-action="{key}"'
        if inner is not None:
            attr += f' data-arg="{inner}"'
        return attr
    html_new = HANDLER_RE.sub(_repl, html)
    print(f"inline handlers extracted: {len(specs)}")
    if not specs:
        print("nothing to migrate")
        return 0

    # 3. Move the unban button to data-action inside app.js. Quote chars are
    # built with chr() so this source file never contains backslash escapes
    # (they do not survive round-trips through editing tools).
    old_btn = "onclick=" + Q2 + "unbanIp('${ip}')" + Q2
    new_btn = ("data-action=" + Q2 + "unban ip" + Q2
               + " data-ip=" + Q2 + "${ip}" + Q2)
    assert js_new.count(old_btn) == 1, "unban button not found once in app.js"
    js_new = js_new.replace(old_btn, new_btn)

    # 4. The delegated listener: one closure per callee, argument read from
    # the element at click time. Registered before first paint; app.js keeps
    # executing its init on window.onload.
    lines = []
    seen = set()
    for key, fname, _quoted, _inner in specs:
        if key in seen:
            continue
        seen.add(key)
        lines.append(f"        {key}: (el) => {fname}(el.dataset.arg),")
    lines.append("        " + Q1 + "unban ip" + Q1
                 + ": (el) => { const ip = el.dataset.ip; if (ip) unbanIp(ip); },")
    listener = (
        "\n"
        "    // Central delegated action listener (CSP script-src 'self': no\n"
        "    // inline handlers exist in the markup; buttons carry data-action\n"
        "    // attributes and read their argument from data-arg / data-ip).\n"
        "    const ACTIONS = {\n"
        + "\n".join(lines) + "\n"
        "    };\n"
        "    document.addEventListener('click', (ev) => {\n"
        "      const el = ev.target.closest('[data-action]');\n"
        "      if (!el) return;\n"
        "      const fn = ACTIONS[el.dataset.action];\n"
        "      if (typeof fn === 'function') fn(el);\n"
        "    });\n"
    )
    js_new = js_new.rstrip() + "\n" + listener

    # 5. index.html: app.js loses `defer` so the listener is live pre-paint.
    old_tag = "<script src=" + Q2 + "./js/app.js" + Q2 + " defer></script>"
    new_tag = "<script src=" + Q2 + "./js/app.js" + Q2 + "></script>"
    assert old_tag in html_new, "app.js script tag not found (defer form)"
    html_new = html_new.replace(old_tag, new_tag)

    # 6. Assertions.
    assert "onclick=" not in html_new, "index.html still has onclick"
    assert "onclick=" not in js_new, "app.js still has onclick"
    assert html_new.count("data-action=") == len(specs), "data-action count mismatch"
    keys = {k for k, _f, _q, _i in specs} | {"unban ip"}
    assert keys == EXPECTED_KEYS, f"unexpected action set: {sorted(keys)}"
    for k, _f, _q, inner in specs:
        assert f'data-action="{k}"' in html_new, f"missing data-action: {k}"
        if inner is not None:
            assert f'data-arg="{inner}"' in html_new, f"missing data-arg: {inner}"

    # 7. Atomic write with backups.
    for path, content in ((HTML_PATH, html_new), (JS_PATH, js_new)):
        shutil.copy2(path, path + ".pre-codemod")
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(content)
    print(f"migrated {len(specs)} handlers into {len(lines)} actions; "
          f"backups: *.pre-codemod")
    return 0


if __name__ == "__main__":
    sys.exit(main())
