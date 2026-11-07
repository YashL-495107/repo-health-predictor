"""protestware_destructive (Behavior) - destructive actions that only run for some users, gated on WHERE or WHEN
the code runs (the node-ipc pattern: delete or overwrite files when the IP geolocates to a target country).

Python (ast only; parsing limits in detectors/pyast.py):
  destructive  shutil.rmtree, os.remove/unlink/rmdir/removedirs, Path.unlink/rmdir, os.kill/killpg, a process
               command that deletes or kills (rm -rf, del /s, format, taskkill, kill -9), mass overwrite (open(..., "w")
               or write_text/write_bytes inside a loop over os.walk/glob/listdir/rglob), an infinite `while True`
               loop without break
  gates        locale (locale.getlocale/getdefaultlocale, LANG/LC_ALL/LC_CTYPE/LANGUAGE), timezone (time.tzname,
               TZ, tm_zone), IP geolocation (ip-api, ipinfo, ipapi, geoip ... URLs, country / countryCode fields),
               hostname (socket.gethostname, platform.node, uname().nodename), date comparisons (datetime/date/time
               compared with a fixed date), and literal country/locale/timezone targets ("RU", "ru_RU", "Europe/Moscow")
  NOT gates    sys.platform, os.name, platform.system()/machine()/release(): OS checks are normal in cleanup code
  gating       the destructive call sits in the body of an if/while whose test uses a gate (directly or through a
               variable assigned from one), or after a gate guard clause (`if gate: return`) in the same block
Tier: gated destructive = high_risk (capability_evidence). Destructive alone = not flagged (build tools, test
fixtures and cleanup code delete legitimately). A gate alone = not flagged.
JS / shell: regex only ("pattern match, no data-flow"): a gate pattern and a destructive pattern in the same file =
review at most, never high_risk. node-ipc (JavaScript) is therefore review here, not high_risk.
colors.js / faker.js style sabotage (an unconditional infinite loop or garbage output for everyone) is NOT gated, so
this detector does not flag it; that is a known miss by design (destructive-alone is not flagged).
Known evasions: gates evaluated in another function or module and passed in, gates read from a remote config,
destruction delayed by a timer or scheduled task, obfuscated calls (see decoded_payload), destruction in native code.
False-positive sources: cleanup code that branches on the time of day or date (cache expiry: a date compared with a
computed, not literal, date is not a gate), locale-aware file handling that also removes temp files, kiosk/demo
tools that reset machines by hostname.
"""
from __future__ import annotations

import ast
import re

from .base import content_gate, enrich, make_result, not_assessed, text_coverage
from . import pyast

DETECTOR_ID, PILLAR = "protestware_destructive", "Behavior"
NEEDS_DATA = True

DESTRUCTIVE_CALLS = {"shutil.rmtree", "os.remove", "os.unlink", "os.rmdir", "os.removedirs", "os.kill", "os.killpg",
                     "signal.pthread_kill"}
DESTRUCTIVE_ATTR = {"unlink", "rmdir", "rmtree"}
WRITE_ATTR = {"write_text", "write_bytes"}
WALK_CALLS = ("os.walk", "glob.glob", "glob.iglob", "os.listdir", "os.scandir")
WALK_ATTR = {"rglob", "glob", "iterdir"}
PROC_CALLS = ("subprocess.", "os.system", "os.popen")
DESTRUCTIVE_CMD = re.compile(r"\brm\s+-[a-z]*r[a-z]*f|\brm\s+-[a-z]*f[a-z]*r|\bdel\s+/[sq]|\bformat\s+[a-z]:|\btaskkill\b|\bkill\s+-9\b|\bshred\b|\bmkfs\b", re.I)
GATE_CALLS = {"locale.getlocale", "locale.getdefaultlocale", "locale.setlocale", "socket.gethostname", "platform.node",
              "time.localtime", "datetime.datetime.now", "datetime.now", "datetime.date.today", "date.today",
              "datetime.datetime.utcnow", "datetime.utcnow", "time.time", "os.uname"}
GATE_ATTRS = {"tzname", "tm_zone", "nodename", "timezone"}
GATE_ENV = re.compile(r"^(LANG|LC_ALL|LC_CTYPE|LC_MESSAGES|LANGUAGE|TZ)$")
GEO_TEXT = re.compile(r"ip-api\.com|ipinfo\.io|ipapi\.co|ipgeolocation|geoip|freegeoip|ip2location|geojs\.io|ipwho\.is|"
                      r"\bcountry_?code\b|\bcountryCode\b|\bcountry_name\b", re.I)
TARGET_LITERAL = re.compile(r"^(RU|BY|UA|CN|IR|KP|ru|by|ua|ru[_-]RU|be[_-]BY|uk[_-]UA|Russia|Belarus|Ukraine|"
                            r"Europe/(Moscow|Minsk|Kiev|Kyiv|Kaliningrad|Samara|Volgograd)|Asia/(Yekaterinburg|Omsk|Novosibirsk|Krasnoyarsk|Irkutsk|Vladivostok))$")
NOT_GATES = {"sys.platform", "os.name", "platform.system", "platform.machine", "platform.release", "platform.platform"}
JS_GATE = re.compile(r"Intl\.DateTimeFormat\(\)\.resolvedOptions\(\)\.timeZone|process\.env\.(?:LANG|TZ|LC_ALL)\b|"
                     r"navigator\.language|ip-api\.com|ipinfo\.io|ipapi\.co|geoip|countryCode|country_code|"
                     r"['\"](?:RU|BY|ru-RU|Europe/Moscow)['\"]|os\.hostname\(\)")
JS_DESTRUCTIVE = re.compile(r"fs\.(?:rmSync|rmdirSync|unlinkSync|writeFileSync|rm|rmdir|unlink)\(|rimraf|process\.kill\(|"
                            r"rm\s+-rf|while\s*\(\s*true\s*\)")
SH_GATE = re.compile(r"\$LANG\b|\$LC_ALL\b|\$TZ\b|timedatectl|/etc/timezone|ipinfo\.io|ip-api\.com|geoip|\bhostname\b")
SH_DESTRUCTIVE = re.compile(r"\brm\s+-[a-z]*r[a-z]*f\b|\bshred\b|\bmkfs\b|\bdd\s+if=/dev/(?:zero|urandom)")


TIME_NOW = ("time.time", "datetime.datetime.now", "datetime.now", "datetime.date.today", "date.today",
            "datetime.datetime.utcnow", "datetime.utcnow", "time.localtime")


def _gate_expr(expr, al, gate_vars: set[str], time_vars: set[str] | None = None) -> str | None:
    """Return a short description if the expression uses a location/time gate, else None."""
    time_vars = time_vars or set()
    if _date_compare(expr) and any((isinstance(n, ast.Call) and pyast.dotted(n.func, al) in TIME_NOW)
                                   or (isinstance(n, ast.Name) and n.id in time_vars) for n in ast.walk(expr)):
        return "a comparison of the current date with a fixed date"
    for n in ast.walk(expr):
        if isinstance(n, ast.Call):
            name = pyast.dotted(n.func, al)
            if name in NOT_GATES:
                continue
            if name in GATE_CALLS or name.endswith((".gethostname", ".getlocale", ".getdefaultlocale")):
                if name in TIME_NOW:
                    continue        # "now" alone is not a gate: only when compared with a fixed date (handled above)
                return f"`{name}()`"
            if name in ("os.getenv", "os.environ.get") and n.args and GATE_ENV.match(pyast.fold_str(n.args[0]) or ""):
                return f"environment variable {pyast.fold_str(n.args[0])}"
        if isinstance(n, ast.Subscript) and pyast.dotted(n.value, al) == "os.environ":
            k = pyast.fold_str(n.slice)
            if k and GATE_ENV.match(k):
                return f"environment variable {k}"
        if isinstance(n, ast.Attribute) and n.attr in GATE_ATTRS and pyast.dotted(n, al) not in NOT_GATES:
            return f"`{pyast.dotted(n, al)}`"
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            if GEO_TEXT.search(n.value):
                return f"geolocation lookup '{n.value[:50]}'"
            if TARGET_LITERAL.match(n.value.strip()) and isinstance(expr, (ast.Compare, ast.BoolOp, ast.UnaryOp)):
                return f"comparison with '{n.value}'"
        if isinstance(n, ast.Name) and n.id in gate_vars:
            return f"`{n.id}` (assigned from a location/time check)"
        if isinstance(n, ast.Attribute) and pyast.dotted(n) in gate_vars:
            return f"`{pyast.dotted(n)}` (assigned from a location/time check)"
    return None


def _date_compare(expr) -> bool:
    """True if expr compares something with a FIXED date (a datetime/date(...) built from literals, or a literal
    year/epoch number such as 2022 or 1646000000)."""
    for n in ast.walk(expr):
        if isinstance(n, ast.Compare):
            for side in [n.left, *n.comparators]:
                if isinstance(side, ast.Call) and pyast.dotted(side.func).split(".")[-1] in ("datetime", "date") \
                        and side.args and all(isinstance(a, ast.Constant) for a in side.args):
                    return True
                if isinstance(side, ast.Constant) and isinstance(side.value, (int, float)) and (2000 <= side.value <= 2100 or side.value > 1e9):
                    return True
            if any(isinstance(s, ast.Attribute) and s.attr in ("year", "month", "day") for s in [n.left, *n.comparators]):
                return any(isinstance(s, ast.Constant) for s in [n.left, *n.comparators])
    return False


def _destructive(call: ast.Call, al, in_walk_loop: bool) -> str | None:
    name = pyast.dotted(call.func, al)
    attr = name.rsplit(".", 1)[-1] if name else ""
    if name in DESTRUCTIVE_CALLS or (attr in DESTRUCTIVE_ATTR and name not in NOT_GATES):
        return f"`{name}`"
    if name.startswith(PROC_CALLS):
        cmd = " ".join(v for a in call.args for x in ast.walk(a) if isinstance(x, ast.Constant) and isinstance(v := x.value, str))
        if DESTRUCTIVE_CMD.search(cmd):
            return f"`{name}` running '{cmd[:60]}'"
    if in_walk_loop:
        if attr in WRITE_ATTR:
            return f"`{name}` over many files"
        if name in ("open", "io.open") and len(call.args) > 1:
            mode = pyast.fold_str(call.args[1]) or ""
            if "w" in mode:
                return "`open(..., 'w')` over many files (overwrite)"
    return None


def _walk_loop(st, al) -> bool:
    if not isinstance(st, (ast.For, ast.AsyncFor)):
        return False
    for c in pyast.calls_in(st.iter):
        name = pyast.dotted(c.func, al)
        if name in WALK_CALLS or name.rsplit(".", 1)[-1] in WALK_ATTR:
            return True
    return False


def _infinite_loop(st) -> bool:
    if not isinstance(st, ast.While) or not (isinstance(st.test, ast.Constant) and st.test.value is True):
        return False
    return not any(isinstance(n, (ast.Break, ast.Return, ast.Raise)) for n in ast.walk(st))


def _guard(st) -> bool:
    body = [b for b in st.body if not isinstance(b, ast.Pass)]
    return bool(body) and all(isinstance(b, (ast.Return, ast.Raise, ast.Continue)) or
                              (isinstance(b, ast.Expr) and isinstance(b.value, ast.Call) and pyast.dotted(b.value.func) in ("sys.exit", "exit", "quit"))
                              for b in body)


def analyse_python(path: str, text: str) -> tuple[list[dict], str | None]:
    tree, err = pyast.safe_parse(text)
    if tree is None:
        return [], err
    al = pyast.aliases(tree)
    findings, seen = [], set()

    time_vars: set[str] = set()

    def scan_block(stmts, gate, gate_vars, in_walk):
        guarded = None
        for st in stmts:
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            active = gate or guarded
            names, val = pyast.assigned_names(st)
            if val is not None and names:
                if _gate_expr(val, al, gate_vars, time_vars):
                    gate_vars.update(names)
                if any(isinstance(c, ast.Call) and pyast.dotted(c.func, al) in TIME_NOW for c in ast.walk(val)):
                    time_vars.update(names)
            if isinstance(st, (ast.If, ast.While)):
                g = _gate_expr(st.test, al, gate_vars, time_vars)
                if g and isinstance(st, ast.If) and _guard(st):
                    guarded = (g, st.lineno)       # `if gate: return` -> the rest of this block is gated
                    continue
                if isinstance(st, ast.While) and _infinite_loop(st) and active:
                    _add(active, st.lineno, "an infinite `while True` loop")
                inner = (g, st.lineno) if g else active
                scan_block(st.body, inner, gate_vars, in_walk)
                scan_block(st.orelse, inner, gate_vars, in_walk)
                continue
            own = [x for x in ast.iter_child_nodes(st) if not isinstance(x, ast.stmt)] if hasattr(st, "body") else [st]
            loop = in_walk or _walk_loop(st, al)
            if active:
                for node in own:
                    for call in pyast.calls_in(node):
                        d = _destructive(call, al, loop)
                        if d:
                            _add(active, call.lineno, d)
            for field in ("body", "orelse", "finalbody"):
                if getattr(st, field, None):
                    scan_block(getattr(st, field), active, gate_vars, loop)
            for h in getattr(st, "handlers", []) or []:
                scan_block(h.body, active, gate_vars, loop)

    def _add(gate, line, what):
        key = (line, what)
        if key in seen:
            return
        seen.add(key)
        g, gline = gate
        f = {"sev": "High", "source": "Behavior data flow", "rule": "Destructive action gated on location/locale/time/host",
             "file": path, "line": line,
             "detail": f"{what} (line {line}) only runs when {g} (line {gline}) matches. This is the protestware pattern: "
                       "harm aimed at users in a given country, locale, timezone, host or date.",
             "fix": "Do not install. Read the gated code path by hand.", "url": None, "strong": True}
        ev = [{"type": "file_line", "file": path, "line": gline, "role": "gate", "what": g, "code": pyast.snippet(text, gline)},
              {"type": "file_line", "file": path, "line": line, "role": "destructive", "what": what, "code": pyast.snippet(text, line)}]
        findings.append({**enrich(f, DETECTOR_ID, "high_risk", ev), "capability_evidence": True, "confidence": "data-flow"})

    for scope_name, body in pyast.scopes(tree):
        scan_block(body, None, set(), False)
    return findings, None


def analyse_pattern(path: str, text: str) -> list[dict]:
    sh = path.lower().endswith((".sh", ".bash"))
    g = (SH_GATE if sh else JS_GATE).search(text)
    d = (SH_DESTRUCTIVE if sh else JS_DESTRUCTIVE).search(text)
    if not (g and d):
        return []
    line = text[:d.start()].count("\n") + 1
    f = {"sev": "Medium", "source": "Behavior pattern match",
         "rule": "Destructive action and a location/locale/time check in the same file (pattern match, no data-flow)",
         "file": path, "line": line, "detail": f"`{d.group(0)[:50]}` and `{g.group(0)[:50]}` in the same file. "
                                               "Pattern match, no data-flow: lower confidence, review only.",
         "fix": "Read the file by hand.", "url": None, "strong": False}
    return [{**enrich(f, DETECTOR_ID, "review"), "capability_evidence": True, "confidence": "pattern match, no data-flow"}]


def detect(ctx) -> dict:
    gate = content_gate(ctx, DETECTOR_ID, PILLAR)
    if gate:
        return gate
    if ctx.data is None:
        return not_assessed(DETECTOR_ID, PILLAR, "repository contents not available")
    findings, skipped, seen = [], [], 0
    for path, text in (ctx.data.get("text") or {}).items():
        if pyast.analysable(path, (".py",)):
            seen += 1
            if seen > pyast.MAX_FILES:
                skipped.append(f"{path}: file limit")
                continue
            fs, err = analyse_python(path, text)
            if err:
                skipped.append(f"{path}: {err}")
            findings += fs
        elif pyast.analysable(path, (".js", ".mjs", ".cjs", ".ts", ".sh", ".bash")):
            findings += analyse_pattern(path, text)
    cov, detail = text_coverage(ctx, ("text",))
    if skipped:
        cov = "partial"
        detail = "; ".join(x for x in (detail, f"{len(skipped)} Python file(s) not analysed, e.g. {skipped[0]}") if x)
    return make_result(DETECTOR_ID, PILLAR, "ran", findings, coverage=cov, coverage_detail=detail)
