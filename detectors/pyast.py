"""Static Python AST helpers for the data-flow detectors (credential_exfiltration, protestware_destructive).

Only ast.parse is used: repository code is NEVER compiled, executed, imported or evaluated. Parsing is bounded so a
hostile file cannot crash or stall the scan: files above MAX_PARSE_BYTES are skipped, trees above MAX_NODES nodes
are skipped, and SyntaxError / RecursionError / MemoryError / ValueError are caught per file.

Taint model (deliberately simple, documented as such): within one scope (a function, or the module top level),
statements are visited in source order; a name assigned from an expression that carries a source becomes tainted
with that source. Module-level tainted names are visible inside functions ("same-module variable chain"). Values
passed through function calls, returns, attributes of other objects, or other modules are NOT tracked.
"""
from __future__ import annotations

import ast
import re
import warnings
from pathlib import PurePosixPath

# Scanned code is only parsed (ast.parse), never executed. Its own invalid escape sequences etc. raise SyntaxWarning at
# parse time; they are noise, so they are silenced for parses made with the SCANNED_FILENAME marker only (a module-level
# filter, which works across threads, unlike catch_warnings). Warnings from this project's own code are unaffected.
SCANNED_FILENAME = "<scanned-code>"
for _cat in (SyntaxWarning, DeprecationWarning):   # invalid escapes: DeprecationWarning before Python 3.12
    warnings.filterwarnings("ignore", category=_cat, module=re.escape(SCANNED_FILENAME) + r"\Z")


MAX_PARSE_BYTES = 400_000
MAX_NODES = 200_000
MAX_FILES = 2000
SKIP_PARTS = {"test", "tests", "testing", "__tests__", "spec", "fixtures", "docs", "doc", "examples", "example",
              "samples", "rules", "signatures"}


def analysable(path: str, exts: tuple[str, ...]) -> bool:
    p = PurePosixPath(path)
    return p.suffix.lower() in exts and not any(x.lower() in SKIP_PARTS for x in p.parts[:-1])


def parse_ok(path: str, text: str) -> bool:
    """True if `path` is a Python file the data-flow detectors analyse with ast (scannable and parseable)."""
    return analysable(path, (".py",)) and safe_parse(text)[0] is not None


_PARSE_CACHE: dict[str, tuple] = {}


def safe_parse(text: str) -> tuple[ast.AST | None, str | None]:
    """(tree, None) or (None, reason). Never raises. Results are memoised by content hash (bounded)."""
    import hashlib
    key = hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()
    if key in _PARSE_CACHE:
        return _PARSE_CACHE[key]
    out = _safe_parse(text)
    if len(_PARSE_CACHE) > 4000:
        _PARSE_CACHE.clear()
    _PARSE_CACHE[key] = out
    return out


def _safe_parse(text: str) -> tuple[ast.AST | None, str | None]:
    if len(text.encode("utf-8", "ignore")) > MAX_PARSE_BYTES:
        return None, "too large"
    try:
        tree = ast.parse(text, filename=SCANNED_FILENAME)
    except SyntaxError:
        return None, "syntax error"
    except (RecursionError, MemoryError, ValueError, OverflowError) as e:
        return None, f"unparseable ({type(e).__name__})"
    n = 0
    for _ in ast.walk(tree):
        n += 1
        if n > MAX_NODES:
            return None, "too complex"
    return tree, None


def aliases(tree: ast.AST) -> dict[str, str]:
    """import requests as r -> {"r": "requests"}; from os import environ -> {"environ": "os.environ"}."""
    out = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                out[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            for a in node.names:
                out[a.asname or a.name] = f"{node.module}.{a.name}"
    return out


def dotted(node, al: dict[str, str] | None = None) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        head = (al or {}).get(node.id, node.id)
        parts.append(head)
    elif isinstance(node, ast.Call):
        parts.append(dotted(node.func, al) + "()")
    else:
        return ""
    return ".".join(reversed(parts))


def fold_str(node) -> str | None:
    """Literal string value of "a", "a" + "b", "".join([...]), f"lit{...}" (literal prefix only for f-strings)."""
    from malware_proof import _fold_str
    v = _fold_str(node)
    if v is not None:
        return v
    if isinstance(node, ast.JoinedStr):
        prefix = ""
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                prefix += part.value
            else:
                break
        return prefix or None
    return None


def parents(tree: ast.AST) -> dict[int, ast.AST]:
    out = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            out[id(child)] = node
    return out


def ordered_statements(body: list) -> list:
    """Statements of one scope in source order, entering if/for/while/with/try blocks but not nested functions or
    classes (those are separate scopes). Iterative, so deep nesting cannot overflow the Python stack."""
    out, stack = [], [list(body)]
    while stack:
        block = stack.pop()
        if not block:
            continue
        st, rest = block[0], block[1:]
        stack.append(rest)
        out.append(st)
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        inner = []
        for field in ("body", "orelse", "finalbody"):
            inner += list(getattr(st, field, []) or [])
        for h in getattr(st, "handlers", []) or []:
            inner += list(h.body)
        for c in getattr(st, "cases", []) or []:
            inner += list(c.body)
        if inner:
            stack.append(inner)
    return out


def scopes(tree: ast.Module) -> list[tuple[str, list]]:
    """[("<module>", statements), ("func_name", statements), ...]; methods are their own scopes."""
    out = [("<module>", tree.body)]
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append((node.name, node.body))
    return out


def assigned_names(st) -> tuple[list[str], ast.AST | None]:
    """Target names and the value expression of an assignment-like statement."""
    def names(t):
        if isinstance(t, ast.Name):
            return [t.id]
        if isinstance(t, (ast.Tuple, ast.List)):
            return [n for e in t.elts for n in names(e)]
        if isinstance(t, ast.Subscript):
            return names(t.value)
        if isinstance(t, ast.Attribute):
            d = dotted(t)
            return [d] if d else []
        if isinstance(t, ast.Starred):
            return names(t.value)
        return []
    if isinstance(st, ast.Assign):
        return [n for t in st.targets for n in names(t)], st.value
    if isinstance(st, (ast.AnnAssign, ast.AugAssign)) and st.value is not None:
        return names(st.target), st.value
    if isinstance(st, (ast.For, ast.AsyncFor)):
        return names(st.target), st.iter
    if isinstance(st, (ast.With, ast.AsyncWith)):
        out, val = [], None
        for item in st.items:
            if item.optional_vars is not None:
                out += names(item.optional_vars)
                val = item.context_expr
        return out, val
    return [], None


def names_in(expr) -> set[str]:
    out = set()
    for n in ast.walk(expr):
        if isinstance(n, ast.Name):
            out.add(n.id)
        elif isinstance(n, ast.Attribute):
            d = dotted(n)
            if d:
                out.add(d)
    return out


def calls_in(node) -> list[ast.Call]:
    return [n for n in ast.walk(node) if isinstance(n, ast.Call)]


def snippet(text: str, line: int | None, width: int = 160) -> str:
    if not line:
        return ""
    lines = text.splitlines()
    return lines[line - 1].strip()[:width] if 0 < line <= len(lines) else ""
