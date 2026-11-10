"""WORDING RULE: never use "safe", "secure", "clean" (or "guarantee") as a verdict in user-visible text.

Scans string literals and comments of the UI / report / CLI / detector modules and the project docs. Allowed:
code identifiers (yaml.safe_load, quote(safe=...) are code, not strings, so they are not scanned), quoted
third-party text listed in ALLOWED_LITERALS, and negated disclaimers ("does not mean safe", "not a guarantee").
"""
import glob
import io
import os
import re
import tokenize

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY_FILES = ["app.py", "trust_check.py", "security.py", "pillars.py", "fragility.py", "scoring.py", "analyze_scan_results.py",
            "inspect_repo.py", "scan_batch.py", "benchmark_fixtures.py", "audit.py", "intelligence.py", "repo_scan.py",
            "malware_proof.py", "repo_behavior.py", "verify_full_stack.py", "releases.py", "http_cache.py"] + \
           [os.path.relpath(p, ROOT) for p in glob.glob(os.path.join(ROOT, "app_pages", "*.py"))] + \
           [os.path.relpath(p, ROOT) for p in glob.glob(os.path.join(ROOT, "detectors", "*.py"))] + \
           [os.path.relpath(p, ROOT) for p in glob.glob(os.path.join(ROOT, "benchmark", "*.py"))]
DOC_FILES = ["README.md", "PROJECT_CAPABILITIES.md", "METHOD.md", "LIMITS.md"] + \
            [os.path.relpath(p, ROOT) for p in glob.glob(os.path.join(ROOT, "docs", "*.md")) if not p.endswith("PLAN.md")] + \
            [os.path.relpath(p, ROOT) for p in glob.glob(os.path.join(ROOT, "skills", "*.md"))] + \
            [os.path.relpath(p, ROOT) for p in glob.glob(os.path.join(ROOT, "benchmark", "*.md"))]

FORBIDDEN = re.compile(r"\b(?:un)?safe(?:r|st|ly|ty)?\b|\bsecure[ds]?\b|\bclean(?:ed|ly|er|est)?\b|\bguarantee[sd]?\b", re.I)
NEGATION = re.compile(r"\b(?:not|never|no|cannot)\b[^.;:!?]{0,40}$", re.I)
# quoted third-party names, and the storage-note marker the benchmark owner asked for ("unsafe name, obtained via
# <method>": a dataset FILE NAME that Windows cannot hold, not a verdict on a package)
# ...and the Upgrade check page title the owner asked for: a question the page answers with indicators, not a verdict
ALLOWED_LITERALS = ("SecureCodingDojo", "unsafe name, obtained via", "is this update safe?")


def violations(text: str) -> list[str]:
    out = []
    for m in FORBIDDEN.finditer(text):
        before = text[:m.start()]
        if NEGATION.search(before):
            continue
        if any(a in text[max(0, m.start() - 20):m.end() + 20] for a in ALLOWED_LITERALS):
            continue
        out.append(text[max(0, m.start() - 40):m.end() + 20].replace("\n", " "))
    return out


def _strip_fstring_fields(literal: str) -> str:
    """Python < 3.12 tokenizes an f-string as ONE string token, replacement fields included; the code inside {...}
    (e.g. quote(name, safe='')) is not user-visible text, so drop it (3.12+ already yields only FSTRING_MIDDLE)."""
    m = re.match(r"^([A-Za-z]*)(['\"])", literal)
    if not m or "f" not in m.group(1).lower():
        return literal
    out, depth, i = [], 0, 0
    while i < len(literal):
        c = literal[i]
        if depth == 0 and literal.startswith("{{", i):
            out.append("{{")
            i += 2
            continue
        if c == "{":
            depth += 1
        elif c == "}" and depth:
            depth -= 1
        elif depth == 0:
            out.append(c)
        i += 1
    return "".join(out)


def _py_texts(path):
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type in (tokenize.STRING, tokenize.COMMENT) or tok.type == getattr(tokenize, "FSTRING_MIDDLE", -1):
            yield tok.start[0], _strip_fstring_fields(tok.string) if tok.type == tokenize.STRING else tok.string


def test_fstring_fields_are_not_text():
    assert _strip_fstring_fields("f'x {quote(a, safe=\\'\\')} y'") == "f'x  y'"
    assert _strip_fstring_fields("f'{{literal}} {v}'") == "f'{{literal}} '"
    assert _strip_fstring_fields("'not an f-string {safe}'") == "'not an f-string {safe}'"


def test_rule_itself():
    assert violations("Clean scan")
    assert violations("This repo is safe to use")
    assert violations("a secure package")
    assert not violations("No findings does not mean safe.")
    assert not violations("This is not a guarantee of anything.")
    assert not violations("'no findings' never means safe")
    assert not violations("No findings is not proof")


def test_no_forbidden_verdict_words_in_user_visible_text():
    bad = []
    for rel in PY_FILES:
        path = os.path.join(ROOT, rel)
        if not os.path.exists(path):
            continue
        for line, text in _py_texts(path):
            bad += [f"{rel}:{line}: ...{v}..." for v in violations(text)]
    for rel in DOC_FILES:
        path = os.path.join(ROOT, rel)
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                bad += [f"{rel}:{n}: ...{v}..." for v in violations(line)]
    assert not bad, "\n".join(bad)
