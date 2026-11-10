"""Additional signals: informational only, NOT part of the frozen ruleset 2026.11.08-12 or the benchmark, unvalidated.

Nothing here feeds the Trust score, a cap, a detector or the verdict. The app shows the result in its own panel.

1. Maintainer email domains (takeover-risk indicator, not proof). The package's maintainer contact domains come from
   the registry (npm packument "maintainers[].email"; PyPI JSON "info.author_email" / "info.maintainer_email").
   Free mail providers are skipped. Each remaining domain is looked up with RDAP (https://rdap.org/domain/<domain>,
   a redirector to the registry's RDAP server). Flags:
     - "domain not registered": the registry's RDAP server answered 404 (rdap.org redirected, then 404). Whoever
       registers the domain can receive the maintainer's password-reset mail.
     - "domain registered after the package's latest release": the RDAP "registration" event is later than the
       latest release, so the domain may have changed hands since the maintainer last published.
   A 404 from rdap.org WITHOUT a redirect means rdap.org knows no RDAP server for that TLD: "could not check", never
   "not registered". Only the domain is kept; the full address is never stored or shown.
   The registrable domain is approximated without the Public Suffix List (last two labels, or three for
   "co.uk"-style second levels); the domain actually looked up is shown.

2. Provenance identity. PyPI: the PEP 740 integrity API for the latest release's files gives
   attestation_bundles[].publisher {kind, repository}. npm: versions[latest].dist.attestations.url lists the
   attestations; the SLSA provenance statement (DSSE payload, base64) names the source repository in
   predicate.buildDefinition.externalParameters.workflow.repository (SLSA v1) or
   predicate.invocation.configSource.uri (SLSA v0.2). The repository is compared with the scanned GitHub repository.
   The signature is NOT cryptographically verified here.

Network: every request has a timeout; a failed or unexpected answer is reported as "could not check", never as a
pass. The fetcher is injected (tests use recorded responses; the app wraps it in st.cache_data).
"""
from __future__ import annotations

import base64
import json
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import quote

PANEL_TITLE = "Additional signals (not part of the frozen ruleset or the benchmark; unvalidated)"
TAKEOVER_NOTE = "takeover-risk indicator, not proof"
SIGNATURE_NOTE = "signature not cryptographically verified here"
FLAG_NOT_REGISTERED = "domain not registered (could be bought and used to reset the maintainer account)"
FLAG_REGISTERED_AFTER = "domain registered after the package's latest release"
COULD_NOT_CHECK = "could not check"

TIMEOUT = (5, 10)            # connect, read (seconds)
MAX_DOMAINS = 5
PYPI_INTEGRITY_ACCEPT = "application/vnd.pypi.integrity.v1+json"

FREE_MAIL = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "hotmail.co.uk", "live.com", "msn.com",
    "yahoo.com", "yahoo.co.uk", "yahoo.co.jp", "ymail.com", "rocketmail.com", "aol.com", "protonmail.com",
    "protonmail.ch", "proton.me", "pm.me", "icloud.com", "me.com", "mac.com", "qq.com", "163.com", "126.com",
    "yeah.net", "sina.com", "foxmail.com", "yandex.ru", "yandex.com", "ya.ru", "mail.ru", "bk.ru", "inbox.ru",
    "list.ru", "gmx.de", "gmx.net", "gmx.com", "web.de", "t-online.de", "zoho.com", "fastmail.com", "fastmail.fm",
    "tutanota.com", "tuta.io", "hey.com", "naver.com", "daum.net", "hanmail.net", "rediffmail.com", "mail.com",
    "outlook.de", "outlook.fr", "hotmail.fr", "hotmail.de", "laposte.net", "orange.fr", "free.fr", "libero.it",
})
_SECOND_LEVEL = {"co", "com", "net", "org", "ac", "gov", "edu", "or", "ne", "go", "gob", "nic"}
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@([A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+)")


# ------------------------------------------------------------------ network (injected)

def http_get_json(url: str, accept: str | None = None, timeout=TIMEOUT) -> dict:
    """GET a JSON document. {"status": int | None, "data": object | None, "redirected": bool, "error": str | None}.
    Never raises; a network error or a non-JSON body is reported in "error"."""
    import requests
    try:
        r = requests.get(url, timeout=timeout, headers={"Accept": accept or "application/json",
                                                         "User-Agent": "repo-health-predictor (additional signals)"})
    except requests.RequestException as e:
        return {"status": None, "data": None, "redirected": False, "error": type(e).__name__}
    data, err = None, None
    if r.status_code == 200:
        try:
            data = r.json()
        except ValueError:
            err = "response was not JSON"
    return {"status": r.status_code, "data": data, "redirected": bool(r.history), "error": err}


def _ok(resp: dict) -> bool:
    return resp.get("status") == 200 and resp.get("data") is not None and not resp.get("error")


def _why(resp: dict) -> str:
    if resp.get("error"):
        return resp["error"]
    return f"HTTP {resp.get('status')}" if resp.get("status") else "no answer"


def _dt(s) -> datetime | None:
    if not isinstance(s, str) or not s:
        return None
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


# ------------------------------------------------------------------ email domains

def email_domain(text: str) -> list[str]:
    """Domains of every address in a registry contact field ("Name <a@b.org>, c@d.io"), lower-case."""
    return [m.lower().strip(".") for m in _EMAIL.findall(text or "")]


def registrable_domain(domain: str) -> str:
    """Approximation without the Public Suffix List: the last two labels, or three when the second-level label is a
    generic one under a two-letter country code (example.co.uk, example.com.au)."""
    labels = [x for x in domain.lower().strip(".").split(".") if x]
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def contact_domains(emails: list[str]) -> dict:
    """{"domains": [registrable domains to check, in order, at most MAX_DOMAINS], "free_mail": n, "other_skipped": n,
    "more": n}. Free mail providers and GitHub no-reply addresses are skipped. Addresses are never returned."""
    seen, free, other = [], 0, 0
    for raw in emails:
        for d in email_domain(raw):
            reg = registrable_domain(d)
            if d.endswith("noreply.github.com") or d.endswith("users.noreply.github.com"):
                other += 1
            elif d in FREE_MAIL or reg in FREE_MAIL:
                free += 1
            elif reg and reg not in seen:
                seen.append(reg)
    return {"domains": seen[:MAX_DOMAINS], "free_mail": free, "other_skipped": other,
            "more": max(0, len(seen) - MAX_DOMAINS)}


def rdap_check(domain: str, latest_release: str | None, fetch) -> dict:
    """{"domain", "status": "registered" | "not_registered" | "could_not_check", "registered_on", "flag", "reason"}."""
    resp = fetch(f"https://rdap.org/domain/{quote(domain)}")
    out = {"domain": domain, "status": "could_not_check", "registered_on": None, "flag": None, "reason": None}
    if resp.get("status") == 404 and not resp.get("error"):
        if resp.get("redirected"):
            out.update(status="not_registered", flag=FLAG_NOT_REGISTERED,
                       reason="the registry's RDAP server has no record of this domain")
        else:
            out["reason"] = f"no RDAP server known for .{domain.rsplit('.', 1)[-1]}"
        return out
    if not _ok(resp) or not isinstance(resp["data"], dict):
        out["reason"] = f"RDAP lookup failed ({_why(resp)})"
        return out
    events = resp["data"].get("events") or []
    reg = next((e.get("eventDate") for e in events if isinstance(e, dict) and e.get("eventAction") == "registration"), None)
    out.update(status="registered", registered_on=(reg or None))
    reg_dt, rel_dt = _dt(reg), _dt(latest_release)
    if reg_dt is None:
        out["reason"] = "registered; RDAP gives no registration date"
    elif rel_dt is None:
        out["reason"] = "registered; the latest release date is not known, so the dates were not compared"
    elif reg_dt > rel_dt:
        out["flag"] = FLAG_REGISTERED_AFTER
        out["reason"] = f"registered {reg_dt.date()}, latest release {rel_dt.date()}"
    else:
        out["reason"] = f"registered {reg_dt.date()}, before the latest release ({rel_dt.date()})"
    return out


# ------------------------------------------------------------------ registry

def registry_record(ecosystem: str, name: str, fetch) -> dict:
    """The facts the two signals need, from one registry request. Contact addresses are reduced to domains here.
    {"status": "ok" | "not_found" | "could_not_check", "reason", "version", "released", "contacts", "npm_attestations"}."""
    if ecosystem == "npm":
        resp = fetch(f"https://registry.npmjs.org/{quote(name, safe='@')}")
    elif ecosystem == "PyPI":
        resp = fetch(f"https://pypi.org/pypi/{quote(name, safe='')}/json")
    else:
        return {"status": "could_not_check", "reason": f"ecosystem {ecosystem} not supported"}
    if resp.get("status") == 404 and not resp.get("error"):
        return {"status": "not_found", "reason": f"'{name}' is not on {ecosystem}"}
    if not _ok(resp) or not isinstance(resp["data"], dict):
        return {"status": "could_not_check", "reason": f"{ecosystem} registry lookup failed ({_why(resp)})"}
    d = resp["data"]
    if ecosystem == "npm":
        version = (d.get("dist-tags") or {}).get("latest")
        released = (d.get("time") or {}).get(version) if version else None
        emails = [m.get("email") or "" for m in d.get("maintainers") or [] if isinstance(m, dict)]
        dist = (((d.get("versions") or {}).get(version) or {}).get("dist") or {}) if version else {}
        return {"status": "ok", "reason": None, "version": version, "released": released,
                "contacts": contact_domains(emails), "npm_attestations": dist.get("attestations"),
                "contact_source": "npm maintainers"}
    info = d.get("info") or {}
    version = info.get("version")
    files = [u for u in d.get("urls") or [] if isinstance(u, dict)]
    times = sorted(u.get("upload_time_iso_8601") for u in files if u.get("upload_time_iso_8601"))
    files.sort(key=lambda u: u.get("packagetype") != "sdist")
    return {"status": "ok", "reason": None, "version": version, "released": times[0] if times else None,
            "contacts": contact_domains([info.get("author_email") or "", info.get("maintainer_email") or ""]),
            "pypi_files": [u.get("filename") for u in files if u.get("filename")],
            "contact_source": "PyPI author_email / maintainer_email"}


# ------------------------------------------------------------------ provenance

def normalise_repo(value: str | None) -> str | None:
    """"https://github.com/Owner/Repo.git", "git+https://github.com/o/r@refs/heads/main", "o/r" -> "owner/repo"
    (lower-case); None when it is not a GitHub repository."""
    if not value:
        return None
    v = value.strip()
    v = re.sub(r"^git\+", "", v)
    v = v.split("@", 1)[0] if v.startswith("http") else v
    m = re.match(r"^(?:https?://)?(?:www\.)?github\.com/([^/\s]+)/([^/\s#?]+)", v, re.I)
    if m:
        owner, repo = m.group(1), m.group(2)
    elif re.fullmatch(r"[\w.\-]+/[\w.\-]+", v):
        owner, repo = v.split("/")
    else:
        return None
    repo = re.sub(r"\.git$", "", repo)
    return f"{owner}/{repo}".lower()


def _npm_statement_repo(att_doc) -> tuple[str | None, str | None]:
    """(source repository, predicate type) from an npm attestations document, SLSA provenance only."""
    for a in (att_doc or {}).get("attestations") or []:
        ptype = a.get("predicateType") or ""
        if "slsa.dev/provenance" not in ptype:
            continue
        payload = (((a.get("bundle") or {}).get("dsseEnvelope")) or {}).get("payload")
        try:
            st = json.loads(base64.b64decode(payload or ""))
        except (ValueError, TypeError):
            continue
        pred = st.get("predicate") or {}
        repo = (((pred.get("buildDefinition") or {}).get("externalParameters") or {}).get("workflow") or {}).get("repository") \
            or (((pred.get("invocation") or {}).get("configSource")) or {}).get("uri")
        if repo:
            return repo, ptype
    return None, None


def provenance_check(ecosystem: str, name: str, record: dict, scanned_repo: str, fetch) -> dict:
    """{"status": "match" | "mismatch" | "none" | "could_not_check", "source_repository", "publisher_kind",
    "version", "detail", "note"}. "none" = the registry has no attestation for the latest release (not a failure)."""
    out = {"status": "could_not_check", "source_repository": None, "publisher_kind": None,
           "version": record.get("version"), "detail": None, "note": SIGNATURE_NOTE}
    want = normalise_repo(scanned_repo)
    if record.get("status") != "ok":
        out["detail"] = record.get("reason") or "registry lookup failed"
        return out
    if ecosystem == "npm":
        att = record.get("npm_attestations")
        if not att or not att.get("url"):
            out.update(status="none", detail=f"no attestation in the npm registry metadata for {record.get('version')}")
            return out
        resp = fetch(att["url"])
        if not _ok(resp):
            out["detail"] = f"attestation lookup failed ({_why(resp)})"
            return out
        repo, ptype = _npm_statement_repo(resp["data"])
        if not repo:
            out["detail"] = "attestation present, but no SLSA provenance statement naming a repository"
            return out
        out.update(source_repository=repo, publisher_kind=ptype)
    elif ecosystem == "PyPI":
        files = record.get("pypi_files") or []
        if not files:
            out.update(status="none", detail=f"no files for {record.get('version')}")
            return out
        found, failed = None, []
        for fn in files[:3]:
            resp = fetch(f"https://pypi.org/integrity/{quote(name, safe='')}/{quote(str(record.get('version')), safe='')}/"
                         f"{quote(fn, safe='')}/provenance", PYPI_INTEGRITY_ACCEPT)
            if resp.get("status") == 404 and not resp.get("error"):
                continue
            if not _ok(resp):
                failed.append(_why(resp))
                continue
            pubs = [b.get("publisher") or {} for b in (resp["data"].get("attestation_bundles") or []) if isinstance(b, dict)]
            pub = next((p for p in pubs if p.get("repository")), None)
            if pub:
                found = pub
                break
        if not found:
            if failed:
                out["detail"] = f"provenance lookup failed ({failed[0]})"
            else:
                out.update(status="none", detail=f"no PEP 740 attestation for the files of {record.get('version')}")
            return out
        kind = found.get("kind") or ""
        repo = found.get("repository")
        out.update(publisher_kind=kind or None,
                   source_repository=(f"https://github.com/{repo}" if kind.lower() == "github" else f"{kind}: {repo}"))
    else:
        out["detail"] = f"ecosystem {ecosystem} not supported"
        return out
    got = normalise_repo(out["source_repository"])
    if got and want and got == want:
        out.update(status="match", detail=f"the provenance names {out['source_repository']}, the scanned repository")
    else:
        out.update(status="mismatch", detail=f"the provenance names {out['source_repository']}, not "
                                             f"https://github.com/{scanned_repo}")
    return out


# ------------------------------------------------------------------ all signals

def collect(ecosystem: str | None, name: str | None, scanned_repo: str, fetch) -> dict:
    """Every additional signal for one package. Never raises. Display only."""
    out = {"title": PANEL_TITLE, "package": None, "registry": None, "domains": [], "provenance": None,
           "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    if not ecosystem or not name:
        out["registry"] = {"status": "not_applicable", "reason": "no published PyPI or npm package found for this repository"}
        return out
    out["package"] = {"ecosystem": ecosystem, "name": name}
    try:
        rec = registry_record(ecosystem, name, fetch)
    except Exception as e:                       # a malformed answer must not break the page
        rec = {"status": "could_not_check", "reason": f"registry answer not understood ({type(e).__name__})"}
    out["registry"] = {k: v for k, v in rec.items() if k not in ("npm_attestations", "pypi_files")}
    if rec.get("status") == "ok":
        domains = rec["contacts"]["domains"]

        def one(d):
            try:
                return rdap_check(d, rec.get("released"), fetch)
            except Exception as e:
                return {"domain": d, "status": "could_not_check", "registered_on": None, "flag": None,
                        "reason": f"RDAP answer not understood ({type(e).__name__})"}
        with ThreadPoolExecutor(max_workers=min(4, max(1, len(domains)))) as ex:
            out["domains"] = list(ex.map(one, domains))
    try:
        out["provenance"] = provenance_check(ecosystem, name, rec, scanned_repo, fetch)
    except Exception as e:
        out["provenance"] = {"status": "could_not_check", "detail": f"provenance answer not understood ({type(e).__name__})",
                             "note": SIGNATURE_NOTE, "source_repository": None, "version": rec.get("version")}
    return out


def has_failure(sig: dict) -> bool:
    reg = sig.get("registry") or {}
    return (reg.get("status") == "could_not_check" or any(d.get("status") == "could_not_check" for d in sig.get("domains") or [])
            or (sig.get("provenance") or {}).get("status") == "could_not_check")
