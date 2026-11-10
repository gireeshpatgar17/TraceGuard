from __future__ import annotations

import json
import os
import re
import time
from collections import Counter
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(ROOT, "static")
GITHUB_API = "https://api.github.com"
OSV_API = "https://api.osv.dev/v1/querybatch"
MAX_FILES = 350
MAX_FILE_BYTES = 180_000
MAX_TOTAL_BYTES = 5_000_000

app = FastAPI(title="TraceGuard", version="1.0.0", description="Evidence-first security analysis for public GitHub repositories")
app.mount("/static", StaticFiles(directory=STATIC), name="static")


class ScanRequest(BaseModel):
    repository_url: str = Field(min_length=10, max_length=300)


def http_json(url: str, *, method: str = "GET", payload: Any = None, headers: dict[str, str] | None = None) -> Any:
    body = json.dumps(payload).encode() if payload is not None else None
    req_headers = {"User-Agent": "TraceGuard/1.0", "Accept": "application/vnd.github+json"}
    if payload is not None:
        req_headers["Content-Type"] = "application/json"
    if os.getenv("GITHUB_TOKEN") and "api.github.com" in url:
        req_headers["Authorization"] = f"Bearer {os.getenv('GITHUB_TOKEN')}"
    req_headers.update(headers or {})
    req = Request(url, data=body, headers=req_headers, method=method)
    try:
        with urlopen(req, timeout=18) as response:
            raw = response.read(6_000_001)
            if len(raw) > 6_000_000:
                raise HTTPException(413, "The repository response is too large to analyze.")
            return json.loads(raw.decode("utf-8"))
    except HTTPError as exc:
        if exc.code == 404:
            raise HTTPException(404, "Repository not found, or it is not public.") from exc
        if exc.code == 403:
            raise HTTPException(429, "GitHub API rate limit reached. Add GITHUB_TOKEN and try again.") from exc
        raise HTTPException(502, f"Upstream service returned HTTP {exc.code}.") from exc
    except (URLError, TimeoutError) as exc:
        raise HTTPException(502, "A security data service could not be reached. Please retry.") from exc


def parse_repo_url(value: str) -> tuple[str, str]:
    parsed = urlparse(value.strip())
    if parsed.scheme != "https" or parsed.hostname not in {"github.com", "www.github.com"}:
        raise HTTPException(400, "Enter an HTTPS URL for a public GitHub repository.")
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2 or not re.fullmatch(r"[A-Za-z0-9_.-]+", parts[0]) or not re.fullmatch(r"[A-Za-z0-9_.-]+", parts[1]):
        raise HTTPException(400, "Use a repository URL like https://github.com/owner/repository.")
    return parts[0], parts[1].removesuffix(".git")


def github_json(path: str) -> Any:
    return http_json(f"{GITHUB_API}{path}")


def fetch_repository(owner: str, repo: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    info = github_json(f"/repos/{owner}/{repo}")
    branch = info.get("default_branch") or "main"
    tree = github_json(f"/repos/{owner}/{repo}/git/trees/{branch}?recursive=1")
    if tree.get("truncated"):
        raise HTTPException(413, "This repository is too large for the first version of TraceGuard.")
    files = [entry for entry in tree.get("tree", []) if entry.get("type") == "blob"]
    # Manifests first, then source and configuration files. Avoid vendor/build directories.
    skip = ("node_modules/", "vendor/", "dist/", "build/", ".git/", "coverage/", ".venv/")
    files = [f for f in files if not f["path"].startswith(skip) and f.get("size", 0) <= MAX_FILE_BYTES]
    files.sort(key=lambda f: (not is_manifest(f["path"]), f["path"].count("/"), f["path"]))
    selected = files[:MAX_FILES]
    content: list[dict[str, Any]] = []
    total = 0
    for item in selected:
        if total >= MAX_TOTAL_BYTES:
            break
        try:
            result = http_json(f"{GITHUB_API}/repos/{owner}/{repo}/contents/{quote(item['path'], safe='/')}?ref={quote(branch, safe='/')}")
            if result.get("encoding") != "base64":
                continue
            import base64
            raw = base64.b64decode(result.get("content", ""))
            total += len(raw)
            text = raw.decode("utf-8", errors="replace")
            content.append({"path": item["path"], "text": text})
        except HTTPException as exc:
            # A file can disappear between tree and content requests; continue with the rest.
            if exc.status_code == 404:
                continue
            raise
    return info, content


def is_manifest(path: str) -> bool:
    name = path.rsplit("/", 1)[-1].lower()
    return name in {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "poetry.lock", "pipfile.lock", "cargo.lock", "go.sum", "gemfile.lock"}


def dependencies_for(files: list[dict[str, str]]) -> list[dict[str, str]]:
    deps: dict[tuple[str, str, str], dict[str, str]] = {}
    for file in files:
        path, text = file["path"], file["text"]
        low = path.lower()
        found: list[tuple[str, str, str]] = []
        try:
            if low.endswith(("package-lock.json", "npm-shrinkwrap.json")):
                data = json.loads(text)
                for name, item in data.get("packages", {}).items():
                    if name and "node_modules/" in name and item.get("version"):
                        pkg = name.split("node_modules/")[-1]
                        found.append(("npm", pkg, str(item["version"])))
                if not found:
                    def walk(obj: dict[str, Any], prefix: str = "") -> None:
                        for name, item in obj.items():
                            if isinstance(item, dict):
                                if item.get("version"):
                                    found.append(("npm", name, str(item["version"])))
                                walk(item.get("dependencies", {}), prefix + name + "/")
                    walk(data.get("dependencies", {}))
            elif low.endswith("requirements.txt"):
                for line in text.splitlines():
                    match = re.match(r"\s*([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9_.+!-]+)", line)
                    if match: found.append(("PyPI", match[1], match[2]))
            elif low.endswith("poetry.lock") or low.endswith("pipfile.lock"):
                if low.endswith("poetry.lock"):
                    for name, version in re.findall(r'(?ms)^name\s*=\s*["\']([^"\']+)["\'].*?^version\s*=\s*["\']([^"\']+)', text):
                        found.append(("PyPI", name, version))
                else:
                    data = json.loads(text)
                    for section in ("default", "develop"):
                        for name, item in data.get(section, {}).items():
                            version = str(item.get("version", "")).lstrip("=<>~")
                            if version: found.append(("PyPI", name, version))
            elif low.endswith("cargo.lock"):
                for name, version in re.findall(r'(?ms)^\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"', text):
                    found.append(("crates.io", name, version))
            elif low.endswith("go.sum"):
                for name, version in re.findall(r"(?m)^([^\s]+)\s+(v[^\s/]+)(?:/go\.mod)?\s+", text):
                    found.append(("Go", name, version))
            elif low.endswith("gemfile.lock"):
                for name, version in re.findall(r"(?m)^    ([A-Za-z0-9_.-]+) \(([^)]+)\)", text):
                    found.append(("RubyGems", name, version.split(" ")[0]))
        except (ValueError, TypeError):
            continue
        for ecosystem, name, version in found:
            key = (ecosystem, name.lower(), version)
            deps[key] = {"ecosystem": ecosystem, "name": name, "version": version, "manifest": path}
    return list(deps.values())


def osv_findings(dependencies: list[dict[str, str]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    # Keep batch requests small and bound the number of outbound queries.
    for start in range(0, min(len(dependencies), 180), 80):
        chunk = dependencies[start:start + 80]
        try:
            result = http_json(OSV_API, method="POST", payload={"queries": [{"package": {"name": d["name"], "ecosystem": d["ecosystem"]}, "version": d["version"]} for d in chunk]})
        except HTTPException:
            continue
        for dep, response in zip(chunk, result.get("results", [])):
            for vuln in response.get("vulns", []):
                severity = "medium"
                score = None
                for item in vuln.get("severity", []):
                    try:
                        score = float(item.get("score", "").split("/")[0])
                        break
                    except (ValueError, IndexError): pass
                if score is not None:
                    severity = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
                aliases = vuln.get("aliases", [])
                affected = vuln.get("affected", [])
                fix = next((v for a in affected for r in a.get("ranges", []) for e in r.get("events", []) if e.get("fixed")), None)
                findings.append({"id": aliases[0] if aliases else vuln.get("id", "OSV"), "title": vuln.get("summary") or vuln.get("id", "Known vulnerability"), "category": "Dependency", "severity": severity, "target": f"{dep['name']}@{dep['version']}", "file": dep["manifest"], "evidence": f"OSV advisory {vuln.get('id', '')}; affected package version {dep['version']}.", "fix": f"Upgrade to {fix}." if fix else "Review the advisory for patched versions.", "url": f"https://osv.dev/vulnerability/{vuln.get('id', '')}", "source": "OSV"})
    return findings


SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b")),
    ("Generic credential", re.compile(r"(?i)(?:api[_-]?key|secret|password|access[_-]?token)\s*[:=]\s*['\"](?!\s*(?:\$\{|<|your_|example|changeme))[^'\"\s]{8,}['\"]")),
]


def source_findings(files: list[dict[str, str]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for file in files:
        path, text = file["path"], file["text"]
        # Secret scanner: retain location and type, never the matched value.
        for number, line in enumerate(text.splitlines(), 1):
            for label, pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append({"id": f"SECRET-{abs(hash((path, number, label))) % 100000:05d}", "title": f"Potential {label} exposed", "category": "Secret", "severity": "critical" if label in {"Private key", "AWS access key"} else "high", "target": label, "file": path, "line": number, "evidence": f"A pattern matching {label.lower()} was detected. The value has been redacted.", "fix": "Revoke and rotate the credential, then move it to a secrets manager or environment variable.", "source": "TraceGuard secret rules"})
        # Small, evidence-backed rules for common insecure patterns.
        checks = [
            ("SQL query built with string formatting", r"(?i)(?:execute|raw|query)\s*\([^\n]*(?:f['\"]|%s|\.format\()", "high", "Use parameterized queries so untrusted input is never concatenated into SQL."),
            ("TLS certificate verification disabled", r"(?i)(?:verify\s*=\s*False|InsecureSkipVerify\s*:\s*true)", "high", "Enable certificate verification and use a trusted certificate chain."),
            ("Dynamic code evaluation", r"(?i)\beval\s*\(", "medium", "Avoid evaluating dynamic strings; use a parser or explicit, safe dispatch."),
            ("Debug mode enabled", r"(?i)(?:debug\s*=\s*True|DEBUG\s*=\s*true)", "medium", "Disable debug mode in production to avoid exposing internals."),
        ]
        for title, expr, severity, fix in checks:
            for number, line in enumerate(text.splitlines(), 1):
                if re.search(expr, line) and not line.lstrip().startswith(("#", "//", "*")):
                    findings.append({"id": f"CODE-{abs(hash((path, number, title))) % 100000:05d}", "title": title, "category": "Code", "severity": severity, "target": title, "file": path, "line": number, "evidence": f"Potentially unsafe pattern detected on line {number}; review the source context.", "fix": fix, "source": "TraceGuard static rules"})
                    break
    return findings


def make_explanation(finding: dict[str, Any]) -> str:
    # Explanations are based exclusively on the scanner's evidence and rule metadata.
    if finding["category"] == "Dependency":
        return f"OSV reports {finding['target']} in a published advisory. {finding['fix']} Confirm compatibility and run your normal regression checks after updating."
    if finding["category"] == "Secret":
        return f"A credential-shaped value appears in {finding['file']} and is redacted in this report. Treat it as exposed: {finding['fix']}"
    return f"The static rule found a potentially unsafe pattern in {finding['file']}:{finding.get('line', '?')}. This is a review signal, not proof of exploitability. {finding['fix']}"


@app.get("/")
def index() -> FileResponse:
    return FileResponse(os.path.join(STATIC, "index.html"))


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "TraceGuard"}


@app.post("/api/scan")
def scan(body: ScanRequest) -> JSONResponse:
    owner, repo = parse_repo_url(body.repository_url)
    info, files = fetch_repository(owner, repo)
    dependencies = dependencies_for(files)
    findings = osv_findings(dependencies) + source_findings(files)
    for finding in findings:
        finding["explanation"] = make_explanation(finding)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (severity_order.get(f["severity"], 9), f["category"], f["file"], f.get("line", 0)))
    summary = Counter(f["severity"] for f in findings)
    return JSONResponse({"repository": {"name": info.get("full_name", f"{owner}/{repo}"), "description": info.get("description"), "url": info.get("html_url", body.repository_url), "stars": info.get("stargazers_count", 0), "branch": info.get("default_branch", "main"), "updated_at": info.get("updated_at")}, "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "files_scanned": len(files), "dependencies_scanned": len(dependencies), "findings": findings, "summary": {"total": len(findings), "critical": summary["critical"], "high": summary["high"], "medium": summary["medium"], "low": summary["low"]}, "coverage": ["OSV dependency advisories", "Credential pattern scan with redaction", "Selected static code rules"], "notes": ["Only public GitHub files were read. Repository code was not executed.", "Static findings are heuristic and should be reviewed in context.", "The explanation layer uses scanner evidence and does not invent advisory details."]})
