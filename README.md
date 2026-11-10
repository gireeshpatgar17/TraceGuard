# TraceGuard

TraceGuard is an evidence-first security analyzer for public GitHub repositories. It combines OSV dependency advisories, redacted credential pattern detection, selected static code rules, severity prioritization, and JSON/CSV reports in one dashboard.

## Run locally

Requires Python 3.10 or newer.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000.

GitHub limits anonymous API use. For a higher limit, set `GITHUB_TOKEN` in your shell before starting the server. A token is optional for public repositories.

## What it scans

- Pinned dependencies in supported npm, PyPI, Cargo, Go, and RubyGems manifests, checked against OSV.
- Common credential shapes, with matched values redacted from findings.
- Selected risky code patterns, such as disabled TLS verification and dynamic evaluation.
- A consolidated report with severity/category filters and JSON/CSV export.

Repository code is never executed. File count and size are capped. The secret and static checks are heuristic rules rather than full Gitleaks or Semgrep engines. Explanations use deterministic guidance grounded in scanner evidence; this version does not call Gemini. Scan history is saved in the browser's local storage.

## Publish to GitHub

Create an empty repository on GitHub, then run these commands from this folder. Replace the URL with your repository's HTTPS URL:

```powershell
git init -b main
git add .
git commit -m "Initial TraceGuard project"
git remote add origin https://github.com/USERNAME/REPOSITORY.git
git push -u origin main
```

The ignore rules exclude virtual environments, Python caches, local `.env` files, and editor/build artifacts. Keep real API tokens in your shell environment; commit only the placeholder `.env.example` file.
