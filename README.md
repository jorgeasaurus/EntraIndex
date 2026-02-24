# Entra Index

Interactive, searchable reference for all 586 Microsoft Entra PowerShell cmdlets (v1.0 and beta). Static site -- no backend, no framework, no build step.

Deployed to GitHub Pages. Data updated daily via GitHub Actions.

## Quick Start

```bash
python3 -m http.server 8000 -d public
# http://localhost:8000
```

## Data Pipeline

A GitHub Actions workflow runs daily: clones the [entra-powershell-docs](https://github.com/MicrosoftDocs/entra-powershell-docs) repo, parses markdown into JSON, commits changes, and deploys to Pages.

To regenerate locally:

```bash
git clone --depth 1 --filter=blob:none --sparse \
  https://github.com/MicrosoftDocs/entra-powershell-docs.git docs
cd docs && git sparse-checkout set docs/reference/v1.0 docs/reference/beta
cd ..
python3 scripts/parse_docs.py docs/docs/reference
```

### Data Files

| File | Purpose |
|------|---------|
| `public/data/manifest.json` | Compact cmdlet index (short keys). Loaded on init for search/filter |
| `public/data/modules/*.json` | Per-module detail (syntax, examples, permissions). Lazy-loaded on card expand |
| `public/data/descriptions.json` | Deferred descriptions |

The parser uses Python stdlib only -- no pip dependencies.

## Themes

Eight visual themes, each a standalone HTML file with identical JS logic. All support light/dark mode toggle and `prefers-color-scheme`.

- Acrylic (default)
- Cyberpunk
- CRT
- Synthwave
- Blueprint
- Solarized
- Geocities
- ISE

## Key Features

- **Fuzzy search** with weighted scoring across name, description, category
- **Filters** -- verb, category, module, API version, permissions
- **Two-tier loading** -- manifest on init, module detail on demand
- **Keyboard navigation** -- `/` search, `j`/`k` navigate, `Enter` expand
- **URL hash state** -- shareable filtered views
- **Export** -- JSON or CSV of filtered results
- **Filter presets** -- save/restore to localStorage

## Project Structure

```
public/
  *.html                    Theme variants (8 files)
  data/
    manifest.json           Cmdlet index (~79 KB)
    descriptions.json       Deferred descriptions (~51 KB)
    modules/                Per-module detail (20 files)
scripts/
  parse_docs.py             Python parser
.github/workflows/
  update-cmdlet-data.yml    Daily automation + GitHub Pages deploy
```
