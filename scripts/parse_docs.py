#!/usr/bin/env python3
"""Parse Microsoft Entra PowerShell documentation markdown files into JSON.

Reads cmdlet docs from a local clone of MicrosoftDocs/entra-powershell-docs
and produces:
  - public/data/manifest.json   (lightweight summary for all cmdlets)
  - public/data/modules/*.json  (per-module detail, loaded lazily)

Usage:
    python3 scripts/parse_docs.py [docs_dir]

docs_dir defaults to ./docs and should point to the directory containing
v1.0/ and beta/ subdirectories.
"""

import json
import os
import re
import sys
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# -- Category mapping (module suffix -> display category) --
CATEGORY_MAP = [
    ("Applications", "Application Management"),
    ("Authentication", "Authentication"),
    ("CertificateBasedAuthentication", "Certificate Auth"),
    ("DirectoryManagement", "Directory Management"),
    ("Governance", "Governance"),
    ("Groups", "Groups"),
    ("NetworkAccess", "Network Access"),
    ("Reports", "Reports"),
    ("SignIns", "Sign-Ins"),
    ("Users", "User Management"),
]

MAX_DESCRIPTION_LEN = 300
MAX_EXAMPLES = 3


def get_category(module_name: str) -> str:
    """Map a module name to a display category."""
    suffix = re.sub(r"^Microsoft\.Entra\.(Beta\.)?", "", module_name)
    for pattern, category in CATEGORY_MAP:
        if suffix.startswith(pattern):
            return category
    return "General"


def parse_front_matter(text: str) -> dict:
    """Extract YAML front matter fields from markdown text."""
    meta = {}
    if not text.startswith("---"):
        return meta
    end = text.find("---", 3)
    if end == -1:
        return meta
    block = text[3:end]
    for line in block.splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            meta[key.strip().lower()] = val.strip()
    return meta


def extract_section(text: str, heading: str) -> str:
    """Extract content between ## HEADING and the next ## heading."""
    pattern = re.compile(
        r"^## " + re.escape(heading) + r"\s*\n(.*?)(?=^## |\Z)",
        re.MULTILINE | re.DOTALL,
    )
    m = pattern.search(text)
    return m.group(1).strip() if m else ""


def extract_synopsis(section: str) -> str:
    """Get the first paragraph from SYNOPSIS, skipping NOTE blocks."""
    lines = []
    in_note = False
    for line in section.splitlines():
        stripped = line.strip()
        if stripped.startswith("> [!NOTE]") or stripped.startswith("> [!TIP]"):
            in_note = True
            continue
        if in_note:
            if stripped.startswith(">"):
                continue
            if not stripped:
                in_note = False
                continue
            in_note = False
        if not stripped and lines:
            break
        if stripped:
            lines.append(stripped)
    return " ".join(lines)


def extract_first_code_block(section: str) -> str:
    """Extract the first fenced code block from a section."""
    m = re.search(r"```[^\n]*\n(.*?)```", section, re.DOTALL)
    return m.group(1).strip() if m else ""


def extract_permissions(section: str) -> list:
    """Parse permission names from the permissions table in DESCRIPTION."""
    permissions = set()
    in_table = False
    for line in section.splitlines():
        stripped = line.strip()
        if stripped.startswith("|") and "Permission" in stripped and "type" in stripped:
            in_table = True
            continue
        if in_table and stripped.startswith("|") and "---" in stripped:
            continue
        if in_table and stripped.startswith("|"):
            cells = [c.strip() for c in stripped.split("|")]
            # cells[0] is empty (before first |), cells[1] is permission type,
            # cells[2] is the comma-separated permissions
            if len(cells) >= 3:
                perms_str = cells[2]
                if "not supported" in perms_str.lower():
                    continue
                for p in re.split(r"[,\s]+", perms_str):
                    p = p.strip().rstrip(",").strip()
                    if p and "." in p and len(p) > 3:
                        permissions.add(p)
        elif in_table and not stripped.startswith("|"):
            break
    return sorted(permissions)


def extract_examples(section: str) -> list:
    """Extract up to MAX_EXAMPLES code blocks from EXAMPLES section."""
    examples = []
    for m in re.finditer(r"```(?:powershell)?\s*\n(.*?)```", section, re.DOTALL):
        code = m.group(1).strip()
        # Strip PS C:\> prompts
        lines = []
        for line in code.splitlines():
            cleaned = re.sub(r"^PS\s+C:\\>\s*", "", line)
            lines.append(cleaned)
        code = "\n".join(lines).strip()
        if code:
            examples.append(code)
        if len(examples) >= MAX_EXAMPLES:
            break
    return examples


def is_cmdlet_file(filepath, text):
    """Check if a markdown file is a cmdlet doc (not a module index page).

    Entra docs lack a 'document type' front matter field, so we check for
    the Verb-Entra naming pattern in the title.
    """
    meta = parse_front_matter(text)
    title = meta.get("title", filepath.stem)
    # Module index pages don't follow Verb-Noun pattern
    if "-Entra" not in title and "-entra" not in title.lower():
        return False, meta
    # Must match standard PowerShell Verb-Noun pattern
    if not re.match(r"^[A-Z][a-z]+-Entra", title):
        return False, meta
    return True, meta


def parse_cmdlet_file(filepath, module_name, api_version):
    """Parse a single cmdlet markdown file."""
    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    is_cmdlet, meta = is_cmdlet_file(filepath, text)
    if not is_cmdlet:
        return None

    cmdlet_name = meta.get("title", filepath.stem)

    # SYNOPSIS -> description
    synopsis_section = extract_section(text, "SYNOPSIS")
    description = extract_synopsis(synopsis_section)
    if not description:
        description = "Microsoft Entra PowerShell cmdlet."
    if len(description) > MAX_DESCRIPTION_LEN:
        description = description[: MAX_DESCRIPTION_LEN - 3] + "..."

    # SYNTAX -> first code block
    syntax_section = extract_section(text, "SYNTAX")
    syntax = extract_first_code_block(syntax_section)
    if not syntax:
        syntax = f"{cmdlet_name} [parameters]"

    # DESCRIPTION -> permissions table
    desc_section = extract_section(text, "DESCRIPTION")
    permissions = extract_permissions(desc_section)

    # EXAMPLES -> code blocks
    examples_section = extract_section(text, "EXAMPLES")
    examples = extract_examples(examples_section)

    verb = cmdlet_name.split("-")[0] if "-" in cmdlet_name else ""

    return {
        "name": cmdlet_name,
        "verb": verb,
        "category": get_category(module_name),
        "module": module_name,
        "apiVersion": api_version,
        "description": description,
        "syntax": syntax,
        "permissions": permissions,
        "examples": examples,
    }


PSGALLERY_URL = (
    "https://www.powershellgallery.com/api/v2/FindPackagesById()"
    "?id='{}'"
)


def fetch_module_version(module_id: str) -> tuple:
    """Fetch the latest version of a module from the PowerShell Gallery."""
    url = PSGALLERY_URL.format(module_id)
    try:
        while url:
            resp = urllib.request.urlopen(url, timeout=60)
            body = resp.read().decode()
            versions = re.findall(r"<d:Version>([^<]+)</d:Version>", body)
            flags = re.findall(
                r"<d:IsLatestVersion[^>]*>([^<]+)</d:IsLatestVersion>", body
            )
            for ver, flag in zip(versions, flags):
                if flag == "true":
                    return (module_id, ver)
            # Follow pagination
            next_match = re.search(
                r'<link rel="next" href="([^"]+)"', body
            )
            url = next_match.group(1).replace("&amp;", "&") if next_match else None
    except Exception:
        pass
    return (module_id, None)


def fetch_all_module_versions(module_names: list) -> dict:
    """Fetch latest versions for all modules concurrently with retries."""
    print(f"Fetching module versions from PowerShell Gallery ({len(module_names)} modules)...")
    versions = {}
    remaining = list(module_names)
    for attempt in range(3):
        with ThreadPoolExecutor(max_workers=10) as executor:
            for module_id, version in executor.map(fetch_module_version, remaining):
                versions[module_id] = version
        remaining = [m for m in remaining if not versions.get(m)]
        if not remaining:
            break
        if attempt < 2:
            print(f"  Retrying {len(remaining)} failed modules...")
    found = sum(1 for v in versions.values() if v)
    print(f"  Resolved {found}/{len(module_names)} module versions")
    return versions


def scan_version_dir(version_dir: Path, api_version: str) -> list:
    """Scan all module directories under a version directory."""
    results = []
    if not version_dir.is_dir():
        return results
    for module_dir in sorted(version_dir.iterdir()):
        if not module_dir.is_dir():
            continue
        module_name = module_dir.name
        for md_file in sorted(module_dir.glob("*.md")):
            cmdlet = parse_cmdlet_file(md_file, module_name, api_version)
            if cmdlet:
                results.append(cmdlet)
    return results


def main():
    docs_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("./docs")

    if not docs_dir.is_dir():
        print(f"Error: docs directory not found: {docs_dir}", file=sys.stderr)
        sys.exit(1)

    script_dir = Path(__file__).resolve().parent
    data_dir = script_dir.parent / "public" / "data"
    modules_dir = data_dir / "modules"
    modules_dir.mkdir(parents=True, exist_ok=True)

    # Scan v1.0 and beta
    v1_dir = docs_dir / "v1.0"
    beta_dir = docs_dir / "beta"

    print(f"Scanning {v1_dir} ...")
    v1_cmdlets = scan_version_dir(v1_dir, "v1.0")
    print(f"  Found {len(v1_cmdlets)} v1.0 cmdlets")

    print(f"Scanning {beta_dir} ...")
    beta_cmdlets = scan_version_dir(beta_dir, "beta")
    print(f"  Found {len(beta_cmdlets)} beta cmdlets")

    all_cmdlets = sorted(v1_cmdlets + beta_cmdlets, key=lambda c: c["name"])
    print(f"\nTotal: {len(all_cmdlets)} cmdlets")

    # Fetch module versions from PowerShell Gallery
    unique_modules = sorted(set(c["module"] for c in all_cmdlets))
    module_versions = fetch_all_module_versions(unique_modules)

    # Build slim manifest (short keys, no descriptions or moduleVersion)
    DEFAULT_DESC = "Microsoft Entra PowerShell cmdlet."
    manifest = []
    descriptions = {}
    for c in all_cmdlets:
        manifest.append({
            "n": c["name"],
            "v": c["verb"],
            "c": c["category"],
            "m": c["module"],
            "a": c["apiVersion"],
            "p": len(c["permissions"]),
            "e": len(c["examples"]) > 0,
        })
        desc = c["description"]
        if desc and desc != DEFAULT_DESC:
            descriptions[c["name"]] = desc

    # Determine the common module version (all modules share the same version)
    version_counts = defaultdict(int)
    for mod, ver in module_versions.items():
        if ver:
            version_counts[ver] += 1
    entra_version = max(version_counts, key=version_counts.get) if version_counts else None

    manifest_wrapper = {"v": entra_version, "d": manifest}
    manifest_path = data_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest_wrapper, separators=(",", ":")), encoding="utf-8")
    manifest_kb = manifest_path.stat().st_size / 1024
    print(f"Written manifest: {manifest_path} ({len(manifest)} entries, {manifest_kb:.0f}KB, module v{entra_version})")

    # Build descriptions file (deferred loading)
    desc_path = data_dir / "descriptions.json"
    desc_path.write_text(json.dumps(descriptions, separators=(",", ":")), encoding="utf-8")
    desc_kb = desc_path.stat().st_size / 1024
    print(f"Written descriptions: {desc_path} ({len(descriptions)} entries, {desc_kb:.0f}KB)")

    # Build per-module detail files
    module_groups = defaultdict(list)
    for c in all_cmdlets:
        module_groups[c["module"]].append(c)

    for module_name, cmdlets in sorted(module_groups.items()):
        module_data = {
            "module": module_name,
            "version": module_versions.get(module_name),
            "cmdlets": {},
        }
        for c in cmdlets:
            module_data["cmdlets"][c["name"]] = {
                "syntax": c["syntax"],
                "examples": c["examples"],
                "permissions": c["permissions"],
            }
        module_path = modules_dir / f"{module_name}.json"
        module_path.write_text(
            json.dumps(module_data, separators=(",", ":")), encoding="utf-8"
        )

    print(f"Written {len(module_groups)} module detail files to {modules_dir}")

    # Stats
    total = len(all_cmdlets)
    with_perms = sum(1 for c in all_cmdlets if c["permissions"])
    with_examples = sum(1 for c in all_cmdlets if c["examples"])
    categories = sorted(set(c["category"] for c in all_cmdlets))
    print(f"\n--- Stats ---")
    print(f"v1.0 cmdlets:  {len(v1_cmdlets)}")
    print(f"beta cmdlets:  {len(beta_cmdlets)}")
    if total:
        print(f"With permissions: {with_perms} ({100*with_perms/total:.1f}%)")
        print(f"With examples:    {with_examples} ({100*with_examples/total:.1f}%)")
    print(f"Categories ({len(categories)}): {', '.join(categories)}")


if __name__ == "__main__":
    main()
