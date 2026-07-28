"""Static guards for the Phase 1E public-endpoint design.

Phase 1E is a design task, so most of its test plan cannot run yet -- there is
no API Gateway, no Web ACL, and no public route to exercise. What *can* be
enforced now are the invariants that would be expensive to discover later:
that no real account ID reaches Git, that nothing shipped to a browser carries
a credential, that CORS never widens to a wildcard, that the logging design
never admits message bodies, and that the direct Function URL is never written
up as the permanent public endpoint.

The detectors are themselves tested against synthetic samples. A scanner that
silently matches nothing would pass every one of these assertions while
protecting nothing, and this repository currently ships no browser-facing files
at all -- so proving the scanner *can* catch a bad file is the only thing that
makes the scan meaningful today.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from app.main import ALLOWED_ORIGINS

REPO_ROOT = Path(__file__).resolve().parents[2]
INFRASTRUCTURE = REPO_ROOT / "infrastructure"
ARCHITECTURE_DOCS = REPO_ROOT / "docs" / "architecture"
ADR = ARCHITECTURE_DOCS / "phase1e-api-gateway-adr.md"
APP_SOURCE = REPO_ROOT / "backend" / "app"

#: Directories that are not source: caches, build output, dependencies.
SKIP_DIRECTORIES = {
    ".git",
    ".venv",
    ".build",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
}

#: Anything served to a browser. Empty today; the guard exists for Phase 2,
#: when a Squarespace embed or static asset could carry a credential.
BROWSER_FACING_SUFFIXES = {
    ".js",
    ".mjs",
    ".cjs",
    ".jsx",
    ".ts",
    ".tsx",
    ".html",
    ".htm",
    ".css",
    ".vue",
    ".svelte",
}

#: An AWS account ID is twelve digits. Placeholders are the only legal form.
ACCOUNT_ID = re.compile(r"\b\d{12}\b")

#: ``openssl rand -hex 32`` produces 64 hex characters. Anything of that shape
#: in a browser-facing file is treated as a leaked secret.
HEX_SECRET = re.compile(r"\b[0-9a-fA-F]{32,}\b")

#: Credential names that must never appear in anything a browser receives.
CREDENTIAL_NAMES = ("X-GG-Key", "GG_API_KEY")


def iter_files(root: Path) -> list[Path]:
    """Every file under ``root``, skipping caches and dependencies."""
    if not root.exists():
        return []
    return [
        path
        for path in root.rglob("*")
        if path.is_file() and not any(part in SKIP_DIRECTORIES for part in path.parts)
    ]


def browser_facing_files(root: Path) -> list[Path]:
    return [
        path
        for path in iter_files(root)
        if path.suffix.lower() in BROWSER_FACING_SUFFIXES
    ]


def label(path: Path) -> str:
    """Repo-relative where possible; bare name for tmp_path samples."""
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return path.name


def find_credentials(paths: list[Path]) -> list[str]:
    """Report ``path:credential`` for every credential name found."""
    hits = []
    for path in paths:
        text = path.read_text(encoding="utf-8", errors="replace")
        for name in CREDENTIAL_NAMES:
            if name in text:
                hits.append(f"{label(path)}:{name}")
    return hits


def find_secret_values(paths: list[Path]) -> list[str]:
    """Report ``path:prefix`` for every secret-shaped literal found."""
    hits = []
    for path in paths:
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in HEX_SECRET.findall(text):
            # Never echo a suspected secret in full, even in a failure.
            hits.append(f"{label(path)}:{match[:8]}...")
    return hits


# ---------------------------------------------------------------------------
# The detectors must actually detect. Without these, the scans below would
# pass vacuously on a repository that ships no browser-facing files.
# ---------------------------------------------------------------------------


def test_credential_detector_catches_a_planted_key(tmp_path: Path) -> None:
    planted = tmp_path / "embed.js"
    planted.write_text('fetch(u, {headers: {"X-GG-Key": k}})', encoding="utf-8")

    assert find_credentials([planted]) != []


def test_secret_detector_catches_a_planted_value(tmp_path: Path) -> None:
    planted = tmp_path / "embed.js"
    planted.write_text(f'const k = "{"a1b2c3d4" * 8}";', encoding="utf-8")

    assert find_secret_values([planted]) != []


def test_secret_detector_ignores_ordinary_text(tmp_path: Path) -> None:
    ordinary = tmp_path / "page.html"
    ordinary.write_text("<p>Educational gut-health content.</p>", encoding="utf-8")

    assert find_secret_values([ordinary]) == []


def test_browser_facing_discovery_finds_known_suffixes(tmp_path: Path) -> None:
    (tmp_path / "a.js").write_text("", encoding="utf-8")
    (tmp_path / "b.html").write_text("", encoding="utf-8")
    (tmp_path / "c.py").write_text("", encoding="utf-8")

    found = {path.name for path in browser_facing_files(tmp_path)}

    assert found == {"a.js", "b.html"}


# ---------------------------------------------------------------------------
# No real account IDs in infrastructure templates or architecture docs.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("root", [INFRASTRUCTURE, ARCHITECTURE_DOCS])
def test_no_real_account_ids_are_committed(root: Path) -> None:
    offenders = [
        f"{path.relative_to(REPO_ROOT)}: {ACCOUNT_ID.findall(text)}"
        for path in iter_files(root)
        if (text := path.read_text(encoding="utf-8", errors="replace"))
        and ACCOUNT_ID.search(text)
    ]

    assert offenders == [], (
        "a twelve-digit account ID appears in a tracked file; use the "
        "<AWS_ACCOUNT_ID> placeholder instead"
    )


def test_phase1e_policies_use_placeholders_and_parse(tmp: None = None) -> None:
    policies = sorted((INFRASTRUCTURE / "phase1e").glob("*.json"))

    assert policies, "expected Phase 1E reference policies"

    for path in policies:
        raw = path.read_text(encoding="utf-8")
        document = json.loads(raw)

        assert "<AWS_ACCOUNT_ID>" in raw, f"{path.name} hard-codes an account"
        assert set(document) <= {"Version", "Statement", "Id"}, (
            f"{path.name} carries a top-level key IAM would reject"
        )


# ---------------------------------------------------------------------------
# Nothing shipped to a browser may carry a credential or a secret value.
# ---------------------------------------------------------------------------


def test_no_browser_facing_file_contains_a_credential_name() -> None:
    assert find_credentials(browser_facing_files(REPO_ROOT)) == []


def test_no_browser_facing_file_contains_a_secret_value() -> None:
    assert find_secret_values(browser_facing_files(REPO_ROOT)) == []


# ---------------------------------------------------------------------------
# CORS never widens to a wildcard, and never carries credentials.
# ---------------------------------------------------------------------------


#: Loopback development origins are the one place plain http is acceptable --
#: they never leave the machine. Everything else must be https.
LOOPBACK_PREFIXES = ("http://localhost", "http://127.0.0.1")


def test_cors_origins_are_never_a_wildcard() -> None:
    assert "*" not in ALLOWED_ORIGINS
    assert not any("*" in origin for origin in ALLOWED_ORIGINS)


def test_non_loopback_cors_origins_are_https() -> None:
    """The Squarespace production origin, when added, must be https."""
    offenders = [
        origin
        for origin in ALLOWED_ORIGINS
        if not origin.startswith(LOOPBACK_PREFIXES)
        and not origin.startswith("https://")
    ]

    assert offenders == []


def test_cors_does_not_allow_credentials() -> None:
    source = (APP_SOURCE / "main.py").read_text(encoding="utf-8")

    assert "allow_credentials=False" in source


def test_design_forbids_wildcard_origins() -> None:
    adr = ADR.read_text(encoding="utf-8")

    assert "Never" in adr and "wildcard" in adr.lower()


# ---------------------------------------------------------------------------
# The logging design never admits request or response bodies.
# ---------------------------------------------------------------------------


def test_logging_design_forbids_request_and_response_bodies() -> None:
    adr = ADR.read_text(encoding="utf-8").lower()

    assert "request or response bodies" in adr
    assert "forbidden" in adr


def test_application_never_logs_a_request_or_response_body() -> None:
    """No logging call may reach for the body of a request or response."""
    suspicious = re.compile(
        r"log(?:ger)?\.\w+\([^)]*(?:request\.body|response\.body|await\s+"
        r"request\.body|\.json\(\))",
        re.IGNORECASE,
    )
    offenders = [
        str(path.relative_to(REPO_ROOT))
        for path in APP_SOURCE.rglob("*.py")
        if suspicious.search(path.read_text(encoding="utf-8"))
    ]

    assert offenders == []


# ---------------------------------------------------------------------------
# The direct Function URL is temporary, and the documentation must say so.
# ---------------------------------------------------------------------------


def plain(text: str) -> str:
    """Normalise Markdown prose for phrase matching.

    Emphasis markers are stripped and every whitespace run is collapsed to a
    single space, because these documents are hard-wrapped -- a sentence the
    reader sees as one phrase is split across a newline in the source.
    """
    return re.sub(r"\s+", " ", re.sub(r"[*_`]", "", text))


def test_function_url_is_not_described_as_the_final_public_endpoint() -> None:
    adr = plain(ADR.read_text(encoding="utf-8"))

    assert "not the final public endpoint" in adr
    assert "retire" in adr.lower()


def test_architecture_docs_mentioning_the_function_url_plan_its_retirement() -> None:
    """Any document that raises the Function URL must also retire it."""
    for path in iter_files(ARCHITECTURE_DOCS):
        text = path.read_text(encoding="utf-8", errors="replace")
        if "Function URL" not in text:
            continue

        assert "retire" in text.lower(), (
            f"{path.relative_to(REPO_ROOT)} describes the Function URL "
            "without planning its retirement"
        )
