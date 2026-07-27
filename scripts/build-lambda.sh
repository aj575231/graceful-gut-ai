#!/usr/bin/env bash
#
# Build a reproducible Lambda deployment package into .build/lambda.zip.
#
# The previously deployed package was hand-built on Windows: 355 of its 356
# entries used backslash separators and it shipped bin/*.exe launchers. This
# script exists so that never happens again -- the archive is written by
# Python's zipfile with forward-slash names, sorted entries, and a fixed
# timestamp, so the same source tree always produces the same bytes.
#
# Dependencies are cross-built for the deployed runtime (Python 3.13,
# manylinux2014_x86_64), so a local 3.13 interpreter is NOT required.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${REPO_ROOT}/.build"
STAGE_DIR="${BUILD_DIR}/package"
ZIP_PATH="${BUILD_DIR}/lambda.zip"

PYTHON_VERSION="3.13"
PLATFORM="manylinux2014_x86_64"

PYTHON_BIN="${PYTHON_BIN:-${REPO_ROOT}/.venv/bin/python}"
if [[ ! -x "${PYTHON_BIN}" ]]; then
  PYTHON_BIN="$(command -v python3)"
fi

echo "==> Cleaning ${STAGE_DIR}"
rm -rf "${STAGE_DIR}" "${ZIP_PATH}"
mkdir -p "${STAGE_DIR}"

echo "==> Installing runtime dependencies (py${PYTHON_VERSION}, ${PLATFORM})"
"${PYTHON_BIN}" -m pip install \
  --quiet \
  --target "${STAGE_DIR}" \
  --requirement "${REPO_ROOT}/backend/requirements-lambda.txt" \
  --platform "${PLATFORM}" \
  --python-version "${PYTHON_VERSION}" \
  --implementation cp \
  --only-binary=:all: \
  --upgrade

echo "==> Copying application source"
cp -R "${REPO_ROOT}/backend/app" "${STAGE_DIR}/app"

echo "==> Pruning build artefacts"
# bin/ holds console-script launchers that Lambda never invokes and that were
# the source of the stray Windows .exe files in the previous package.
rm -rf "${STAGE_DIR}/bin"
find "${STAGE_DIR}" -type d -name '__pycache__' -prune -exec rm -rf {} +
find "${STAGE_DIR}" -type d \( -name '*.dist-info' -o -name '*.egg-info' \) \
  -prune -exec rm -rf {} +
find "${STAGE_DIR}" -type f -name '*.py[co]' -delete

echo "==> Writing ${ZIP_PATH}"
"${PYTHON_BIN}" - "${STAGE_DIR}" "${ZIP_PATH}" <<'PY'
import pathlib
import stat
import sys
import zipfile

stage = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])

# Fixed timestamp keeps the archive byte-identical across rebuilds.
FIXED_TIME = (1980, 1, 1, 0, 0, 0)

paths = sorted(p for p in stage.rglob("*") if p.is_file())

with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    for path in paths:
        # as_posix() guarantees forward slashes regardless of build platform.
        arcname = path.relative_to(stage).as_posix()
        info = zipfile.ZipInfo(arcname, date_time=FIXED_TIME)
        info.compress_type = zipfile.ZIP_DEFLATED
        mode = 0o755 if path.stat().st_mode & stat.S_IXUSR else 0o644
        info.external_attr = mode << 16
        archive.writestr(info, path.read_bytes())

print(f"    {len(paths)} entries")
PY

echo "==> Verifying archive"
"${PYTHON_BIN}" - "${ZIP_PATH}" <<'PY'
import sys
import zipfile

names = zipfile.ZipFile(sys.argv[1]).namelist()

problems = []
backslashes = [n for n in names if "\\" in n]
executables = [n for n in names if n.startswith("bin/") or n.endswith(".exe")]
if backslashes:
    problems.append(f"{len(backslashes)} entries contain a backslash")
if executables:
    problems.append(f"{len(executables)} console-script/exe entries present")
for required in (
    "app/main.py",
    "app/lambda_handler.py",
    "app/config.py",
    "app/secrets.py",
):
    if required not in names:
        problems.append(f"missing {required}")

# Deployed postures read the shared secret through Powertools. Without it in
# the package every gated route fails closed with a 503 at runtime, which is
# safe but is a silent outage -- catch it at build time instead.
if not any(n.startswith("aws_lambda_powertools/") for n in names):
    problems.append("aws_lambda_powertools is missing from the package")

if problems:
    sys.exit("    FAILED: " + "; ".join(problems))

print(f"    OK: {len(names)} entries, all forward-slash, no bin/ or .exe")
PY

echo "==> Built $(du -h "${ZIP_PATH}" | cut -f1) at ${ZIP_PATH}"
