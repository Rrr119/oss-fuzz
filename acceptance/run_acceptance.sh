#!/usr/bin/env bash
# End-to-end acceptance for OSS-Fuzz config validation and repro generation.
#
# It creates three intentionally invalid project.yaml files, plus one valid
# file. The invalid configurations must fail static validation and print an
# actionable fix. The valid configuration must generate an executable shell
# script whose --help and --dry-run modes run locally without Docker.
#
# Usage:
#   bash acceptance/run_acceptance.sh [--work-dir DIR]
#
# Environment:
#   PYTHON  Python interpreter with PyYAML available.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ -z "${PYTHON:-}" ]]; then
  if [[ -x "$REPO_ROOT/.venv/bin/python" ]]; then
    PYTHON_BIN="$REPO_ROOT/.venv/bin/python"
  else
    PYTHON_BIN="python3"
  fi
else
  PYTHON_BIN="$PYTHON"
fi

WORK_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --work-dir)
      WORK_DIR="$2"
      shift 2
      ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$WORK_DIR" ]]; then
  WORK_DIR="$(mktemp -d /tmp/oss-fuzz-onboarding-XXXXXX)"
fi
mkdir -p "$WORK_DIR"

cd "$REPO_ROOT"

if ! "$PYTHON_BIN" -c 'import yaml' >/dev/null 2>&1; then
  echo "PyYAML is required for $PYTHON_BIN." >&2
  echo "Fix: use infra/.venv or run: $PYTHON_BIN -m pip install PyYAML" >&2
  exit 1
fi

write_config() {
  local name="$1"
  local contents="$2"
  local dir="$WORK_DIR/$name"
  mkdir -p "$dir"
  printf '%s' "$contents" > "$dir/project.yaml"
  printf '%s\n' "$dir"
}

expect_validation_failure() {
  local name="$1"
  local expected_fix="$2"
  local config="$WORK_DIR/$name/project.yaml"
  local output="$WORK_DIR/$name/validation.log"

  set +e
  "$PYTHON_BIN" infra/helper.py validate-config "$config" \
    >"$output" 2>&1
  local rc=$?
  set -e

  if [[ "$rc" -eq 0 ]]; then
    echo "FAIL: $name passed validation but should be invalid." >&2
    cat "$output" >&2
    exit 1
  fi
  if ! grep -qi 'Fix' "$output"; then
    echo "FAIL: $name did not print a fix." >&2
    cat "$output" >&2
    exit 1
  fi
  if ! grep -q "$expected_fix" "$output"; then
    echo "FAIL: $name did not suggest $expected_fix." >&2
    cat "$output" >&2
    exit 1
  fi
  echo "[ok] $name rejected and suggests $expected_fix"
}

bad_language_dir="$(write_config bad-language 'language: java
main_repo: https://example.com/bad-language.git
fuzzing_engines: [libfuzzer]
sanitizers: [address]
')"

bad_engine_dir="$(write_config bad-engine 'language: jvm
main_repo: https://example.com/bad-engine.git
fuzzing_engines: [libFuzzer]
sanitizers: [address]
')"

bad_sanitizer_dir="$(write_config bad-sanitizer 'language: c++
main_repo: https://example.com/bad-sanitizer.git
fuzzing_engines: [libfuzzer]
sanitizers:
  - addres
')"

good_dir="$(write_config good 'language: c++
main_repo: https://example.com/good.git
fuzzing_engines: [libfuzzer]
sanitizers: [address]
architectures: [x86_64]
')"

expect_validation_failure bad-language 'jvm'
expect_validation_failure bad-engine 'libfuzzer'
expect_validation_failure bad-sanitizer 'address'

SCRIPT_PATH="$WORK_DIR/reproduce-good.sh"
"$PYTHON_BIN" infra/helper.py generate-repro "$good_dir" \
  --output "$SCRIPT_PATH" \
  --fuzzer demo_fuzzer \
  --testcase "$WORK_DIR/crash.bin"
printf 'minimal crash input\n' > "$WORK_DIR/crash.bin"

test -x "$SCRIPT_PATH"
bash -n "$SCRIPT_PATH"
"$SCRIPT_PATH" --help >/dev/null
"$SCRIPT_PATH" >/dev/null

"$SCRIPT_PATH" --dry-run > "$WORK_DIR/dry-run.log" 2>&1
grep -q 'validate-config' "$WORK_DIR/dry-run.log"
grep -q 'build_fuzzers' "$WORK_DIR/dry-run.log"
grep -q 'reproduce' "$WORK_DIR/dry-run.log"

MOCK_BIN="$WORK_DIR/mock-bin"
mkdir -p "$MOCK_BIN"
cat > "$MOCK_BIN/docker" <<'MOCK_DOCKER'
#!/usr/bin/env bash
echo "MOCK_DOCKER $*"
exit 0
MOCK_DOCKER
chmod +x "$MOCK_BIN/docker"
PATH="$MOCK_BIN:$PATH" "$SCRIPT_PATH" --sanitizer address \
  > "$WORK_DIR/mock-run.log" 2>&1
grep -q 'MOCK_DOCKER.*build' "$WORK_DIR/mock-run.log"
grep -q 'MOCK_DOCKER.*reproduce' "$WORK_DIR/mock-run.log"

echo "[ok] valid config generated executable script: $SCRIPT_PATH"
echo "[ok] script --help and --dry-run passed"
echo "[ok] script build/reproduce chain passed with a mock docker binary"
echo
echo "ACCEPTANCE PASSED. Artifacts kept in: $WORK_DIR"
