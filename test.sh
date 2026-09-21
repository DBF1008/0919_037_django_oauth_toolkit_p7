#!/usr/bin/env bash
#
# Manual unit test runner for the unified error handling / structured logging
# feature. Runs targeted tests first (fast feedback), then the full Django
# OAuth Toolkit test suite.
#
# Usage:
#   ./test.sh                # targeted tests + full suite
#   ./test.sh --quick        # targeted tests only
#   ./test.sh -k pattern     # pass extra args through to pytest
#
# Environment:
#   PYTHON       Python interpreter to use (must have the project test deps)
#
set -euo pipefail

cd "$(dirname "$0")"

export DJANGO_SETTINGS_MODULE="${DJANGO_SETTINGS_MODULE:-tests.settings}"
export PYTHONPATH="${PYTHONPATH:-$(pwd)}"

PYTHON="${PYTHON:-python3}"

if ! "$PYTHON" -c "import django, oauthlib, pytest" >/dev/null 2>&1; then
    echo "Dependencies are missing for: $PYTHON" >&2
    echo "Create/activate a virtualenv and install the test extras, e.g.:" >&2
    echo "  uv pip install -e '.[test]'" >&2
    exit 1
fi

PYTEST=("$PYTHON" -m pytest -p no:cacheprovider -o addopts="")

QUICK=0
ARGS=()
for arg in "$@"; do
    if [[ "$arg" == "--quick" ]]; then
        QUICK=1
    else
        ARGS+=("$arg")
    fi
done

FEATURE_TESTS=(
    tests/test_error_handling.py
    tests/test_mixins.py
    tests/test_token_view.py
    tests/test_token_endpoint_cors.py
    tests/test_oauth2_validators.py
    tests/test_oauth2_provider_middleware.py
    tests/test_application_views.py
)

echo "==> Ruff lint + format check"
"$PYTHON" -m ruff check oauth2_provider tests/test_error_handling.py
"$PYTHON" -m ruff format --check oauth2_provider tests/test_error_handling.py

echo "==> Targeted unit tests (new error handling feature)"
"${PYTEST[@]}" "${FEATURE_TESTS[@]}" ${ARGS[@]+"${ARGS[@]}"}

if [[ "$QUICK" == "1" ]]; then
    exit 0
fi

echo "==> Full unit test suite"
"${PYTEST[@]}" tests/ --ignore=tests/app ${ARGS[@]+"${ARGS[@]}"}
