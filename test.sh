#!/usr/bin/env bash
#
# Manual test runner for the unified error handling / structured logging work.
#
# Usage:
#   ./test.sh            run the unit tests covering the new feature
#   ./test.sh --all      run the full repository test suite
#   ./test.sh --lint     run ruff lint + format checks
#   ./test.sh --verbose  run the feature tests with verbose output
#
# The script auto-detects the project virtual environment (.venv-t first,
# falling back to .venv-test) or a system python3 with pytest installed.
set -euo pipefail

cd "$(dirname "$0")"

FEATURE_TESTS=(
    tests/test_exceptions.py
    tests/test_logging_utils.py
    tests/test_request_id_middleware.py
    tests/test_validator_logging.py
    tests/test_error_handling.py
    tests/test_oauth2_backends.py
    tests/test_mixins.py
    tests/test_token_view.py
    tests/test_oauth2_validators.py
    tests/test_oauth2_provider_middleware.py
    tests/test_authorization_code.py
    tests/test_password.py
    tests/test_client_credential.py
    tests/test_device.py
    tests/test_token_revocation.py
    tests/test_oidc_views.py
)

pick_python() {
    if [ -x ".venv-t/bin/python" ]; then
        echo ".venv-t/bin/python"
    elif [ -x ".venv-test/bin/python" ]; then
        echo ".venv-test/bin/python"
    elif command -v python3 >/dev/null 2>&1; then
        echo "python3"
    else
        echo "No Python interpreter found" >&2
        exit 1
    fi
}

PYTHON="$(pick_python)"
export DJANGO_SETTINGS_MODULE="${DJANGO_SETTINGS_MODULE:-tests.settings}"
export PYTHONPATH="${PYTHONPATH:-.}"
export PYTEST_ADDOPTS="${PYTEST_ADDOPTS:-}"

pick_ruff() {
    if "$PYTHON" -c "import ruff" >/dev/null 2>&1; then
        echo "$PYTHON -m ruff"
    elif command -v ruff >/dev/null 2>&1; then
        echo "ruff"
    else
        echo "ruff is not installed (install with 'pip install ruff')" >&2
        return 1
    fi
}

run_lint() {
    RUFF="$(pick_ruff)"
    echo "==> ruff check"
    $RUFF check oauth2_provider tests
    echo "==> ruff format --check"
    $RUFF format --check oauth2_provider tests
}

case "${1:-}" in
    --all)
        "$PYTHON" -m pytest tests/ -p no:cacheprovider --no-cov
        ;;
    --lint)
        run_lint
        ;;
    --verbose|-v)
        "$PYTHON" -m pytest "${FEATURE_TESTS[@]}" -p no:cacheprovider --no-cov -v
        ;;
    "")
        echo "==> Running feature unit tests with $PYTHON"
        "$PYTHON" -m pytest "${FEATURE_TESTS[@]}" -p no:cacheprovider --no-cov
        echo "==> Running lint"
        run_lint
        echo "==> All manual checks passed"
        ;;
    *)
        # Forward any other arguments straight to pytest.
        "$PYTHON" -m pytest "$@" -p no:cacheprovider --no-cov
        ;;
esac
