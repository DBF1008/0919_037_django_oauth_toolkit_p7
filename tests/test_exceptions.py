import json

from oauthlib.oauth2 import OAuth2Error
from oauthlib.oauth2.rfc6749.errors import (
    InvalidClientError,
)
from oauthlib.oauth2.rfc6749.errors import (
    ServerError as OAuthLibServerError,
)

from oauth2_provider.exceptions import (
    FatalClientError,
    OAuthToolkitError,
    RecoverableError,
    ServerError,
    as_oauthlib_error,
)


class TestExceptionHierarchy:
    def test_new_errors_are_oauth_toolkit_errors(self):
        assert issubclass(RecoverableError, OAuthToolkitError)
        assert issubclass(ServerError, OAuthToolkitError)
        assert issubclass(FatalClientError, OAuthToolkitError)

    def test_recoverable_error_defaults_to_temporarily_unavailable_503(self):
        error = RecoverableError()
        assert error.oauthlib_error.error == "temporarily_unavailable"
        assert error.oauthlib_error.status_code == 503
        payload = json.loads(error.oauthlib_error.json)
        assert payload["error"] == "temporarily_unavailable"

    def test_server_error_defaults_to_server_error_500(self):
        error = ServerError()
        assert error.oauthlib_error.error == "server_error"
        assert error.oauthlib_error.status_code == 500

    def test_server_error_accepts_description(self):
        error = ServerError(description="database is down")
        payload = json.loads(error.oauthlib_error.json)
        assert payload["error"] == "server_error"
        assert payload["error_description"] == "database is down"

    def test_server_error_overrides_oauthlib_status_even_when_wrapped(self):
        # oauthlib's own server_error targets redirects and keeps HTTP 400.
        error = ServerError(error=OAuthLibServerError())
        assert error.oauthlib_error.status_code == 500

    def test_redirect_uri_is_propagated(self):
        error = RecoverableError(redirect_uri="https://client.example/cb")
        assert error.oauthlib_error.redirect_uri == "https://client.example/cb"


class TestAsOAuthLibError:
    def test_passes_through_oauthlib_error(self):
        oauthlib_error = InvalidClientError()
        assert as_oauthlib_error(oauthlib_error) is oauthlib_error

    def test_unwraps_toolkit_error(self):
        error = ServerError()
        assert as_oauthlib_error(error) is error.oauthlib_error
        assert isinstance(as_oauthlib_error(error), OAuth2Error)

    def test_plain_exception_becomes_generic_server_error(self):
        result = as_oauthlib_error(ValueError("unexpected"))
        assert result.error == "server_error"
        assert result.status_code == 500
