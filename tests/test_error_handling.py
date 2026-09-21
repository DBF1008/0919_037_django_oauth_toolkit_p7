import json
import logging

import pytest
from django.http import HttpResponse
from django.test import RequestFactory, override_settings
from oauthlib.oauth2 import InvalidClientError, InvalidRequestError
from oauthlib.oauth2.rfc6749.errors import TemporarilyUnavailableError

from oauth2_provider.exceptions import (
    FatalClientError,
    OAuthToolkitError,
    RecoverableError,
    ServerError,
)
from oauth2_provider.log_utils import (
    STRUCTURED_LOG_FIELDS,
    StructuredLogFilter,
    bind_log_context,
    get_log_context,
    log_event,
    reset_log_context,
    update_log_context_from_request,
)
from oauth2_provider.middleware import RequestIDMiddleware
from oauth2_provider.views.mixins import OAuthLibMixin

from .common_testing import OAuth2ProviderTestCase as TestCase


class TestExceptionHierarchy(TestCase):
    def test_recoverable_error_is_oauth_toolkit_error(self):
        error = RecoverableError()
        self.assertIsInstance(error, OAuthToolkitError)

    def test_server_error_is_oauth_toolkit_error(self):
        error = ServerError()
        self.assertIsInstance(error, OAuthToolkitError)

    def test_fatal_and_recoverable_and_server_are_distinct(self):
        classes = (FatalClientError, RecoverableError, ServerError)
        for error_class in classes:
            for other_class in classes:
                if error_class is not other_class:
                    self.assertNotIsInstance(error_class(), other_class)

    def test_error_keeps_oauthlib_error(self):
        oauthlib_error = TemporarilyUnavailableError()
        error = RecoverableError(error=oauthlib_error)
        self.assertIs(error.oauthlib_error, oauthlib_error)


@pytest.mark.usefixtures("oauth2_settings")
class TestErrorResponseToHttp(TestCase):
    def setUp(self):
        super().setUp()
        self.mixin = OAuthLibMixin()

    def test_generic_oauth_toolkit_error_passes_status_and_body_through(self):
        oauthlib_error = InvalidClientError()
        error = OAuthToolkitError(error=oauthlib_error)
        response = self.mixin.error_response_to_http(error)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertEqual(json.loads(response.content), json.loads(oauthlib_error.json))

    def test_fatal_client_error_passes_status_through(self):
        oauthlib_error = InvalidRequestError()
        error = FatalClientError(error=oauthlib_error)
        response = self.mixin.error_response_to_http(error)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["error"], "invalid_request")

    def test_recoverable_error_maps_to_503(self):
        error = RecoverableError()
        response = self.mixin.error_response_to_http(error)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(json.loads(response.content)["error"], "temporarily_unavailable")

    def test_recoverable_error_keeps_wrapped_oauthlib_error_body(self):
        wrapped = TemporarilyUnavailableError(description="upstream timeout")
        error = RecoverableError(error=wrapped)
        response = self.mixin.error_response_to_http(error)
        self.assertEqual(response.status_code, 503)
        payload = json.loads(response.content)
        self.assertEqual(payload["error"], "temporarily_unavailable")
        self.assertEqual(payload["error_description"], "upstream timeout")

    def test_server_error_maps_to_500(self):
        error = ServerError()
        response = self.mixin.error_response_to_http(error)
        self.assertEqual(response.status_code, 500)
        self.assertEqual(json.loads(response.content)["error"], "server_error")

    def test_unclassified_exception_maps_to_500_server_error(self):
        response = self.mixin.error_response_to_http(RuntimeError("boom"))
        self.assertEqual(response.status_code, 500)
        self.assertEqual(json.loads(response.content)["error"], "server_error")

    def test_oauthlib_error_headers_are_propagated(self):
        oauthlib_error = InvalidClientError()
        error = OAuthToolkitError(error=oauthlib_error)
        response = self.mixin.error_response_to_http(error)
        self.assertEqual(response["WWW-Authenticate"], 'Bearer error="invalid_client"')

    def test_parse_oauth2_body_handles_non_json(self):
        self.assertIsNone(self.mixin._parse_oauth2_body("not json"))
        self.assertIsNone(self.mixin._parse_oauth2_body(b""))
        self.assertIsNone(self.mixin._parse_oauth2_body(None))
        self.assertEqual(
            self.mixin._parse_oauth2_body('{"error": "invalid_grant"}'),
            {"error": "invalid_grant"},
        )


class TestStructuredLogging(TestCase):
    def setUp(self):
        super().setUp()
        reset_log_context()

    def tearDown(self):
        reset_log_context()
        super().tearDown()

    def test_bind_and_reset_log_context(self):
        bind_log_context(client_id="abc", grant_type="authorization_code")
        bind_log_context(user_id=42)
        self.assertEqual(
            get_log_context(),
            {"client_id": "abc", "grant_type": "authorization_code", "user_id": 42},
        )
        reset_log_context()
        self.assertEqual(get_log_context(), {})

    def test_bind_log_context_ignores_none_values(self):
        bind_log_context(client_id="abc", grant_type=None)
        self.assertEqual(get_log_context(), {"client_id": "abc"})

    def test_log_event_includes_structured_fields(self):
        bind_log_context(client_id="abc", grant_type="password", user_id=7, request_id="req-1")
        with self.assertLogs("oauth2_provider", level="DEBUG") as logs:
            log_event("debug", "something happened", detail="value")
        record = logs.records[0]
        self.assertEqual(record.client_id, "abc")
        self.assertEqual(record.grant_type, "password")
        self.assertEqual(record.user_id, 7)
        self.assertEqual(record.request_id, "req-1")
        self.assertIn("detail='value'", record.getMessage())

    def test_structured_log_filter_fills_missing_fields(self):
        record = logging.LogRecord("oauth2_provider", logging.INFO, __file__, 1, "msg", None, None)
        self.assertTrue(StructuredLogFilter().filter(record))
        for field in STRUCTURED_LOG_FIELDS:
            self.assertIsNone(getattr(record, field))

    def test_structured_log_filter_uses_context_values(self):
        bind_log_context(request_id="req-2")
        record = logging.LogRecord("oauth2_provider", logging.INFO, __file__, 1, "msg", None, None)
        StructuredLogFilter().filter(record)
        self.assertEqual(record.request_id, "req-2")
        self.assertIsNone(record.client_id)

    def test_update_log_context_from_oauthlib_like_request(self):
        class Client:
            client_id = "client-123"

        class User:
            pk = 99

        class Request:
            client_id = "client-123"
            grant_type = "client_credentials"
            user = User()
            client = Client()
            request_id = "req-3"

        update_log_context_from_request(Request())
        context = get_log_context()
        self.assertEqual(context["client_id"], "client-123")
        self.assertEqual(context["grant_type"], "client_credentials")
        self.assertEqual(context["user_id"], 99)
        self.assertEqual(context["request_id"], "req-3")

    def test_update_log_context_from_request_without_optional_fields(self):
        class Request:
            client_id = None
            grant_type = None
            client = None
            user = None

        update_log_context_from_request(Request())
        self.assertEqual(get_log_context(), {})


class TestRequestIDMiddleware(TestCase):
    def setUp(self):
        super().setUp()
        reset_log_context()
        self.factory = RequestFactory()

    def tearDown(self):
        reset_log_context()
        super().tearDown()

    def _get_response(self, request):
        return HttpResponse("ok")

    def test_request_id_is_generated_when_header_absent(self):
        request = self.factory.get("/o/token/")
        middleware = RequestIDMiddleware(self._get_response)
        response = middleware(request)
        self.assertTrue(request.request_id)
        self.assertEqual(response["X-Request-ID"], request.request_id)

    def test_request_id_header_is_reused(self):
        request = self.factory.get("/o/token/", HTTP_X_REQUEST_ID="correlation-123")
        middleware = RequestIDMiddleware(self._get_response)
        response = middleware(request)
        self.assertEqual(request.request_id, "correlation-123")
        self.assertEqual(response["X-Request-ID"], "correlation-123")

    def test_request_id_is_pushed_into_log_context(self):
        seen = {}

        def get_response(request):
            seen["context"] = get_log_context()
            return HttpResponse("ok")

        request = self.factory.get("/o/token/", HTTP_X_REQUEST_ID="correlation-456")
        RequestIDMiddleware(get_response)(request)
        self.assertEqual(seen["context"]["request_id"], "correlation-456")

    def test_log_context_is_reset_after_request(self):
        request = self.factory.get("/o/token/", HTTP_X_REQUEST_ID="correlation-789")
        RequestIDMiddleware(self._get_response)(request)
        self.assertEqual(get_log_context(), {})


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings({"REQUEST_ID_HEADER": "HTTP_X_CORRELATION_ID"})
def test_custom_request_id_header():
    reset_log_context()
    factory = RequestFactory()
    request = factory.get("/o/token/", HTTP_X_CORRELATION_ID="custom-id")
    response = RequestIDMiddleware(lambda req: HttpResponse("ok"))(request)
    assert request.request_id == "custom-id"
    assert response["X-Correlation-Id"] == "custom-id"
    assert get_log_context() == {}


def _token_view():
    from oauth2_provider.views.base import TokenView

    view = TokenView()
    view.kwargs = {}
    return view


def _revoke_view():
    from oauth2_provider.views.base import RevokeTokenView

    view = RevokeTokenView()
    view.kwargs = {}
    return view


def test_token_endpoint_non_json_error_body_returns_server_error(mocker):
    request = RequestFactory().post("/o/token/", {"grant_type": "password"})
    view = _token_view()
    mocker.patch.object(
        view,
        "create_token_response",
        return_value=(None, {}, "<html>bad gateway</html>", 502),
    )
    response = view.authorization_flow_token_response(request)
    assert response.status_code == 500
    assert json.loads(response.content)["error"] == "server_error"


def test_token_endpoint_non_json_success_body_returns_server_error(mocker):
    request = RequestFactory().post("/o/token/", {"grant_type": "password"})
    view = _token_view()
    mocker.patch.object(
        view,
        "create_token_response",
        return_value=(None, {}, "not-a-json-body", 200),
    )
    response = view.authorization_flow_token_response(request)
    assert response.status_code == 500
    assert json.loads(response.content)["error"] == "server_error"


def test_token_endpoint_server_exception_returns_500(mocker):
    request = RequestFactory().post("/o/token/", {"grant_type": "password"})
    view = _token_view()
    mocker.patch.object(view, "create_token_response", side_effect=ServerError())
    response = view.authorization_flow_token_response(request)
    assert response.status_code == 500
    assert json.loads(response.content)["error"] == "server_error"


def test_token_endpoint_server_exception_wrapping_raw_error(mocker):
    # The backend wraps unexpected failures as ServerError(error=raw_exception);
    # the raw exception has no oauthlib ``.json`` attribute.
    request = RequestFactory().post("/o/token/", {"grant_type": "password"})
    view = _token_view()
    mocker.patch.object(
        view,
        "create_token_response",
        side_effect=ServerError(error=ValueError("kaboom")),
    )
    response = view.authorization_flow_token_response(request)
    assert response.status_code == 500
    assert json.loads(response.content)["error"] == "server_error"


def test_token_endpoint_recoverable_exception_returns_503(mocker):
    request = RequestFactory().post("/o/token/", {"grant_type": "password"})
    view = _token_view()
    mocker.patch.object(view, "create_token_response", side_effect=RecoverableError())
    response = view.authorization_flow_token_response(request)
    assert response.status_code == 503
    assert json.loads(response.content)["error"] == "temporarily_unavailable"


def test_revocation_endpoint_server_exception_returns_500(mocker):
    request = RequestFactory().post("/o/revoke_token/")
    view = _revoke_view()
    mocker.patch.object(view, "create_revocation_response", side_effect=ServerError())
    response = view.post(request)
    assert response.status_code == 500
    assert json.loads(response.content)["error"] == "server_error"


def test_revocation_endpoint_recoverable_exception_returns_503(mocker):
    request = RequestFactory().post("/o/revoke_token/")
    view = _revoke_view()
    mocker.patch.object(view, "create_revocation_response", side_effect=RecoverableError())
    response = view.post(request)
    assert response.status_code == 503
    assert json.loads(response.content)["error"] == "temporarily_unavailable"


@pytest.mark.django_db
def test_create_token_response_wraps_unexpected_exception(mocker):
    from oauth2_provider.oauth2_backends import OAuthLibCore

    core = OAuthLibCore()
    request = RequestFactory().post(
        "/o/token/",
        data={"grant_type": "authorization_code", "code": "code", "client_id": "cid"},
    )
    mocker.patch.object(core.server, "create_token_response", side_effect=ValueError("boom"))
    with pytest.raises(ServerError):
        core.create_token_response(request)


@pytest.mark.django_db
def test_log_context_is_reset_after_backend_call(mocker):
    from oauth2_provider.oauth2_backends import OAuthLibCore

    core = OAuthLibCore()
    request = RequestFactory().post(
        "/o/token/",
        data={"grant_type": "authorization_code", "code": "code", "client_id": "cid"},
    )
    mocker.patch.object(core.server, "create_token_response", side_effect=ValueError("boom"))
    with pytest.raises(ServerError):
        core.create_token_response(request)
    assert get_log_context() == {}


@pytest.mark.django_db
@override_settings(
    MIDDLEWARE=[
        "django.middleware.common.CommonMiddleware",
        "oauth2_provider.middleware.RequestIDMiddleware",
    ]
)
def test_request_id_middleware_echoes_header_on_token_endpoint(client):
    response = client.post(
        "/o/token/",
        data={"grant_type": "password"},
        HTTP_X_REQUEST_ID="e2e-correlation-id",
    )
    assert response["X-Request-ID"] == "e2e-correlation-id"


@pytest.mark.django_db
@override_settings(
    MIDDLEWARE=[
        "django.middleware.common.CommonMiddleware",
        "oauth2_provider.middleware.RequestIDMiddleware",
    ]
)
def test_request_id_middleware_generates_id_when_absent(client):
    response = client.post("/o/token/", data={"grant_type": "password"})
    assert response["X-Request-ID"]
    assert len(response["X-Request-ID"]) == 32


@pytest.mark.django_db
@pytest.mark.parametrize(
    "extra_middleware",
    [["oauth2_provider.middleware.RequestIDMiddleware"]],
)
def test_token_endpoint_returns_standard_json_error_with_request_id(client, settings, extra_middleware):
    settings.MIDDLEWARE = [*settings.MIDDLEWARE, *extra_middleware]

    with self_assert_logs("oauth2_provider", level="DEBUG") as cap:
        response = client.post(
            "/o/token/",
            data={"grant_type": "client_credentials", "client_id": "unknown"},
            HTTP_X_REQUEST_ID="log-correlation-id",
        )
    assert response.status_code == 401
    assert response["Content-Type"] == "application/json"
    payload = response.json()
    assert payload["error"] == "invalid_client"
    assert response["X-Request-ID"] == "log-correlation-id"
    assert any(getattr(record, "request_id", None) == "log-correlation-id" for record in cap.records)


class _LogsContext:
    def __init__(self, logger, level):
        self.logger = logger
        self.level = level
        self.records = []

    def __enter__(self):
        target = logging.getLogger(self.logger)
        self._target = target
        self._old_level = target.level
        target.setLevel(self.level)

        class _Handler(logging.Handler):
            def __init__(self, sink):
                super().__init__()
                self.sink = sink

            def emit(self_inner, record):
                self_inner.sink.append(record)

        self._handler = _Handler(self.records)
        target.addHandler(self._handler)
        return self

    def __exit__(self, *exc):
        self._target.removeHandler(self._handler)
        self._target.setLevel(self._old_level)
        self._handler.close()
        return False


def self_assert_logs(logger, level="INFO"):
    level_value = getattr(logging, level.upper()) if isinstance(level, str) else level
    return _LogsContext(logger, level_value)
