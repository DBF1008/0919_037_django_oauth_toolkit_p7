import json
from urllib.parse import urlencode

import pytest
from django.test import RequestFactory
from django.views.generic import View
from oauthlib.oauth2.rfc6749.errors import InvalidClientError

from oauth2_provider.exceptions import (
    FatalClientError,
    OAuthToolkitError,
    RecoverableError,
    ServerError,
)
from oauth2_provider.models import get_application_model
from oauth2_provider.views.base import TokenView
from oauth2_provider.views.mixins import OAuthLibMixin
from tests import presets

from .common_testing import OAuth2ProviderTestCase as TestCase


try:
    from unittest import mock
except ImportError:
    import mock


class ErrorMappingView(OAuthLibMixin, View):
    pass


@pytest.mark.usefixtures("oauth2_settings")
class TestErrorResponseToHttp(TestCase):
    def setUp(self):
        super().setUp()
        self.view = ErrorMappingView()

    def test_server_error_maps_to_500_json(self):
        response = self.view.error_response_to_http(ServerError(description="boom"))
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response["Content-Type"], "application/json")
        payload = json.loads(response.content)
        self.assertEqual(payload["error"], "server_error")
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertEqual(response["Pragma"], "no-cache")

    def test_recoverable_error_maps_to_503(self):
        response = self.view.error_response_to_http(RecoverableError())
        self.assertEqual(response.status_code, 503)
        self.assertEqual(json.loads(response.content)["error"], "temporarily_unavailable")

    def test_fatal_client_error_maps_to_400(self):
        oauthlib_error = InvalidClientError()
        response = self.view.error_response_to_http(FatalClientError(error=oauthlib_error))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(json.loads(response.content)["error"], "invalid_client")

    def test_generic_oauth_toolkit_error_uses_wrapped_status(self):
        response = self.view.error_response_to_http(OAuthToolkitError(error=InvalidClientError()))
        self.assertEqual(response.status_code, 401)

    def test_plain_exception_is_wrapped_as_server_error(self):
        response = self.view.error_response_to_http(ValueError("unexpected"))
        self.assertEqual(response.status_code, 500)
        self.assertEqual(json.loads(response.content)["error"], "server_error")

    def test_explicit_status_overrides(self):
        response = self.view.error_response_to_http(ServerError(), status=503)
        self.assertEqual(response.status_code, 503)

    def test_error_is_logged_with_event_name(self):
        with self.assertLogs("oauth2_provider", level="ERROR") as logs:
            self.view.error_response_to_http(ServerError())
        self.assertEqual(logs.records[0].event, "server_oauth_error")

    def test_recoverable_error_logged_at_warning(self):
        with self.assertLogs("oauth2_provider", level="WARNING") as logs:
            self.view.error_response_to_http(RecoverableError())
        self.assertEqual(logs.records[0].event, "recoverable_oauth_error")


@pytest.mark.usefixtures("oauth2_settings")
class TestBuildOAuthHttpResponse(TestCase):
    def setUp(self):
        super().setUp()
        self.view = ErrorMappingView()

    def test_json_body_is_rendered_as_json(self):
        response = self.view.build_oauth_http_response(
            (None, {"X-Custom": "yes"}, '{"access_token": "tok"}', 200)
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["X-Custom"], "yes")
        self.assertEqual(json.loads(response.content), {"access_token": "tok"})

    def test_empty_body_is_supported_for_revocation(self):
        response = self.view.build_oauth_http_response((None, {}, "", 200))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"")

    def test_non_json_body_does_not_raise(self):
        with self.assertLogs("oauth2_provider", level="ERROR") as logs:
            response = self.view.build_oauth_http_response((None, {}, "this is not json", 500))
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.content, b"this is not json")
        self.assertEqual(logs.records[0].event, "invalid_oauth_response_body")

    def test_three_tuple_result(self):
        response = self.view.build_oauth_http_response(({"X-Device": "1"}, '{"device_code": "x"}', 200))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["X-Device"], "1")

    def test_success_responses_have_no_cache_headers(self):
        response = self.view.build_oauth_http_response((None, {}, '{"ok": true}', 200))
        self.assertNotIn("Cache-Control", response)


class MalformedCore:
    def create_token_response(self, request):
        return None, {}, "not json", 200


class ErrorStatusCore:
    def create_token_response(self, request):
        return None, {}, '{"error": "invalid_client"}', 401


class ServerFailureCore:
    def create_token_response(self, request):
        raise RuntimeError("core exploded")


@pytest.mark.usefixtures("oauth2_settings")
class TestTokenViewRobustness(TestCase):
    factory = RequestFactory()

    def _post(self, core):
        request = self.factory.post(
            "/o/token/",
            data=urlencode({"grant_type": "client_credentials"}),
            content_type="application/x-www-form-urlencoded",
        )
        view = TokenView()
        view.request = request
        if isinstance(core, ServerFailureCore):
            with mock.patch(
                "oauthlib.oauth2.Server.create_token_response", side_effect=RuntimeError("core exploded")
            ):
                return view.authorization_flow_token_response(request)
        with mock.patch.object(OAuthLibMixin, "get_oauthlib_core", return_value=core):
            return view.authorization_flow_token_response(request)

    def test_non_json_success_body_becomes_500(self):
        with self.assertLogs("oauth2_provider", level="ERROR"):
            response = self._post(MalformedCore())
        self.assertEqual(response.status_code, 500)
        self.assertEqual(json.loads(response.content)["error"], "server_error")

    def test_oauth_error_response_is_passed_through(self):
        response = self._post(ErrorStatusCore())
        self.assertEqual(response.status_code, 401)
        self.assertEqual(json.loads(response.content)["error"], "invalid_client")

    def test_unexpected_backend_failure_becomes_500(self):
        with self.assertLogs("oauth2_provider", level="ERROR"):
            response = self._post(ServerFailureCore())
        self.assertEqual(response.status_code, 500)
        self.assertEqual(json.loads(response.content)["error"], "server_error")


@pytest.mark.oauth2_settings(presets.DEFAULT_SCOPES_RW)
@pytest.mark.django_db
def test_token_endpoint_echoes_request_id_and_logs_context(client, oauth2_settings, caplog, test_user):
    ApplicationModel = get_application_model()
    ApplicationModel.objects.create(
        name="integration-app",
        user=test_user,
        client_id="integration_client",
        client_type=ApplicationModel.CLIENT_PUBLIC,
        authorization_grant_type=ApplicationModel.GRANT_PASSWORD,
        client_secret="integration-secret-value",
    )
    caplog.set_level("INFO", logger="oauth2_provider")
    body = urlencode(
        {
            "grant_type": "password",
            "username": "test_user",
            "password": "123456",
            "client_id": "integration_client",
            "client_secret": "integration-secret-value",
        }
    )
    response = client.post(
        "/o/token/",
        data=body,
        content_type="application/x-www-form-urlencoded",
        HTTP_X_REQUEST_ID="integration-req-1",
    )
    assert response.status_code == 200, response.content
    assert response["X-Request-ID"] == "integration-req-1"
    context_records = [r for r in caplog.records if getattr(r, "request_id", None)]
    assert any(r.request_id == "integration-req-1" for r in context_records)
    assert any(getattr(r, "client_id", None) == "integration_client" for r in context_records)
    assert any(getattr(r, "grant_type", None) == "password" for r in context_records)
    assert any(getattr(r, "user_id", None) == "test_user" for r in context_records)
