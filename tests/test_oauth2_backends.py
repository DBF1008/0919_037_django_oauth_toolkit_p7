import base64
import json

import pytest
from django.contrib.auth import get_user_model
from django.test import RequestFactory
from django.utils.timezone import now, timedelta

from oauth2_provider.backends import get_oauthlib_core
from oauth2_provider.models import get_access_token_model, get_application_model, redirect_to_uri_allowed
from oauth2_provider.oauth2_backends import JSONOAuthLibCore, OAuthLibCore
from tests import presets
from tests.common_testing import OAuth2ProviderTestCase as TestCase


try:
    from unittest import mock
except ImportError:
    import mock


@pytest.mark.usefixtures("oauth2_settings")
class TestOAuthLibCoreBackend(TestCase):
    factory = RequestFactory()

    @classmethod
    def setUpTestData(cls):
        cls.oauthlib_core = OAuthLibCore()

    def test_swappable_server_class(self):
        self.oauth2_settings.OAUTH2_SERVER_CLASS = mock.MagicMock
        oauthlib_core = OAuthLibCore()
        self.assertTrue(isinstance(oauthlib_core.server, mock.MagicMock))

    def test_form_urlencoded_extract_params(self):
        payload = "grant_type=password&username=john&password=123456"
        request = self.factory.post("/o/token/", payload, content_type="application/x-www-form-urlencoded")

        uri, http_method, body, headers = self.oauthlib_core._extract_params(request)
        self.assertIn("grant_type=password", body)
        self.assertIn("username=john", body)
        self.assertIn("password=123456", body)

    def test_application_json_extract_params(self):
        payload = json.dumps(
            {
                "grant_type": "password",
                "username": "john",
                "password": "123456",
            }
        )
        request = self.factory.post("/o/token/", payload, content_type="application/json")

        uri, http_method, body, headers = self.oauthlib_core._extract_params(request)
        self.assertNotIn("grant_type=password", body)
        self.assertNotIn("username=john", body)
        self.assertNotIn("password=123456", body)


UserModel = get_user_model()
ApplicationModel = get_application_model()
AccessTokenModel = get_access_token_model()


@pytest.mark.usefixtures("oauth2_settings")
class TestOAuthLibCoreBackendErrorHandling(TestCase):
    factory = RequestFactory()

    @classmethod
    def setUpTestData(cls):
        cls.oauthlib_core = OAuthLibCore()
        cls.user = UserModel.objects.create_user("john", "test@example.com", "123456")
        cls.app = ApplicationModel.objects.create(
            name="app",
            client_id="app_id",
            client_secret="app_secret",
            client_type=ApplicationModel.CLIENT_CONFIDENTIAL,
            authorization_grant_type=ApplicationModel.GRANT_PASSWORD,
            user=cls.user,
        )

    def test_create_token_response_valid(self):
        payload = (
            "grant_type=password&username=john&password=123456&client_id=app_id&client_secret=app_secret"
        )
        request = self.factory.post(
            "/o/token/",
            payload,
            content_type="application/x-www-form-urlencoded",
            HTTP_AUTHORIZATION="Basic %s" % base64.b64encode(b"john:123456").decode(),
        )

        uri, headers, body, status = self.oauthlib_core.create_token_response(request)
        self.assertEqual(status, 200)

    def test_create_token_response_query_params(self):
        payload = (
            "grant_type=password&username=john&password=123456&client_id=app_id&client_secret=app_secret"
        )
        request = self.factory.post(
            "/o/token/?test=foo",
            payload,
            content_type="application/x-www-form-urlencoded",
            HTTP_AUTHORIZATION="Basic %s" % base64.b64encode(b"john:123456").decode(),
        )
        uri, headers, body, status = self.oauthlib_core.create_token_response(request)

        self.assertEqual(status, 400)
        self.assertDictEqual(
            json.loads(body),
            {"error": "invalid_request", "error_description": "URL query parameters are not allowed"},
        )

    def test_create_revocation_response_valid(self):
        AccessTokenModel.objects.create(
            user=self.user, token="tokstr", application=self.app, expires=now() + timedelta(days=365)
        )
        payload = "client_id=app_id&client_secret=app_secret&token=tokstr"
        request = self.factory.post(
            "/o/revoke_token/",
            payload,
            content_type="application/x-www-form-urlencoded",
            HTTP_AUTHORIZATION="Basic %s" % base64.b64encode(b"john:123456").decode(),
        )
        uri, headers, body, status = self.oauthlib_core.create_revocation_response(request)
        self.assertEqual(status, 200)

    def test_create_revocation_response_query_params(self):
        token = AccessTokenModel.objects.create(
            user=self.user, token="tokstr", application=self.app, expires=now() + timedelta(days=365)
        )
        payload = "client_id=app_id&client_secret=app_secret&token=tokstr"
        request = self.factory.post(
            "/o/revoke_token/?test=foo",
            payload,
            content_type="application/x-www-form-urlencoded",
            HTTP_AUTHORIZATION="Basic %s" % base64.b64encode(b"john:123456").decode(),
        )
        uri, headers, body, status = self.oauthlib_core.create_revocation_response(request)
        self.assertEqual(status, 400)
        self.assertDictEqual(
            json.loads(body),
            {"error": "invalid_request", "error_description": "URL query parameters are not allowed"},
        )
        token.delete()


class TestCustomOAuthLibCoreBackend(TestCase):
    """
    Tests that the public API behaves as expected when we override
    the OAuthLibCoreBackend core methods.
    """

    class MyOAuthLibCore(OAuthLibCore):
        def _get_extra_credentials(self, request):
            return 1

    factory = RequestFactory()

    def test_create_token_response_gets_extra_credentials(self):
        """
        Make sures that extra_credentials parameter is passed to oauthlib
        """
        payload = "grant_type=password&username=john&password=123456"
        request = self.factory.post("/o/token/", payload, content_type="application/x-www-form-urlencoded")

        with mock.patch("oauthlib.oauth2.Server.create_token_response") as create_token_response:
            mocked = mock.MagicMock()
            create_token_response.return_value = mocked, mocked, mocked
            core = self.MyOAuthLibCore()
            core.create_token_response(request)
            self.assertTrue(create_token_response.call_args[0][4] == 1)


class TestJSONOAuthLibCoreBackend(TestCase):
    factory = RequestFactory()

    def test_application_json_extract_params(self):
        payload = json.dumps(
            {
                "grant_type": "password",
                "username": "john",
                "password": "123456",
            }
        )
        request = self.factory.post("/o/token/", payload, content_type="application/json")
        oauthlib_core = JSONOAuthLibCore()

        uri, http_method, body, headers = oauthlib_core._extract_params(request)
        self.assertIn("grant_type=password", body)
        self.assertIn("username=john", body)
        self.assertIn("password=123456", body)


class TestOAuthLibCore(TestCase):
    factory = RequestFactory()

    def test_validate_authorization_request_unsafe_query(self):
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + "a_casual_token",
        }
        request = self.factory.get("/fake-resource?next=/fake", **auth_headers)

        oauthlib_core = get_oauthlib_core()
        oauthlib_core.verify_request(request, scopes=[])


@pytest.mark.parametrize(
    "uri, expected_result",
    # localhost is _not_ a loopback URI
    [
        ("http://localhost:3456", False),
        # only http scheme is supported for loopback URIs
        ("https://127.0.0.1:3456", False),
        ("http://127.0.0.1:3456", True),
        ("http://[::1]", True),
        ("http://[::1]:34", True),
    ],
)
def test_uri_loopback_redirect_check(uri, expected_result):
    allowed_uris = ["http://127.0.0.1", "http://[::1]"]
    if expected_result:
        assert redirect_to_uri_allowed(uri, allowed_uris)
    else:
        assert not redirect_to_uri_allowed(uri, allowed_uris)


@pytest.mark.usefixtures("oauth2_settings")
class TestUnifiedErrorHandling(TestCase):
    factory = RequestFactory()

    @classmethod
    def setUpTestData(cls):
        cls.oauthlib_core = OAuthLibCore()

    def _request(self, payload=""):
        return self.factory.post(
            "/o/token/",
            payload,
            content_type="application/x-www-form-urlencoded",
        )

    def test_unexpected_token_server_failure_becomes_500_tuple(self):
        request = self._request("grant_type=client_credentials")
        with mock.patch.object(
            self.oauthlib_core.server,
            "create_token_response",
            side_effect=RuntimeError("db down"),
        ):
            with self.assertLogs("oauth2_provider", level="ERROR") as logs:
                uri, headers, body, status = self.oauthlib_core.create_token_response(request)
        self.assertEqual(status, 500)
        self.assertIsNone(uri)
        self.assertEqual(json.loads(body)["error"], "server_error")
        self.assertEqual(logs.records[0].event, "token_request_failure")

    def test_oauth2_error_on_token_endpoint_returns_error_tuple(self):
        from oauthlib.oauth2.rfc6749.errors import InvalidClientError

        request = self._request("grant_type=client_credentials")
        with mock.patch.object(
            self.oauthlib_core.server,
            "create_token_response",
            side_effect=InvalidClientError(),
        ):
            uri, headers, body, status = self.oauthlib_core.create_token_response(request)
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)["error"], "invalid_client")

    def test_unexpected_revocation_failure_becomes_500_tuple(self):
        request = self._request("token=abc")
        with mock.patch.object(
            self.oauthlib_core.server,
            "create_revocation_response",
            side_effect=RuntimeError("boom"),
        ):
            with self.assertLogs("oauth2_provider", level="ERROR") as logs:
                uri, headers, body, status = self.oauthlib_core.create_revocation_response(request)
        self.assertEqual(status, 500)
        self.assertEqual(json.loads(body)["error"], "server_error")
        self.assertEqual(logs.records[0].event, "revocation_request_failure")

    def test_extract_params_binds_structured_log_context(self):
        from oauth2_provider.logging_utils import get_log_context, reset_log_context

        reset_log_context()
        request = self.factory.post(
            "/o/token/",
            {"grant_type": "password", "client_id": "ctx-client"},
        )
        request.request_id = "ctx-req"
        self.oauthlib_core._extract_params(request)
        context = get_log_context()
        self.assertEqual(context["request_id"], "ctx-req")
        self.assertEqual(context["client_id"], "ctx-client")
        self.assertEqual(context["grant_type"], "password")
        reset_log_context()


@pytest.mark.usefixtures("oauth2_settings")
class TestJSONOAuthLibCoreInvalidBody(TestCase):
    factory = RequestFactory()

    def test_invalid_json_body_returns_empty_and_logs(self):
        request = self.factory.post("/o/token/", "{not json", content_type="application/json")
        with self.assertLogs("oauth2_provider", level="WARNING") as logs:
            body = JSONOAuthLibCore().extract_body(request)
        self.assertEqual(body, "")
        self.assertEqual(logs.records[0].event, "invalid_json_body")

    def test_json_non_object_body_returns_empty_and_logs(self):
        request = self.factory.post("/o/token/", "[1, 2, 3]", content_type="application/json")
        with self.assertLogs("oauth2_provider", level="WARNING") as logs:
            body = JSONOAuthLibCore().extract_body(request)
        self.assertEqual(body, "")
        self.assertEqual(logs.records[0].event, "invalid_json_body")


@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_unexpected_userinfo_failure_becomes_500_tuple(oauth2_settings, caplog):
    factory = RequestFactory()
    oidc_core = OAuthLibCore()
    request = factory.get("/o/userinfo/")
    caplog.set_level("ERROR", logger="oauth2_provider")
    with mock.patch.object(
        type(oidc_core.server),
        "create_userinfo_response",
        side_effect=RuntimeError("boom"),
    ):
        uri, headers, body, status = oidc_core.create_userinfo_response(request)
    assert status == 500
    assert json.loads(body)["error"] == "server_error"
    assert caplog.records[0].event == "userinfo_request_failure"
