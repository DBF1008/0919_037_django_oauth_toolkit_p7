import pytest

from oauth2_provider.logging_utils import get_log_context, reset_log_context
from oauth2_provider.oauth2_validators import OAuth2Validator

from .common_testing import OAuth2ProviderTestCase as TestCase


@pytest.mark.usefixtures("oauth2_settings")
class TestValidatorStructuredLogging(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.validator = OAuth2Validator()

    def teardown_method(self, method):
        reset_log_context()

    def _request(self, auth_header, client_id=None):
        from oauthlib.common import Request

        body = "grant_type=password"
        if client_id:
            body += "&client_id=" + client_id
        headers = {"HTTP_AUTHORIZATION": auth_header} if auth_header else {}
        return Request("/o/token/", http_method="POST", body=body, headers=headers)

    def test_malformed_basic_auth_is_logged_with_reason(self):
        request = self._request("Basic !!!not-base64")
        with self.assertLogs("oauth2_provider", level="DEBUG") as logs:
            result = self.validator._authenticate_basic_auth(request)
        self.assertFalse(result)
        self.assertEqual(logs.records[0].event, "client_auth_failed")
        self.assertEqual(logs.records[0].evt_reason, "invalid_base64")

    def test_unknown_client_basic_auth_logs_client_id(self):
        import base64

        raw = base64.b64encode(b"ghost-client:secret").decode()
        request = self._request("Basic " + raw)
        with self.assertLogs("oauth2_provider", level="DEBUG") as logs:
            result = self.validator._authenticate_basic_auth(request)
        self.assertFalse(result)
        record = next(r for r in logs.records if r.event == "client_auth_failed")
        self.assertEqual(record.evt_reason, "unknown_client")
        self.assertEqual(record.client_id, "ghost-client")
        self.assertEqual(record.grant_type, "password")

    def test_secret_is_never_logged(self):
        import base64

        raw = base64.b64encode(b"ghost-client:super-secret-value").decode()
        request = self._request("Basic " + raw)
        with self.assertLogs("oauth2_provider", level="DEBUG") as logs:
            self.validator._authenticate_basic_auth(request)
        for record in logs.records:
            self.assertNotIn("super-secret-value", record.getMessage())
            self.assertNotIn("super-secret-value", str(record.__dict__))

    def test_authenticate_client_binds_context_on_success(self):
        import base64

        from oauth2_provider.models import get_application_model

        Application = get_application_model()
        Application.objects.create(
            name="logging-app",
            client_id="logging_client",
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_PASSWORD,
            client_secret="logging-secret",
        )
        raw = base64.b64encode(b"logging_client:logging-secret").decode()
        request = self._request("Basic " + raw)
        try:
            self.assertTrue(self.validator.authenticate_client(request))
            self.assertEqual(get_log_context()["client_id"], "logging_client")
            self.assertEqual(get_log_context()["grant_type"], "password")
        finally:
            reset_log_context()
