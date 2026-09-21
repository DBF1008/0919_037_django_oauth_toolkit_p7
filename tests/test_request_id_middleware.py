import logging

import pytest
from django.http import HttpResponse
from django.test import RequestFactory

from oauth2_provider.logging_utils import get_log_context, reset_log_context
from oauth2_provider.middleware import REQUEST_ID_RESPONSE_HEADER, RequestIDMiddleware


factory = RequestFactory()


def make_middleware(view):
    return RequestIDMiddleware(view)


class TestRequestIDMiddleware:
    def setup_method(self):
        reset_log_context()

    def teardown_method(self):
        reset_log_context()

    def test_generates_request_id_when_header_missing(self):
        def view(request):
            assert request.request_id
            assert get_log_context()["request_id"] == request.request_id
            return HttpResponse("ok")

        response = make_middleware(view)(factory.get("/"))
        assert response.status_code == 200
        assert response[REQUEST_ID_RESPONSE_HEADER]
        assert len(response[REQUEST_ID_RESPONSE_HEADER]) == 32

    def test_honours_inbound_request_id_header(self):
        request = factory.get("/", HTTP_X_REQUEST_ID="corr-id-123")
        response = make_middleware(lambda r: HttpResponse("ok"))(request)
        assert response[REQUEST_ID_RESPONSE_HEADER] == "corr-id-123"
        assert request.request_id == "corr-id-123"

    def test_rejects_malformed_inbound_header(self):
        request = factory.get("/", HTTP_X_REQUEST_ID="bad id with spaces\n")
        response = make_middleware(lambda r: HttpResponse("ok"))(request)
        generated = response[REQUEST_ID_RESPONSE_HEADER]
        assert generated != "bad id with spaces\n"
        assert len(generated) == 32

    def test_context_is_reset_after_request(self):
        make_middleware(lambda r: HttpResponse("ok"))(factory.get("/"))
        assert get_log_context()["request_id"] is None

    def test_context_reset_even_when_view_raises(self):
        def failing_view(request):
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError):
            make_middleware(failing_view)(factory.get("/"))
        assert get_log_context()["request_id"] is None

    def test_logs_inside_view_carry_request_id(self):
        records = []

        class Handler(logging.Handler):
            def emit(self, record):
                records.append(record)

        from oauth2_provider.logging_utils import get_oauth_logger

        logger = get_oauth_logger("oauth2_provider")
        handler = Handler()
        logger.addHandler(handler)

        def view(request):
            logger.warning("inside the view")
            return HttpResponse("ok")

        try:
            response = make_middleware(view)(factory.get("/", HTTP_X_REQUEST_ID="trace-9"))
        finally:
            logger.removeHandler(handler)

        assert records[0].request_id == "trace-9"
        assert response[REQUEST_ID_RESPONSE_HEADER] == "trace-9"
