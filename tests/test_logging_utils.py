import json
import logging

import pytest

from oauth2_provider.logging_utils import (
    CONTEXT_FIELDS,
    OAuthContextFilter,
    StructuredFormatter,
    bind_log_context,
    configure_logging,
    get_log_context,
    get_oauth_logger,
    log_context,
    log_event,
    reset_log_context,
)


@pytest.fixture(autouse=True)
def clean_context():
    reset_log_context()
    yield
    reset_log_context()


class TestLogContext:
    def test_context_starts_empty(self):
        assert get_log_context() == {field: None for field in CONTEXT_FIELDS}

    def test_bind_and_reset(self):
        bind_log_context(request_id="req-1", client_id="client-1")
        assert get_log_context()["request_id"] == "req-1"
        assert get_log_context()["client_id"] == "client-1"
        reset_log_context()
        assert get_log_context()["request_id"] is None

    def test_context_manager_restores_previous_values(self):
        bind_log_context(request_id="outer")
        with log_context(request_id="inner", grant_type="password"):
            assert get_log_context()["request_id"] == "inner"
            assert get_log_context()["grant_type"] == "password"
        assert get_log_context()["request_id"] == "outer"
        assert get_log_context()["grant_type"] is None

    def test_context_manager_restores_on_exception(self):
        bind_log_context(client_id="outer")
        with pytest.raises(RuntimeError):
            with log_context(client_id="inner"):
                raise RuntimeError("boom")
        assert get_log_context()["client_id"] == "outer"

    def test_unknown_field_rejected(self):
        with pytest.raises(TypeError):
            bind_log_context(unknown="x")


class TestOAuthContextFilter:
    def test_record_enriched_with_context_fields(self):
        bind_log_context(request_id="req-42", client_id="abc", grant_type="client_credentials")
        record = logging.LogRecord("oauth2_provider", logging.INFO, __file__, 1, "msg", None, None)
        assert OAuthContextFilter().filter(record)
        assert record.request_id == "req-42"
        assert record.client_id == "abc"
        assert record.grant_type == "client_credentials"
        assert record.user_id is None

    def test_explicit_record_attribute_wins(self):
        bind_log_context(request_id="from-context")
        record = logging.LogRecord("oauth2_provider", logging.INFO, __file__, 1, "msg", None, None)
        record.request_id = "from-record"
        OAuthContextFilter().filter(record)
        assert record.request_id == "from-record"


class TestStructuredFormatter:
    def test_json_payload_contains_context_fields(self):
        bind_log_context(request_id="req-1", client_id="c-1", grant_type="password", user_id="alice")
        record = logging.LogRecord("oauth2_provider", logging.WARNING, __file__, 1, "msg", None, None)
        record.event = "client_auth_failed"
        OAuthContextFilter().filter(record)
        payload = json.loads(StructuredFormatter().format(record))
        assert payload["level"] == "WARNING"
        assert payload["event"] == "client_auth_failed"
        assert payload["request_id"] == "req-1"
        assert payload["client_id"] == "c-1"
        assert payload["grant_type"] == "password"
        assert payload["user_id"] == "alice"

    def test_none_fields_omitted(self):
        record = logging.LogRecord("oauth2_provider", logging.INFO, __file__, 1, "msg", None, None)
        OAuthContextFilter().filter(record)
        payload = json.loads(StructuredFormatter().format(record))
        for field in CONTEXT_FIELDS:
            assert field not in payload

    def test_exception_info_serialized(self):
        try:
            raise ValueError("bad value")
        except ValueError:
            import sys

            record = logging.LogRecord(
                "oauth2_provider", logging.ERROR, __file__, 1, "msg", None, sys.exc_info()
            )
        payload = json.loads(StructuredFormatter().format(record))
        assert "ValueError: bad value" in payload["exception"]


class TestLoggerConfiguration:
    def test_configure_is_idempotent(self):
        logger = logging.getLogger("oauth2_provider.test_idempotent")
        configure_logging(logger.name)
        filters_before = list(logger.filters)
        configure_logging(logger.name)
        assert logger.filters == filters_before
        assert any(isinstance(f, OAuthContextFilter) for f in logger.filters)

    def test_get_oauth_logger_enriches_records(self):
        logger = get_oauth_logger("oauth2_provider.test_enrich")
        bind_log_context(request_id="req-77")
        records = []

        class Handler(logging.Handler):
            def emit(self, record):
                records.append(record)

        handler = Handler()
        logger.addHandler(handler)
        try:
            logger.warning("something happened")
        finally:
            logger.removeHandler(handler)
        assert records[0].request_id == "req-77"

    def test_log_event_attaches_event_and_extra_fields(self):
        logger = get_oauth_logger("oauth2_provider.test_event")
        bind_log_context(client_id="client-x")
        records = []

        class Handler(logging.Handler):
            def emit(self, record):
                records.append(record)

        handler = Handler()
        logger.addHandler(handler)
        try:
            log_event(
                logger,
                logging.WARNING,
                "client_auth_failed",
                reason="invalid_client_secret",
                client_id="client-override",
            )
        finally:
            logger.removeHandler(handler)

        record = records[0]
        assert record.event == "client_auth_failed"
        assert record.evt_reason == "invalid_client_secret"
        assert record.client_id == "client-override"
