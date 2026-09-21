"""
Structured logging primitives for django-oauth-toolkit.

Every log record emitted through :func:`get_oauth_logger` is enriched with the
standard OAuth request context fields ``client_id``, ``grant_type``,
``user_id`` and ``request_id``.  The fields are stored in :mod:`contextvars`
so they are safe to use with both threaded and asynchronous Django views.

Projects render the fields either as plain text using
:class:`ContextFormatter` or as one JSON object per line using
:class:`StructuredFormatter`.
"""

import contextvars
import json
import logging
from contextlib import contextmanager


#: Name of the HTTP header used to carry a request identifier.
REQUEST_ID_HEADER = "HTTP_X_REQUEST_ID"

#: Standard context fields that are injected on every log record.
CONTEXT_FIELDS = ("request_id", "client_id", "grant_type", "user_id")

request_id_var = contextvars.ContextVar("oauth2_request_id", default=None)
client_id_var = contextvars.ContextVar("oauth2_client_id", default=None)
grant_type_var = contextvars.ContextVar("oauth2_grant_type", default=None)
user_id_var = contextvars.ContextVar("oauth2_user_id", default=None)


@contextmanager
def log_context(**kwargs):
    """
    Temporarily bind OAuth context fields, restoring previous values on exit.

    Only :data:`CONTEXT_FIELDS` keys are accepted; passing ``None`` clears the
    corresponding field for the duration of the block.
    """
    tokens = {}
    for key, value in kwargs.items():
        if key not in CONTEXT_FIELDS:
            raise TypeError("Unknown log context field: {!r}".format(key))
        tokens[key] = _CONTEXT_VARS[key].set(value)
    try:
        yield
    finally:
        for key, token in tokens.items():
            _CONTEXT_VARS[key].reset(token)


def bind_log_context(**kwargs):
    """
    Bind OAuth context fields on the current :mod:`contextvars` context.

    Unlike :func:`log_context`, the values stay set until explicitly reset
    (typically by the request ID middleware in a ``finally`` block).
    """
    for key, value in kwargs.items():
        if key not in CONTEXT_FIELDS:
            raise TypeError("Unknown log context field: {!r}".format(key))
        _CONTEXT_VARS[key].set(value)


def reset_log_context():
    """Reset every OAuth context field to its empty default."""
    for var in _CONTEXT_VARS.values():
        var.set(None)


def get_log_context():
    """Return a snapshot of the current OAuth context fields."""
    return {key: var.get() for key, var in _CONTEXT_VARS.items()}


_CONTEXT_VARS = {
    "request_id": request_id_var,
    "client_id": client_id_var,
    "grant_type": grant_type_var,
    "user_id": user_id_var,
}


class OAuthContextFilter(logging.Filter):
    """
    Ensure every record carries the standard OAuth context fields.

    Existing attributes on the record (for example an explicit ``request_id``
    passed via ``extra``) always take precedence over the context defaults.
    """

    def filter(self, record):
        for field in CONTEXT_FIELDS:
            if not hasattr(record, field):
                setattr(record, field, _CONTEXT_VARS[field].get())
        return True


class StructuredFormatter(logging.Formatter):
    """Render log records as a single JSON object per line."""

    def __init__(self, *args, include_logger=True, **kwargs):
        super().__init__(*args, **kwargs)
        self.include_logger = include_logger

    def format(self, record):
        payload = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage(),
        }
        if self.include_logger:
            payload["logger"] = record.name
        for field in CONTEXT_FIELDS:
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = value
        event = getattr(record, "event", None)
        if event:
            payload["event"] = event
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class ContextFormatter(logging.Formatter):
    """
    Human readable formatter that appends the OAuth context fields to the
    default logging output, for example::

        WARNING invalid client client_id=abc123 grant_type=password request_id=f42...
    """

    def format(self, record):
        message = super().format(record)
        context = []
        for field in CONTEXT_FIELDS:
            value = getattr(record, field, None)
            if value is not None:
                context.append("{}={}".format(field, value))
        if context:
            message = "{} [{}]".format(message, " ".join(context))
        return message


def configure_logging(logger_name="oauth2_provider"):
    """
    Ensure the named logger (and the root logger, so handlers attached above
    it also see enriched records) has :class:`OAuthContextFilter` attached.

    The operation is idempotent and does not change handlers or levels, so it
    is safe to call when the package is imported as well as from project
    logging configuration.
    """
    logger = logging.getLogger(logger_name)
    if not any(isinstance(log_filter, OAuthContextFilter) for log_filter in logger.filters):
        logger.addFilter(OAuthContextFilter())
    root = logging.getLogger()
    if not any(isinstance(log_filter, OAuthContextFilter) for log_filter in root.filters):
        root.addFilter(OAuthContextFilter())
    return logger


def get_oauth_logger(name="oauth2_provider"):
    """
    Return a logger guaranteed to enrich records with OAuth context fields.
    """
    return configure_logging(name)


def log_event(logger, level, event, message=None, exc_info=None, **fields):
    """
    Emit a structured log line.

    :param logger: a :class:`logging.Logger` instance
    :param level: numeric logging level (e.g. ``logging.WARNING``)
    :param event: short machine readable event name (e.g. ``client_auth_failed``)
    :param message: optional human readable message; defaults to ``event``
    :param exc_info: exception info as accepted by :meth:`logging.Logger.log`
    :param fields: extra key/value pairs rendered by structured formatters
    """
    extra = {"event": event}
    for key, value in fields.items():
        if key in CONTEXT_FIELDS:
            extra[key] = value
        else:
            extra["evt_{}".format(key)] = value
    logger.log(level, message or event, extra=extra, exc_info=exc_info)
