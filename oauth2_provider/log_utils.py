"""
Structured logging support for django-oauth-toolkit.

Every log record emitted by the package is enriched with the following fields
(when available), so deployments can correlate token endpoint activity across
logs:

* ``client_id``: OAuth2 client identifier extracted from the request.
* ``grant_type``: OAuth2 grant type of the current request.
* ``user_id``: primary key of the resource owner (if authenticated).
* ``request_id``: unique identifier of the current request (see
  :class:`oauth2_provider.middleware.RequestIDMiddleware`).

Context is stored in :class:`contextvars.ContextVar` so it works both with
synchronous Django views and asynchronous code, without relying on a mutable
thread-local.
"""

import logging
from contextvars import ContextVar


log = logging.getLogger("oauth2_provider")

#: Fields automatically attached to every structured log record.
STRUCTURED_LOG_FIELDS = ("client_id", "grant_type", "user_id", "request_id")

#: Request-scoped log context. Reset to an empty mapping at the end of a request.
_log_context = ContextVar("oauth2_provider_log_context", default={})


def bind_log_context(**fields):
    """
    Merge ``fields`` into the request-scoped log context.

    ``None`` values are ignored so callers can blindly pass attributes that may
    not be present on the oauthlib request.
    """
    current = dict(_log_context.get())
    for key in STRUCTURED_LOG_FIELDS:
        value = fields.get(key)
        if value is not None:
            current[key] = value
    _log_context.set(current)


def reset_log_context():
    """
    Clear the request-scoped log context.
    """
    _log_context.set({})


def get_log_context():
    """
    Return a copy of the current structured log context.
    """
    return dict(_log_context.get())


def update_log_context_from_request(request):
    """
    Populate the structured log context from an oauthlib or Django request.

    The method is tolerant of partially built requests: attributes that are not
    available are simply skipped.
    """
    fields = {}

    client_id = getattr(request, "client_id", None)
    if not client_id:
        client = getattr(request, "client", None)
        client_id = getattr(client, "client_id", None)
    if client_id:
        fields["client_id"] = client_id

    grant_type = getattr(request, "grant_type", None)
    if grant_type:
        fields["grant_type"] = grant_type

    user = getattr(request, "user", None)
    user_id = getattr(user, "pk", None) or getattr(user, "id", None)
    if user_id is not None:
        fields["user_id"] = user_id

    request_id = getattr(request, "request_id", None)
    if request_id:
        fields["request_id"] = request_id

    if fields:
        bind_log_context(**fields)


class StructuredLogFilter(logging.Filter):
    """
    Ensure every record of the ``oauth2_provider`` logger carries the structured
    fields, defaulting missing ones to ``None``.
    """

    def filter(self, record):
        context = _log_context.get()
        for field in STRUCTURED_LOG_FIELDS:
            if not hasattr(record, field):
                setattr(record, field, context.get(field))
        return True


def log_event(level, event, **fields):
    """
    Emit a structured log event.

    :param level: logging level name (``"debug"``, ``"info"``, ``"warning"``,
        ``"error"`` or ``"exception"``) or a numeric level.
    :param event: human readable message describing the event.
    :param fields: extra keyword arguments are rendered as ``key=value`` pairs
        and passed as ``extra`` context to the logger.
    """
    context = get_log_context()
    extra = dict(context)

    parts = []
    for key, value in fields.items():
        if key == "exc_info":
            continue
        parts.append("{}={!r}".format(key, value))
        extra[key] = value

    message = event
    if parts:
        message = "{} ({})".format(event, ", ".join(parts))

    if level == "exception" or level == logging.ERROR:
        log.log(
            logging.ERROR if level == "exception" else level,
            message,
            extra=extra,
            exc_info=fields.get("exc_info", level == "exception"),
        )
    else:
        numeric_level = level if isinstance(level, int) else logging.getLevelName(level.upper())
        log.log(numeric_level, message, extra=extra)
