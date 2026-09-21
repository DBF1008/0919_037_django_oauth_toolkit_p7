.. _observability:

Error handling and structured logging
=====================================

Django OAuth Toolkit exposes a unified error handling and observability layer
so every OAuth/OIDC endpoint reacts to failures the same way and every log
line can be correlated to a request.

.. contents::
   :local:
   :depth: 2

Error hierarchy
---------------

All errors raised by the package derive from
``oauth2_provider.exceptions.OAuthToolkitError``:

* ``FatalClientError`` — the request itself is malformed or malicious (unknown
  client, forbidden redirect URI, ...). It is never redirected back to the
  client supplied ``redirect_uri`` and maps to an HTTP ``400`` response.
* ``RecoverableError`` — a transient failure (maintenance, temporary
  overloading). It maps to HTTP ``503 Service Unavailable`` with the
  ``temporarily_unavailable`` error code from :rfc:`5.2.3`; clients are
  expected to retry the unchanged request later.
* ``ServerError`` — an unexpected failure of the authorization server. It maps
  to HTTP ``500 Internal Server Error`` with the ``server_error`` error code
  from :rfc:`5.2`.

All responses produced from these errors follow the JSON format of :rfc:`5.2`
and carry the ``Cache-Control: no-store`` and ``Pragma: no-cache`` headers
required by :rfc:`5.1`.

Mapping errors to HTTP responses
--------------------------------

``OAuthLibMixin`` provides ``error_response_to_http`` which maps an
``OAuthToolkitError`` (or even a plain exception) to a standard
``HttpResponse``::

    from oauth2_provider.exceptions import RecoverableError, ServerError

    # Returns a 503 application/json response
    response = self.error_response_to_http(RecoverableError())

    # Returns a 500 application/json response
    response = self.error_response_to_http(ServerError(description="database is down"))

The token, revocation, device authorization and userinfo endpoints use the
shared ``build_oauth_http_response`` helper. It accepts the tuple returned by
the OAuthLib backend and safely handles JSON bodies, empty bodies (the
revocation endpoint returns an empty body on success, see :rfc:`2.2`) and
unexpected non-JSON payloads instead of letting ``json.loads`` raise.

If an OAuthLib endpoint raises something that is not an ``OAuth2Error``,
``OAuthLibCore`` now catches it, logs a structured ``*_failure`` event and
returns a ``server_error`` tuple rather than propagating a crash to the WSGI
handler.

Request IDs
-----------

Add the middleware near the top of ``MIDDLEWARE`` so it wraps every
request::

    MIDDLEWARE = [
        "oauth2_provider.middleware.RequestIDMiddleware",
        # ...
    ]

For each request the middleware:

* reuses the inbound ``X-Request-ID`` header when it is present and well
  formed (ASCII letters, digits, ``.``, ``_`` and ``-``, up to 128
  characters), otherwise generates a UUID4;
* stores the identifier on ``request.request_id``;
* stores it in a :mod:`contextvars` variable so log lines emitted during the
  request — including code without access to the Django request — carry the
  same value;
* echoes it back on the response ``X-Request-ID`` header;
* always clears the context afterwards to avoid leaking identifiers between
  requests served by the same worker.

Structured logging
------------------

Every log emitted through the ``oauth2_provider`` logger is enriched with the
standard fields:

* ``request_id``
* ``client_id``
* ``grant_type``
* ``user_id``

The fields live in :mod:`contextvars`; they are bound automatically by the
OAuthLib backend (from the raw request) and refined by the validator once the
client and resource owner are known. Failed authentications log a machine
readable event and a ``reason`` (for example ``invalid_base64``,
``unknown_client``, ``invalid_client_secret``). Client secrets and passwords
are never written to the logs.

You can bind fields manually, for example from custom views or validators::

    from oauth2_provider.logging_utils import bind_log_context, log_context

    bind_log_context(client_id="my-client", grant_type="client_credentials")

    # or, scoped to a block:
    with log_context(user_id="alice"):
        ...

Events are emitted with :func:`log_event`::

    import logging
    from oauth2_provider.logging_utils import get_oauth_logger, log_event

    log_event(
        get_oauth_logger(),
        logging.WARNING,
        "my_custom_event",
        "Human readable message",
        reason="something-happened",
    )

Text rendering
~~~~~~~~~~~~~~

``ContextFormatter`` appends the context fields to the classic logging
output::

    WARNING Token request rejected: invalid_client [client_id=abc grant_type=password request_id=f42...]

JSON rendering
~~~~~~~~~~~~~~

``StructuredFormatter`` renders one JSON object per line and is suitable for
log aggregation systems. Configure it through Django's ``LOGGING`` setting::

    LOGGING = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "oauth_structured": {
                "()": "oauth2_provider.logging_utils.StructuredFormatter",
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "oauth_structured",
            },
        },
        "loggers": {
            "oauth2_provider": {
                "handlers": ["console"],
                "level": "INFO",
                "propagate": False,
            },
        },
    }

Example output::

    {"timestamp": "2026-09-21 10:30:00,123", "level": "INFO", "message": "Token request succeeded", "logger": "oauth2_provider", "request_id": "f42c1b8e", "client_id": "abc123", "grant_type": "password", "user_id": "john", "event": "token_request_success"}

Log events
~~~~~~~~~~

The package emits the following machine readable events:

==============================  =====================================================
event                           meaning
==============================  =====================================================
``token_request_success``       a token request completed with HTTP 200
``token_request_error``         an OAuth error response was returned by the token endpoint
``token_request_failure``       an unexpected exception was caught on the token endpoint
``revocation_request_error``    an OAuth error response was returned on revocation
``revocation_request_failure``  an unexpected exception was caught on revocation
``device_authorization_error``  an OAuth error response was returned on device authorization
``device_authorization_failure`` unexpected exception on device authorization
``userinfo_request_error``      an OAuth error response was returned on userinfo
``userinfo_request_failure``    an unexpected exception was caught on userinfo
``client_auth_failed``          client authentication failed (see ``reason``)
``resource_owner_auth_failed``  resource owner password credentials were rejected
``invalid_json_body``           a request advertised a JSON body that could not be parsed
``introspection_request_failed`` the external introspection server could not be reached
``introspection_response_invalid`` the introspection server returned an unusable response
``access_token_invalid``        a presented access token could not be accepted
``authorization_code_invalid``  an authorization code was unknown or expired
``invalid_oauth_response_body`` an OAuth endpoint returned a non-JSON body unexpectedly
``fatal_client_oauth_error``    a fatal client error was mapped to an HTTP response
``recoverable_oauth_error``     a transient error was mapped to HTTP 503
``server_oauth_error``          a server error was mapped to HTTP 500
==============================  =====================================================
