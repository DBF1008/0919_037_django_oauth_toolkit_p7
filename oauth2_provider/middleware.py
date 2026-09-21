import hashlib
import re
import uuid

from django.contrib.auth import authenticate
from django.utils.cache import patch_vary_headers

from oauth2_provider.logging_utils import (
    REQUEST_ID_HEADER,
    bind_log_context,
    get_oauth_logger,
    reset_log_context,
)
from oauth2_provider.models import get_access_token_model


log = get_oauth_logger("oauth2_provider")

#: Response header used to echo the request identifier back to the client.
REQUEST_ID_RESPONSE_HEADER = "X-Request-ID"

# Request identifiers are opaque tokens but must be safe to log and echo in a
# response header, so restrict them to a conservative character set.
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class RequestIDMiddleware:
    """
    Attach a request identifier to every request.

    The identifier is taken from the incoming ``X-Request-ID`` header when it
    is present and well formed, otherwise a new UUID4 is generated. It is:

    * exposed on ``request.request_id`` and the response ``X-Request-ID``
      header;
    * stored in a :mod:`contextvars` variable so every log emitted while the
      request is handled carries the same ``request_id`` field, including logs
      produced in background code that never sees the Django request object.

    The context is always reset in a ``finally`` block to avoid leaking the
    identifier onto other requests handled by the same worker.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request_id = request.META.get(REQUEST_ID_HEADER)
        if not request_id or not _REQUEST_ID_RE.match(request_id):
            request_id = uuid.uuid4().hex
        request.request_id = request_id
        bind_log_context(request_id=request_id)
        try:
            response = self.get_response(request)
        finally:
            reset_log_context()
        response[REQUEST_ID_RESPONSE_HEADER] = request_id
        return response


class OAuth2TokenMiddleware:
    """
    Middleware for OAuth2 user authentication

    This middleware is able to work along with AuthenticationMiddleware and its behaviour depends
    on the order it's processed with.

    If it comes *after* AuthenticationMiddleware and request.user is valid, leave it as is and does
    not proceed with token validation. If request.user is the Anonymous user proceeds and try to
    authenticate the user using the OAuth2 access token.

    If it comes *before* AuthenticationMiddleware, or AuthenticationMiddleware is not used at all,
    tries to authenticate user with the OAuth2 access token and set request.user field. Setting
    also request._cached_user field makes AuthenticationMiddleware use that instead of the one from
    the session.

    It also adds "Authorization" to the "Vary" header, so that django's cache middleware or a
    reverse proxy can create proper cache keys.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # do something only if request contains a Bearer token
        if request.META.get("HTTP_AUTHORIZATION", "").startswith("Bearer"):
            if not hasattr(request, "user") or request.user.is_anonymous:
                user = authenticate(request=request)
                if user:
                    request.user = request._cached_user = user

        response = self.get_response(request)
        patch_vary_headers(response, ("Authorization",))
        return response


class OAuth2ExtraTokenMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        authheader = request.META.get("HTTP_AUTHORIZATION", "")
        splits = authheader.split(maxsplit=1)
        if authheader.startswith("Bearer") and len(splits) == 2:
            tokenstring = splits[1]
            AccessToken = get_access_token_model()
            try:
                token_checksum = hashlib.sha256(tokenstring.encode("utf-8")).hexdigest()
                token = AccessToken.objects.get(token_checksum=token_checksum)
                request.access_token = token
            except AccessToken.DoesNotExist:
                log.debug("Bearer token not found while attaching the token to the request")
        response = self.get_response(request)
        return response
