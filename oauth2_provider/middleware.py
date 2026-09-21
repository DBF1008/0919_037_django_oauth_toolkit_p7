import hashlib
import logging
import uuid

from django.contrib.auth import authenticate
from django.utils.cache import patch_vary_headers

from oauth2_provider.log_utils import bind_log_context, reset_log_context
from oauth2_provider.models import get_access_token_model
from oauth2_provider.settings import oauth2_settings


log = logging.getLogger("oauth2_provider")

DEFAULT_REQUEST_ID_HEADER = "HTTP_X_REQUEST_ID"


class RequestIDMiddleware:
    """
    Middleware that assigns a request ID to every request and exposes it to
    the structured logging context.

    If the incoming request carries a request ID header (``X-Request-ID`` by
    default, configurable through ``REQUEST_ID_HEADER``), its value is reused
    so that IDs can be propagated across services. Otherwise a random UUID4 is
    generated. The ID is:

    * stored on ``request.request_id``,
    * pushed into the structured logging context (``request_id`` field), and
    * echoed back to the client through the response header.

    The context-var based context is always reset once the response has been
    produced, so IDs never leak between requests regardless of thread reuse.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def _get_header_name(self):
        return getattr(oauth2_settings, "REQUEST_ID_HEADER", DEFAULT_REQUEST_ID_HEADER)

    def __call__(self, request):
        header_name = self._get_header_name()
        request_id = request.META.get(header_name) or uuid.uuid4().hex
        request.request_id = request_id
        bind_log_context(request_id=request_id)

        try:
            response = self.get_response(request)
            response[header_name.replace("HTTP_", "").replace("_", "-").title()] = request_id
            return response
        finally:
            reset_log_context()


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
            except AccessToken.DoesNotExist as e:
                log.exception("OAuth2 access token not found", exc_info=e)
        response = self.get_response(request)
        return response
