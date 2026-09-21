class OAuthToolkitError(Exception):
    """
    Base class for exceptions
    """

    def __init__(self, error=None, redirect_uri=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.oauthlib_error = error

        if redirect_uri:
            self.oauthlib_error.redirect_uri = redirect_uri


class FatalClientError(OAuthToolkitError):
    """
    Class for critical errors caused by the client (e.g. a malicious
    redirect_uri or client_id). The client cannot recover by retrying the
    same request.
    """

    pass


class RecoverableError(OAuthToolkitError):
    """
    Class for transient errors (e.g. temporary unavailability of an upstream
    service) after which the client MAY retry the request. Mapped to an HTTP
    ``503 Service Unavailable`` response with the OAuth2
    ``temporarily_unavailable`` error code as per :rfc:`5.2.5`.
    """

    pass


class ServerError(OAuthToolkitError):
    """
    Class for unexpected server-side failures that are not the client's fault.
    Mapped to an HTTP ``500 Internal Server Error`` response with the OAuth2
    ``server_error`` error code as per :rfc:`5.2`.
    """

    pass


class OIDCError(Exception):
    """
    General class to derive from for all OIDC related errors.
    """

    status_code = 400
    error = None

    def __init__(self, description=None):
        if description is not None:
            self.description = description

        message = "({}) {}".format(self.error, self.description)
        super().__init__(message)


class InvalidRequestFatalError(OIDCError):
    """
    For fatal errors. These are requests with invalid parameter values, missing parameters or otherwise
    incorrect requests.
    """

    error = "invalid_request"


class ClientIdMissmatch(InvalidRequestFatalError):
    description = "Mismatch between the Client ID of the ID Token and the Client ID that was provided."


class InvalidOIDCClientError(InvalidRequestFatalError):
    description = "The client is unknown or no client has been included."


class InvalidOIDCRedirectURIError(InvalidRequestFatalError):
    description = "Invalid post logout redirect URI."


class InvalidIDTokenError(InvalidRequestFatalError):
    description = "The ID Token is expired, revoked, malformed, or otherwise invalid."


class LogoutDenied(OIDCError):
    error = "logout_denied"
    description = "Logout has been refused by the user."
