from django.utils.translation import ugettext as _
from django_digest import HttpDigestAuthenticator
from rest_framework.authentication import (
    BaseAuthentication, get_authorization_header)
from rest_framework.exceptions import AuthenticationFailed


class DigestAuthentication(BaseAuthentication):
    def __init__(self):
        self.authenticator = HttpDigestAuthenticator()
	self.allow_thread_sharing = True

    def authenticate(self, request):
        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != b'digest':
            return None
	else:
	    return request.user, None

    def authenticate_header(self, request):
        response = self.authenticator.build_challenge_response()

        return response['WWW-Authenticate']
