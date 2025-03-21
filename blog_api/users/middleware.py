from rest_framework_simplejwt.tokens import UntypedToken
from rest_framework.exceptions import AuthenticationFailed

class JWTAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        auth = request.headers.get('Authorization')
        if auth:
            try:
                token = auth.split(' ')[1]
                UntypedToken(token) 
            except Exception:
                raise AuthenticationFailed('Invalid token')

        response = self.get_response(request)
        return response
