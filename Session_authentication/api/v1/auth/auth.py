#!/usr/bin/env python3
"""
Auth class module
"""
from flask import request
from typing import List, TypeVar


class Auth:
    """
    Template class for authentication systems
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Checks if authentication is required for a given path.
        """
        if path is None:
            return True
        if excluded_paths is None or not excluded_paths:
            return True

        # Slash tolerance: ensure path ends with a slash for comparison
        if not path.endswith('/'):
            path += '/'

        if path in excluded_paths:
            return False

        return True

    def authorization_header(self, request=None) -> str:
        """
        Retrieves the authorization header from the request.
        """
        if request is None:
            return None

        # request.headers.get returns None if the key doesn't exist
        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieves the current user from the request.
        Returns:
          - None (for now)
        """
        return None

    def session_cookie(self, request=None):
        """
        Returns a cookie value from a request
        """
        if request is None:
            return None

        from os import getenv
        session_name = getenv('SESSION_NAME', '_my_session_id')
        return request.cookies.get(session_name)
