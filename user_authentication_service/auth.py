#!/usr/bin/env python3
"""
Auth module
"""

import bcrypt
import uuid
from sqlalchemy.orm.exc import NoResultFound
from db import DB
from user import User


def _hash_password(password: str) -> str:
    """
    Hashes a password with bcrypt and returns a salt hash string.
    """
    return bcrypt.hashpw(password.encode('utf-8'),
                         bcrypt.gensalt()).decode('utf-8')


def _generate_uuid() -> str:
    """
    Generates a UUID string.
    """
    return str(uuid.uuid4())


class Auth:
    """
    Auth class to interact with the authentication database.
    """

    def __init__(self):
        """Initialize the DB instance"""
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
        Registers a new user if it does not already exist.

        Raises:
            ValueError: If a user with the provided email already exists.
        """
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            hashed_password = _hash_password(password)
            return self._db.add_user(email, hashed_password)

    def valid_login(self, email: str, password: str) -> bool:
        """
        Validates whether the provided login credentials match the database.
        """
        try:
            user = self._db.find_user_by(email=email)
            return bcrypt.checkpw(password.encode('utf-8'),
                                  user.hashed_password.encode('utf-8'))
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """
        Creates a new session for the user mapped to the provided email.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None

        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)

        return session_id

    def get_user_from_session_id(self, session_id: str) -> User:
        """
        Locates the user mapping to a specific session ID.
        """
        if not session_id:
            return None
        try:
            return self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """
        Destroys a user's active session.
        """
        try:
            self._db.update_user(user_id, session_id=None)
        except NoResultFound:
            pass

    def get_reset_password_token(self, email: str) -> str:
        """
        Generates a token to safely update the password of a mapped user.

        Raises:
            ValueError: If the user doesn't exist.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError

        token = _generate_uuid()
        self._db.update_user(user.id, reset_token=token)

        return token

    def update_password(self, reset_token: str, password: str) -> None:
        """
        Updates the user's password mapped to the reset token.

        Raises:
            ValueError: If the token is invalid/doesn't match a user.
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError

        new_hash = _hash_password(password)
        self._db.update_user(user.id,
                             hashed_password=new_hash,
                             reset_token=None)