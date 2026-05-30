#!/usr/bin/env python3
""" User module
"""
import hashlib
from models.base import Base


class User(Base):
    """ User class
    """
    def __init__(self, *args: list, **kwargs: dict):
        """ Initialize a User instance
        """
        super().__init__(*args, **kwargs)
        self.email = kwargs.get('email')
        self._password = kwargs.get('_password')
        self.first_name = kwargs.get('first_name')
        self.last_name = kwargs.get('last_name')

    @property
    def password(self) -> str:
        """ Getter for password
        """
        return self._password

    @password.setter
    def password(self, pwd: str):
        """ Setter for password
        """
        if pwd is None or type(pwd) is not str:
            self._password = None
        else:
            self._password = hashlib.md5(pwd.encode()).hexdigest()

    def is_valid_password(self, pwd: str) -> bool:
        """ Validate password
        """
        if pwd is None or type(pwd) is not str:
            return False
        if self.password is None:
            return False
        return hashlib.md5(pwd.encode()).hexdigest() == self.password

    def display_name(self) -> str:
        """ Display name
        """
        if self.email is None and self.first_name is None \
                and self.last_name is None:
            return ""
        if self.first_name is None and self.last_name is None:
            return "{}".format(self.email)
        if self.last_name is None:
            return "{}".format(self.first_name)
        if self.first_name is None:
            return "{}".format(self.last_name)
        else:
            return "{} {}".format(self.first_name, self.last_name)
