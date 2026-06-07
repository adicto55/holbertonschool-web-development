#!/usr/bin/env python3
"""
Auth module
"""
import bcrypt


def _hash_password(password: str) -> str:
    """
    Hashes a password using bcrypt.
    
    Args:
        password (str): The plaintext password to hash.
        
    Returns:
        str: The salted, hashed password as a string.
    """
    # bcrypt requires passwords to be encoded as bytes
    encoded_password = password.encode('utf-8')
    
    # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    hashed_bytes = bcrypt.hashpw(encoded_password, salt)
    
    # Return the string representation of the hash
    return hashed_bytes.decode('utf-8')