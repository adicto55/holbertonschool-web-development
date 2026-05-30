#!/usr/bin/env python3
""" Init models package
"""
from models.user import User

User.load_from_file()
