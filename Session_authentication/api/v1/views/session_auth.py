#!/usr/bin/env python3
""" Session Auth views
"""
from flask import request, jsonify, abort
from api.v1.views import app_views
from models.user import User
from os import getenv


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login():
    """ POST /api/v1/auth_session/login
    """
    # Get email and password from request
    email = request.form.get('email')
    password = request.form.get('password')

    # Validate email
    if email is None or email == "":
        return jsonify({"error": "email missing"}), 400

    # Validate password
    if password is None or password == "":
        return jsonify({"error": "password missing"}), 400

    # Search for user by email
    try:
        users = User.search({'email': email})
    except Exception:
        return jsonify({"error": "no user found for this email"}), 404

    if not users or len(users) == 0:
        return jsonify({"error": "no user found for this email"}), 404

    user = users[0]

    # Validate password
    if not user.is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401

    # Create session ID
    from api.v1.app import auth
    session_id = auth.create_session(user.id)

    # Create response with user JSON
    response = jsonify(user.to_json())

    # Set cookie with session ID
    session_name = getenv('SESSION_NAME', '_my_session_id')
    response.set_cookie(session_name, session_id)

    return response


@app_views.route('/auth_session/logout', methods=['DELETE'], strict_slashes=False)
def logout():
    """ DELETE /api/v1/auth_session/logout
    """
    from api.v1.app import auth

    if auth.destroy_session(request) is False:
        abort(404)

    return jsonify({}), 200
