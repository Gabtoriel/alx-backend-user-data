#!/usr/bin/env python3
"""Basic flask app"""
from flask import Flask, jsonify, request, abort, redirect, url_for
from auth import Auth


app = Flask(__name__)
AUTH = Auth()


@app.route("/", methods=["GET"])
def index():
    """Index route for the app"""
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"])
def register():
    """Register a new user"""
    data = request.form
    email = data.get("email", None)
    password = data.get("password", None)
    try:
        AUTH.register_user(email, password)
    except ValueError:
        return jsonify({"message": "email already registered"}), 400

    return jsonify({"email": f"{email}", "message": "user created"})


@app.route("/sessions", methods=["POST"])
def login():
    """Logs in and creates a new session for a user"""
    data = request.form
    email = data.get("email", None)
    password = data.get("password", None)
    try:
        assert email is not None
        assert password is not None
    except AssertionError:
        abort(401)
    if not AUTH.valid_login(email, password):
        abort(401)
    session_id = AUTH.create_session(email)
    if session_id is None:
        abort(401)
    response = jsonify({"email": f"{email}", "message": "logged in"})
    response.set_cookie("session_id", session_id)
    return response


@app.route("/sessions", methods=["DELETE"])
def delete_session():
    """Logout a logged in user"""
    if request.method == "DELETE":
        session_id = request.cookies.get("session_id")
        user = AUTH.get_user_from_session_id(session_id)
        if user is None:
            abort(403)
        AUTH.destroy_session(user.id)

    return redirect(url_for('index'))


@app.route("/profile", methods=["GET"])
def profile():
    """profile of a logged in user"""
    session_id = request.cookies.get("session_id", None)
    if session_id is None:
        abort(403)
    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        abort(403)

    return jsonify({"email": f"{user.email}"})


@app.route("/reset_password", methods=["POST"])
def reset_password():
    """password reset for a user"""
    email = request.form.get("email", None)

    try:
        reset_token = AUTH.get_reset_password_token(email)
    except ValueError:
        abort(403)
    return jsonify({"email": f"{email}", "reset_token": f"{reset_token}"}), 200


@app.route("/reset_password", methods=["PUT"])
def update_password():
    """reset token for password reset"""
    data = request.form
    email = data.get("email", None)
    new_password = data.get("new_password", None)
    reset_token = data.get("reset_token", None)

    try:
        reset_token = AUTH.update_password(reset_token, new_password)
    except ValueError:
        abort(403)
    return jsonify({"email": f"{email}", "message": "Password updated"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
