#!/usr/bin/env python3
"""module for authentication"""
import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4


def _hash_password(password: str) -> bytes:
    """Hash password to bytes"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def _generate_uuid() -> str:
    """returns a string representation of a new UUID"""
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Register a new user"""
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            hashed_password = _hash_password(password)
            new_user = self._db.add_user(email, hashed_password)
            return new_user
        # if there's a result for the email then raise value errorregister
        raise ValueError(f"User {email} already exists")

    def valid_login(self, email: str, password: str) -> bool:
        """Check for valid login credentials"""
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False
        pwd_bytes = password.encode()
        if bcrypt.checkpw(pwd_bytes, user.hashed_password) is True:
            return True
        return False

    def create_session(self, email: str) -> str:
        """Create a session and return the session_id"""
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None
        session_id = _generate_uuid()
        user.session_id = session_id
        try:
            self._db.update_user(user.id, session_id=session_id)
        except ValueError:
            return None
        return session_id

    def get_user_from_session_id(self, session_id: str) -> User:
        """Find and return user from a session"""
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None
        return user

    def destroy_session(self, user_id: int) -> str:
        """Destroy a user session and return None"""
        try:
            user = self._db.find_user_by(id=user_id)
        except NoResultFound:
            return None
        # session_id = _generate_uuid()
        # user.session_id = session_id
        try:
            self._db.update_user(user.id, session_id=None)
        except ValueError:
            return None
        return None

    def get_reset_password_token(self, email: str) -> str:
        """return a resest token"""
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError
        reset_token = _generate_uuid()
        user.reset_token = reset_token
        try:
            self._db.update_user(user.id, reset_token=reset_token)
        except ValueError:
            return None
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """Update user password"""
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError
        hashed_password = _hash_password(password)
        try:
            self._db.update_user(user.id, hashed_password=hashed_password,
                                 reset_token=None)
        except ValueError:
            return ValueError
        return None
