#!/usr/bin/python3
"""Defines the User_keys model, storing cryptographic keys for users."""

import models
from models.base_model import BaseModel, Base
from sqlalchemy import Column, String, ForeignKey, BLOB


class User_keys(BaseModel, Base):
    """Representation of user cryptographic keys."""
    if models.storage_t == 'db':
        __tablename__ = 'user_keyss'
        user_id = Column(String(60), ForeignKey('users.id'), nullable=False, unique=True)
        private_key = Column(String(4096), nullable=False)
        public_key = Column(String(4096), nullable=False)
        shared_key = Column(BLOB, nullable=True)
    else:
        user_id = ""
        private_key = ""
        public_key = ""
        shared_key = ""

    def __init__(self, *args, **kwargs):
        """initializes user"""
        super().__init__(*args, **kwargs)
