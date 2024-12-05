#!/usr/bin/python3
"""Defines the Message model for storing encrypted messages between users."""

import models
from models.base_model import BaseModel, Base
from sqlalchemy import Column, String, ForeignKey


class Message(BaseModel, Base):
    """Representation of encrypted messages between users."""
    if models.storage_t == 'db':
        __tablename__ = 'messages'
        sender_id = Column(String(60), ForeignKey('users.id'), nullable=False)
        recipient_id = Column(String(60), ForeignKey('users.id'), nullable=False)
        ciphertext = Column(String(4096), nullable=False)
        iv = Column(String(128), nullable=False)
        encrypted_key = Column(String(4096), nullable=False)
    else:
        sender_id = ""
        recipient_id = ""
        ciphertext = ""
        iv = ""
        encrypted_key = ""

    def __init__(self, *args, **kwargs):
        """initializes user"""
        super().__init__(*args, **kwargs)
