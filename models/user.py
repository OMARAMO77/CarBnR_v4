#!/usr/bin/python3
""" holds class User"""

import models
from models.base_model import BaseModel, Base
from os import getenv
import sqlalchemy
from sqlalchemy import Column, String
from sqlalchemy.orm import relationship
from hashlib import md5


class User(BaseModel, Base):
    """Representation of a user """
    if models.storage_t == 'db':
        __tablename__ = 'users'
        email = Column(String(128), nullable=False, unique=True)
        password = Column(String(128), nullable=False)
        first_name = Column(String(128), nullable=True)
        last_name = Column(String(128), nullable=True)
        region = Column(String(128), nullable=True)
        phone_number = Column(String(128), nullable=True)
        reviews = relationship("Review", backref="user")
        bookings = relationship("Booking", backref="user")
        locations = relationship(
            "Location", backref="user", cascade="all, delete, delete-orphan"
        )
        user_keys = relationship(
            "User_keys", backref="user", cascade="all, delete, delete-orphan"
        )
        messages_sent = relationship(
            "Message",
            foreign_keys="Message.sender_id",
            back_populates="user_sender",
            overlaps="sent_messages,user_sender",
        )
        messages_received = relationship(
            "Message",
            foreign_keys="Message.recipient_id",
            back_populates="user_recipient",
            overlaps="received_messages,user_recipient",
        )
    else:
        email = ""
        password = ""
        first_name = ""
        last_name = ""
        region = ""
        phone_number = ""

    def __init__(self, *args, **kwargs):
        """initializes user"""
        super().__init__(*args, **kwargs)

    def __setattr__(self, name, value):
        """sets a password with md5 encryption"""
        if name == "password":
            value = md5(value.encode()).hexdigest()
        super().__setattr__(name, value)
