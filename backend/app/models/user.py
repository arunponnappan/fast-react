from sqlalchemy import Column, Integer, String, Enum, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from app.core.database import Base
import enum
from datetime import datetime

class UserRole(enum.Enum):
    ADMIN = "ADMIN"
    STAFF = "STAFF"
    MEMBER = "MEMBER"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(UserRole, native_enum=False), default=UserRole.MEMBER)  # ✅ Fix: Use uppercase MEMBER
    status = Column(String, default="Active")
    profile_picture = Column(String, default="default.jpg")
    activities = relationship("UserActivity", back_populates="user")


    # Activity Tracking
    last_login = Column(DateTime, nullable=True)
    last_logout = Column(DateTime, nullable=True)
    session_duration = Column(Integer, nullable=True)  # In seconds
    browser = Column(String, nullable=True)
    location = Column(String, nullable=True)

class UserActivity(Base):
    __tablename__ = "user_activities"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    login_time = Column(DateTime, default=datetime.utcnow)
    logout_time = Column(DateTime, nullable=True)
    session_duration = Column(Integer, nullable=True)
    browser = Column(String(255), nullable=True)
    location = Column(String(255), nullable=True)

    user = relationship("User", back_populates="activities")

activities = relationship("UserActivity", back_populates="user", cascade="all, delete-orphan")