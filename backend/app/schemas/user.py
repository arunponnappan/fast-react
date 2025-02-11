from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from app.models.user import UserRole

class UserBase(BaseModel):
    email: EmailStr
    username: str

class UserCreate(UserBase):
    password: str
    role: Optional[UserRole] = UserRole.MEMBER

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    password: Optional[str] = None
    profile_picture: Optional[str] = None
    status: Optional[str] = None  # Active or Inactive

class UserInDBBase(UserBase):
    id: int
    status: str
    role: UserRole
    profile_picture: Optional[str] = None  # ✅ Allow None values

    class Config:
        from_attributes = True
        fields = {"hashed_password": {"exclude": True}}  # ✅ Exclude password field



class User(UserInDBBase):
    pass

class UserActivity(BaseModel):
    login_time: str
    logout_time: Optional[str] = None
    session_duration: Optional[int] = None
    browser: Optional[str] = None
    location: Optional[str] = None

class UserWithActivity(UserInDBBase):
    activities: list[UserActivity] = []

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class TokenPayload(BaseModel):
    sub: int
    exp: int
    type: str
