from pydantic import BaseModel, EmailStr
from datetime import datetime

# Registration request payload
class UserCreate(BaseModel):
    email: EmailStr
    password: str

# Login request payload
class UserLogin(BaseModel):
    email: EmailStr
    password: str

# API response payload (matches Chapter 7 spec & hides password_hash)
class UserResponse(BaseModel):
    id: int
    email: EmailStr
    created_at: datetime

    class Config:
        from_attributes = True

# JWT Token response structure
class Token(BaseModel):
    access_token: str
    token_type: str