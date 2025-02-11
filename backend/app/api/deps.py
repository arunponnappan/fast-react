from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.config import settings
from app.core.database import get_db
from app.models.user import User, UserRole
from app.schemas.auth import TokenPayload

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login")

async def get_current_user(db: AsyncSession = Depends(get_db), token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        token_data = TokenPayload(**payload)
        if token_data.type != "access":
            raise credentials_exception
    except JWTError:
        raise credentials_exception
        
    user = await db.get(User, int(token_data.sub))
    if not user:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    if current_user.status != "Active":
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

def check_admin_user(current_user: User = Depends(get_current_active_user)) -> User:
    if current_user.role != UserRole.admin:
        raise HTTPException(status_code=403, detail="User lacks admin privileges")
    return current_user

def check_staff_user(current_user: User = Depends(get_current_active_user)) -> User:
    if current_user.role not in [UserRole.admin, UserRole.staff]:
        raise HTTPException(status_code=403, detail="User lacks staff privileges")
    return current_user
