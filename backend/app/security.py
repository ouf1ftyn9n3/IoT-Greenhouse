from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlmodel import Session, select

from .config import Settings
from .database import get_session
from .models import User

settings = Settings()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(subject: str, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = {"sub": subject, "type": "access"}
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.jwt_secret, algorithm=settings.jwt_algorithm)

def create_refresh_token(subject: str, expires_delta: Optional[timedelta] = None) -> str:
    """
        Создает refresh токен для обновления access токена
        Args:
            subject: email пользователя
            expires_delta: время жизни токена
        Returns:
            str: refresh токен
    """
    to_encode = {"sub": subject, "type": "refresh"}
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=settings.refresh_token_expire_minutes)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.jwt_secret, algorithm=settings.jwt_algorithm)

def decode_access_token(token: str) -> str:
    try:
        payload = jwt.decode(
            token, settings.jwt_secret, algorithms=[settings.jwt_algorithm]
        )
        if payload.get("type") != "access":
            raise JWTError("Token is not an access token")
        subject: Optional[str] = payload.get("sub")
        if subject is None:
            raise JWTError("Subject not found in token")
        return subject
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    
def decode_refresh_token(token: str) -> str:
    """
        Декодирует refresh токен и возвращает email пользователя
        Args:
            token: refresh токен
        Returns:
            str: email пользователя
    """
    try:
        payload = jwt.decode(
            token, settings.jwt_secret, algorithms=[settings.jwt_algorithm]
        )
        subject: Optional[str] = payload.get("sub")
        if subject is None:
            raise JWTError("Subject not found in token")
        if payload.get("type") != "refresh":
            raise JWTError("Token is not a refresh token")
        return subject
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def _get_user_by_email(session: Session, email: str) -> User | None:
    statement = select(User).where(User.email == email)
    return session.exec(statement).first()


def get_current_user(
    token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)
) -> User:
    email = decode_access_token(token)
    user = _get_user_by_email(session, email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found for provided token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user
