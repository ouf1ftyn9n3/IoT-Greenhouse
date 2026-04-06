from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select

from ..config import Settings
from ..database import get_session
from ..models import User
from ..schemas import UserCreate, UserRead
from ..security import create_access_token, create_refresh_token, decode_refresh_token
from ..services.auth import authenticate_user, register_user

settings = Settings()
router = APIRouter(prefix="/auth", tags=["auth"])


@router.options("/register")
def register_options():
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, session: Session = Depends(get_session)) -> UserRead:
    try:
        user = register_user(session, payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return user


@router.options("/login")
def login_options():
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/login")
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session),
):
    """
        Аутентифицирует пользователя
        Args:
            form_data: данные формы
        Returns:
            dict: access токен, пользователь
            рефреш токен устанавливается в куку
    """
    user = authenticate_user(session, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )
    access_token = create_access_token(subject=user.email)
    refresh_token = create_refresh_token(subject=user.email)

    response = JSONResponse(content={
        "access_token": access_token,
        "token_type": "bearer",
        "user": UserRead.from_orm(user).dict(),
    })
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=settings.refresh_token_expire_minutes * 60,
        path="/auth",
    )
    return response

@router.post("/refresh")
def refresh(
    request: Request,
    session: Session = Depends(get_session),
):
    """
        Обновляет access токен и refresh токен
        Args:
            request: запрос
        Returns:
            dict: access токен, пользователь
            рефреш токен устанавливается в куку
    """
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token missing",
        )

    email = decode_refresh_token(refresh_token)
    user = session.exec(select(User).where(User.email == email)).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    new_access = create_access_token(subject=user.email)
    new_refresh = create_refresh_token(subject=user.email)

    response = JSONResponse(content={
        "access_token": new_access,
        "token_type": "bearer",
        "user": UserRead.from_orm(user).dict(),
    })
    response.set_cookie(
        key="refresh_token",
        value=new_refresh,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=settings.refresh_token_expire_minutes * 60,
        path="/auth",
    )
    return response


@router.post("/logout")
def logout():
    response = JSONResponse(content={"detail": "Logged out"})
    response.delete_cookie(key="refresh_token", path="/auth")
    return response
