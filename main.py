"""main.py - FastAPI auth with JWT (env-configured) + reset-password endpoint
(keeps config via env; ready for Render; includes GET /, /signup, /signin, /forgot-password, /reset-password, /me)
"""
import os
import secrets
from datetime import datetime, timedelta
from typing import AsyncGenerator, Optional

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import Column, Integer, String, Boolean, DateTime, select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from passlib.context import CryptContext
from email_validator import validate_email
from dotenv import load_dotenv
from jose import jwt, JWTError

load_dotenv(override=False)

# CONFIG
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("Set DATABASE_URL in environment (e.g. postgresql+asyncpg://user:pass@host:port/db)")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+asyncpg://", 1)
elif DATABASE_URL.startswith("postgresql://") and "+asyncpg" not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("Set SECRET_KEY in environment (a long random string)")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60 * 24 * 7))
ROOT_URL = os.getenv("ROOT_URL", "http://localhost:8000").rstrip("/")

pwd_ctx = CryptContext(schemes=["argon2"], deprecated="auto")

engine = create_async_engine(DATABASE_URL, echo=False, future=True)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)
    reset_token = Column(String, nullable=True)
    reset_token_expiry = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class SignUp(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6)

class SignInIn(BaseModel):
    email: EmailStr
    password: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: Optional[int] = None

class ForgotPasswordIn(BaseModel):
    email: EmailStr

class ResetPasswordIn(BaseModel):
    token: str = Field(..., min_length=8)
    new_password: str = Field(..., min_length=6)

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session

def hash_password(password: str) -> str:
    return pwd_ctx.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_ctx.verify(password, hashed)

def generate_reset_token() -> str:
    return secrets.token_urlsafe(32)

def create_access_token(subject: str, expires_minutes: Optional[int] = None) -> str:
    to_encode = {"sub": subject}
    if expires_minutes is None:
        expires_minutes = ACCESS_TOKEN_EXPIRE_MINUTES
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/signin")

app = FastAPI(title="Auth (JWT) with Reset Password")

@app.on_event("startup")
async def startup_create_tables():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

@app.get("/")
async def root():
    return {"status": "ok", "service": "FastAPI backend is running"}

@app.post("/signup")
async def signup(payload: SignUp, db: AsyncSession = Depends(get_db)):
    try:
        validate_email(payload.email)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid email")

    q = await db.execute(select(User).where(User.email == payload.email.lower()))
    existing = q.scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = User(
        email=payload.email.lower(),
        hashed_password=hash_password(payload.password),
        created_at=datetime.utcnow()
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return {"message": "User created successfully", "user_id": new_user.id, "email": new_user.email}

@app.post("/signin", response_model=TokenOut)
async def signin(
    form_data: OAuth2PasswordRequestForm = Depends(None),
    body: SignInIn | None = None,
    db: AsyncSession = Depends(get_db)
):
    if form_data and form_data.username:
        email = form_data.username.lower()
        password = form_data.password
    elif body:
        email = body.email.lower()
        password = body.password
    else:
        raise HTTPException(status_code=400, detail="Missing credentials")

    q = await db.execute(select(User).where(User.email == email))
    user = q.scalar_one_or_none()

    auth_error = HTTPException(status_code=401, detail="Incorrect email or password")
    if not user:
        raise auth_error

    if not verify_password(password, user.hashed_password):
        raise auth_error

    if not user.is_active:
        raise HTTPException(status_code=400, detail="User is inactive")

    token = create_access_token(subject=user.email)
    return {"access_token": token, "token_type": "bearer", "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60}

@app.post("/forgot-password")
async def forgot_password(payload: ForgotPasswordIn, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    q = await db.execute(select(User).where(User.email == payload.email.lower()))
    user = q.scalar_one_or_none()

    generic_msg = {"message": "If the email exists, password reset instructions have been sent."}
    if not user:
        return generic_msg

    token = generate_reset_token()
    expiry = datetime.utcnow() + timedelta(minutes=30)

    user.reset_token = token
    user.reset_token_expiry = expiry
    db.add(user)
    await db.commit()

    reset_link = f"{ROOT_URL}/reset?token={token}"

    def _print_link(link: str):
        print("PASSWORD RESET LINK (developer):", link)

    background_tasks.add_task(_print_link, reset_link)
    return generic_msg

@app.post("/reset-password")
async def reset_password(payload: ResetPasswordIn, db: AsyncSession = Depends(get_db)):
    q = await db.execute(select(User).where(User.reset_token == payload.token))
    user = q.scalar_one_or_none()

    generic_msg = {"message": "If the token is valid, the password has been reset."}

    if not user:
        return generic_msg

    if not user.reset_token_expiry or user.reset_token_expiry < datetime.utcnow():
        user.reset_token = None
        user.reset_token_expiry = None
        db.add(user)
        await db.commit()
        return generic_msg

    user.hashed_password = hash_password(payload.new_password)
    user.reset_token = None
    user.reset_token_expiry = None
    db.add(user)
    await db.commit()
    return generic_msg

async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    q = await db.execute(select(User).where(User.email == email.lower()))
    user = q.scalar_one_or_none()
    if user is None:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return user

@app.get("/me")
async def read_me(current_user: User = Depends(get_current_user)):
    return {"id": current_user.id, "email": current_user.email, "created_at": current_user.created_at.isoformat()}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
