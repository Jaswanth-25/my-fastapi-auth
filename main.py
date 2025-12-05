"""main.py - FastAPI auth with JWT + Reset Password + DEV reset-token output"""

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

# Load environment variables
load_dotenv()

# === CONFIG ===
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL missing")

# Render sometimes gives postgres:// without async, fix automatically
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+asyncpg://", 1)
elif DATABASE_URL.startswith("postgresql://") and "+asyncpg" not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY missing")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60 * 24 * 7))

ROOT_URL = os.getenv("ROOT_URL", "https://my-fastapi-app-b3zg.onrender.com").rstrip("/")

pwd_ctx = CryptContext(schemes=["argon2"], deprecated="auto")

engine = create_async_engine(DATABASE_URL, echo=False, future=True)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
Base = declarative_base()

# === DATABASE MODELS ===

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)

    reset_token = Column(String, nullable=True)
    reset_token_expiry = Column(DateTime, nullable=True)

    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


# === SCHEMAS ===

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
    token: str
    new_password: str = Field(..., min_length=6)


# === HELPERS ===

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session

def hash_password(password: str) -> str:
    return pwd_ctx.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_ctx.verify(password, hashed)

def generate_reset_token() -> str:
    return secrets.token_urlsafe(32)

def create_access_token(subject: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": subject, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/signin")

app = FastAPI(title="FastAPI Auth + Reset Password")


# === STARTUP ===

@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


# === ROUTES ===

@app.get("/")
def root():
    return {"status": "ok", "service": "FastAPI backend running"}


@app.post("/signup")
async def signup(payload: SignUp, db: AsyncSession = Depends(get_db)):
    validate_email(payload.email)

    q = await db.execute(select(User).where(User.email == payload.email.lower()))
    if q.scalar_one_or_none():
        raise HTTPException(400, "Email already registered")

    user = User(
        email=payload.email.lower(),
        hashed_password=hash_password(payload.password)
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    return {"message": "User created", "user_id": user.id}


@app.post("/signin", response_model=TokenOut)
async def signin(
    form: OAuth2PasswordRequestForm = Depends(None),
    body: SignInIn | None = None,
    db: AsyncSession = Depends(get_db)
):
    if form:
        email = form.username.lower()
        password = form.password
    elif body:
        email = body.email.lower()
        password = body.password
    else:
        raise HTTPException(400, "Missing credentials")

    q = await db.execute(select(User).where(User.email == email))
    user = q.scalar_one_or_none()

    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(401, "Incorrect email or password")

    token = create_access_token(user.email)
    return {"access_token": token, "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60}


@app.post("/forgot-password")
async def forgot_password(payload: ForgotPasswordIn, background: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    q = await db.execute(select(User).where(User.email == payload.email.lower()))
    user = q.scalar_one_or_none()

    if not user:
        return {"message": "If email exists, reset link sent"}

    token = generate_reset_token()
    expiry = datetime.utcnow() + timedelta(minutes=30)

    user.reset_token = token
    user.reset_token_expiry = expiry
    db.add(user)
    await db.commit()

    reset_link = f"{ROOT_URL}/reset?token={token}"

    def _print(link: str):
        print("PASSWORD RESET LINK (developer):", link)

    background.add_task(_print, reset_link)

    # DEV MODE ONLY — exposes token in response
    return {
        "message": "If email exists, reset link sent",
        "dev_reset_token": token
    }


@app.post("/reset-password")
async def reset_password(payload: ResetPasswordIn, db: AsyncSession = Depends(get_db)):
    q = await db.execute(select(User).where(User.reset_token == payload.token))
    user = q.scalar_one_or_none()

    if not user:
        return {"message": "If token is valid, password reset"}

    # Token expired?
    if not user.reset_token_expiry or user.reset_token_expiry < datetime.utcnow():
        user.reset_token = None
        user.reset_token_expiry = None
        await db.commit()
        return {"message": "If token is valid, password reset"}

    # Apply new password
    user.hashed_password = hash_password(payload.new_password)
    user.reset_token = None
    user.reset_token_expiry = None
    await db.commit()

    return {"message": "Password updated"}


# === CURRENT USER ===

async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
    except:
        raise HTTPException(401, "Invalid token")

    q = await db.execute(select(User).where(User.email == email))
    user = q.scalar_one_or_none()
    if not user:
        raise HTTPException(401, "Invalid token")

    return user


@app.get("/me")
async def me(user: User = Depends(get_current_user)):
    return {
        "id": user.id,
        "email": user.email,
        "created_at": str(user.created_at)
    }


# === LOCAL RUN ===

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)), reload=True)
