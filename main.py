"""main.py - FastAPI auth with JWT + Reset Password + DEV reset-token output
Enhanced: CORS, logging, optional SMTP send, DEV_MODE toggle, more robust signin handling.
"""

import os
import secrets
import logging
import smtplib
from datetime import datetime, timedelta
from typing import AsyncGenerator, Optional

from fastapi import (
    FastAPI,
    HTTPException,
    Depends,
    BackgroundTasks,
    status,
    Request,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
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

# -----------------------
# Config & Environment
# -----------------------
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

# Development mode: if true, endpoint returns the reset token in response (useful for testing).
DEV_MODE = os.getenv("DEV_MODE", "true").lower() in ("1", "true", "yes")

# Optional SMTP (if provided, we will attempt to send emails)
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587)) if os.getenv("SMTP_PORT") else None
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
EMAIL_FROM = os.getenv("EMAIL_FROM", "no-reply@example.com")

# -----------------------
# Logging
# -----------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("fastapi-auth")

# -----------------------
# Password hashing
# -----------------------
# Argon2 is secure but requires argon2-cffi installed. If you want bcrypt change here.
pwd_ctx = CryptContext(schemes=["argon2"], deprecated="auto")

# -----------------------
# Database
# -----------------------
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


# -----------------------
# Pydantic Schemas
# -----------------------
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


# -----------------------
# Helpers
# -----------------------
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session


def hash_password(password: str) -> str:
    return pwd_ctx.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return pwd_ctx.verify(password, hashed)
    except Exception:
        return False


def generate_reset_token() -> str:
    return secrets.token_urlsafe(32)


def create_access_token(subject: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": subject, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/signin")

app = FastAPI(title="FastAPI Auth + Reset Password")

# Allow CORS for testing; lock this down in production.
origins_env = os.getenv("CORS_ORIGINS", "*")
if origins_env.strip() == "":
    origins = ["*"]
elif origins_env.strip() == "*":
    origins = ["*"]
else:
    origins = [o.strip() for o in origins_env.split(",")]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------
# Startup: ensure tables
# -----------------------
@app.on_event("startup")
async def startup():
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables ensured")
    except Exception as e:
        logger.exception("Failed to initialize database: %s", e)
        raise


# -----------------------
# Email helper (optional)
# -----------------------
def send_reset_email_smtp(to_email: str, reset_link: str) -> None:
    """Simple SMTP send (no TLS/STARTTLS error handling here beyond basic)."""
    if not SMTP_HOST or not SMTP_PORT:
        raise RuntimeError("SMTP not configured")

    body = f"Subject: Password reset\n\nClick the link to reset your password:\n{reset_link}\n\nIf you didn't request this, ignore."
    try:
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10)
        server.starttls()
        if SMTP_USER and SMTP_PASS:
            server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(EMAIL_FROM, to_email, body)
        server.quit()
        logger.info("Sent reset email to %s", to_email)
    except Exception as e:
        logger.exception("Failed to send reset email: %s", e)
        # Don't raise — we don't want the API to fail just because email couldn't be sent.


# -----------------------
# Routes
# -----------------------
@app.get("/")
def root():
    return {"status": "ok", "service": "FastAPI backend running"}


@app.post("/signup")
async def signup(payload: SignUp, db: AsyncSession = Depends(get_db)):
    validate_email(payload.email)

    q = await db.execute(select(User).where(User.email == payload.email.lower()))
    if q.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    user = User(
        email=payload.email.lower(),
        hashed_password=hash_password(payload.password),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    return {"message": "User created", "user_id": user.id}


@app.post("/signin", response_model=TokenOut)
async def signin(request: Request, body: SignInIn | None = None, db: AsyncSession = Depends(get_db)):
    """
    Accepts either OAuth2 form-encoded (username/password) or JSON {email, password}.
    Returns a bearer access token on success.
    """
    # Detect form login (OAuth2 standard)
    form_email = None
    form_password = None
    content_type = request.headers.get("content-type", "")
    if content_type.startswith("application/x-www-form-urlencoded"):
        form = await request.form()
        form_email = form.get("username")
        form_password = form.get("password")

    if form_email and form_password:
        email = str(form_email).lower()
        password = str(form_password)
    elif body:
        email = body.email.lower()
        password = body.password
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing credentials")

    q = await db.execute(select(User).where(User.email == email))
    user = q.scalar_one_or_none()

    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")

    token = create_access_token(user.email)
    return {"access_token": token, "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60}


@app.post("/forgot-password")
async def forgot_password(payload: ForgotPasswordIn, background: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    q = await db.execute(select(User).where(User.email == payload.email.lower()))
    user = q.scalar_one_or_none()

    # Always respond with a generic message to avoid account enumeration
    if not user:
        logger.info("Password reset requested for non-existing email: %s", payload.email)
        return {"message": "If email exists, reset link sent"}

    token = generate_reset_token()
    expiry = datetime.utcnow() + timedelta(minutes=30)

    user.reset_token = token
    user.reset_token_expiry = expiry
    db.add(user)
    await db.commit()

    reset_link = f"{ROOT_URL}/reset?token={token}"

    # Print to logs (useful for Render logs)
    def _print(link: str):
        logger.info("PASSWORD RESET LINK (developer): %s", link)

    background.add_task(_print, reset_link)

    # Try sending email if SMTP is configured (non-blocking via background)
    if SMTP_HOST:
        background.add_task(send_reset_email_smtp, user.email, reset_link)

    # DEV MODE ONLY — exposes token in response (for testing on Render). Turn OFF in production.
    if DEV_MODE:
        return {
            "message": "If email exists, reset link sent",
            "dev_reset_token": token,
            "dev_reset_link": reset_link,
        }

    return {"message": "If email exists, reset link sent"}


@app.post("/reset-password")
async def reset_password(payload: ResetPasswordIn, db: AsyncSession = Depends(get_db)):
    q = await db.execute(select(User).where(User.reset_token == payload.token))
    user = q.scalar_one_or_none()

    # Generic response to avoid leaking token validity
    if not user:
        logger.info("Attempt to use invalid reset token: %s", payload.token[:8] + "...")
        return {"message": "If token is valid, password reset"}

    # Token expired?
    if not user.reset_token_expiry or user.reset_token_expiry < datetime.utcnow():
        logger.info("Reset token expired for user %s", user.email)
        user.reset_token = None
        user.reset_token_expiry = None
        await db.commit()
        return {"message": "If token is valid, password reset"}

    # Apply new password
    user.hashed_password = hash_password(payload.new_password)
    user.reset_token = None
    user.reset_token_expiry = None
    await db.commit()

    logger.info("Password updated for user %s", user.email)
    return {"message": "Password updated"}


# -----------------------
# Current user & /me
# -----------------------
async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    q = await db.execute(select(User).where(User.email == email))
    user = q.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return user


@app.get("/me")
async def me(user: User = Depends(get_current_user)):
    return {
        "id": user.id,
        "email": user.email,
        "created_at": str(user.created_at),
    }


# -----------------------
# Local run (development)
# -----------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)), reload=True)
