
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from argon2 import PasswordHasher
import hashlib, secrets, time, redis, jwt, pyotp
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import datetime, timedelta
import httpx
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import os

SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./vault.db")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost")

app = FastAPI(title="Feranmi VaultGuard Pro API", version="11.0") # ← Your name here
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
r = redis.from_url(REDIS_URL, decode_responses=True)
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class AuditLog(Base):
    __tablename__ = "audits"
    id = Column(Integer, primary_key=True)
    ip = Column(String)
    password_sha256 = Column(String)
    score = Column(Integer)
    entropy = Column(Integer)
    breached = Column(Boolean)
    timestamp = Column(DateTime, default=datetime.utcnow)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True)
    password_hash = Column(String)
    totp_secret = Column(String)
    failed_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime)

Base.metadata.create_all(engine)

class PasswordCheck(BaseModel):
    password: str

class UserRegister(BaseModel):
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str
    totp: str

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def check_breach(password: str) -> tuple[bool, int]:
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    cached = r.get(f"hibp:{prefix}")
    if cached:
        lines = cached.split('\n')
    else:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
            lines = resp.text.split('\n')
            r.setex(f"hibp:{prefix}", 86400, resp.text)
    for line in lines:
        if line.startswith(suffix):
            return True, int(line.split(':')[1])
    return False, 0

def calculate_entropy(p: str) -> int:
    charset = 0
    if any(c.islower() for c in p): charset += 26
    if any(c.isupper() for c in p): charset += 26
    if any(c.isdigit() for c in p): charset += 10
    if any(not c.isalnum() for c in p): charset += 33
    return int(len(p) * (charset.bit_length() if charset else 0))

@app.post("/api/v11/check")
@limiter.limit("20/minute")
async def check_password(request: Request, data: PasswordCheck, db=Depends(get_db)):
    p = data.password
    if len(p) < 4: raise HTTPException(400, "Too short")
    start = time.perf_counter()
    score = 100
    deductions = []
    if len(p) < 20: score -= 60; deductions.append("-60: Below 20 chars CNSA 2.0")
    if len(p) < 32: score -= 40; deductions.append("-40: Below 32 chars Apocalypse")
    variety = sum([any(c.islower() for c in p), any(c.isupper() for c in p), any(c.isdigit() for c in p), any(not c.isalnum() for c in p)])
    score -= (4 - variety) * 25
    if any(word in p.lower() for word in ['password','123456','qwerty','admin','nigeria','lagos']):
        score -= 100; deductions.append("-100: Top breach dictionary")
    breached, count = await check_breach(p)
    if breached: score -= 100; deductions.append(f"-100: Breached {count:,} times")
    entropy = calculate_entropy(p)
    audit = AuditLog(ip=get_remote_address(request), password_sha256=hashlib.sha256(p.encode()).hexdigest(), score=max(0, score), entropy=entropy, breached=breached)
    db.add(audit)
    db.commit()
    return {
        "score": max(0, score), "entropy": entropy, "breached": breached, "breach_count": count,
        "deductions": deductions, "grade": "Ω" if score >= 99 else "A+" if score >= 95 else "A" if score >= 90 else "F",
        "crack_time_classical": f"{2**(entropy-1) / 1e20:.0e} years",
        "crack_time_quantum": f"{2**(entropy/2) / 1e20:.0e} years",
        "processing_time_ms": round((time.perf_counter() - start) * 1000, 2),
        "fips_140_3_l4": score >= 95, "cnsa_2_0_ts": score >= 99, "argon2id": True
    }

@app.post("/api/v11/register")
async def register(user: UserRegister, db=Depends(get_db)):
    if db.query(User).filter(User.email == user.email).first(): raise HTTPException(400, "Email exists")
    hashed = ph.hash(user.password)
    totp_secret = pyotp.random_base32()
    db_user = User(email=user.email, password_hash=hashed, totp_secret=totp_secret)
    db.add(db_user)
    db.commit()
    return {"msg": "Registered", "totp_secret": totp_secret, "totp_uri": pyotp.totp.TOTP(totp_secret).provisioning_uri(user.email, "Feranmi VaultGuard Pro")} # ← Your name here

@app.post("/api/v11/login")
async def login(data: UserLogin, db=Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if not user: raise HTTPException(401, "Invalid credentials")
    if user.locked_until and user.locked_until > datetime.utcnow(): raise HTTPException(423, f"Account locked until {user.locked_until}")
    try: ph.verify(user.password_hash, data.password)
    except:
        user.failed_attempts += 1
        if user.failed_attempts >= 5: user.locked_until = datetime.utcnow() + timedelta(minutes=15)
        db.commit()
        raise HTTPException(401, "Invalid credentials")
    if not pyotp.TOTP(user.totp_secret).verify(data.totp): raise HTTPException(401, "Invalid TOTP")
    user.failed_attempts = 0
    db.commit()
    token = jwt.encode({"sub": user.email, "exp": datetime.utcnow() + timedelta(hours=24)}, SECRET_KEY, algorithm="HS256")
    return {"token": token, "msg": "Login success"}

@app.get("/api/v11/health")
async def health(): return {"status": "ok", "version": "11.0", "owner": "Feranmi"} # ← Your name here
=======
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker
from passlib.hash import bcrypt

app = FastAPI()
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)
@app.get("/health")
def health_check():
    return {"status": "ok"}
    # Database setup
DATABASE_URL = "sqlite:///./users.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# User table
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)

Base.metadata.create_all(bind=engine)

# Pydantic models
class LoginData(BaseModel):
    email: str
    password: str

@app.post("/login")
def login(data: LoginData):
    db = SessionLocal()
    user = db.query(User).filter(User.email == data.email).first()

    if not user:
        db.close()
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not bcrypt.verify(data.password, user.hashed_password):
        db.close()
        raise HTTPException(status_code=401, detail="Invalid email or password")

    db.close()
    return {"email": user.email, "status": "logged in"}
class RegisterData(BaseModel):
    email: str
    password: str

@app.post("/register")
def register(data: RegisterData):
    db = SessionLocal()
    
    # Check if user already exists
    if db.query(User).filter(User.email == data.email).first():
        db.close()
        raise HTTPException(status_code=400, detail="Email already exists")
    
    # Hash password and create user
    hashed = bcrypt.hash(data.password)
    new_user = User(email=data.email, hashed_password=hashed)
    db.add(new_user)
    db.commit()
    db.close()
    return {"status": "registered", "email": data.email}
class PasswordCheck(BaseModel):
    password: str

@app.post("/api/v1/check")
async def check_password(data: PasswordCheck):
    password = data.password
    
    length = len(password)
    score = 0
    if length >= 8: score += 1
    if length >= 12: score += 1
    if any(c.isdigit() for c in password): score += 1
    if any(c.isupper() for c in password): score += 1
    if any(c.islower() for c in password): score += 1
    if any(not c.isalnum() for c in password): score += 1
    
    entropy = min(length * 4, 100)
    
    return {"score": score, "entropy": entropy}
