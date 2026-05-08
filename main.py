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
    allow_methods=["*"],
    allow_headers=["*"],
)
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