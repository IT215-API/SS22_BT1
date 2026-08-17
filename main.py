import os
from datetime import datetime, timedelta

import bcrypt
import jwt
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field

# 1. Load environment variables
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")  # Default to HS256 if not set

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is not set in the .env file. Please create one based on .env.example")

ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI(title="DevConnect Authentication System")

# In-memory "database" for demonstration purposes
# In a real application, this would be a proper database (e.g., PostgreSQL, MongoDB)
USERS_DB = {}  # {username: hashed_password}

# Pydantic models for request bodies
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

# --- JWT Utility Functions ---
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    # Add standard JWT claims
    to_encode.update({"exp": expire, "iat": datetime.utcnow(), "sub": data.get("username")})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

# --- Dependency for protected routes ---
async def get_current_user(token: str = Depends(oauth2_scheme)):
    return decode_access_token(token)

# --- API Endpoints ---

@app.post("/api/register", summary="Register a new user", status_code=status.HTTP_201_CREATED)
async def register_user(user: UserCreate):
    if user.username in USERS_DB:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )

    # Generate a random salt and hash password using bcrypt
    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())
    USERS_DB[user.username] = hashed_password.decode('utf-8') # Store as UTF-8 string
    return {"message": "User registered successfully"}

@app.post("/api/login", response_model=Token, summary="Login user and get access token")
async def login_for_access_token(user_data: UserLogin):
    stored_hashed_password = USERS_DB.get(user_data.username)

    if not stored_hashed_password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",  # Generic message for security
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Verify password with bcrypt
    # bcrypt.checkpw handles both the salt extraction and hashing for comparison
    if not bcrypt.checkpw(user_data.password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",  # Generic message for security
            headers={"WWW-Authenticate": "Bearer"},
        )

    # If credentials are correct, create an Access Token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"username": user_data.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/api/profile", summary="Get user profile (protected route)")
async def read_users_me(current_username: str = Depends(get_current_user)):
    # If we reach here, the token is valid and current_username contains the username from the JWT
    return {"message": f"Welcome, {current_username}!"}

# Optional: Root endpoint for basic check
@app.get("/")
async def root():
    return {"message": "DevConnect Auth System is running! Access /docs for API documentation."}