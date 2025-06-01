from fastapi import Request, HTTPException, status
from sqlmodel import SQLModel, Field
from typing import Optional
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import jwt, JWTError

import os
from dotenv import load_dotenv

load_dotenv()

# from the terminal: openssl rand -hex 32
# this generates an SSL private key for our SECRET_KEY
# the secret key and algorithm are combined and encoded with user information in the create_access_token function
# The create_access_token function is in the get_current_user function
SECRET_KEY = os.getenv('SECRET')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ----------------
# Authentication Table User Model
#-----------------
class User(SQLModel, table=True):
    __tablename__ = "user_identity"
    id: Optional[int] = Field(primary_key=True, index=True)
    username: str = Field(unique=True, index=True)
    email: Optional[str] = Field(unique=True)
    full_name: Optional[str] = Field(default=None)
    is_active: bool = Field(default=True)
    hashed_password: str

# ----------------
# User Schema Model
# -----------------
class CreateUser(SQLModel):
    username: str
    email: str
    full_name: str
    password: str

# --------------------------------------
# Response Model for the /token endpoint
# --------------------------------------
class Token(SQLModel):
    access_token: str
    token_type: str

# -----------------------
# OAuth form requirement (email and password) transferred to html form requirement (username and password)
# -----------------------
class LoginForm:
    def __init__(self, request: Request):
        self.request: Request = request
        self.username: Optional[str] = None
        self.password: Optional[str] = None

    async def create_oauth_form(self):
        form = await self.request.form()
        self.username = form.get("email")
        self.password = form.get("password")



# --------------------------
# Password Hashing Functions
# --------------------------
def get_password_hash(password):
    return bcrypt_context.hash(password)
def verify_password(plain_password, hashed_password):
    return bcrypt_context.verify(plain_password, hashed_password)

# ------------------------------------------
# Authentication and Authorization Functions
# ------------------------------------------

# These functions are both called by the /token endpoint
# 1. authenticate_user
# 2. create_access_token creates an access token - if the user is successfully authenticated
def authenticate_user(username: str, password: str, session):
    user = session.query(User).filter(User.username == username).first()
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(username: str, user_id: int, expires_delta: Optional[timedelta] = None):
    encode = {'sub': username, "id": user_id}
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    encode.update({'exp': expire})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)


# --------------------------------------------------------------------
# get_current_user decodes the JWT for resource endpoint authorization
# --------------------------------------------------------------------

async def get_current_user(request:Request):
    try:
        token = request.cookies.get("access_token")  # get JWT from browser
        if token is None:
            return None
        payload = jwt.decode(token, SECRET_KEY, ALGORITHM)
        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        if username is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate user.")
        return {'username': username, 'id': user_id}   # where does this go?
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate user.")