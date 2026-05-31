# stoken.py

import jwt

SECRET_KEY = "mysecretkey"

def endata(data):
    return jwt.encode(
        data,
        SECRET_KEY,
        algorithm="HS256"
    )

def dndata(token):
    return jwt.decode(
        token,
        SECRET_KEY,
        algorithms=["HS256"]
    )