# stoken.py

import jwt

SECRET_KEY = "mysecretkey"


def endata(data):

    # if plain string/email passed
    if isinstance(data, str):

        payload = {
            "email": data
        }

    else:
        # existing dict logic
        payload = data

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm="HS256"
    )


def dndata(token):

    return jwt.decode(
        token,
        SECRET_KEY,
        algorithms=["HS256"]
    )