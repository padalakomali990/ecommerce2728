import re

def validate_username(username):
    return bool(username)

def validate_email(email):

    email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'

    return bool(
        re.match(email_pattern, email)
    )

def validate_password(password):

    return len(password) >= 6