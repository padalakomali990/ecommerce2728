import secrets

def genotp():
    """
    Generate secure 6 digit OTP
    """
    return str(secrets.randbelow(900000) + 100000)