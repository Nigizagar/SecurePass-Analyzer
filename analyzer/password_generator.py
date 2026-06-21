import secrets
import string

def generate_secure_password(length=14, use_upper=True, use_lower=True, use_digits=True, use_symbols=True):
    """
    Membuat password acak yang aman menggunakan modul kriptografi 'secrets'.
    """
    charset = ""
    if use_upper: charset += string.ascii_uppercase
    if use_lower: charset += string.ascii_lowercase
    if use_digits: charset += string.digits
    if use_symbols: charset += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    if not charset:
        charset = string.ascii_lowercase + string.digits
    
    password = []
    if use_upper: password.append(secrets.choice(string.ascii_uppercase))
    if use_lower: password.append(secrets.choice(string.ascii_lowercase))
    if use_digits: password.append(secrets.choice(string.digits))
    if use_symbols: password.append(secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))
    
    remaining_length = length - len(password)
    password += [secrets.choice(charset) for _ in range(remaining_length)]

    secrets.SystemRandom().shuffle(password)
    
    return "".join(password)