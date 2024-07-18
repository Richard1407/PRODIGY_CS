import re

def password_strength(password):
    strength = 0
    feedback = ""

    # Length
    if len(password) < 8:
        feedback += "Password is too short. It should be at least 8 characters long.\n"
    else:
        strength += 1

    # Uppercase letters
    if re.search(r"[A-Z]", password):
        strength += 1
    else:
        feedback += "Password should contain at least one uppercase letter.\n"

    # Lowercase letters
    if re.search(r"[a-z]", password):
        strength += 1
    else:
        feedback += "Password should contain at least one lowercase letter.\n"

    # Numbers
    if re.search(r"\d", password):
        strength += 1
    else:
        feedback += "Password should contain at least one number.\n"

    # Special characters
    if re.search(r"[!@#$%^&*()_+=-{};:'<>,./?]", password):
        strength += 1
    else:
        feedback += "Password should contain at least one special character.\n"

    # Password strength levels
    if strength == 5:
        feedback = "Strong password!"
    elif strength >= 3:
        feedback = "Medium password. Consider adding more complexity."
    else:
        feedback = "Weak password. Please improve the password strength."

    return feedback

def main():
    password = input("Enter a password: ")
    print(password_strength(password))

if __name__ == "__main__":
    main()