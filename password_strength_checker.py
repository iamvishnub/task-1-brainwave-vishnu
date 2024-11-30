import re

def check_password_strength(password):
    # Initialize score and feedback
    score = 0
    feedback = []

    # Check length
    if len(password) >= 12:
        score += 2
        feedback.append("✅ Password length is sufficient.")
    elif 8 <= len(password) < 12:
        score += 1
        feedback.append("⚠️ Password length is okay, but consider using 12 or more characters.")
    else:
        feedback.append("❌ Password is too short. Use at least 8 characters.")

    # Check for uppercase, lowercase, digits, and special characters
    if re.search(r'[A-Z]', password):
        score += 1
        feedback.append("✅ Contains uppercase letters.")
    else:
        feedback.append("❌ Add uppercase letters.")

    if re.search(r'[a-z]', password):
        score += 1
        feedback.append("✅ Contains lowercase letters.")
    else:
        feedback.append("❌ Add lowercase letters.")

    if re.search(r'[0-9]', password):
        score += 1
        feedback.append("✅ Contains digits.")
    else:
        feedback.append("❌ Add digits.")

    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
        feedback.append("✅ Contains special characters.")
    else:
        feedback.append("❌ Add special characters (e.g., !, @, #, $).")

    # Check for uniqueness (repeated patterns or common sequences)
    if re.search(r'(.)\1{2,}', password):
        feedback.append("⚠️ Avoid repeated characters.")
    else:
        score += 1

    if re.search(r'(123|abc|password|qwerty|letmein)', password.lower()):
        feedback.append("⚠️ Avoid common sequences or easy-to-guess patterns.")
    else:
        score += 1

    # Provide feedback based on score
    if score >= 7:
        feedback.insert(0, "🔒 Password Strength: Strong")
    elif 4 <= score < 7:
        feedback.insert(0, "🛡️ Password Strength: Moderate")
    else:
        feedback.insert(0, "🚨 Password Strength: Weak")

    return feedback

# Input and output
password = input("Enter your password: ")
feedback = check_password_strength(password)
for line in feedback:
    print(line)
