from werkzeug.security import generate_password_hash, check_password_hash


password = input('Enter password')
hashed_password=generate_password_hash(password, salt_length=8)
print(hashed_password)