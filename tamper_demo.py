import os
import sqlite3
from app import db, decrypt_bytes, encrypt_bytes

# Get the latest uploaded paper
con = db()
paper = con.execute(
    "SELECT * FROM papers ORDER BY id DESC LIMIT 1"
).fetchone()
con.close()

if not paper:
    print("No question paper found.")
    exit()

storage_path = os.path.join("storage", paper["encrypted_file"])

# Read encrypted paper
with open(storage_path, "rb") as f:
    encrypted_data = f.read()

# Decrypt it
original_data = decrypt_bytes(encrypted_data)

# Simulate tampering
tampered_data = original_data + b"\nTAMPERED CONTENT"

# Encrypt the modified paper again
tampered_encrypted = encrypt_bytes(tampered_data)

# Replace stored encrypted file
with open(storage_path, "wb") as f:
    f.write(tampered_encrypted)

print("======================================")
print("TAMPERING SIMULATION COMPLETED")
print("======================================")
print("The question paper was modified.")
print("The ORIGINAL SHA-256 hash in the database")
print("was NOT changed.")
print("Now access the paper from the website.")
print("The system should detect tampering.")