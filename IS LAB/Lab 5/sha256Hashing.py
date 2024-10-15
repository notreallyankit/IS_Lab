#SHA 256
import hashlib

def sha256_hash(data):
    # Create a new SHA-256 hash object
    sha256 = hashlib.sha256()

    # Update the hash object with the bytes-like object (data)
    sha256.update(data)

    # Return the hexadecimal digest of the hash
    return sha256.hexdigest()

# Input data to hash
data = b"Secure Transactions using SHA-256"

# Perform SHA-256 hashing
hash_value = sha256_hash(data)

# Print the resulting hash
print(f"SHA-256 Hash: {hash_value}")