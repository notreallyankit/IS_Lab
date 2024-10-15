# Design a Python-based experiment to analyze the performance of MD5,
# SHA-1, and SHA-256 hashing techniques in terms of computation time
# and collision resistance. Generate a dataset of random strings ranging
# from 50 to 100 strings, compute the hash values using each hashing
# technique, and measure the time taken for hash computation. Implement
# collision detection algorithms to identify any collisions within the
# hashed dataset.

import hashlib

def hash_text_sha256(input_text):
    # Create a new sha256 hash object
    sha256_hash = hashlib.sha256()

    # Update the hash object with the bytes of the input text
    sha256_hash.update(input_text.encode('utf-8'))

    # Return the hexadecimal digest of the hash
    return sha256_hash.hexdigest()

# Example usage
input_text = "Hash this text using SHA-256"
hashed_value = hash_text_sha256(input_text)
print(f"Original Text: {input_text}")
print(f"SHA-256 Hash: {hashed_value}")