from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

# Step 1: Generate RSA private and public keys
key = RSA.generate(2048)
private_key = key
public_key = key.publickey()

# Step 2: Encrypt the message (simulating an encrypted text for the signature)
message = b"Confidential Information"
cipher_rsa = PKCS1_OAEP.new(public_key)
ciphertext = cipher_rsa.encrypt(message)

# Step 3: Hash the encrypted message
hash_obj = SHA256.new(ciphertext)

# Step 4: Sign the hash of the ciphertext with the private key
signature = pkcs1_15.new(private_key).sign(hash_obj)

print(f"Ciphertext: {ciphertext.hex()}")
print(f"Signature: {signature.hex()}")

# Step 5: Verify the signature using the public key
try:
    pkcs1_15.new(public_key).verify(hash_obj, signature)
    print("The signature is valid.")
except (ValueError, TypeError):
    print("The signature is not valid.")
