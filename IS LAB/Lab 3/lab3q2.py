# Using ECC (Elliptic Curve Cryptography), encrypt the message "Secure Transactions" with
# the public key. Then decrypt the ciphertext with the private key to verify the original message.

from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Step 1: Generate ECC keys (for both the sender and receiver)
private_key = ECC.generate(curve='P-256')  # Receiver's private key
public_key = private_key.public_key()  # Receiver's public key

# Step 2: Serialize the public key (for demonstration, to mimic sending it)
public_key_bytes = public_key.export_key(format='PEM')

# Step 3: Derive a shared secret (in practice, the sender uses their private key to compute the same shared secret)
shared_secret = private_key.pointQ.x.to_bytes()  # Receiver's private key generates the shared secret

# Step 4: Hash the shared secret to create a key for AES encryption
hashed_shared_secret = SHA256.new(shared_secret).digest()

# Message to be encrypted
message = b"Secure Transactions"

# Step 5: AES Encryption using the derived key
cipher = AES.new(hashed_shared_secret, AES.MODE_CBC)
ciphertext = cipher.encrypt(pad(message, AES.block_size))
iv = cipher.iv  # Store the IV for decryption

print("Ciphertext (AES-Encrypted):", ciphertext.hex())

# Step 6: AES Decryption using the same shared secret
decipher = AES.new(hashed_shared_secret, AES.MODE_CBC, iv=iv)
plaintext = unpad(decipher.decrypt(ciphertext), AES.block_size)

print("Decrypted message:", plaintext.decode())