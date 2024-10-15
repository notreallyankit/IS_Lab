#AES-256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

msg=b"Performance Testing of Encryption Algorithms"
AES_key=get_random_bytes(32)  #24 for AES-192, 16 for AES-128

aes_cipher = AES.new(AES_key, AES.MODE_ECB)
padded_message = pad(msg, AES.block_size)
aes_ciphertext=aes_cipher.encrypt(padded_message)
print(aes_ciphertext)

aes_plaintext=unpad(aes_cipher.decrypt(aes_ciphertext),AES.block_size)
print(aes_plaintext)





