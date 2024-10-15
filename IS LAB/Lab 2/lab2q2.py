# Encrypt the message "Sensitive Information" using AES-128 with the following key:
# "0123456789ABCDEF0123456789ABCDEF". Then decrypt the ciphertext to verify the
# original message.

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad

key=b"0123456789ABCDEF0123456789ABCDEF"
msg=b'Sensitive Information'

paddedmsg=pad(msg,AES.block_size)
cipher=AES.new(key,AES.MODE_ECB)

ciphertext=cipher.encrypt(paddedmsg)
print('Ciphertext: ',ciphertext)

decipher=AES.new(key,AES.MODE_ECB)
plaintext=unpad(decipher.decrypt(ciphertext),AES.block_size)
print('Plaintext: ',plaintext)