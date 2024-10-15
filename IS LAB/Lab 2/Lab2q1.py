from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

key=b'abcdefgh'

cipher=DES.new(key,DES.MODE_ECB)
msg=b'this is ankit tojo doing DES'
paddedmsg=pad(msg,DES.block_size)

ciphertext=cipher.encrypt(paddedmsg)
print('Ciphertext: ',ciphertext)

decipher=DES.new(key,DES.MODE_ECB)
plaintext=unpad(decipher.decrypt(ciphertext),DES.block_size)
print('Plaintext: ',plaintext)