# Encrypt the following block of data using DES with the key "A1B2C3D4E5F60708". The data
# to be encrypted is: Mathematica
# Block1: 54686973206973206120636f6e666964656e7469616c206d657373616765
# Block2: 416e64207468697320697320746865207365636f6e6420626c6f636b

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad,unpad

key1=b"A1B2C3D4E5F60708"
key2=b"416e64207468697320697320746865207365636f6e6420626c6f636b"
msg=b"Mathematica"

cipher=DES.new(key1,DES.MODE_ECB)
paddedmsg=pad(msg,DES.block_size)

ciphertext=cipher.encrypt(paddedmsg)
print("Key 1 ciphertext: ",ciphertext)
