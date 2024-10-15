# Using RSA, encrypt the message "Asymmetric Encryption" with the public key (n, e). Then
# decrypt the ciphertext with the private key (n, d) to verify the original message.

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

key=RSA.generate(2048)
pvtkey=key.export_key()
pubkey=key.publickey().export_key()
msg="Asymmetric key".encode('utf-8')

def rsaencrpyt(msg,key):
    rsapublickey=RSA.import_key(pubkey)
    cipher=PKCS1_OAEP.new(rsapublickey)
    encryptedmsg=cipher.encrypt(msg)
    return binascii.hexlify(encryptedmsg).decode('utf-8')

def rsadecrypt(msg, key):
    rsapvtkey=RSA.import_key(pvtkey)
    cipher=PKCS1_OAEP.new(rsapvtkey)
    decryptedmsg=cipher.decrypt(binascii.unhexlify(msg))
    return decryptedmsg.decode('utf-8')

rsatext=rsaencrpyt(msg,pubkey)
text2=rsadecrypt(rsatext,pvtkey)

print(rsatext)
print(text2)

