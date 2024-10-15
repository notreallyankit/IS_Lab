# Implement the hash function in Python. Your function should start with
# an initial hash value of 5381 and for each character in the input string,
# multiply the current hash value by 33, add the ASCII value of the
# character, and use bitwise operations to ensure thorough mixing of the
# bits. Finally, ensure the hash value is kept within a 32-bit range by
# applying an appropriate mask

def hash_func(msg):
    hash=5381
    for c in msg:
        hash=(hash*33)^ord(c)
        hash=hash & 0xFFFFFFFF
    return hash

msg="test sample case"
hashval=hash_func(msg)
print("Hash value: ",hashval)