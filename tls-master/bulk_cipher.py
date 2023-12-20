#Task 3

import random
import string
import os
import pyaes

BLOCK_SIZE = 16

def encrypt_aes_block(plaintext, key):

    if type(key) != bytes or type(key) != bytearray:
        if type(key) == str:
            key = bytes(key, 'ascii')
        else:
            key = bytes(key)
    if type(plaintext) != bytes or type(key) != bytearray:
        if type(plaintext) == str:
            plaintext = bytes(plaintext, 'ascii')
        else:
            plaintext = bytes(plaintext)

    if len(key) != 16 or len(plaintext) != 16:
        raise ValueError("Size of plaintext or key has to be 16 bytes")

    pyaesECB = pyaes.AESModeOfOperationECB(key)
    ciphertext = pyaesECB.encrypt(plaintext)

    return ciphertext

def decrypt_aes_block(ciphertext, key):

    if type(key) != bytes or type(key) != bytearray:
        if type(key) == str:
            key = bytes(key, 'ascii')
        else:
            key = bytes(key)
    if type(ciphertext) != bytes or type(key) != bytearray:
        if type(ciphertext) == str:
            ciphertext = bytes(ciphertext, 'ascii')
        else:
            ciphertext = bytes(ciphertext)

    if len(key) != 16 or len(ciphertext) != 16:
        raise ValueError("Size of ciphertext or key has to be 16 bytes")

    pyaesECB = pyaes.AESModeOfOperationECB(key)
    ciphertext = pyaesECB.decrypt(ciphertext)

    return ciphertext

def pad(x):

    if type(x) != bytearray:
        raise TypeError("Input has to be bytearray type!")

    pad_size = 16 - (len(x) % 16)

    return x.ljust(len(x)+pad_size, bytes([pad_size]))

def unpad(x):

    if type(x) != bytearray:
        raise TypeError("Input has to be bytearray type!")

    pad_size = int(x[-1])
    return x[:len(x)-pad_size]

def encrypt_aes_cbc(key,iv, plaintext):

    padded = pad(plaintext)
    split = [padded[i:i+16] for i in range(0,len(padded),16)]

    cipher = bytearray()

    for i, block in enumerate(split):

        if i == 0:
            #xor with iv
            cipher += encrypt_aes_block(xor(block,iv),key)
        else:
            pass
            #xor with last block of ciphertext
            cipher += encrypt_aes_block(xor(block,cipher[-16:]),key)

    return cipher

def decrypt_aes_cbc(key,iv, ciphertext):

    unpadded_plaintext = inner_decrypt_aes_cbc(ciphertext,key,iv)

    return unpad(unpadded_plaintext)

def inner_decrypt_aes_cbc(ciphertext,key,iv):
    c = ciphertext
    
    split = [c[i:i+16] for i in range(0,len(c),16)]
    plaintext = bytearray()

    for i,block in enumerate(split):
        if i == 0:
            #xor with iv
            d = decrypt_aes_block(block,key)
            plaintext += xor(d,iv)
        else:
            #xorr with last block of ciphertext
            d = decrypt_aes_block(block,key)
            plaintext += xor(d,split[i-1])


    return plaintext

def xor(b1,b2):
    if not (type(b1) == bytearray or type(b1) == bytes):
        raise TypeError("Input type has to be either bytes or bytearray")
  
    return bytearray( [ x^y for x,y in zip(b1,b2) ] )

def encrypt(key:bytes,iv:bytes,msg:string) -> bytes:
    msg = bytearray(msg, 'ascii')
    return encrypt_aes_cbc(key,iv,msg)

def decrypt(key:bytes,iv:bytes,msg:string) -> str:
    decipher = decrypt_aes_cbc(key,iv,msg)
    return decipher.decode()



key = os.urandom(BLOCK_SIZE)
iv = os.urandom(BLOCK_SIZE)
msg = ''.join(random.choice(string.ascii_lowercase) for i in range(1024))
assert decrypt(key, iv, encrypt(key, iv, msg)) == msg


