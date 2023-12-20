# Task 1 & Task 2
import hashlib
import pyaes
import os

def diffie_hellman(k,exp,mod) -> int:
    return pow(k,exp,mod)

def get_key_from_secret(secret) -> bytes:
    h = hex(secret)
    #Unknown bug with secret larger then 513 hex decimals.
    _bytes = bytes.fromhex(h[2:512])
    return hashlib.sha1(_bytes).digest()[:16]


    
A_PRIV = 125
B_PRIV = 111
G = 2
P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
#Alice
a_pub = diffie_hellman(G,A_PRIV,P)

#Bob
b_pub = diffie_hellman(G,B_PRIV,P)

shared_key_via_bob = diffie_hellman(a_pub,B_PRIV,P)
shared_key_via_alice = diffie_hellman(b_pub,A_PRIV,P)
secret = shared_key_via_alice
assert shared_key_via_alice == shared_key_via_bob 

key = get_key_from_secret(secret)
assert (len(key) == 16)




    

    
