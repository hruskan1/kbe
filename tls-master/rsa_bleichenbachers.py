# Task 8

from rsa_alg import *
import hashlib
import re

p = 19480788016963928122154998009409704650199579180935803274714730386316184054417141690600073553930946636444075859515663914031205286780328040150640437671830139
q = 17796969605776551869310475203125552045634696428993510870214166498382761292983903655073238902946874986503030958347986885039275191424502139015148025375449097

def generate_message_hash(msg:bytes, n:int=p*q ):
    return hashlib.sha1(msg).digest()
    

def generate_signature(priv_key:int, sha1_hash:bytes,n:int=p*q) -> bytes:
    
    prefix = b'\x00\x01'
    asni = b'\x30\x21\x30\x09\x06\x05\x2B\x0E\x03\x02\x1A\x05\x00\x04\x14'

    tot_size = (n.bit_length() + 7) // 8
    current_size = (len(prefix +b'\x00' + asni + sha1_hash ))

    message_bytes = prefix + b'\xFF'*(tot_size - current_size)  + b'\x00' + asni + sha1_hash

    message_int = int_from_bytes(message_bytes)
    signature = pow(message_int,priv_key,n)

    return signature

def verify_signature(pub_key:int,signature:int,sha1_hash:bytes, n:int=p*q) -> bool:
    
    ANSI = '3021300906052B0E03021A05000414'.lower()
    retreived_hash = int_to_bytes( pow( signature, pub_key, n) )
    retreived_hash_hex = retreived_hash.hex()
    sha1_hash_hex = sha1_hash.hex()

    #print("Retrived hash:",retreived_hash_hex)
    #print("Data hash:",'00'+ANSI+sha1_hash_hex)

    return re.match('01f*00'+ ANSI + sha1_hash_hex,retreived_hash_hex) is not None

def fake_signature(sha1_hash:bytes,n:int=p*q):
    
    # approach based on C^3 = (A-B)^3 = A^3 - 3A^2B + 3AB^2 - B^3 not working
    #asni = b'\x30\x21\x30\x09\x06\x05\x2B\x0E\x03\x02\x1A\x05\x00\x04\x14'
    #d = b"\x00"+asni+sha1_hash+b"\x03"
    #n = 2**(8*(len(d)-1)) - int_from_bytes(d)
    #n +=   - n%3
    #assert(n % 3 == 0)
    #fake_sig = 2**(8*2*(len(d)-1))- (n//3) 

    prefix = b'\x00\x01'
    asni = b'\x30\x21\x30\x09\x06\x05\x2B\x0E\x03\x02\x1A\x05\x00\x04\x14'
    garbage = b'\xFF'*80 #the bigger the better
    #take for example just FF pad
    byte_hash_pattern_look_alike  = prefix + b'\xFF\x00' +asni+sha1_hash + garbage
    hash_pattern_look_alike = int_from_bytes(byte_hash_pattern_look_alike)
    fake_signiture = find_invpow(hash_pattern_look_alike, 3) #assume e=3

    #return prefix + b'\xFF\x00' +asni+sha1_hash, fake_signiture
    return fake_signiture
    

def find_invpow(x,n):
    
    """Finds the integer component of the n'th root of x,
    an integer such that y ** n <= x < (y + 1) ** n.
    https://stackoverflow.com/questions/55436001/cube-root-of-a-very-large-number-using-only-math-library
    """
    high = 1
    while high ** n < x:
        high *= 2
    low = high//2
    while low < high:
        mid = (low + high) // 2
        if low < mid and mid**n < x:
            low = mid
        elif high > mid and mid**n > x:
            high = mid
        else:
            return mid
    return mid + 1


message = b'Trust no one'
msg_sha1 = generate_message_hash(message)
public_key,private_key = generate_key(p=p, q=q, e=3)

signature = generate_signature(private_key, msg_sha1,p*q)

assert verify_signature(public_key, signature, msg_sha1)
assert verify_signature(public_key, fake_signature(msg_sha1), msg_sha1)
