#Task 9

#SHA-1 hash algorithm
from rsa_alg import invmod
import hashlib

P = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
Q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
G = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291


# y is public key (y = G**x) #  0<k<2**16
# x is private key
msg_hash=0x2bc546792a7624fb6e972b0fb85081fd20a8a28
y = 0x33ff14f19fa9cf09b28747cdfe97252c4be46c9c4c2ee68a2231cb4b262dd839962eff659bd30f706e6cb2470117f211eadfadeac267bc4fecde6d4c058cdf5d7b8c75ba663ce7a87d22b171413b8d3b6ceee31b139051c385a06b8b2e2e587a15e87381c93f866bf7b122fda5c1f44d20480137906ed6026ed96c3793fde263
r = 548099063082341131477253921760299949438196259240
s = 857042759984254168557880549501802188789837994940
key_hash = 0x8f96763dea794b79094eef4717ceb5f10631d634


def recover_private_key():
    #if brute force of k yeilds x such that g**x = y, we were successful
    
    # compute r^(-1) mod q
    r_inv = invmod(r,Q)
    for k in range(0,2**16):
        print("\r{}/{}".format(k,2**16),end="")
        x = ((k*s - msg_hash)*r_inv) % Q
        
        # if you have key hash H(x)
        _bytes = bytes(hex(x)[2:].encode()) #
        if (hashlib.sha1(_bytes).digest().hex() == hex(key_hash)[2:]):
            return x
        
        #if you do not have key hash
        #if (pow(G,x,P) == y): 
            #return x
    
           


x = recover_private_key()

assert(pow(G,x,P) == y)
print("\nBruteforced x:")
print(hex(x))
            
            
