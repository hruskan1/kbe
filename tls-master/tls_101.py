# Task 4

import sys
import os

from dh_alg import P,G,diffie_hellman,get_key_from_secret
import bulk_cipher as bc

BLOCK_SIZE = 16

class Agent():  
    def __init__(self,msg=None, p=P, g=G):
        self.msg = msg
        self.p = p
        self.g = g
        self.private_key = int.from_bytes(os.urandom(4),sys.byteorder)
        self.shared_key = None

    def send_public_data(self):

        return self.p,self.g

    def receive_public_data(self,p,g):
        self.p = p
        self.g = g
        pass

    def send_public_key(self):
        return diffie_hellman(self.g,self.private_key,self.p)

    def receive_public_key(self,public_key)  -> None:
        self.shared_key = get_key_from_secret(diffie_hellman(public_key,self.private_key,self.p))
        

    def send_message(self):
        iv = os.urandom(16)
        return(iv + bc.encrypt(self.shared_key,iv,self.msg))

    def receive_message(self,encrypted_msg):
        iv = encrypted_msg[:16]
        cipher = encrypted_msg[16:]
        self.msg = bc.decrypt(self.shared_key,iv,cipher)
        




alice = Agent("I'M 5UppER Kewl h4zKEr")
bob = Agent()


# Alice has da message, Bob doesn't
assert alice.msg
assert not bob.msg

# Negotiate parameters publicly
bob.receive_public_data(*alice.send_public_data())
alice.receive_public_data(*bob.send_public_data())


# Exchange keys publicly

bob.receive_public_key(alice.send_public_key())
alice.receive_public_key(bob.send_public_key())

# Pass da message
bob.receive_message(alice.send_message())

# Bob has it now
assert alice.msg == bob.msg
