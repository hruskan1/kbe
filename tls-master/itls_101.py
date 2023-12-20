#Task 5

from tls_101 import Agent
from dh_alg import P,G,diffie_hellman,get_key_from_secret
import bulk_cipher as bc

class MITM(Agent):

    def receive_public_key(self,public_key):
        #proof of concept only

        if not self.shared_key: #Alice 
             self.shared_key = get_key_from_secret(diffie_hellman(public_key,self.private_key,self.p))
        else: #Bob
             self.shared_key_2 = get_key_from_secret(diffie_hellman(public_key,self.private_key,self.p))

    def intercept_message(self,encrypted_msg):
        iv = encrypted_msg[:16]
        cipher = encrypted_msg[16:]
        self.msg = bc.decrypt(self.shared_key,iv,cipher)

        return(iv + bc.encrypt(self.shared_key_2,iv,self.msg))



alice = Agent("I'M 5UppER Kewl h4zKEr")
bob = Agent()
mallory = MITM('M')

# Alice has da message, Bob doesn't
assert alice.msg
assert not bob.msg

# Negotiate parameters publicly
mallory.receive_public_data(*alice.send_public_data())
bob.receive_public_data(*mallory.send_public_data())
mallory.receive_public_data(*bob.send_public_data())
alice.receive_public_data(*mallory.send_public_data())

# Exchange keys publicly
mallory.receive_public_key(alice.send_public_key())
bob.receive_public_key(mallory.send_public_key())
mallory.receive_public_key(bob.send_public_key())
alice.receive_public_key(mallory.send_public_key())

print("Alice key:",alice.shared_key)
print("Mallory key:", mallory.shared_key)
print('--------------------------------')
print("Bob key:",bob.shared_key)
print("Mallory key:", mallory.shared_key_2)


# Pass da message
bob.receive_message(mallory.intercept_message(alice.send_message()))
# Bob has it now
assert bob.msg == alice.msg
# Mallory too
assert mallory.msg == alice.msg
