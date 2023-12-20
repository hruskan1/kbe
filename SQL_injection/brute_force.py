import hashlib
import itertools

# This script creates all variations of 5  lower letter/digit password and its hashes 
# and compare it with stolen credentials from database of hashes.
    
size_of_password = 5
my_hash = '4a90c2db5ab816ca36e23bdcfa51201a2fbd7808'
my_salt = '7aac6'

possible_characters = []

#add lower case alphabet
for i in range(26):
    possible_characters.append(chr(i+ord('a')))
#add numbers
for i in range(10):
    possible_characters.append(chr(i+ord('0')))

print(possible_characters)

index = 0
for password in itertools.product(possible_characters,repeat=size_of_password):
    
    salted_password = "".join(password) + my_salt
    
    hash_object = hashlib.sha1(salted_password.encode())
    hash_hex = hash_object.hexdigest()
    index += 1
    if (index % 10000 == 0):
        print("ID:{}\t pass: {}\t hash: {}".format(index,"".join(password),hash_hex))
    if (hash_hex == my_hash):
        print("Success: ID:{}\t pass: {}\t hash: {}".format(index,"".join(password),hash_hex))
        break
