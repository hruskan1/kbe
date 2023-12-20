import rsa
pP = 13604067676942311473880378997445560402287533018336255431768131877166265134668090936142489291434933287603794968158158703560092550835351613469384724860663783
pQ = 20711176938531842977036011179660439609300527493811127966259264079533873844612186164429520631818559067891139294434808806132282696875534951083307822997248459

def generate_key(e:int=3, p:int = pP,q:int = pQ):
    mod = (p-1)*(q-1)
    
    try:
        d = invmod(e,mod)
    except Exception:
        d = 0

    return e,d #public, private

def encrypt(pub_key:int,_bytes:bytes) -> bytes:
    msg = int_from_bytes(_bytes)
    cipher = encrypt_int(pub_key,msg)
    return int_to_bytes(cipher)

def decrypt(priv_key,_bytes:bytes) -> bytes:
    cipher = int_from_bytes(_bytes)
    msg = decrypt_int(priv_key,cipher)
    return int_to_bytes(msg)


def encrypt_int(pub_key:int,_int:int,n:int = pP*pQ) -> int:
    return pow(_int,pub_key,n)
    

def decrypt_int(priv_key:int,_int:int,n:int = pP*pQ) -> int:
    return pow(_int,priv_key,n)


def egcd(a:int,b:int)-> tuple:
    if (a == 0):
        return (b,0,1)
    else:
        gcd,y,x = egcd(b % a, a)
        return (gcd,x - (b//a) * y, y)


def invmod(a:int,mod:int) -> int:
    gcd,x,y = egcd(a,mod)
    if gcd != 1:
        raise Exception("Inverse of {} does not exists in field  Z_{}".format(a,mod))
    else:
        return x % mod



def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')
    
def int_from_bytes(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, 'big')





