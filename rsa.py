import random
import base64
import hashlib
import os

def gcm(a, b):
    # MDC = Máximo Divisor Comum
    while b:
        a, b = b, a % b
    return a # returns int


def lcm(a, b):
    # MMC = Mínimo Múltiplo Comum
    return a * b // gcm(a, b) # returns int

def modinv(a, m):
    # Inverso multiplicativo modular
    if gcm(a, m) != 1:
        raise ValueError("Modular inverse does not exist")
    return pow(a, -1, m) # returns int

def miller_rabin_primality(n, rounds = 40):
    """Baseado nas implementações de:
    https://gist.github.com/Ayrx/5884790
    https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Primality_Testing
    """
    if n == 2:
        return True
    if n & 1 == 0:
        return False
    
    r = 0 
    s = n - 1

    while s & 1 == 0:
        r += 1
        s = s >> 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True # returns bool 

def generate_prime(bits):
    # Gera um número primo aleatório com n bits de tamanho
    while True:
        p = random.randint(2 ** (bits - 1), 2 ** bits - 1)
        if miller_rabin_primality(p):
            return p # returns int

def coprime(a,b):
    # Testa primalidade entre si, mdc(a,b) = 1
    return gcm(a,b) == 1 # returns bool

def rsa_gen_keys():
    # Gera as chaves pública e privada
    p = generate_prime(1024)
    q = generate_prime(1024)

    while p == q:
        q = generate_prime(1024)
    
    n = p * q
    phi = lcm(p - 1, q - 1)

    e = random.randint(2, phi - 1)
    while not coprime(e, phi) and e < phi:
        e = random.randint(2, phi - 1)

    d = modinv(e, phi)
    key = [(e, n), (d, n)]
    return key # returns tuple

def rsa_encrypt(key, message):
    # Criptografa a mensagem com a chave pública
    e, n = key
    message = int.from_bytes(message, 'big')
    return pow(message, e, n) # returns int

def rsa_decrypt(key, message):
    # Descriptografa a mensagem com a chave privada
    d, n = key
    return pow(message, d, n) # returns int

""" Adição funções OAEP """

def mgf1(seed: bytes, length: int, hash_function=hashlib.sha3_256):
    """Implementado em https://en.wikipedia.org/wiki/Mask_generation_function"""
    hLen = hash_function().digest_size
    # https://www.ietf.org/rfc/rfc2437.txt
    # 1.If l > 2^32(hLen), output "mask too long" and stop.
    if length > (hLen << 32):
        raise ValueError("mask too long")
    # 2.Let T  be the empty octet string.
    T = b""
    # 3.For counter from 0 to \lceil{l / hLen}\rceil-1, do the following:
    # Note: \lceil{l / hLen}\rceil-1 is the number of iterations needed,
    #       but it's easier to check if we have reached the desired length.
    counter = 0
    while len(T) < length:
        # a.Convert counter to an octet string C of length 4 with the primitive I2OSP: C = I2OSP (counter, 4)
        C = int.to_bytes(counter, 4, 'big')
        # b.Concatenate the hash of the seed Z and C to the octet string T: T = T || Hash (Z || C)
        T += hash_function(seed + C).digest()
        counter += 1
    # 4.Output the leading l octets of T as the octet string mask.
    return T[:length]

def xor(data: bytes, mask: bytes):
    result = b""
    for i in range(max(len(data), len(mask))):
        if i < len(data) and i < len(mask):
            result += bytes([data[i] ^ mask[i]])
        elif i < len(data):
            result += bytes(data[i])
        else:
            break
    return result

def oaep_encode(msg: bytes, k: int, label = b""):
    msg_size = len(msg)
    lhash = hashlib.sha3_256(label).digest()
    hash_size = len(lhash)
    ps = b"\x00" * (k - msg_size - 2 * hash_size - 2)
    db = lhash + ps + b"\x01" + msg
    seed = os.urandom(hash_size)
    db_mask = mgf1(seed, k - hash_size - 1)
    masked_db = xor(db, db_mask)
    seed_mask = mgf1(masked_db, hash_size)
    masked_seed = xor(seed, seed_mask)
    em = b"\x00" + masked_seed + masked_db
    return em

def oaep_decode(em: bytes, k: int, label = b""):
    lhash = hashlib.sha3_256(label).digest()
    em = em.to_bytes(k, 'big')
    # em_len = len(em)
    hash_size = len(lhash)

    _, masked_seed, masked_db = em[:1], em[1:hash_size + 1], em[hash_size + 1:]
    seed_mask = mgf1(masked_db, hash_size)
    seed = xor(masked_seed, seed_mask)
    db_mask = mgf1(seed, k - hash_size - 1)
    db = xor(masked_db, db_mask)
    i = hash_size
    
    while i < len(db):
        if db[i] == 1:
            i += 1
            continue
        elif db[i] == 1:
            i += 1
            break
    
    msg = db[i:]
    return msg

def rsa_encrypt_oaep(key, message):
    # Criptografa a mensagem com a chave pública
    e, n = key
    aux = n.bit_length() // 8
    return rsa_encrypt(key, oaep_encode(message, aux))

def rsa_decrypt_oaep(key, message):
    # Descriptografa a mensagem com a chave privada
    d, n = key
    aux = n.bit_length() // 8
    return oaep_decode(rsa_decrypt(key, message), aux)


if __name__ == "__main__":
    # Teste
    # key = rsa_gen_keys()
    # print(key)
    # message = b'teste'
    # print(message)
    # encrypted = rsa_encrypt_oaep(key[0], message)
    # print(encrypted)
    # decrypted = rsa_decrypt_oaep(key[1], encrypted)
    # print(decrypted)