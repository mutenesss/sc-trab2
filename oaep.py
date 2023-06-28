import random
import base64
import hashlib
from rsa import *

def mgf1(seed: bytes, length: int, hash_function=hashlib.sha3_256):
    """Implementado em https://en.wikipedia.org/wiki/Mask_generation_function"""
    hLen = hash_function().digest_size
    if length > (hLen << 32):
        raise ValueError("mask too long")
    mask = b""
    counter = 0
    while len(mask) < length:
        C = int.to_bytes(counter, 4, 'big')
        mask += hash_function(seed + C).digest()
        counter += 1
    return mask[:length]

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
    print(msg)
    # Hash da label
    lhash = hashlib.sha3_256(label).digest()

    # Obtem tamanho da mensagem e do hash
    msg_length = len(msg)
    hash_size = len(lhash)

    # Criacao do padding ps
    zero_pad = b"\x00" * (k - msg_length - 2 * hash_size - 2)

    # Criacao do bloco de dados DB
    db = lhash + zero_pad + b"\x01" + msg

    # Soma mask e DB
    seed = os.urandom(hash_size)
    db_mask = mgf1(seed, k - hash_size - 1)
    masked_db = xor(db, db_mask)

    # Gera mask para seed
    seed_mask = mgf1(masked_db, hash_size)

    # Soma seed e mask e retorna a mensagem criptografada
    masked_seed = xor(seed, seed_mask)
    em = b"\x00" + masked_seed + masked_db
    return em # returns bytes


def oaep_decode(em: bytes, k: int, label = b""):
    if em[:1] != b'\x00':
        raise ValueError("Invalid padding")
    
    # Gera hash da label
    lhash = hashlib.sha3_256(label).digest()

    # Obtem tamanho do hash
    hash_size = len(lhash)

    # Separa a mensagem em blocos
    masked_seed, masked_db = em[1:hash_size + 1], em[hash_size + 1:]
    
    # Gera mask para seed
    seed_mask = mgf1(masked_db, hash_size)

    # Recupera seed
    seed = xor(masked_seed, seed_mask)

    # Gera db mask
    db_mask = mgf1(seed, k - hash_size - 1)

    # Recupera db
    db = xor(masked_db, db_mask)

    # Recupera mensagem
    lhash2, zero_pad_msg = db[:hash_size], db[hash_size:]

    if lhash != lhash2:
        raise ValueError("Hashes don't match")
    
    print(zero_pad_msg)
    
    for i in range(0, len(zero_pad_msg), 2):
        if zero_pad_msg[i : i + 1] == b'\x00':
            break
        msg = zero_pad_msg[:i + 1]
    
    
    # if zero_pad_msg[i - 1] != b'\x01':
    #     raise ValueError("Invalid Padding")
    
    # for j in range(len(zero_pad_msg) - len(msg)):
    #     if zero_pad_msg[j+1] != b'\x00':
    #         raise ValueError("Invalid Padding")
    print(msg)
    return msg


key = b'string of some more than 16 bytes'
# data = b'sample message for testing'
data = b'outra mensagem de teste com tamanho maior'
result_enc = encrypt(key, data) # bytes
rsa_keys = rsa_gen_keys()
rsa_enc = rsa_encrypt(rsa_keys[0], result_enc) # int
rsa_dec = rsa_decrypt(rsa_keys[1], rsa_enc)

# AES => bytes => bytes => RSA => bytes => int => OAEP
# => int => bytes => RSA => bytes => bytes => AES

rsa_enc_bytes = rsa_enc.to_bytes(1024, 'little')
oaep_encoded = oaep_encode(rsa_enc_bytes, 1024) # bytes

oaep_decoded = oaep_decode(oaep_encoded, 1024) # bytes

aux = int.from_bytes(oaep_decoded, 'little')
rsa_dec2 = rsa_decrypt(rsa_keys[1], aux) # int

aux2 = rsa_dec2.to_bytes(1024, 'little')
aes_dec = decrypt(key, aux2) # bytes
print(aes_dec) 