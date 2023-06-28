import hashlib
import os

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
    
    for i in range(0, len(zero_pad_msg)):
        if zero_pad_msg[i] == 0:
            # teste se padding = 0
            continue
        if zero_pad_msg[i] == 1:
            # teste do byte 1
            return zero_pad_msg[i + 1:]
            
    # if zero_pad_msg[i - 1] != b'\x01':
    #     raise ValueError("Invalid Padding")
    
    # for j in range(len(zero_pad_msg) - len(msg)):
    #     if zero_pad_msg[j+1] != b'\x00':
    #         raise ValueError("Invalid Padding")
    