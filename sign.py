import hashlib
import base64
from rsa import rsa_encrypt, rsa_decrypt

def sign(msg: bytes, keys):
    hash = hashlib.sha3_256(msg).digest()
    sig = rsa_encrypt(keys[0], hash)
    sig = base64.b64encode(sig.to_bytes(256, 'big'))
    return sig

def verify(msg: bytes, sig: bytes, keys):
    hash = hashlib.sha3_256(msg).digest()
    sig = base64.b64decode(sig)
    sig = int.from_bytes(sig, 'big')
    hash_sig = rsa_decrypt(keys[1], sig).to_bytes(256, 'big')
    # Remove padding da hash_sig calculada
    for i in range(0, len(hash_sig)):
        if hash_sig[i] != 0:
            hash_sig = hash_sig[i:]
            break
    return hash == hash_sig

